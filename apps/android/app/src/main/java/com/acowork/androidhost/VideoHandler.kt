package com.acowork.androidhost

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.CamcorderProfile
import android.media.MediaRecorder
import android.os.Build
import android.os.Handler
import android.os.SystemClock
import android.view.Surface
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** MediaRecorder plus a Camera2 record template. One session at a time. */
object VideoHandler {
    private val recording = AtomicBoolean(false)
    private var recorder: MediaRecorder? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var file: File? = null
    private var startedAt = 0L
    private var audioOn = false

    private var owner: String? = null

    fun handle(context: Context, handler: Handler, workDir: String, args: JSONObject, agent: String): JSONObject {
        val op = args.optString("op")
        val duration = if (args.has("duration_ms")) args.getLong("duration_ms") else -1L
        if (duration >= 0 && op.isEmpty()) {
            val started = start(context, handler, workDir, args, agent) ?: return DeviceJson.err("failed", "video did not start")
            if (started.optBoolean("ok") == false) return started
            val deadline = SystemClock.elapsedRealtime() + duration
            while (recording.get() && SystemClock.elapsedRealtime() < deadline) {
                Thread.sleep(50)
            }
            return stop(agent)
        }
        return when (op) {
            "", "start" -> start(context, handler, workDir, args, agent) ?: DeviceJson.err("failed", "video did not start")
            "stop" -> stop(agent)
            "status" -> status()
            else -> DeviceJson.err("invalid_argument", "op must be start, stop, or status")
        }
    }

    @SuppressLint("MissingPermission")
    private fun start(context: Context, handler: Handler, workDir: String, args: JSONObject, agent: String): JSONObject? {
        if (recording.get()) return DeviceJson.err("busy", DeviceBridge.busyMessage("video", owner))
        val audio = !args.has("audio_enabled") || args.getBoolean("audio_enabled")
        val perms = mutableListOf(android.Manifest.permission.CAMERA)
        if (audio) perms.add(android.Manifest.permission.RECORD_AUDIO)
        val missing = DevicePermissions.firstMissing(context, perms)
        if (missing != null) return DevicePermissions.required(context, missing)
        if (!DeviceBridge.tryAcquireCamera(agent)) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("camera", DeviceBridge.cameraHolder()))
        }
        if (audio && !DeviceBridge.tryAcquireMic(agent)) {
            DeviceBridge.releaseCamera()
            return DeviceJson.err("busy", DeviceBridge.busyMessage("microphone", DeviceBridge.micHolder()))
        }
        return try {
            DeviceBridge.pushKind("camera")
            if (audio) DeviceBridge.pushKind("microphone")
            audioOn = audio
            owner = DeviceBridge.agentLabel(agent)
            val manager = context.getSystemService(CameraManager::class.java)
            val cameraId = PhotoHandler.pickCamera(manager, args)
            val out = DeviceJson.captureFile(
                workDir,
                args.optString("output_path").ifBlank { null },
                extFor(args.optString("output_format", "mpeg_4")),
            )
            val rec = if (Build.VERSION.SDK_INT >= 31) MediaRecorder(context) else MediaRecorder()
            configure(context, rec, args, out, audio, cameraId)
            rec.prepare()
            val surface: Surface = rec.surface
            val deviceRef = AtomicReference<CameraDevice?>()
            val errorRef = AtomicReference<String?>()
            val opened = CountDownLatch(1)
            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(cam: CameraDevice) {
                    deviceRef.set(cam)
                    opened.countDown()
                }
                override fun onDisconnected(cam: CameraDevice) {
                    errorRef.set("camera disconnected")
                    cam.close()
                    opened.countDown()
                }
                override fun onError(cam: CameraDevice, error: Int) {
                    errorRef.set("camera error $error")
                    cam.close()
                    opened.countDown()
                }
            }, handler)
            if (!opened.await(8, TimeUnit.SECONDS) || errorRef.get() != null) {
                rec.release()
                throw IllegalStateException(errorRef.get() ?: "openCamera timed out")
            }
            val cam = deviceRef.get()!!
            val configured = CountDownLatch(1)
            val sessionRef = AtomicReference<CameraCaptureSession?>()
            cam.createCaptureSession(listOf(surface), object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    sessionRef.set(s)
                    configured.countDown()
                }
                override fun onConfigureFailed(s: CameraCaptureSession) {
                    errorRef.set("session configure failed")
                    configured.countDown()
                }
            }, handler)
            if (!configured.await(8, TimeUnit.SECONDS) || errorRef.get() != null) {
                cam.close()
                rec.release()
                throw IllegalStateException(errorRef.get() ?: "session configure timed out")
            }
            val template = when (args.optString("template", "record")) {
                "manual" -> CameraDevice.TEMPLATE_MANUAL
                "preview" -> CameraDevice.TEMPLATE_PREVIEW
                else -> CameraDevice.TEMPLATE_RECORD
            }
            val request = cam.createCaptureRequest(template)
            request.addTarget(surface)
            CameraRequests.apply(request, args.optJSONObject("capture_request"))
            val sess = sessionRef.get()!!
            sess.setRepeatingRequest(request.build(), null, handler)
            rec.start()
            recorder = rec
            camera = cam
            session = sess
            file = out
            startedAt = SystemClock.elapsedRealtime()
            recording.set(true)
            val data = JSONObject()
                .put("path", out.absolutePath)
                .put("camera_id", cameraId)
                .put("recording", true)
                .put("audio_enabled", audio)
            DeviceJson.ok("recording ${out.absolutePath}", data)
        } catch (t: UnsupportedOperationException) {
            cleanupQuietly()
            DeviceJson.err("unsupported_api", t.message ?: "unsupported")
        } catch (t: IllegalArgumentException) {
            cleanupQuietly()
            DeviceJson.err("invalid_argument", t.message ?: "invalid video arguments")
        } catch (t: Throwable) {
            cleanupQuietly()
            DeviceJson.err("failed", t.message ?: t.toString())
        }
    }

    private fun stop(agent: String): JSONObject {
        if (!recording.get()) return DeviceJson.err("invalid_argument", "video is not recording")
        val who = DeviceBridge.agentLabel(agent)
        if (owner != null && owner != who) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("video", owner))
        }
        val out = file
        val elapsed = SystemClock.elapsedRealtime() - startedAt
        cleanupQuietly()
        if (out == null || !out.exists()) return DeviceJson.err("failed", "recording produced no file")
        val data = DeviceJson.fileMeta(out).put("duration_ms", elapsed)
        return DeviceJson.ok("video ${out.absolutePath}", data)
    }

    private fun status(): JSONObject {
        val data = JSONObject()
            .put("recording", recording.get())
            .put("path", file?.absolutePath ?: JSONObject.NULL)
            .put("elapsed_ms", if (recording.get()) SystemClock.elapsedRealtime() - startedAt else 0)
        return DeviceJson.ok(if (recording.get()) "recording" else "idle", data)
    }

    private fun cleanupQuietly() {
        recording.set(false)
        runCatching { session?.stopRepeating() }
        runCatching { session?.close() }
        runCatching { recorder?.stop() }
        runCatching { recorder?.reset() }
        runCatching { recorder?.release() }
        runCatching { camera?.close() }
        session = null
        recorder = null
        camera = null
        if (audioOn) {
            DeviceBridge.popKind("microphone")
            DeviceBridge.releaseMic()
        }
        DeviceBridge.popKind("camera")
        DeviceBridge.releaseCamera()
        audioOn = false
        owner = null
    }

    private fun configure(
        context: Context,
        rec: MediaRecorder,
        args: JSONObject,
        out: File,
        audio: Boolean,
        cameraId: String,
    ) {
        val profileName = args.optString("camcorder_profile")
        if (audio) {
            rec.setAudioSource(audioSource(args.optString("audio_source", "camcorder")))
        }
        rec.setVideoSource(MediaRecorder.VideoSource.SURFACE)
        if (profileName.isNotEmpty()) {
            val q = profileQuality(profileName)
            val legacyId = cameraId.toIntOrNull()
            val profile = if (legacyId != null && CamcorderProfile.hasProfile(legacyId, q)) {
                CamcorderProfile.get(legacyId, q)
            } else if (CamcorderProfile.hasProfile(q)) {
                CamcorderProfile.get(q)
            } else {
                throw IllegalArgumentException("camcorder profile $profileName is not available")
            }
            rec.setProfile(profile)
        } else {
            rec.setOutputFormat(outputFormat(args.optString("output_format", "mpeg_4")))
            rec.setVideoEncoder(videoEncoder(args.optString("video_encoder", "h264")))
            if (audio) rec.setAudioEncoder(audioEncoder(args.optString("audio_encoder", "aac")))
        }
        args.optJSONObject("video_size")?.let {
            rec.setVideoSize(it.getInt("width"), it.getInt("height"))
        }
        if (args.has("video_bit_rate")) rec.setVideoEncodingBitRate(args.getInt("video_bit_rate"))
        if (args.has("video_frame_rate")) rec.setVideoFrameRate(args.getInt("video_frame_rate"))
        if (args.has("capture_rate")) rec.setCaptureRate(args.getDouble("capture_rate"))
        if (audio && args.has("audio_bit_rate")) rec.setAudioEncodingBitRate(args.getInt("audio_bit_rate"))
        if (audio && args.has("audio_sample_rate")) rec.setAudioSamplingRate(args.getInt("audio_sample_rate"))
        if (audio && args.has("audio_channels")) rec.setAudioChannels(args.getInt("audio_channels"))
        if (args.has("orientation_hint")) rec.setOrientationHint(args.getInt("orientation_hint"))
        args.optJSONObject("location")?.let {
            rec.setLocation(it.getDouble("latitude").toFloat(), it.getDouble("longitude").toFloat())
        }
        val maxDuration = if (args.has("max_duration_ms")) args.getInt("max_duration_ms") else 600_000
        if (maxDuration > 0) rec.setMaxDuration(maxDuration)
        if (args.has("max_file_size_bytes") && args.getLong("max_file_size_bytes") > 0) {
            rec.setMaxFileSize(args.getLong("max_file_size_bytes"))
        }
        rec.setOutputFile(out.absolutePath)
        if (Build.VERSION.SDK_INT >= 28 && args.has("preferred_device_id")) {
            val id = args.getInt("preferred_device_id")
            val am = context.getSystemService(android.media.AudioManager::class.java)
            val device = am.getDevices(android.media.AudioManager.GET_DEVICES_INPUTS).firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("unknown preferred_device_id $id")
            rec.setPreferredDevice(device)
        } else if (args.has("preferred_device_id")) {
            throw UnsupportedOperationException("unsupported_api: preferred_device_id requires API 28")
        }
        if (Build.VERSION.SDK_INT >= 30 && args.has("privacy_sensitive")) {
            rec.setPrivacySensitive(args.getBoolean("privacy_sensitive"))
        } else if (args.has("privacy_sensitive")) {
            throw UnsupportedOperationException("unsupported_api: privacy_sensitive requires API 30")
        }
    }

    private fun extFor(format: String) = when (format) {
        "webm" -> "webm"
        "three_gpp" -> "3gp"
        else -> "mp4"
    }
}

internal fun outputFormat(name: String): Int = when (name) {
    "mpeg_4" -> MediaRecorder.OutputFormat.MPEG_4
    "webm" -> MediaRecorder.OutputFormat.WEBM
    "three_gpp" -> MediaRecorder.OutputFormat.THREE_GPP
    else -> throw IllegalArgumentException("output_format must be mpeg_4, webm, or three_gpp")
}

internal fun videoEncoder(name: String): Int = when (name) {
    "default" -> MediaRecorder.VideoEncoder.DEFAULT
    "h263" -> MediaRecorder.VideoEncoder.H263
    "h264" -> MediaRecorder.VideoEncoder.H264
    "hevc" -> if (Build.VERSION.SDK_INT >= 24) MediaRecorder.VideoEncoder.HEVC else throw UnsupportedOperationException("unsupported_api: hevc requires API 24")
    "mpeg_4_sp" -> MediaRecorder.VideoEncoder.MPEG_4_SP
    "vp8" -> if (Build.VERSION.SDK_INT >= 21) MediaRecorder.VideoEncoder.VP8 else throw UnsupportedOperationException("unsupported_api: vp8")
    "vp9" -> if (Build.VERSION.SDK_INT >= 33) MediaRecorder.VideoEncoder.VP9 else throw UnsupportedOperationException("unsupported_api: vp9 requires API 33")
    "av1" -> if (Build.VERSION.SDK_INT >= 33) MediaRecorder.VideoEncoder.AV1 else throw UnsupportedOperationException("unsupported_api: av1 requires API 33")
    "dolby_vision" -> if (Build.VERSION.SDK_INT >= 33) MediaRecorder.VideoEncoder.DOLBY_VISION else throw UnsupportedOperationException("unsupported_api: dolby_vision requires API 33")
    else -> throw IllegalArgumentException("unknown video_encoder $name")
}

internal fun audioEncoder(name: String): Int = when (name) {
    "default" -> MediaRecorder.AudioEncoder.DEFAULT
    "amr_nb" -> MediaRecorder.AudioEncoder.AMR_NB
    "amr_wb" -> MediaRecorder.AudioEncoder.AMR_WB
    "aac" -> MediaRecorder.AudioEncoder.AAC
    "he_aac" -> MediaRecorder.AudioEncoder.HE_AAC
    "aac_eld" -> MediaRecorder.AudioEncoder.AAC_ELD
    "vorbis" -> MediaRecorder.AudioEncoder.VORBIS
    "opus" -> if (Build.VERSION.SDK_INT >= 29) MediaRecorder.AudioEncoder.OPUS else throw UnsupportedOperationException("unsupported_api: opus requires API 29")
    else -> throw IllegalArgumentException("unknown audio_encoder $name")
}

internal fun audioSource(name: String): Int = when (name) {
    "default" -> MediaRecorder.AudioSource.DEFAULT
    "mic" -> MediaRecorder.AudioSource.MIC
    "camcorder" -> MediaRecorder.AudioSource.CAMCORDER
    "voice_recognition" -> MediaRecorder.AudioSource.VOICE_RECOGNITION
    "voice_communication" -> MediaRecorder.AudioSource.VOICE_COMMUNICATION
    "unprocessed" -> MediaRecorder.AudioSource.UNPROCESSED
    "voice_performance" -> if (Build.VERSION.SDK_INT >= 29) MediaRecorder.AudioSource.VOICE_PERFORMANCE else throw UnsupportedOperationException("unsupported_api: voice_performance requires API 29")
    "voice_uplink" -> MediaRecorder.AudioSource.VOICE_UPLINK
    "voice_downlink" -> MediaRecorder.AudioSource.VOICE_DOWNLINK
    "voice_call" -> MediaRecorder.AudioSource.VOICE_CALL
    else -> throw IllegalArgumentException("unknown audio_source $name")
}

internal fun profileQuality(name: String): Int {
    val key = name.removePrefix("QUALITY_")
    return when (key) {
        "QCIF" -> CamcorderProfile.QUALITY_QCIF
        "CIF" -> CamcorderProfile.QUALITY_CIF
        "480P" -> CamcorderProfile.QUALITY_480P
        "720P" -> CamcorderProfile.QUALITY_720P
        "1080P" -> CamcorderProfile.QUALITY_1080P
        "2160P" -> CamcorderProfile.QUALITY_2160P
        "HIGH" -> CamcorderProfile.QUALITY_HIGH
        "LOW" -> CamcorderProfile.QUALITY_LOW
        "QVGA" -> CamcorderProfile.QUALITY_QVGA
        "TIME_LAPSE_HIGH" -> CamcorderProfile.QUALITY_TIME_LAPSE_HIGH
        "TIME_LAPSE_LOW" -> CamcorderProfile.QUALITY_TIME_LAPSE_LOW
        "TIME_LAPSE_1080P" -> CamcorderProfile.QUALITY_TIME_LAPSE_1080P
        "TIME_LAPSE_720P" -> CamcorderProfile.QUALITY_TIME_LAPSE_720P
        "TIME_LAPSE_480P" -> CamcorderProfile.QUALITY_TIME_LAPSE_480P
        "TIME_LAPSE_QVGA" -> CamcorderProfile.QUALITY_TIME_LAPSE_QVGA
        "TIME_LAPSE_CIF" -> CamcorderProfile.QUALITY_TIME_LAPSE_CIF
        "TIME_LAPSE_QCIF" -> CamcorderProfile.QUALITY_TIME_LAPSE_QCIF
        "HIGH_SPEED_HIGH" -> CamcorderProfile.QUALITY_HIGH_SPEED_HIGH
        "HIGH_SPEED_LOW" -> CamcorderProfile.QUALITY_HIGH_SPEED_LOW
        "HIGH_SPEED_1080P" -> CamcorderProfile.QUALITY_HIGH_SPEED_1080P
        "HIGH_SPEED_720P" -> CamcorderProfile.QUALITY_HIGH_SPEED_720P
        "HIGH_SPEED_480P" -> CamcorderProfile.QUALITY_HIGH_SPEED_480P
        else -> throw IllegalArgumentException("unknown camcorder_profile $name")
    }
}
