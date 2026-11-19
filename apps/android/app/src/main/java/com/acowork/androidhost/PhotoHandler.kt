package com.acowork.androidhost

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Handler
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** One Camera2 still capture. Runs on the caller thread; callbacks use [handler]. */
object PhotoHandler {
    @SuppressLint("MissingPermission")
    fun take(context: Context, handler: Handler, workDir: String, args: JSONObject, agent: String): JSONObject {
        val missing = DevicePermissions.firstMissing(context, listOf(android.Manifest.permission.CAMERA))
        if (missing != null) return DevicePermissions.required(context, missing)
        if (!DeviceBridge.tryAcquireCamera(agent)) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("camera", DeviceBridge.cameraHolder()))
        }
        return try {
            DeviceBridge.pushKind("camera")
            try {
                capture(context, handler, workDir, args)
            } finally {
                DeviceBridge.popKind("camera")
            }
        } finally {
            DeviceBridge.releaseCamera()
        }
    }

    @SuppressLint("MissingPermission")
    private fun capture(context: Context, handler: Handler, workDir: String, args: JSONObject): JSONObject {
        val manager = context.getSystemService(CameraManager::class.java)
        val cameraId = pickCamera(manager, args)
        val chars = manager.getCameraCharacteristics(cameraId)
        val map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            ?: return DeviceJson.err("failed", "camera $cameraId has no stream map")
        val jpegSizes = map.getOutputSizes(ImageFormat.JPEG)
            ?: return DeviceJson.err("failed", "camera $cameraId has no JPEG sizes")
        val size = jpegSizes.maxBy { it.width.toLong() * it.height }
        val reader = ImageReader.newInstance(size.width, size.height, ImageFormat.JPEG, 2)
        val deviceRef = AtomicReference<CameraDevice?>()
        val errorRef = AtomicReference<String?>()
        try {
            val opened = CountDownLatch(1)
            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    deviceRef.set(camera)
                    opened.countDown()
                }
                override fun onDisconnected(camera: CameraDevice) {
                    errorRef.set("camera disconnected")
                    camera.close()
                    opened.countDown()
                }
                override fun onError(camera: CameraDevice, error: Int) {
                    errorRef.set("camera error $error")
                    camera.close()
                    opened.countDown()
                }
            }, handler)
            if (!opened.await(8, TimeUnit.SECONDS)) return DeviceJson.err("failed", "openCamera timed out")
            errorRef.get()?.let { return DeviceJson.err("failed", it) }
            val camera = deviceRef.get() ?: return DeviceJson.err("failed", "camera did not open")

            val configured = CountDownLatch(1)
            val sessionRef = AtomicReference<CameraCaptureSession?>()
            camera.createCaptureSession(listOf(reader.surface), object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(session: CameraCaptureSession) {
                    sessionRef.set(session)
                    configured.countDown()
                }
                override fun onConfigureFailed(session: CameraCaptureSession) {
                    errorRef.set("capture session configure failed")
                    configured.countDown()
                }
            }, handler)
            if (!configured.await(8, TimeUnit.SECONDS)) return DeviceJson.err("failed", "session configure timed out")
            errorRef.get()?.let { return DeviceJson.err("failed", it) }
            val session = sessionRef.get() ?: return DeviceJson.err("failed", "no capture session")

            val template = when (args.optString("template", "still")) {
                "manual" -> CameraDevice.TEMPLATE_MANUAL
                "preview" -> CameraDevice.TEMPLATE_PREVIEW
                else -> CameraDevice.TEMPLATE_STILL_CAPTURE
            }
            val warmup = if (args.has("warmup_frames")) {
                args.getInt("warmup_frames")
            } else if (template == CameraDevice.TEMPLATE_MANUAL) 0 else 3

            val imageBytes = AtomicReference<ByteArray?>()
            val imageLatch = CountDownLatch(1)
            val acceptImage = java.util.concurrent.atomic.AtomicBoolean(false)
            reader.setOnImageAvailableListener({ r ->
                if (!acceptImage.get()) {
                    r.acquireNextImage()?.close()
                    return@setOnImageAvailableListener
                }
                val image = r.acquireNextImage() ?: return@setOnImageAvailableListener
                try {
                    val buf = image.planes[0].buffer
                    val bytes = ByteArray(buf.remaining())
                    buf.get(bytes)
                    imageBytes.set(bytes)
                } finally {
                    image.close()
                    imageLatch.countDown()
                }
            }, handler)

            val resultRef = AtomicReference<android.hardware.camera2.TotalCaptureResult?>()
            if (warmup > 0) {
                val warmed = CountDownLatch(1)
                var seen = 0
                val preview = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
                preview.addTarget(reader.surface)
                applyConvenience(preview, chars, args)
                session.setRepeatingRequest(preview.build(), object : CameraCaptureSession.CaptureCallback() {
                    override fun onCaptureCompleted(
                        session: CameraCaptureSession,
                        request: CaptureRequest,
                        result: android.hardware.camera2.TotalCaptureResult,
                    ) {
                        seen += 1
                        if (seen >= warmup) warmed.countDown()
                    }
                }, handler)
                warmed.await(5, TimeUnit.SECONDS)
                session.stopRepeating()
            }
            val still = camera.createCaptureRequest(template)
            still.addTarget(reader.surface)
            applyConvenience(still, chars, args)
            CameraRequests.apply(still, args.optJSONObject("capture_request"))
            val captured = CountDownLatch(1)
            acceptImage.set(true)
            session.capture(still.build(), object : CameraCaptureSession.CaptureCallback() {
                override fun onCaptureCompleted(
                    session: CameraCaptureSession,
                    request: CaptureRequest,
                    result: android.hardware.camera2.TotalCaptureResult,
                ) {
                    resultRef.set(result)
                    captured.countDown()
                }
                override fun onCaptureFailed(
                    session: CameraCaptureSession,
                    request: CaptureRequest,
                    failure: android.hardware.camera2.CaptureFailure,
                ) {
                    errorRef.set("capture failed reason=${failure.reason}")
                    captured.countDown()
                }
            }, handler)
            if (!captured.await(10, TimeUnit.SECONDS)) return DeviceJson.err("failed", "capture timed out")
            errorRef.get()?.let { return DeviceJson.err("failed", it) }
            if (!imageLatch.await(5, TimeUnit.SECONDS)) return DeviceJson.err("failed", "no JPEG produced")
            val bytes = imageBytes.get() ?: return DeviceJson.err("failed", "empty JPEG")
            val file = DeviceJson.captureFile(workDir, args.optString("output_path").ifBlank { null }, "jpg")
            file.writeBytes(bytes)
            session.close()
            camera.close()
            deviceRef.set(null)
            val data = DeviceJson.fileMeta(file)
                .put("width", size.width)
                .put("height", size.height)
                .put("camera_id", cameraId)
            resultRef.get()?.let { data.put("capture_result", CameraRequests.readResult(it)) }
            return DeviceJson.finish(
                "photo ${file.absolutePath} ${size.width}x${size.height}",
                data,
                workDir,
                args.optString("output").ifBlank { null },
            )
        } catch (t: UnsupportedOperationException) {
            val msg = t.message ?: "unsupported_api"
            val code = if (msg.startsWith("unsupported_api")) "unsupported_api" else "failed"
            return DeviceJson.err(code, msg.removePrefix("unsupported_api: ").ifBlank { msg })
        } catch (t: IllegalArgumentException) {
            return DeviceJson.err("invalid_argument", t.message ?: "invalid capture request")
        } catch (t: Throwable) {
            return DeviceJson.err("failed", t.message ?: t.toString())
        } finally {
            reader.close()
            deviceRef.get()?.close()
        }
    }

    private fun applyConvenience(
        builder: CaptureRequest.Builder,
        chars: CameraCharacteristics,
        args: JSONObject,
    ) {
        val quality = if (args.has("jpeg_quality")) args.getInt("jpeg_quality") else 95
        builder.set(CaptureRequest.JPEG_QUALITY, quality.coerceIn(1, 100).toByte())
        if (args.has("jpeg_orientation")) {
            builder.set(CaptureRequest.JPEG_ORIENTATION, args.getInt("jpeg_orientation"))
        } else {
            val sensor = chars.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
            val facing = chars.get(CameraCharacteristics.LENS_FACING)
            val orientation = if (facing == CameraCharacteristics.LENS_FACING_FRONT) (360 - sensor) % 360 else sensor
            builder.set(CaptureRequest.JPEG_ORIENTATION, orientation)
        }
        args.optJSONObject("location")?.let {
            builder.set(CaptureRequest.JPEG_GPS_LOCATION, android.location.Location("device-bridge").apply {
                latitude = it.getDouble("latitude")
                longitude = it.getDouble("longitude")
                if (it.has("altitude")) altitude = it.getDouble("altitude")
            })
        }
    }

    fun pickCamera(manager: CameraManager, args: JSONObject): String {
        val explicit = args.optString("camera_id")
        if (explicit.isNotEmpty()) {
            if (explicit !in manager.cameraIdList) {
                throw IllegalArgumentException("unknown camera_id $explicit")
            }
            return explicit
        }
        val want = when (args.optString("lens_facing", "back")) {
            "front" -> CameraCharacteristics.LENS_FACING_FRONT
            "external" -> CameraCharacteristics.LENS_FACING_EXTERNAL
            "back" -> CameraCharacteristics.LENS_FACING_BACK
            else -> throw IllegalArgumentException("lens_facing must be back, front, or external")
        }
        return manager.cameraIdList.firstOrNull {
            manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == want
        } ?: throw IllegalArgumentException("no camera for lens_facing")
    }
}
