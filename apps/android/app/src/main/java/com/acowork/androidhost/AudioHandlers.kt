package com.acowork.androidhost

import android.annotation.SuppressLint
import android.content.Context
import android.media.AudioAttributes
import android.media.AudioDeviceInfo
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
import android.os.Build
import android.os.SystemClock
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

object AudioRecordHandler {
    private val recording = AtomicBoolean(false)
    private var recorder: MediaRecorder? = null
    private var pcm: AudioRecord? = null
    private var pcmThread: Thread? = null
    private var file: File? = null
    private var startedAt = 0L
    private var containerName = "aac_m4a"
    private val effects = JSONObject()
    private var owner: String? = null

    fun handle(context: Context, workDir: String, args: JSONObject, agent: String): JSONObject {
        val duration = if (args.has("duration_ms")) args.getLong("duration_ms") else -1L
        val op = args.optString("op")
        if (duration >= 0 && op.isEmpty()) {
            val started = start(context, workDir, args, agent)
            if (!started.optBoolean("ok")) return started
            val deadline = SystemClock.elapsedRealtime() + duration
            while (recording.get() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(40)
            return stop(agent)
        }
        return when (op) {
            "", "start" -> start(context, workDir, args, agent)
            "stop" -> stop(agent)
            "status" -> status()
            else -> DeviceJson.err("invalid_argument", "op must be start, stop, or status")
        }
    }

    @SuppressLint("MissingPermission")
    private fun start(context: Context, workDir: String, args: JSONObject, agent: String): JSONObject {
        if (!DeviceBridge.tryAcquireMic(agent)) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("microphone", DeviceBridge.micHolder()))
        }
        if (!recording.compareAndSet(false, true)) {
            DeviceBridge.releaseMic()
            return DeviceJson.err("busy", DeviceBridge.busyMessage("audio recording", owner))
        }
        val missing = DevicePermissions.firstMissing(context, listOf(android.Manifest.permission.RECORD_AUDIO))
        if (missing != null) {
            recording.set(false)
            DeviceBridge.releaseMic()
            return DevicePermissions.required(context, missing)
        }
        containerName = args.optString("container", "aac_m4a")
        owner = DeviceBridge.agentLabel(agent)
        DeviceBridge.pushKind("microphone")
        return try {
            val ext = when (containerName) {
                "wav" -> "wav"
                "raw_pcm" -> "pcm"
                "amr_nb", "amr_wb" -> "amr"
                "opus" -> "ogg"
                else -> "m4a"
            }
            val out = DeviceJson.captureFile(workDir, args.optString("output_path").ifBlank { null }, ext)
            if (containerName == "wav" || containerName == "raw_pcm") startPcm(context, args, out)
            else startCompressed(context, args, out)
            file = out
            startedAt = SystemClock.elapsedRealtime()
            DeviceJson.ok(
                "recording ${out.absolutePath}",
                JSONObject().put("path", out.absolutePath).put("container", containerName).put("recording", true).put("effects", effects),
            )
        } catch (t: UnsupportedOperationException) {
            failStart()
            DeviceJson.err("unsupported_api", t.message ?: "unsupported")
        } catch (t: IllegalArgumentException) {
            failStart()
            DeviceJson.err("invalid_argument", t.message ?: "invalid audio arguments")
        } catch (t: Throwable) {
            failStart()
            DeviceJson.err("failed", t.message ?: t.toString())
        }
    }

    @SuppressLint("MissingPermission")
    private fun startCompressed(context: Context, args: JSONObject, out: File) {
        val rec = if (Build.VERSION.SDK_INT >= 31) MediaRecorder(context) else MediaRecorder()
        rec.setAudioSource(audioSource(args.optString("audio_source", "mic")))
        when (containerName) {
            "amr_nb" -> {
                rec.setOutputFormat(MediaRecorder.OutputFormat.AMR_NB)
                rec.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_NB)
            }
            "amr_wb" -> {
                rec.setOutputFormat(MediaRecorder.OutputFormat.AMR_WB)
                rec.setAudioEncoder(MediaRecorder.AudioEncoder.AMR_WB)
            }
            "opus" -> {
                if (Build.VERSION.SDK_INT < 29) throw UnsupportedOperationException("opus requires API 29")
                rec.setOutputFormat(MediaRecorder.OutputFormat.OGG)
                rec.setAudioEncoder(MediaRecorder.AudioEncoder.OPUS)
            }
            else -> {
                rec.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
                rec.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            }
        }
        if (args.has("sample_rate")) rec.setAudioSamplingRate(args.getInt("sample_rate"))
        if (args.has("bit_rate")) rec.setAudioEncodingBitRate(args.getInt("bit_rate"))
        if (args.has("audio_channels")) rec.setAudioChannels(args.getInt("audio_channels"))
        val maxDuration = if (args.has("max_duration_ms")) args.getInt("max_duration_ms") else 600_000
        if (maxDuration > 0) rec.setMaxDuration(maxDuration)
        if (args.has("max_file_size_bytes") && args.getLong("max_file_size_bytes") > 0) {
            rec.setMaxFileSize(args.getLong("max_file_size_bytes"))
        }
        applyPreferred(context, args) { rec.setPreferredDevice(it) }
        if (Build.VERSION.SDK_INT >= 30 && args.has("privacy_sensitive")) rec.setPrivacySensitive(args.getBoolean("privacy_sensitive"))
        else if (args.has("privacy_sensitive")) throw UnsupportedOperationException("privacy_sensitive requires API 30")
        rec.setOutputFile(out.absolutePath)
        rec.prepare()
        rec.start()
        recorder = rec
        effects.put("applied_on", "media_recorder")
    }

    @SuppressLint("MissingPermission")
    private fun startPcm(context: Context, args: JSONObject, out: File) {
        val rate = if (args.has("sample_rate")) args.getInt("sample_rate") else 44100
        val encoding = pcmEncoding(args.optString("encoding", "pcm_16bit"))
        val mask = channelMask(args)
        val format = AudioFormat.Builder().setSampleRate(rate).setEncoding(encoding).setChannelMask(mask)
        if (args.has("channel_index_mask")) format.setChannelIndexMask(args.getInt("channel_index_mask"))
        val built = format.build()
        val min = AudioRecord.getMinBufferSize(rate, mask, encoding)
        val buf = if (args.has("buffer_size_bytes")) args.getInt("buffer_size_bytes").coerceAtLeast(min) else min * 2
        val b = AudioRecord.Builder().setAudioSource(audioSource(args.optString("audio_source", "mic"))).setAudioFormat(built).setBufferSizeInBytes(buf)
        if (Build.VERSION.SDK_INT >= 30 && args.has("privacy_sensitive")) b.setPrivacySensitive(args.getBoolean("privacy_sensitive"))
        else if (args.has("privacy_sensitive")) throw UnsupportedOperationException("privacy_sensitive requires API 30")
        if (args.has("audio_session_id")) {
            throw UnsupportedOperationException("unsupported_api: AudioRecord.Builder has no public setSessionId; the assigned id is returned as audio_session_id")
        }
        val rec = b.build()
        applyPreferred(context, args) { rec.preferredDevice = it }
        rec.startRecording()
        pcm = rec
        val want = args.optJSONObject("effects")
        val session = rec.audioSessionId
        effects.put("audio_session_id", session)
        effects.put("sample_rate", rate)
        effects.put("encoding", args.optString("encoding", "pcm_16bit"))
        effects.put("channel_mask", mask)
        if (want?.optBoolean("aec") == true && AcousticEchoCanceler.isAvailable()) {
            AcousticEchoCanceler.create(session)?.enabled = true
            effects.put("aec", true)
        } else effects.put("aec", false)
        if (want?.optBoolean("ns") == true && NoiseSuppressor.isAvailable()) {
            NoiseSuppressor.create(session)?.enabled = true
            effects.put("ns", true)
        } else effects.put("ns", false)
        if (want?.optBoolean("agc") == true && AutomaticGainControl.isAvailable()) {
            AutomaticGainControl.create(session)?.enabled = true
            effects.put("agc", true)
        } else effects.put("agc", false)
        val bits = when (encoding) {
            AudioFormat.ENCODING_PCM_8BIT -> 8
            AudioFormat.ENCODING_PCM_FLOAT -> 32
            else -> 16
        }
        val channels = if (mask == AudioFormat.CHANNEL_IN_STEREO) 2 else 1
        pcmThread = Thread {
            FileOutputStream(out).use { output ->
                if (containerName == "wav") output.write(ByteArray(44))
                val chunk = ByteArray(buf)
                while (recording.get()) {
                    val n = rec.read(chunk, 0, chunk.size)
                    if (n < 0) break
                    if (n > 0) output.write(chunk, 0, n)
                }
            }
            if (containerName == "wav" && out.exists()) {
                val pcmLen = (out.length() - 44).toInt().coerceAtLeast(0)
                val header = wavHeader(pcmLen, rate, channels, bits, encoding == AudioFormat.ENCODING_PCM_FLOAT)
                java.io.RandomAccessFile(out, "rw").use { it.write(header) }
            }
        }.also { it.start() }
    }

    private fun failStart() {
        recording.set(false)
        owner = null
        DeviceBridge.popKind("microphone")
        DeviceBridge.releaseMic()
    }

    private fun stop(agent: String): JSONObject {
        if (!recording.get() && recorder == null && pcm == null) {
            return DeviceJson.err("invalid_argument", "audio is not recording")
        }
        val who = DeviceBridge.agentLabel(agent)
        if (owner != null && owner != who) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("audio recording", owner))
        }
        val elapsed = SystemClock.elapsedRealtime() - startedAt
        recording.set(false)
        runCatching { recorder?.stop() }
        runCatching { recorder?.release() }
        recorder = null
        runCatching { pcm?.stop() }
        val session = pcm?.audioSessionId
        runCatching { pcm?.release() }
        pcm = null
        runCatching { pcmThread?.join(2000) }
        pcmThread = null
        DeviceBridge.popKind("microphone")
        DeviceBridge.releaseMic()
        owner = null
        val out = file
        if (out == null || !out.exists()) return DeviceJson.err("failed", "recording produced no file")
        val data = DeviceJson.fileMeta(out)
            .put("duration_ms", elapsed)
            .put("container", containerName)
            .put("effects", effects)
        if (session != null) data.put("audio_session_id", session)
        return DeviceJson.ok("audio ${out.absolutePath}", data)
    }

    private fun status(): JSONObject {
        val data = JSONObject()
            .put("recording", recording.get())
            .put("path", file?.absolutePath)
            .put("container", containerName)
            .put("elapsed_ms", if (recording.get()) SystemClock.elapsedRealtime() - startedAt else 0)
            .put("effects", effects)
        return DeviceJson.ok(if (recording.get()) "recording" else "idle", data)
    }
}

object AudioPlayHandler {
    private const val MAX_PLAYERS = 4

    private class Play(
        val player: MediaPlayer,
        val playing: AtomicBoolean = AtomicBoolean(false),
    )

    private val plays = java.util.concurrent.ConcurrentHashMap<String, Play>()
    private val slots = java.util.concurrent.atomic.AtomicInteger(0)

    fun handle(context: Context, workDir: String, args: JSONObject, agent: String): JSONObject {
        val key = DeviceBridge.agentLabel(agent)
        val op = args.optString("op", "play_and_wait")
        return try {
            when (op) {
                "play_and_wait", "start" -> start(context, workDir, args, key, wait = op != "start")
                "pause" -> {
                    val play = plays[key] ?: return DeviceJson.err("invalid_argument", "nothing is playing")
                    play.player.pause()
                    play.playing.set(false)
                    status(key, "paused")
                }
                "resume" -> {
                    val play = plays[key] ?: return DeviceJson.err("invalid_argument", "nothing is playing")
                    play.player.start()
                    play.playing.set(true)
                    status(key, "playing")
                }
                "stop" -> {
                    release(key)
                    DeviceJson.ok("stopped", JSONObject().put("playing", false).put("agent", key))
                }
                "seek" -> {
                    val play = plays[key] ?: return DeviceJson.err("invalid_argument", "nothing is playing")
                    val mode = seekMode(args.optString("seek_mode", "closest"))
                    play.player.seekTo(args.optLong("seek_ms"), mode)
                    status(key, "seeked")
                }
                "status" -> status(key, if (plays[key]?.playing?.get() == true) "playing" else "idle")
                else -> DeviceJson.err("invalid_argument", "unknown op $op")
            }
        } catch (t: IllegalArgumentException) {
            DeviceJson.err("invalid_argument", t.message ?: "invalid playback arguments")
        } catch (t: UnsupportedOperationException) {
            DeviceJson.err("unsupported_api", t.message ?: "unsupported")
        } catch (t: Throwable) {
            DeviceJson.err("failed", t.message ?: t.toString())
        }
    }

    private fun start(context: Context, workDir: String, args: JSONObject, key: String, wait: Boolean): JSONObject {
        if (args.optBoolean("loop") && wait) {
            return DeviceJson.err("invalid_argument", "loop cannot be combined with play_and_wait")
        }
        val path = args.optString("path")
        if (path.isBlank()) return DeviceJson.err("invalid_argument", "path is required")
        val file = DeviceJson.underWorkDir(workDir, path)
        if (!file.isFile) return DeviceJson.err("invalid_argument", "file not found: ${file.absolutePath}")
        if (plays.containsKey(key)) release(key)
        if (slots.incrementAndGet() > MAX_PLAYERS) {
            slots.decrementAndGet()
            return DeviceJson.err("busy", "audio playback is at capacity ($MAX_PLAYERS concurrent players)")
        }
        DeviceBridge.pushKind("media")
        val mp = MediaPlayer()
        val play = Play(mp)
        plays[key] = play
        try {
        val attrs = args.optJSONObject("audio_attributes")
        if (attrs != null) mp.setAudioAttributes(audioAttributes(attrs))
        else mp.setAudioStreamType(streamType(args.optString("stream_type", "music")))
        if (args.has("audio_session_id")) mp.audioSessionId = args.getInt("audio_session_id")
        mp.setDataSource(file.absolutePath)
        mp.isLooping = args.optBoolean("loop")
        mp.prepare()
        applyPlaybackParams(mp, args)
        if (args.has("seek_ms")) mp.seekTo(args.getLong("seek_ms"), seekMode(args.optString("seek_mode", "closest")))
        val left = if (args.has("left_volume")) args.getDouble("left_volume").toFloat() else args.optDouble("volume", 1.0).toFloat()
        val right = if (args.has("right_volume")) args.getDouble("right_volume").toFloat() else left
        mp.setVolume(left, right)
        if (args.has("aux_effect_id")) mp.attachAuxEffect(args.getInt("aux_effect_id"))
        if (args.has("aux_effect_send_level")) mp.setAuxEffectSendLevel(args.getDouble("aux_effect_send_level").toFloat())
        applyPreferred(context, args) { mp.preferredDevice = it }
        val done = CountDownLatch(1)
        mp.setOnCompletionListener {
            play.playing.set(false)
            done.countDown()
        }
        mp.setOnErrorListener { _, _, _ ->
            play.playing.set(false)
            done.countDown()
            true
        }
        mp.start()
        play.playing.set(true)
        if (wait) {
            val cap = (mp.duration.toLong() + 5_000L).coerceAtMost(590_000L).coerceAtLeast(1_000L)
            done.await(cap, TimeUnit.MILLISECONDS)
            val data = statusData(mp, play.playing.get(), file)
            release(key)
            return DeviceJson.ok("played ${file.absolutePath}", data)
        }
        return DeviceJson.ok("playing ${file.absolutePath}", statusData(mp, true, file))
        } catch (t: Throwable) {
            release(key)
            throw t
        }
    }

    private fun status(key: String, content: String): JSONObject {
        val play = plays[key]
        val data = if (play == null) JSONObject().put("playing", false) else statusData(play.player, play.playing.get(), null)
        return DeviceJson.ok(content, data)
    }

    private fun statusData(mp: MediaPlayer, playing: Boolean, file: File?): JSONObject {
        val data = JSONObject()
            .put("playing", playing)
            .put("duration_ms", runCatching { mp.duration }.getOrDefault(0))
            .put("position_ms", runCatching { mp.currentPosition }.getOrDefault(0))
            .put("audio_session_id", mp.audioSessionId)
        if (file != null) data.put("path", file.absolutePath)
        return data
    }

    private fun release(key: String) {
        val play = plays.remove(key) ?: return
        play.playing.set(false)
        runCatching { play.player.stop() }
        runCatching { play.player.release() }
        DeviceBridge.popKind("media")
        slots.updateAndGet { n -> (n - 1).coerceAtLeast(0) }
    }
}

private fun pcmEncoding(name: String): Int = when (name) {
    "pcm_8bit" -> AudioFormat.ENCODING_PCM_8BIT
    "pcm_16bit" -> AudioFormat.ENCODING_PCM_16BIT
    "pcm_float" -> AudioFormat.ENCODING_PCM_FLOAT
    "pcm_24bit" -> if (Build.VERSION.SDK_INT >= 31) AudioFormat.ENCODING_PCM_24BIT_PACKED else throw UnsupportedOperationException("pcm_24bit requires API 31")
    "pcm_32bit" -> if (Build.VERSION.SDK_INT >= 31) AudioFormat.ENCODING_PCM_32BIT else throw UnsupportedOperationException("pcm_32bit requires API 31")
    else -> throw IllegalArgumentException("unknown encoding $name")
}

private fun channelMask(args: JSONObject): Int {
    if (!args.has("channel_mask")) return AudioFormat.CHANNEL_IN_MONO
    val raw = args.get("channel_mask")
    return when (raw) {
        "mono" -> AudioFormat.CHANNEL_IN_MONO
        "stereo" -> AudioFormat.CHANNEL_IN_STEREO
        else -> DeviceJson.asInt(raw)
    }
}

private fun applyPreferred(context: Context, args: JSONObject, set: (AudioDeviceInfo) -> Unit) {
    if (!args.has("preferred_device_id")) return
    if (Build.VERSION.SDK_INT < 28) throw UnsupportedOperationException("preferred_device_id requires API 28")
    val id = args.getInt("preferred_device_id")
    val am = context.getSystemService(AudioManager::class.java)
    val all = am.getDevices(AudioManager.GET_DEVICES_ALL)
    val device = all.firstOrNull { it.id == id } ?: throw IllegalArgumentException("unknown preferred_device_id $id")
    set(device)
}

private fun audioAttributes(o: JSONObject): AudioAttributes {
    val b = AudioAttributes.Builder()
    b.setUsage(when (o.optString("usage", "media")) {
        "game" -> AudioAttributes.USAGE_GAME
        "voice_communication" -> AudioAttributes.USAGE_VOICE_COMMUNICATION
        "alarm" -> AudioAttributes.USAGE_ALARM
        "notification" -> AudioAttributes.USAGE_NOTIFICATION
        "assistance", "assistance_sonification" -> AudioAttributes.USAGE_ASSISTANCE_SONIFICATION
        "assistance_accessibility" -> AudioAttributes.USAGE_ASSISTANCE_ACCESSIBILITY
        "assistance_navigation" -> AudioAttributes.USAGE_ASSISTANCE_NAVIGATION_GUIDANCE
        "assistant" -> AudioAttributes.USAGE_ASSISTANT
        "notification_ringtone" -> AudioAttributes.USAGE_NOTIFICATION_RINGTONE
        "notification_event" -> AudioAttributes.USAGE_NOTIFICATION_EVENT
        "unknown" -> AudioAttributes.USAGE_UNKNOWN
        else -> AudioAttributes.USAGE_MEDIA
    })
    b.setContentType(when (o.optString("content_type", "unknown")) {
        "music" -> AudioAttributes.CONTENT_TYPE_MUSIC
        "speech" -> AudioAttributes.CONTENT_TYPE_SPEECH
        "movie" -> AudioAttributes.CONTENT_TYPE_MOVIE
        "sonification" -> AudioAttributes.CONTENT_TYPE_SONIFICATION
        else -> AudioAttributes.CONTENT_TYPE_UNKNOWN
    })
    val flags = o.optJSONArray("flags")
    if (flags != null) {
        var mask = 0
        for (i in 0 until flags.length()) {
            mask = mask or when (flags.getString(i)) {
                "audibility_enforced" -> AudioAttributes.FLAG_AUDIBILITY_ENFORCED
                "hw_av_sync" -> AudioAttributes.FLAG_HW_AV_SYNC
                "low_latency" -> AudioAttributes.FLAG_LOW_LATENCY
                else -> 0
            }
        }
        if (mask != 0) b.setFlags(mask)
    }
    if (Build.VERSION.SDK_INT >= 29 && o.has("capture_policy")) {
        val policy = when (o.getString("capture_policy")) {
            "none" -> AudioAttributes.ALLOW_CAPTURE_BY_NONE
            "system" -> AudioAttributes.ALLOW_CAPTURE_BY_SYSTEM
            else -> AudioAttributes.ALLOW_CAPTURE_BY_ALL
        }
        b.setAllowedCapturePolicy(policy)
    }
    return b.build()
}

@Suppress("DEPRECATION")
private fun streamType(name: String): Int = when (name) {
    "voice_call" -> AudioManager.STREAM_VOICE_CALL
    "ring" -> AudioManager.STREAM_RING
    "alarm" -> AudioManager.STREAM_ALARM
    "notification" -> AudioManager.STREAM_NOTIFICATION
    "system" -> AudioManager.STREAM_SYSTEM
    "dtmf" -> AudioManager.STREAM_DTMF
    "accessibility" -> AudioManager.STREAM_ACCESSIBILITY
    else -> AudioManager.STREAM_MUSIC
}

private fun seekMode(name: String): Int = when (name) {
    "previous_sync" -> MediaPlayer.SEEK_PREVIOUS_SYNC
    "next_sync" -> MediaPlayer.SEEK_NEXT_SYNC
    "closest_sync" -> MediaPlayer.SEEK_CLOSEST_SYNC
    else -> MediaPlayer.SEEK_CLOSEST
}

private fun applyPlaybackParams(mp: MediaPlayer, args: JSONObject) {
    if (!args.has("playback_speed") && !args.has("pitch") && !args.has("audio_fallback_mode")) return
    val params = mp.playbackParams
    if (args.has("playback_speed")) params.speed = args.getDouble("playback_speed").toFloat()
    if (args.has("pitch")) params.pitch = args.getDouble("pitch").toFloat()
    if (args.has("audio_fallback_mode")) {
        params.audioFallbackMode = when (args.getString("audio_fallback_mode")) {
            "mute" -> android.media.PlaybackParams.AUDIO_FALLBACK_MODE_MUTE
            "fail" -> android.media.PlaybackParams.AUDIO_FALLBACK_MODE_FAIL
            else -> android.media.PlaybackParams.AUDIO_FALLBACK_MODE_DEFAULT
        }
    }
    mp.playbackParams = params
}

private fun wavHeader(pcmBytes: Int, rate: Int, channels: Int, bits: Int, float: Boolean): ByteArray {
    val byteRate = rate * channels * bits / 8
    val block = channels * bits / 8
    val buf = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
    buf.put("RIFF".toByteArray())
    buf.putInt(pcmBytes + 36)
    buf.put("WAVE".toByteArray())
    buf.put("fmt ".toByteArray())
    buf.putInt(16)
    buf.putShort(if (float) 3 else 1)
    buf.putShort(channels.toShort())
    buf.putInt(rate)
    buf.putInt(byteRate)
    buf.putShort(block.toShort())
    buf.putShort(bits.toShort())
    buf.put("data".toByteArray())
    buf.putInt(pcmBytes)
    return buf.array()
}
