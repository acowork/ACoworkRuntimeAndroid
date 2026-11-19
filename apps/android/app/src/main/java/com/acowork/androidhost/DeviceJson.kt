package com.acowork.androidhost

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** JSON helpers shared by the device bridge. The wire format is one compact object. */
object DeviceJson {
    const val SPILL_BUDGET = 24 * 1024

    fun err(code: String, message: String): JSONObject =
        JSONObject()
            .put("ok", false)
            .put("error_code", code)
            .put("error", message)
            .put("content", message)
            .put("data", JSONObject())

    fun ok(content: String, data: JSONObject): JSONObject =
        JSONObject()
            .put("ok", true)
            .put("content", content)
            .put("data", data)

    fun asInt(v: Any?): Int = when (v) {
        is Int -> v
        is Long -> v.toInt()
        is Double -> v.toInt()
        is Float -> v.toInt()
        is String -> v.toInt()
        else -> throw IllegalArgumentException("expected integer, got $v")
    }

    fun asLong(v: Any?): Long = when (v) {
        is Int -> v.toLong()
        is Long -> v
        is Double -> v.toLong()
        is String -> v.toLong()
        else -> throw IllegalArgumentException("expected long, got $v")
    }

    fun asFloat(v: Any?): Float = when (v) {
        is Int -> v.toFloat()
        is Long -> v.toFloat()
        is Double -> v.toFloat()
        is Float -> v
        is String -> v.toFloat()
        else -> throw IllegalArgumentException("expected number, got $v")
    }

    fun asBool(v: Any?): Boolean = when (v) {
        is Boolean -> v
        is String -> v == "true"
        is Int -> v != 0
        else -> throw IllegalArgumentException("expected boolean, got $v")
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim().removePrefix("0x").replace(" ", "").replace(":", "")
        if (clean.isEmpty()) return ByteArray(0)
        if (clean.length % 2 != 0) throw IllegalArgumentException("hex length must be even")
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    fun bytesToHex(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): String {
        val end = (offset + length).coerceAtMost(bytes.size)
        val sb = StringBuilder((end - offset) * 2)
        for (i in offset until end) sb.append("%02x".format(bytes[i]))
        return sb.toString()
    }

    fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return bytesToHex(digest)
    }

    fun sha256File(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return bytesToHex(md.digest())
    }

    /** A path inside [workDir]. Absolute paths must still land under it. */
    fun underWorkDir(workDir: String, requested: String): File {
        if (workDir.isBlank()) throw IllegalArgumentException("work_dir is required")
        val base = File(workDir).canonicalFile
        val raw = File(requested)
        val file = (if (raw.isAbsolute) raw else File(base, requested)).canonicalFile
        val basePath = base.path
        if (file.path != basePath && !file.path.startsWith(basePath + File.separator)) {
            throw IllegalArgumentException("path escapes the agent work dir: $requested")
        }
        return file
    }

    fun captureFile(workDir: String, requested: String?, ext: String): File {
        val file = if (requested.isNullOrBlank()) {
            val dir = File(File(workDir).canonicalFile, "device-captures")
            dir.mkdirs()
            File(dir, "${UUID.randomUUID()}.$ext")
        } else {
            underWorkDir(workDir, requested)
        }
        file.parentFile?.mkdirs()
        return file
    }

    /**
     * Keep small results inline. Past [SPILL_BUDGET], or when the caller asked
     * for `output=file`, write the JSON beside the other captures.
     */
    fun finish(content: String, data: JSONObject, workDir: String, output: String?): JSONObject {
        val text = data.toString()
        val spill = output == "file" || text.length > SPILL_BUDGET
        if (!spill || workDir.isBlank()) return ok(content, data)
        val file = captureFile(workDir, null, "json")
        file.writeText(text)
        val spilled = JSONObject()
            .put("spilled", true)
            .put("path", file.absolutePath)
            .put("length", file.length())
            .put("sha256", sha256File(file))
            .put("prefix", text.take(160))
        return ok("$content\nfull JSON: ${file.absolutePath}", spilled)
    }

    fun putBytes(out: JSONObject, name: String, bytes: ByteArray, workDir: String, output: String?) {
        if (output == "file" || bytes.size > 4096) {
            val file = captureFile(workDir, null, "bin")
            file.writeBytes(bytes)
            out.put(name, JSONObject()
                .put("path", file.absolutePath)
                .put("length", bytes.size)
                .put("sha256", sha256(bytes))
                .put("prefix", bytesToHex(bytes, 0, minOf(64, bytes.size))))
        } else {
            out.put(name, bytesToHex(bytes))
        }
    }

    fun fileMeta(file: File): JSONObject = JSONObject()
        .put("path", file.absolutePath)
        .put("size_bytes", file.length())
        .put("sha256", sha256File(file))
        .put("mime", mimeFor(file))

    fun mimeFor(file: File): String = when (file.extension.lowercase()) {
        "jpg", "jpeg" -> "image/jpeg"
        "mp4" -> "video/mp4"
        "webm" -> "video/webm"
        "3gp" -> "video/3gpp"
        "m4a" -> "audio/mp4"
        "amr" -> "audio/amr"
        "wav" -> "audio/wav"
        "pcm" -> "application/octet-stream"
        "ogg" -> "audio/ogg"
        else -> "application/octet-stream"
    }
}

/** Best-effort JSON for the Android types Camera2 and USB hand back. */
object JsonValues {
    fun put(out: JSONObject, name: String, value: Any?) {
        if (value == null) return
        out.put(name, adapt(value))
    }

    fun adapt(value: Any): Any = when (value) {
        is Int, is Long, is Double, is Boolean, is String -> value
        is Float -> value.toDouble()
        is IntArray -> JSONArray().apply { value.forEach { put(it) } }
        is LongArray -> JSONArray().apply { value.forEach { put(it) } }
        is FloatArray -> JSONArray().apply { value.forEach { put(it.toDouble()) } }
        is ByteArray -> DeviceJson.bytesToHex(value)
        is android.util.Size -> JSONObject().put("width", value.width).put("height", value.height)
        is android.util.SizeF -> JSONObject().put("width", value.width).put("height", value.height)
        is android.graphics.Rect -> JSONObject()
            .put("left", value.left).put("top", value.top)
            .put("right", value.right).put("bottom", value.bottom)
        is android.util.Range<*> -> JSONArray().put(adapt(value.lower as Any)).put(adapt(value.upper as Any))
        is android.util.Rational -> JSONObject().put("numerator", value.numerator).put("denominator", value.denominator)
        is android.hardware.camera2.params.MeteringRectangle -> JSONObject()
            .put("x", value.x).put("y", value.y)
            .put("width", value.width).put("height", value.height)
            .put("weight", value.meteringWeight)
        is android.hardware.camera2.params.RggbChannelVector -> JSONArray()
            .put(value.red.toDouble()).put(value.greenEven.toDouble())
            .put(value.greenOdd.toDouble()).put(value.blue.toDouble())
        is android.hardware.camera2.params.ColorSpaceTransform -> {
            val arr = JSONArray()
            for (i in 0 until 9) {
                val r = value.getElement(i / 3, i % 3)
                arr.put(r.numerator).put(r.denominator)
            }
            arr
        }
        is android.location.Location -> JSONObject()
            .put("latitude", value.latitude)
            .put("longitude", value.longitude)
            .put("altitude", value.altitude)
        is Array<*> -> JSONArray().apply { value.filterNotNull().forEach { put(adapt(it)) } }
        else -> value.toString()
    }
}
