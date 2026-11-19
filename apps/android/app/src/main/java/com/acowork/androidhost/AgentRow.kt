package com.acowork.androidhost

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import org.json.JSONObject
import java.io.File

/** One installed agent, ready for a list row. Instance id stays off the row. */
data class AgentRow(
    val instanceId: String,
    val name: String,
    val packageId: String,
    val running: Boolean,
    val avatarRes: Int,
    val avatar: Bitmap?,
)

object AgentRows {
    fun load(context: Context, home: File, installedJson: String?): List<AgentRow> {
        val agents = installedJson
            ?.let { runCatching { JSONObject(it).optJSONObject("agents") }.getOrNull() }
            ?: return emptyList()
        val rows = mutableListOf<AgentRow>()
        val keys = agents.keys()
        while (keys.hasNext()) {
            val instanceId = keys.next()
            val row = agents.optJSONObject(instanceId) ?: continue
            val packageId = row.optString("agent_id")
            val installPath = row.optString("install_path")
            val config = readConfig(home, instanceId)
            val manifest = readManifest(installPath)
            val name = firstNonBlank(
                config?.optString("name"),
                row.optString("name"),
                packageId,
            ) ?: packageId.ifBlank { instanceId }
            val (res, bitmap) = resolveAvatar(context, installPath, packageId, config, manifest)
            rows += AgentRow(
                instanceId,
                name,
                packageId,
                running = false,
                avatarRes = res,
                avatar = bitmap,
            )
        }
        val running = runningInstanceIds(rows.map { it.instanceId }.toSet())
        return rows
            .map { it.copy(running = it.instanceId in running) }
            .sortedBy { it.name.lowercase() }
    }

    /** Engine processes carry `--agent-instance-id` on their command line. */
    private fun runningInstanceIds(known: Set<String>): Set<String> {
        if (known.isEmpty()) return emptySet()
        val running = mutableSetOf<String>()
        val dirs = File("/proc").listFiles() ?: return emptySet()
        for (dir in dirs) {
            if (dir.name.toIntOrNull() == null) continue
            val bytes = runCatching { File(dir, "cmdline").readBytes() }.getOrNull() ?: continue
            if (bytes.isEmpty()) continue
            val cmd = bytes.toString(Charsets.UTF_8)
            if (!cmd.contains("libacowork_engine") && !cmd.contains("acowork-android")) continue
            for (id in known) {
                if (cmd.contains(id)) running += id
            }
        }
        return running
    }

    private fun readConfig(home: File, instanceId: String): JSONObject? {
        val file = home.resolve("agents/$instanceId/config/agent_config.json")
        if (!file.isFile) return null
        return runCatching { JSONObject(file.readText()) }.getOrNull()
    }

    private fun readManifest(installPath: String): Map<String, String> {
        if (installPath.isBlank()) return emptyMap()
        val file = File(installPath, "manifest.toml")
        if (!file.isFile) return emptyMap()
        val text = runCatching { file.readText() }.getOrNull() ?: return emptyMap()
        return mapOf(
            "avatar" to (tomlString(text, "avatar") ?: ""),
            "builtin_avatar" to (tomlString(text, "builtin_avatar") ?: ""),
        )
    }

    private fun tomlString(text: String, key: String): String? {
        val match = Regex("""(?m)^\s*$key\s*=\s*"([^"]*)"""").find(text) ?: return null
        return match.groupValues[1].takeIf { it.isNotBlank() }
    }

    private fun resolveAvatar(
        context: Context,
        installPath: String,
        packageId: String,
        config: JSONObject?,
        manifest: Map<String, String>,
    ): Pair<Int, Bitmap?> {
        val configAvatar = config?.optString("avatar").orEmpty()
        val configBuiltin = config?.optString("builtin_avatar").orEmpty()
        val manifestAvatar = manifest["avatar"].orEmpty()
        val manifestBuiltin = manifest["builtin_avatar"].orEmpty()
        val fileRel = configAvatar.ifBlank { if (configBuiltin.isBlank()) manifestAvatar else "" }
        val builtin = configBuiltin.ifBlank { if (configAvatar.isBlank()) manifestBuiltin else "" }
        decodeAvatar(installPath, fileRel)?.let { return 0 to it }
        val res = builtinRes(context, builtin).takeIf { it != 0 }
            ?: fallbackRes(context, packageId.ifBlank { installPath })
        return res to null
    }

    private fun decodeAvatar(installPath: String, relative: String): Bitmap? {
        val file = safeChild(installPath, relative) ?: return null
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (bounds.outWidth / sample > 256 || bounds.outHeight / sample > 256) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        return BitmapFactory.decodeFile(file.path, opts)
    }

    private fun safeChild(basePath: String, relative: String): File? {
        if (basePath.isBlank() || relative.isBlank() || relative.contains("..")) return null
        val base = File(basePath)
        val file = File(base, relative)
        if (!file.isFile) return null
        val baseCanon = runCatching { base.canonicalPath }.getOrNull() ?: return null
        val fileCanon = runCatching { file.canonicalPath }.getOrNull() ?: return null
        val prefix = if (baseCanon.endsWith(File.separator)) baseCanon else baseCanon + File.separator
        if (!fileCanon.startsWith(prefix)) return null
        return file
    }

    private fun builtinRes(context: Context, raw: String): Int {
        val n = normalizeBuiltin(raw) ?: return 0
        return context.resources.getIdentifier("icon_$n", "drawable", context.packageName)
    }

    private fun fallbackRes(context: Context, seed: String): Int {
        val n = Math.floorMod(seed.hashCode(), 20) + 1
        return context.resources.getIdentifier("icon_%02d".format(n), "drawable", context.packageName)
    }

    /** `icon-05`, `5`, and `05` all mean the bundled `icon_05` drawable. */
    private fun normalizeBuiltin(raw: String): String? {
        val t = raw.trim()
        if (t.isEmpty()) return null
        val digits = when {
            t.startsWith("icon-") -> t.removePrefix("icon-")
            t.all { it.isDigit() } -> t
            else -> return null
        }
        val n = digits.toIntOrNull() ?: return null
        if (n !in 1..20) return null
        return "%02d".format(n)
    }

    private fun firstNonBlank(vararg values: String?): String? =
        values.firstOrNull { !it.isNullOrBlank() }
}
