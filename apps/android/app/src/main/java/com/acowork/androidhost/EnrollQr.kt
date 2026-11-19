package com.acowork.androidhost

import android.net.Uri

/**
 * Shared enroll paste / QR / deep-link payload.
 *
 * Desktop copies: `acowork://enroll?gateway=http://HOST:19876&token=TOKEN`
 * Phone pastes (or scans) once — Gateway + Token both fill.
 */
object EnrollQr {
    data class Payload(val gateway: String, val token: String)

    fun parse(raw: String): Payload? {
        val text = raw.trim().trim('"')
        if (text.isEmpty()) return null

        // Deep link (Desktop "Copy enroll code")
        if (text.startsWith("acowork://", ignoreCase = true) ||
            text.startsWith("acowork-enroll://", ignoreCase = true)
        ) {
            val uri = Uri.parse(text.replace("acowork-enroll://", "acowork://"))
            val gateway = uri.getQueryParameter("gateway")?.trim().orEmpty()
            val token = uri.getQueryParameter("token")?.trim().orEmpty()
            if (gateway.isNotEmpty() && !gateway.contains("127.0.0.1")) {
                return Payload(gateway, token)
            }
        }

        // JSON fallback: {"gateway":"...","token":"..."}
        if (text.startsWith("{")) {
            val g = Regex(""""gateway"\s*:\s*"([^"]+)"""").find(text)?.groupValues?.getOrNull(1)
            val t = Regex(""""token"\s*:\s*"([^"]+)"""").find(text)?.groupValues?.getOrNull(1).orEmpty()
            if (!g.isNullOrBlank() && !g.contains("127.0.0.1")) {
                return Payload(g, t)
            }
        }

        // Desktop shell command paste:
        // acowork-node start --gateway host:19875 --token XXX
        // We want HTTP gateway on 19876 for the APK.
        val token = Regex("""--token\s+(\S+)""").find(text)?.groupValues?.getOrNull(1)
        val gwHost = Regex("""--gateway\s+(\S+)""").find(text)?.groupValues?.getOrNull(1)
        if (!gwHost.isNullOrBlank() && !token.isNullOrBlank()) {
            val host = gwHost.removePrefix("[").substringBefore("]").substringBefore(":").trim()
            if (host.isNotEmpty() && host != "127.0.0.1" && host != "::1") {
                return Payload("http://$host:19876", token)
            }
        }
        return null
    }

    fun encode(gateway: String, token: String): String {
        return Uri.Builder()
            .scheme("acowork")
            .authority("enroll")
            .appendQueryParameter("gateway", gateway)
            .appendQueryParameter("token", token)
            .build()
            .toString()
    }
}
