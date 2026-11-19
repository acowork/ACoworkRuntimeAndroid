package com.acowork.androidhost

import java.net.Inet4Address
import java.net.NetworkInterface

/** Pick a non-loopback IPv4 the Gateway can dial back to (usually Wi‑Fi). */
object NetUtil {
    fun lanIpv4(): String? {
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return null
        for (iface in ifaces) {
            if (!iface.isUp || iface.isLoopback) continue
            val name = iface.name.lowercase()
            // Prefer Wi‑Fi / WLAN; skip cellular/vpn when a wifi address exists.
            val isWifi = name.startsWith("wlan") || name.startsWith("wifi") || name == "eth0"
            for (addr in iface.inetAddresses) {
                if (addr !is Inet4Address || addr.isLoopbackAddress) continue
                val host = addr.hostAddress ?: continue
                if (isWifi) return host
            }
        }
        // Fallback: any site-local IPv4.
        val ifaces2 = NetworkInterface.getNetworkInterfaces() ?: return null
        for (iface in ifaces2) {
            if (!iface.isUp || iface.isLoopback) continue
            for (addr in iface.inetAddresses) {
                if (addr is Inet4Address && !addr.isLoopbackAddress && addr.isSiteLocalAddress) {
                    return addr.hostAddress
                }
            }
        }
        return null
    }
}
