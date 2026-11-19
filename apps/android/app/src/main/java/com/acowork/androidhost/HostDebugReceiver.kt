package com.acowork.androidhost

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * adb smoke (LAN path — no USB tunnels):
 *
 * ```
 * adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver \
 *   -a com.acowork.androidhost.DEBUG --es cmd start \
 *   --es gateway http://192.168.17.113:19876 --es name apk-phone
 * ```
 *
 * Dial-back = auto Wi‑Fi IPv4:19900.
 */
class HostDebugReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val cmd = intent?.getStringExtra(EXTRA_CMD)?.lowercase().orEmpty()
        val pending = goAsync()
        Thread {
            try {
                val result = when (cmd) {
                    "probe" -> {
                        if (!Native.loaded) {
                            """{"ok":false,"error":"${Native.loadError}"}"""
                        } else {
                            val home = context.filesDir.resolve("acowork").absolutePath
                            Native.probeSummary(home, context.packageName)
                        }
                    }
                    "version" -> {
                        if (!Native.loaded) {
                            """{"ok":false,"error":"${Native.loadError}"}"""
                        } else {
                            val lan = NetUtil.lanIpv4()
                            """{"ok":true,"version":"${Native.version()}","lan":"$lan"}"""
                        }
                    }
                    "status" -> {
                        if (!Native.loaded) {
                            """{"ok":false,"error":"${Native.loadError}"}"""
                        } else {
                            Native.nodeStatus()
                        }
                    }
                    "start" -> {
                        val gateway = intent?.getStringExtra(EXTRA_GATEWAY).orEmpty()
                        if (gateway.isBlank() || gateway.contains("127.0.0.1")) {
                            """{"ok":false,"error":"gateway must be PC LAN URL, not 127.0.0.1"}"""
                        } else {
                            val token = intent?.getStringExtra(EXTRA_TOKEN).orEmpty()
                            val name = intent?.getStringExtra(EXTRA_NAME).orEmpty()
                            val lan = NetUtil.lanIpv4()
                            HostForegroundService.start(context, gateway, token, name)
                            """{"ok":true,"started":true,"gateway":"$gateway","advertise":"http://$lan:${HostForegroundService.NODE_PROXY_PORT}"}"""
                        }
                    }
                    "stop" -> {
                        HostForegroundService.stop(context)
                        """{"ok":true,"stopped":true}"""
                    }
                    else -> """{"ok":false,"error":"unknown cmd `$cmd`"}"""
                }
                Log.i(TAG, result)
            } catch (t: Throwable) {
                Log.e(TAG, """{"ok":false,"error":"${t.message}"}""", t)
            } finally {
                pending.finish()
            }
        }.start()
    }

    companion object {
        const val TAG = "ACoworkHost"
        const val EXTRA_CMD = "cmd"
        const val EXTRA_GATEWAY = "gateway"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_NAME = "name"
    }
}
