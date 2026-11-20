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
                    "device_status" -> deviceStatus(context)
                    "device_photo" -> devicePhoto(context)
                    "device_use" -> deviceUse(context, intent)
                    "request_root" -> Native.invoke { requestRoot() }
                    "dangerous" -> {
                        val on = intent?.getStringExtra("on").orEmpty() == "1"
                        Native.invoke { setDangerousMode(on) }
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
        const val TAG = "ACoworkNode"
        const val EXTRA_CMD = "cmd"
        const val EXTRA_GATEWAY = "gateway"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_NAME = "name"
    }

    private fun deviceStatus(context: Context): String {
        val work = context.filesDir.resolve("acowork").absolutePath
        return StatusHandler.query(context, work, org.json.JSONObject()).toString()
    }

    private fun devicePhoto(context: Context): String {
        if (!DeviceBridge.isReady()) {
            return """{"ok":false,"error_code":"bridge_unavailable","error":"start the host first"}"""
        }
        val work = context.filesDir.resolve("acowork").absolutePath
        return PhotoHandler.take(
            DeviceBridge.appContext,
            DeviceBridge.cameraHandler,
            work,
            org.json.JSONObject(),
            "adb-smoke",
        ).toString()
    }

    private fun deviceUse(context: Context, intent: Intent?): String {
        val op = intent?.getStringExtra("op").orEmpty().ifBlank { "status" }
        val args = org.json.JSONObject().put("op", op)
        if (!DeviceBridge.isReady() && op != "status") {
            return """{"ok":false,"error_code":"bridge_unavailable","error":"start the host first"}"""
        }
        val work = context.filesDir.resolve("acowork").absolutePath
        val app = if (DeviceBridge.isReady()) DeviceBridge.appContext else context.applicationContext
        return AndroidUseHandler.handle(app, work, args, "adb-smoke").toString()
    }
}
