package com.acowork.androidhost

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

/**
 * Keeps the process alive and owns the native Node host loop (ADR-AND-004 / C2).
 *
 * Dial-back = phone Wi‑Fi IPv4:19900. MQTT reconnect is handled inside the
 * native session — do **not** stop/start the whole host on every network blip
 * (that published LWT offline/online once a second).
 */
class HostForegroundService : Service() {
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var everLostNetwork = false
    @Volatile private var startKey: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                startKey = null
                if (Native.loaded) {
                    Native.stopNode()
                }
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val gateway = intent?.getStringExtra(EXTRA_GATEWAY)
                    ?: prefs().getString(PREF_GATEWAY, "")
                    ?: ""
                val token = intent?.getStringExtra(EXTRA_TOKEN)
                    ?: prefs().getString(PREF_TOKEN, "")
                    ?: ""
                val name = intent?.getStringExtra(EXTRA_NAME)
                    ?: prefs().getString(PREF_NAME, "")
                    ?: ""
                startAsForeground(gateway)
                startNative(gateway, token, name, force = false)
                // Observe network only — MQTT soft-reconnect owns recovery.
                // Restarting the whole native host here re-fires LWT and
                // caused a 1Hz offline/online flap on Wi‑Fi blips.
                registerNetworkCallback()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        networkCallback?.let {
            runCatching { connectivityManager().unregisterNetworkCallback(it) }
        }
        networkCallback = null
        if (Native.loaded) {
            Native.stopNode()
        }
        startKey = null
        super.onDestroy()
    }

    private fun startAsForeground(gateway: String) {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text, gateway))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startNative(
        gateway: String,
        token: String,
        name: String,
        force: Boolean,
    ) {
        if (!Native.loaded) return
        val lan = NetUtil.lanIpv4()
        if (lan.isNullOrBlank()) {
            Log.e(TAG, """{"ok":false,"error":"no Wi-Fi IPv4 for dial-back"}""")
            return
        }
        val key = listOf(gateway, token, name, lan).joinToString("|")
        if (!force && key == startKey) {
            val status = runCatching { Native.nodeStatus() }.getOrDefault("")
            if (status.contains("\"running\":true")) {
                Log.i(TAG, """{"ok":true,"skip":"already running","key":"$lan"}""")
                return
            }
        }
        val home = filesDir.resolve("acowork").absolutePath
        killOrphanEngines(home)
        val engine = applicationInfo.nativeLibraryDir + "/libacowork_engine.so"
        prefs().edit()
            .putString(PREF_GATEWAY, gateway)
            .putString(PREF_TOKEN, token)
            .putString(PREF_NAME, name)
            .apply()
        Log.i(TAG, """{"advertise":"http://$lan:$NODE_PROXY_PORT","gateway":"$gateway","force":$force}""")
        if (startKey != null) {
            Native.stopNode()
            try {
                Thread.sleep(600)
            } catch (_: InterruptedException) {
            }
        }
        Native.startNode(
            home,
            gateway,
            token,
            name,
            lan,
            NODE_PROXY_PORT.toString(),
            engine,
        )
        startKey = key
        everLostNetwork = false
    }


    private fun killOrphanEngines(home: String) {
        try {
            val procDir = java.io.File("/proc")
            val dirs = procDir.listFiles() ?: return
            for (dir in dirs) {
                val pid = dir.name.toIntOrNull() ?: continue
                val status = runCatching { java.io.File(dir, "status").readText() }.getOrNull() ?: continue
                val ppid = status.lineSequence()
                    .firstOrNull { it.startsWith("PPid:") }
                    ?.substringAfter(":")
                    ?.trim()
                    ?.toIntOrNull()
                    ?: continue
                if (ppid != 1) continue
                val cmdlineBytes = runCatching { java.io.File(dir, "cmdline").readBytes() }.getOrNull() ?: continue
                val cmd = cmdlineBytes.toString(Charsets.UTF_8).replace('\u0000', ' ')
                if (!cmd.contains("libacowork_engine") && !cmd.contains("acowork-android")) continue
                if (!cmd.contains("runtime")) continue
                if (!cmd.contains(home)) continue
                Log.w(TAG, "reaping orphan runtime pid=$pid")
                android.os.Process.killProcess(pid)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "killOrphanEngines: ${t.message}")
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = connectivityManager()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                everLostNetwork = true
                Log.i(TAG, """{"network":"lost","action":"mqtt_owns_reconnect"}""")
            }

            override fun onAvailable(network: Network) {
                if (!everLostNetwork) return
                everLostNetwork = false
                Log.i(TAG, """{"network":"available","action":"no_native_restart"}""")
            }
        }
        networkCallback = cb
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(req, cb)
    }

    private fun connectivityManager() =
        getSystemService(ConnectivityManager::class.java)

    private fun prefs() = getSharedPreferences(PREFS, MODE_PRIVATE)

    companion object {
        private const val TAG = "ACoworkHost"
        const val CHANNEL_ID = "acowork_host"
        const val NOTIFICATION_ID = 19900
        const val PREFS = "acowork_host"
        const val PREF_GATEWAY = "gateway_http"
        const val PREF_TOKEN = "enrollment_token"
        const val PREF_NAME = "node_name"
        const val NODE_PROXY_PORT = 19900

        const val ACTION_STOP = "com.acowork.androidhost.STOP"
        const val EXTRA_GATEWAY = "gateway"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_NAME = "name"

        fun start(
            context: Context,
            gateway: String,
            token: String,
            name: String,
        ) {
            val intent = Intent(context, HostForegroundService::class.java).apply {
                putExtra(EXTRA_GATEWAY, gateway)
                putExtra(EXTRA_TOKEN, token)
                putExtra(EXTRA_NAME, name)
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, HostForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            ContextCompat.startForegroundService(context, intent)
        }
    }
}
