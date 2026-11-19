package com.acowork.androidhost

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Handler
import android.os.HandlerThread
import android.system.Os
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.security.SecureRandom
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Filesystem Unix socket the runtime engine dials. One JSON line in, one JSON
 * line out. The socket lives in the app-private node home.
 */
/** Thrown when a hardware resource is already owned by another in-flight call or agent. */
class DeviceBusyException(message: String) : RuntimeException(message)

object DeviceBridge {
    private const val TAG = "ACoworkDevice"
    /** One request-response occupies a worker for the whole call, including play_and_wait. */
    const val MAX_INFLIGHT = 16
    private const val REQUEST_READ_MS = 10_000
    private val running = AtomicBoolean(false)
    private val cameraOwner = AtomicReference<String?>(null)
    private val micOwner = AtomicReference<String?>(null)
    private val bleScanOwner = AtomicReference<String?>(null)
    private val inflight = AtomicInteger(0)
    private val auditLock = Any()
    private var server: LocalServerSocket? = null
    private var listenSocket: LocalSocket? = null
    private var acceptThread: Thread? = null
    private val pool = ThreadPoolExecutor(
        4,
        MAX_INFLIGHT,
        30L,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        { r -> Thread(r, "acowork-device-call").apply { isDaemon = true } },
    ) { r, executor ->
        if (!executor.isShutdown) {
            // Accept thread must not block on a long call. Tell the peer immediately.
            (r as? ClientTask)?.reject()
        }
    }
    private var token: String = ""
    private lateinit var cameraThread: HandlerThread
    lateinit var cameraHandler: Handler
        private set
    private lateinit var bridgeThread: HandlerThread
    lateinit var handler: Handler
        private set
    lateinit var appContext: android.content.Context
        private set
    var host: HostForegroundService? = null

    fun attach(service: HostForegroundService) {
        host = service
        appContext = service.applicationContext
    }

    fun isReady(): Boolean = ::appContext.isInitialized && running.get()

    fun start(home: File) {
        if (!running.compareAndSet(false, true)) return
        home.mkdirs()
        if (!::cameraThread.isInitialized || !cameraThread.isAlive) {
            cameraThread = HandlerThread("acowork-camera")
            cameraThread.start()
            cameraHandler = Handler(cameraThread.looper)
            bridgeThread = HandlerThread("acowork-bridge")
            bridgeThread.start()
            handler = Handler(bridgeThread.looper)
        }
        token = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val tokenFile = File(home, "device-bridge.token")
        tokenFile.writeText(token)
        val sock = File(home, "device-bridge.sock")
        if (sock.exists()) sock.delete()
        try {
            val listen = LocalSocket()
            listen.bind(LocalSocketAddress(sock.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
            runCatching { Os.chmod(sock.absolutePath, 384) } // 0600
            server = LocalServerSocket(listen.fileDescriptor)
            listenSocket = listen
        } catch (e: Exception) {
            Log.e(TAG, "bridge listen failed: ${e.message}")
            running.set(false)
            return
        }
        acceptThread = Thread({ acceptLoop() }, "acowork-device-accept").also { it.start() }
        Log.i(TAG, "device bridge listening ${sock.absolutePath}")
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        server?.let { runCatching { it.close() } }
        listenSocket?.let { runCatching { it.close() } }
        server = null
        listenSocket = null
        acceptThread?.join(500)
        acceptThread = null
    }

    fun agentLabel(agent: String): String = agent.ifBlank { "anonymous" }

    fun tryAcquireCamera(agent: String): Boolean = cameraOwner.compareAndSet(null, agentLabel(agent))
    fun cameraHolder(): String? = cameraOwner.get()
    fun releaseCamera() { cameraOwner.set(null) }

    fun tryAcquireMic(agent: String): Boolean = micOwner.compareAndSet(null, agentLabel(agent))
    fun micHolder(): String? = micOwner.get()
    fun releaseMic() { micOwner.set(null) }

    fun tryAcquireBleScan(agent: String): Boolean = bleScanOwner.compareAndSet(null, agentLabel(agent))
    fun bleScanHolder(): String? = bleScanOwner.get()
    fun releaseBleScan() { bleScanOwner.set(null) }

    fun busyMessage(resource: String, holder: String?): String =
        "$resource is in use" + if (holder.isNullOrBlank()) "" else " by $holder"

    fun busy(resource: String, holder: String?): DeviceBusyException =
        DeviceBusyException(busyMessage(resource, holder))

    fun snapshot(): JSONObject = JSONObject()
        .put("inflight", inflight.get())
        .put("max_inflight", MAX_INFLIGHT)
        .put("camera", cameraOwner.get() ?: JSONObject.NULL)
        .put("microphone", micOwner.get() ?: JSONObject.NULL)
        .put("ble_scan", bleScanOwner.get() ?: JSONObject.NULL)

    fun pushKind(kind: String) { host?.pushDeviceKind(kind) }
    fun popKind(kind: String) { host?.popDeviceKind(kind) }

    private fun acceptLoop() {
        val srv = server ?: return
        while (running.get()) {
            val client = try {
                srv.accept()
            } catch (_: Exception) {
                break
            }
            pool.execute(ClientTask(client))
        }
    }

    private class ClientTask(private val client: LocalSocket) : Runnable {
        override fun run() = handleClient(client)
        fun reject() {
            try {
                writeJson(
                    client,
                    envelope(null, DeviceJson.err("busy", "device bridge is at capacity ($MAX_INFLIGHT concurrent calls)")),
                )
            } catch (_: Throwable) {
            } finally {
                runCatching { client.close() }
            }
        }
    }

    private fun handleClient(client: LocalSocket) {
        inflight.incrementAndGet()
        try {
            client.soTimeout = REQUEST_READ_MS
            val line = readLine(client.inputStream, 8 * 1024 * 1024)
            client.soTimeout = 0
            val response = if (line == null) {
                DeviceJson.err("invalid_argument", "empty request")
            } else {
                dispatch(line)
            }
            writeJson(client, response)
        } catch (t: Throwable) {
            Log.w(TAG, "bridge call failed: ${t.message}")
        } finally {
            inflight.decrementAndGet()
            runCatching { client.close() }
        }
    }

    private fun writeJson(client: LocalSocket, response: JSONObject) {
        val out = client.outputStream
        out.write(response.toString().toByteArray(Charsets.UTF_8))
        out.write('\n'.code)
        out.flush()
    }

    private fun dispatch(line: String): JSONObject {
        val req = try {
            JSONObject(line)
        } catch (_: Throwable) {
            return envelope(null, DeviceJson.err("invalid_argument", "request is not JSON"))
        }
        if (req.optString("token") != token) {
            return envelope(req.optString("id"), DeviceJson.err("bridge_unavailable", "device bridge token rejected"))
        }
        val tool = req.optString("tool")
        val args = req.optJSONObject("args") ?: JSONObject()
        val workDir = req.optString("work_dir")
        val agent = req.optString("agent_id")
        val result = try {
            when (tool) {
                "android_device_status" -> StatusHandler.query(appContext, workDir, args)
                "android_photo" -> PhotoHandler.take(appContext, cameraHandler, workDir, args, agent)
                "android_video_record" -> VideoHandler.handle(appContext, cameraHandler, workDir, args, agent)
                "android_audio_record" -> AudioRecordHandler.handle(appContext, workDir, args, agent)
                "android_audio_play" -> AudioPlayHandler.handle(appContext, workDir, args, agent)
                "android_ble_scan" -> BleScanHandler.scan(appContext, handler, workDir, args, agent)
                "android_ble_gatt" -> BleGattHandler.handle(appContext, handler, args, agent)
                "android_usb_hid" -> UsbHidHandler.handle(appContext, handler, workDir, args, agent)
                else -> DeviceJson.err("invalid_argument", "unknown device tool $tool")
            }
        } catch (t: DeviceBusyException) {
            DeviceJson.err("busy", t.message ?: "busy")
        } catch (t: IllegalArgumentException) {
            DeviceJson.err("invalid_argument", t.message ?: "invalid argument")
        } catch (t: UnsupportedOperationException) {
            val msg = t.message?.removePrefix("unsupported_api:")?.trim().orEmpty()
            DeviceJson.err("unsupported_api", msg.ifEmpty { "unsupported on this API level" })
        } catch (t: Throwable) {
            DeviceJson.err("failed", t.message ?: t.toString())
        }
        audit(homeOf(workDir), agent, tool, args, result)
        return envelope(req.optString("id"), result)
    }

    private fun envelope(id: String?, body: JSONObject): JSONObject {
        body.put("v", 1)
        body.put("id", id ?: "")
        return body
    }

    private fun homeOf(workDir: String): File? {
        if (workDir.isBlank()) return null
        val agents = File(workDir).parentFile
        return agents?.parentFile
    }

    private fun audit(home: File?, agent: String, tool: String, args: JSONObject, result: JSONObject) {
        if (home == null) return
        val safeArgs = JSONObject(args.toString())
        strip(safeArgs)
        val line = JSONObject()
            .put("time_ms", System.currentTimeMillis())
            .put("agent", agent)
            .put("tool", tool)
            .put("op", args.optString("op"))
            .put("ok", result.optBoolean("ok"))
            .put("error_code", result.optString("error_code"))
            .put("args", safeArgs)
            .toString()
        runCatching {
            synchronized(auditLock) {
                File(home, "device-audit.jsonl").appendText(line + "\n")
            }
        }
    }

    private fun strip(o: JSONObject) {
        val drop = listOf("value_hex", "data_hex", "advertising_data", "manufacturer_data", "service_data")
        for (key in drop) if (o.has(key)) o.put(key, "<omitted>")
        val keys = o.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val child = o.optJSONObject(key) ?: continue
            strip(child)
        }
    }

    private fun readLine(input: InputStream, max: Int): String? {
        val buf = java.io.ByteArrayOutputStream()
        while (buf.size() <= max) {
            val b = input.read()
            if (b < 0) return if (buf.size() == 0) null else buf.toString(Charsets.UTF_8.name())
            if (b == '\n'.code) return buf.toString(Charsets.UTF_8.name())
            buf.write(b)
        }
        throw IllegalArgumentException("request exceeds $max bytes")
    }
}
