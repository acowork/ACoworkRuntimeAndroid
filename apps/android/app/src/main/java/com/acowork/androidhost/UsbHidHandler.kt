package com.acowork.androidhost

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Handler
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

object UsbHidHandler {
    const val ACTION_USB_PERMISSION = "com.acowork.androidhost.USB_PERMISSION"

    private class Open(
        val device: UsbDevice,
        val connection: UsbDeviceConnection,
        val owner: String,
        val lock: Any = Any(),
        val claimed: MutableSet<Int> = HashSet(),
        var idleMs: Long = 60_000,
        var idle: Runnable? = null,
    )

    private val open = ConcurrentHashMap<Int, Open>()
    private var receiver = false

    fun handle(context: Context, handler: Handler, workDir: String, args: JSONObject, agent: String): JSONObject {
        ensureReceiver(context)
        val op = args.optString("op")
        if (op.isEmpty()) return DeviceJson.err("invalid_argument", "op is required")
        val usb = context.getSystemService(UsbManager::class.java)
        return try {
            when (op) {
                "list" -> list(usb, workDir, args)
                "open" -> open(context, usb, handler, args, agent)
                "close" -> close(usb, args, agent)
                "claim" -> claim(usb, args, agent)
                "release" -> release(usb, args, agent)
                "set_configuration" -> setConfig(usb, args, agent)
                "set_interface" -> setInterface(usb, args, agent)
                "control_transfer" -> control(usb, workDir, args, agent)
                "transfer" -> transfer(usb, workDir, args, agent)
                "get_raw_descriptors" -> raw(usb, workDir, args)
                else -> DeviceJson.err("invalid_argument", "unknown usb op $op")
            }
        } catch (t: DeviceBusyException) {
            DeviceJson.err("busy", t.message ?: "busy")
        } catch (t: IllegalArgumentException) {
            DeviceJson.err("invalid_argument", t.message ?: "invalid usb arguments")
        } catch (t: IllegalStateException) {
            DeviceJson.err("failed", t.message ?: "usb failed")
        }
    }

    fun permissionIntent(context: Context): PendingIntent {
        val flags = if (Build.VERSION.SDK_INT >= 31) {
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val intent = Intent(ACTION_USB_PERMISSION).setPackage(context.packageName)
        return PendingIntent.getBroadcast(context, 0, intent, flags)
    }

    private fun list(usb: UsbManager, workDir: String, args: JSONObject): JSONObject {
        val devices = JSONArray()
        for (device in usb.deviceList.values) {
            if (!isHid(device)) continue
            devices.put(describe(usb, device))
        }
        val data = JSONObject().put("devices", devices).put("count", devices.length())
        return DeviceJson.finish("usb hid devices ${devices.length()}", data, workDir, args.optString("output").ifBlank { null })
    }

    private fun open(context: Context, usb: UsbManager, handler: Handler, args: JSONObject, agent: String): JSONObject {
        val device = find(usb, args)
        if (!usb.hasPermission(device)) {
            DevicePermissions.usb(context, device.deviceName)
            return DeviceJson.err(
                "permission_required",
                "Grant USB access for ${device.deviceName} (vid=${device.vendorId} pid=${device.productId}) from the ACowork Host notification, then retry.",
            )
        }
        val who = DeviceBridge.agentLabel(agent)
        val existing = open[device.deviceId]
        if (existing != null) {
            if (existing.owner != who) {
                return DeviceJson.err("busy", DeviceBridge.busyMessage("usb ${device.deviceName}", existing.owner))
            }
            sessionTouch(handler, existing, args)
            return DeviceJson.ok("opened ${device.deviceName}", describe(usb, device).put("opened", true))
        }
        DeviceBridge.pushKind("connected")
        val connection = usb.openDevice(device)
            ?: return DeviceJson.err("failed", "openDevice returned null").also { DeviceBridge.popKind("connected") }
        val session = Open(device, connection, who)
        val raced = open.putIfAbsent(device.deviceId, session)
        if (raced != null) {
            connection.close()
            DeviceBridge.popKind("connected")
            return DeviceJson.err("busy", DeviceBridge.busyMessage("usb ${device.deviceName}", raced.owner))
        }
        sessionTouch(handler, session, args)
        return DeviceJson.ok("opened ${device.deviceName}", describe(usb, device).put("opened", true))
    }

    private fun sessionTouch(handler: Handler, session: Open, args: JSONObject) {
        session.idleMs = if (args.has("idle_timeout_ms")) args.getLong("idle_timeout_ms") else 60_000L
        if (args.has("interface_id")) claimOn(handler, session, args)
        bumpIdle(handler, session)
    }

    private fun close(usb: UsbManager, args: JSONObject, agent: String): JSONObject {
        val device = find(usb, args)
        val session = open[device.deviceId] ?: return DeviceJson.ok("already closed", JSONObject().put("device_id", device.deviceId))
        val who = DeviceBridge.agentLabel(agent)
        if (session.owner != who) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("usb ${device.deviceName}", session.owner))
        }
        open.remove(device.deviceId)
        session.idle?.let { DeviceBridge.handler.removeCallbacks(it) }
        session.claimed.toList().forEach { id ->
            runCatching { session.connection.releaseInterface(interfaceById(session.device, id)) }
        }
        session.connection.close()
        DeviceBridge.popKind("connected")
        return DeviceJson.ok("closed ${device.deviceName}", JSONObject().put("device_id", device.deviceId))
    }

    private fun claim(usb: UsbManager, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        synchronized(session.lock) {
            claimOn(DeviceBridge.handler, session, args)
            bumpIdle(DeviceBridge.handler, session)
        }
        return DeviceJson.ok("claimed interface ${args.optInt("interface_id")}", JSONObject().put("device_id", session.device.deviceId))
    }

    private fun release(usb: UsbManager, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        val id = args.getInt("interface_id")
        val iface = interfaceById(session.device, id)
        synchronized(session.lock) {
            session.connection.releaseInterface(iface)
            session.claimed.remove(id)
        }
        return DeviceJson.ok("released interface $id", JSONObject().put("device_id", session.device.deviceId))
    }

    private fun setConfig(usb: UsbManager, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        val id = args.getInt("configuration_id")
        val cfg = (0 until session.device.configurationCount)
            .map { session.device.getConfiguration(it) }
            .firstOrNull { it.id == id }
            ?: throw IllegalArgumentException("no configuration id $id")
        val ok = synchronized(session.lock) { session.connection.setConfiguration(cfg) }
        if (!ok) return DeviceJson.err("failed", "setConfiguration rejected")
        bumpIdle(DeviceBridge.handler, session)
        return DeviceJson.ok("configuration $id", JSONObject().put("configuration_id", id))
    }

    private fun setInterface(usb: UsbManager, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        val iface = interfaceById(session.device, args.getInt("interface_id"))
        val ok = synchronized(session.lock) { session.connection.setInterface(iface) }
        if (!ok) return DeviceJson.err("failed", "setInterface rejected")
        bumpIdle(DeviceBridge.handler, session)
        return DeviceJson.ok("interface ${iface.id}", JSONObject().put("interface_id", iface.id))
    }

    private fun control(usb: UsbManager, workDir: String, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        val requestType = args.getInt("request_type")
        val request = args.getInt("request")
        val value = args.getInt("value")
        val index = args.getInt("index")
        val timeout = if (args.has("timeout_ms")) args.getInt("timeout_ms") else 1000
        val outbound = DeviceJson.hexToBytes(args.optString("data_hex"))
        val inbound = (requestType and UsbConstants.USB_DIR_IN) != 0
        val length = when {
            args.has("length") -> args.getInt("length")
            inbound -> 64
            else -> outbound.size
        }
        if (length < 0 || length > 1_048_576) {
            return DeviceJson.err("invalid_argument", "length must be 0..1048576")
        }
        val buffer = if (inbound) ByteArray(length) else outbound.copyOf(maxOf(length, outbound.size))
        val n = synchronized(session.lock) {
            session.connection.controlTransfer(requestType, request, value, index, buffer, length, timeout)
        }
        if (n < 0) return DeviceJson.err("failed", "controlTransfer returned $n")
        bumpIdle(DeviceBridge.handler, session)
        val data = JSONObject().put("transferred", n).put("device_id", session.device.deviceId)
        if (inbound) {
            val slice = buffer.copyOf(n)
            DeviceJson.putBytes(data, "data_hex", slice, workDir, args.optString("output").ifBlank { null })
        }
        return DeviceJson.ok("controlTransfer $n bytes", data)
    }

    private fun transfer(usb: UsbManager, workDir: String, args: JSONObject, agent: String): JSONObject {
        val session = need(usb, args, agent)
        val endpoint = endpoint(session.device, args)
        val timeout = if (args.has("timeout_ms")) args.getInt("timeout_ms") else 1000
        val outbound = DeviceJson.hexToBytes(args.optString("data_hex"))
        val inbound = endpoint.direction == UsbConstants.USB_DIR_IN
        val length = when {
            args.has("length") -> args.getInt("length")
            inbound -> endpoint.maxPacketSize.coerceAtLeast(64)
            else -> outbound.size
        }
        if (length < 0 || length > 1_048_576) return DeviceJson.err("invalid_argument", "length must be 0..1048576")
        val buffer = if (inbound) ByteArray(length) else outbound.copyOf(length.coerceAtLeast(outbound.size))
        val n = synchronized(session.lock) {
            session.connection.bulkTransfer(endpoint, buffer, length, timeout)
        }
        if (n < 0) return DeviceJson.err("failed", "bulkTransfer returned $n")
        bumpIdle(DeviceBridge.handler, session)
        val data = JSONObject()
            .put("transferred", n)
            .put("endpoint_address", endpoint.address)
            .put("device_id", session.device.deviceId)
        if (inbound) DeviceJson.putBytes(data, "data_hex", buffer.copyOf(n), workDir, args.optString("output").ifBlank { null })
        return DeviceJson.ok("transfer $n bytes", data)
    }

    private fun raw(usb: UsbManager, workDir: String, args: JSONObject): JSONObject {
        val device = find(usb, args)
        if (!usb.hasPermission(device)) {
            DevicePermissions.usb(context = usbContext(usb), device.deviceName)
            return DeviceJson.err("permission_required", "Grant USB access for ${device.deviceName}, then retry.")
        }
        val session = open[device.deviceId]
        val connection = session?.connection ?: usb.openDevice(device) ?: return DeviceJson.err("failed", "openDevice returned null")
        val bytes = connection.rawDescriptors ?: ByteArray(0)
        if (session == null) connection.close()
        val data = JSONObject().put("device_id", device.deviceId).put("length", bytes.size)
        DeviceJson.putBytes(data, "descriptors_hex", bytes, workDir, args.optString("output").ifBlank { null })
        return DeviceJson.ok("raw descriptors ${bytes.size} bytes", data)
    }

    private fun usbContext(usb: UsbManager): Context = DeviceBridge.appContext

    private fun need(usb: UsbManager, args: JSONObject, agent: String): Open {
        val device = find(usb, args)
        val session = open[device.deviceId] ?: throw IllegalStateException("device ${device.deviceId} is not open")
        val who = DeviceBridge.agentLabel(agent)
        if (session.owner != who) throw DeviceBridge.busy("usb ${device.deviceName}", session.owner)
        return session
    }

    private fun claimOn(handler: Handler, session: Open, args: JSONObject) {
        val iface = interfaceById(session.device, args.getInt("interface_id"))
        val force = !args.has("force_claim") || args.getBoolean("force_claim")
        if (!session.connection.claimInterface(iface, force)) {
            throw IllegalStateException("claimInterface ${iface.id} rejected")
        }
        session.claimed.add(iface.id)
        if (args.has("alternate_setting")) {
            // claim uses the interface object, which already carries its alternate setting
        }
        bumpIdle(handler, session)
    }

    private fun bumpIdle(handler: Handler, session: Open) {
        session.idle?.let { handler.removeCallbacks(it) }
        if (session.idleMs <= 0) return
        val task = Runnable {
            session.claimed.toList().forEach { id ->
                runCatching { session.connection.releaseInterface(interfaceById(session.device, id)) }
            }
            session.claimed.clear()
        }
        session.idle = task
        handler.postDelayed(task, session.idleMs)
    }

    private fun find(usb: UsbManager, args: JSONObject): UsbDevice {
        val id = if (args.has("device_id")) args.getInt("device_id") else -1
        val name = args.optString("device_name")
        val vid = if (args.has("vendor_id")) args.getInt("vendor_id") else -1
        val pid = if (args.has("product_id")) args.getInt("product_id") else -1
        val serial = args.optString("serial")
        return usb.deviceList.values.firstOrNull { device ->
            isHid(device) &&
                (id < 0 || device.deviceId == id) &&
                (name.isEmpty() || device.deviceName == name) &&
                (vid < 0 || device.vendorId == vid) &&
                (pid < 0 || device.productId == pid) &&
                (serial.isEmpty() || runCatching { device.serialNumber }.getOrNull() == serial)
        } ?: throw IllegalArgumentException("no matching HID device")
    }

    private fun isHid(device: UsbDevice): Boolean {
        if (device.deviceClass == UsbConstants.USB_CLASS_HID) return true
        for (i in 0 until device.interfaceCount) {
            if (device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_HID) return true
        }
        return false
    }

    private fun interfaceById(device: UsbDevice, id: Int): UsbInterface {
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            if (iface.id == id) return iface
        }
        throw IllegalArgumentException("no interface id $id")
    }

    private fun endpoint(device: UsbDevice, args: JSONObject): UsbEndpoint {
        val address = if (args.has("endpoint_address")) args.getInt("endpoint_address") else null
        val number = if (args.has("endpoint_number")) args.getInt("endpoint_number") else null
        val direction = when (args.optString("direction")) {
            "in" -> UsbConstants.USB_DIR_IN
            "out" -> UsbConstants.USB_DIR_OUT
            else -> null
        }
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            for (e in 0 until iface.endpointCount) {
                val ep = iface.getEndpoint(e)
                if (address != null && ep.address == address) return ep
                if (number != null && ep.endpointNumber == number && (direction == null || ep.direction == direction)) return ep
            }
        }
        throw IllegalArgumentException("endpoint not found")
    }

    private fun describe(usb: UsbManager, device: UsbDevice): JSONObject {
        val configs = JSONArray()
        for (c in 0 until device.configurationCount) {
            val cfg = device.getConfiguration(c)
            val ifaces = JSONArray()
            for (i in 0 until cfg.interfaceCount) {
                val iface = cfg.getInterface(i)
                val eps = JSONArray()
                for (e in 0 until iface.endpointCount) {
                    val ep = iface.getEndpoint(e)
                    eps.put(JSONObject()
                        .put("address", ep.address)
                        .put("number", ep.endpointNumber)
                        .put("direction", if (ep.direction == UsbConstants.USB_DIR_IN) "in" else "out")
                        .put("type", ep.type)
                        .put("max_packet_size", ep.maxPacketSize)
                        .put("interval", ep.interval)
                        .put("attributes", ep.attributes))
                }
                ifaces.put(JSONObject()
                    .put("id", iface.id)
                    .put("alternate", iface.alternateSetting)
                    .put("class", iface.interfaceClass)
                    .put("subclass", iface.interfaceSubclass)
                    .put("protocol", iface.interfaceProtocol)
                    .put("name", iface.name)
                    .put("endpoints", eps))
            }
            configs.put(JSONObject()
                .put("id", cfg.id)
                .put("name", cfg.name)
                .put("max_power_ma", cfg.maxPower)
                .put("self_powered", cfg.isSelfPowered)
                .put("interfaces", ifaces))
        }
        return JSONObject()
            .put("device_id", device.deviceId)
            .put("device_name", device.deviceName)
            .put("vendor_id", device.vendorId)
            .put("product_id", device.productId)
            .put("device_class", device.deviceClass)
            .put("device_subclass", device.deviceSubclass)
            .put("device_protocol", device.deviceProtocol)
            .put("manufacturer", runCatching { device.manufacturerName }.getOrNull())
            .put("product", runCatching { device.productName }.getOrNull())
            .put("serial", runCatching { device.serialNumber }.getOrNull())
            .put("version", device.version)
            .put("has_permission", usb.hasPermission(device))
            .put("configurations", configs)
    }

    private fun ensureReceiver(context: Context) {
        if (receiver) return
        val filter = IntentFilter(ACTION_USB_PERMISSION)
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                // The agent retries the tool after the user grants access.
            }
        }
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED)
        else context.registerReceiver(r, filter)
        receiver = true
    }
}
