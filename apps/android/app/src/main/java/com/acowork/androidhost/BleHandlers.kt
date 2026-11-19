package com.acowork.androidhost

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.ParcelUuid
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

object BleScanHandler {
    @SuppressLint("MissingPermission")
    fun scan(context: Context, handler: Handler, workDir: String, args: JSONObject, agent: String): JSONObject {
        val missing = DevicePermissions.firstMissing(context, DevicePermissions.bleScan())
        if (missing != null) return DevicePermissions.required(context, missing)
        val adapter = context.getSystemService(BluetoothManager::class.java).adapter
            ?: return DeviceJson.err("failed", "this device has no Bluetooth adapter")
        if (!adapter.isEnabled) return DeviceJson.err("failed", "Bluetooth is off")
        val scanner = adapter.bluetoothLeScanner ?: return DeviceJson.err("failed", "BLE scanner is unavailable")
        if (!DeviceBridge.tryAcquireBleScan(agent)) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("ble scan", DeviceBridge.bleScanHolder()))
        }
        DeviceBridge.pushKind("connected")
        val duration = if (args.has("duration_ms")) args.getLong("duration_ms") else 10_000L
        val includeRaw = !args.has("include_raw") || args.getBoolean("include_raw")
        val results = JSONArray()
        val done = CountDownLatch(1)
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                results.put(scanJson(result, includeRaw))
            }
            override fun onBatchScanResults(batch: MutableList<ScanResult>) {
                batch.forEach { results.put(scanJson(it, includeRaw)) }
            }
            override fun onScanFailed(errorCode: Int) {
                done.countDown()
            }
        }
        return try {
            scanner.startScan(scanFilters(args.optJSONArray("filters")), scanSettings(args.optJSONObject("settings")), callback)
            done.await(duration, TimeUnit.MILLISECONDS)
            scanner.stopScan(callback)
            val data = JSONObject().put("results", results).put("count", results.length())
            DeviceJson.finish("ble scan returned ${results.length()} result(s)", data, workDir, args.optString("output").ifBlank { null })
        } catch (t: SecurityException) {
            DeviceJson.err("permission_required", t.message ?: "bluetooth permission denied")
        } catch (t: IllegalArgumentException) {
            DeviceJson.err("invalid_argument", t.message ?: "invalid scan arguments")
        } finally {
            DeviceBridge.releaseBleScan()
            DeviceBridge.popKind("connected")
        }
    }
}

object BleGattHandler {
    private val sessions = ConcurrentHashMap<String, GattSession>()
    private val notes = ConcurrentHashMap<String, ConcurrentLinkedQueue<JSONObject>>()
    private var bondReceiver = false
    private val bondLatch = AtomicReference<CountDownLatch?>(null)
    private val bondState = AtomicInteger(-1)

    @SuppressLint("MissingPermission")
    fun handle(context: Context, handler: Handler, args: JSONObject, agent: String): JSONObject {
        val op = args.optString("op")
        val address = args.optString("address")
        if (op.isEmpty() || address.isEmpty()) {
            return DeviceJson.err("invalid_argument", "op and address are required")
        }
        val missing = DevicePermissions.firstMissing(context, DevicePermissions.bleConnect())
        if (missing != null) return DevicePermissions.required(context, missing)
        val timeout = if (args.has("timeout_ms")) args.getLong("timeout_ms") else 10_000L
        return try {
            when (op) {
                "connect" -> connect(context, handler, address, args, timeout, agent)
                "disconnect" -> {
                    val session = need(address, agent)
                    sessions.remove(address)
                    session.gatt?.disconnect()
                    DeviceJson.ok("disconnecting $address", JSONObject().put("address", address))
                }
                "close" -> {
                    val session = need(address, agent)
                    sessions.remove(address)
                    session.gatt?.close()
                    notes.remove(address)
                    DeviceJson.ok("closed $address", JSONObject().put("address", address))
                }
                "discover_services" -> withSession(address, agent, timeout) { discover(address, timeout) }
                "list" -> run { need(address, agent); list(address) }
                "request_mtu" -> withSession(address, agent, timeout) { requestMtu(address, args.getInt("mtu"), timeout) }
                "request_connection_priority" -> withSession(address, agent, timeout) { priority(address, args.optString("priority", "balanced")) }
                "set_preferred_phy" -> withSession(address, agent, timeout) { phy(address, args, timeout) }
                "read_phy" -> withSession(address, agent, timeout) { readPhy(address, timeout) }
                "read_rssi" -> withSession(address, agent, timeout) { readRssi(address, timeout) }
                "read" -> withSession(address, agent, timeout) { readChar(address, args, timeout) }
                "write" -> withSession(address, agent, timeout) { writeChar(address, args, timeout) }
                "read_descriptor" -> withSession(address, agent, timeout) { readDesc(address, args, timeout) }
                "write_descriptor" -> withSession(address, agent, timeout) { writeDesc(address, args, timeout) }
                "subscribe" -> withSession(address, agent, timeout) { subscribe(address, args, timeout) }
                "unsubscribe" -> withSession(address, agent, timeout) { subscribe(address, args, timeout, enable = false) }
                "create_bond" -> bond(context, address, args, timeout)
                "fetch_uuids" -> fetchUuids(address)
                "get_bond_state" -> DeviceJson.ok("bond state", JSONObject().put("bond_state", device(address).bondState))
                "status" -> run {
                    if (sessions.containsKey(address)) need(address, agent)
                    status(address)
                }
                else -> DeviceJson.err("invalid_argument", "unknown gatt op $op")
            }
        } catch (t: DeviceBusyException) {
            DeviceJson.err("busy", t.message ?: "busy")
        } catch (t: SecurityException) {
            DevicePermissions.required(context, android.Manifest.permission.BLUETOOTH_CONNECT)
        } catch (t: IllegalArgumentException) {
            DeviceJson.err("invalid_argument", t.message ?: "invalid gatt arguments")
        } catch (t: IllegalStateException) {
            DeviceJson.err("failed", t.message ?: "gatt failed")
        }
    }

    @SuppressLint("MissingPermission")
    private fun connect(context: Context, handler: Handler, address: String, args: JSONObject, timeout: Long, agent: String): JSONObject {
        if (args.has("phy_options") && args.getInt("phy_options") != 0) {
            throw UnsupportedOperationException("unsupported_api: connectGatt has no public phy_options argument; use set_preferred_phy")
        }
        val who = DeviceBridge.agentLabel(agent)
        val existing = sessions[address]
        if (existing != null) {
            if (existing.owner == who) {
                return DeviceJson.ok(
                    "already connected $address",
                    JSONObject().put("address", address).put("connection_state", existing.state).put("gatt_status", existing.status),
                )
            }
            return DeviceJson.err("busy", DeviceBridge.busyMessage("gatt $address", existing.owner))
        }
        DeviceBridge.pushKind("connected")
        val adapter = context.getSystemService(BluetoothManager::class.java).adapter
        val device = adapter.getRemoteDevice(address)
        val session = GattSession(address, who)
        if (sessions.putIfAbsent(address, session) != null) {
            DeviceBridge.popKind("connected")
            return DeviceJson.err("busy", DeviceBridge.busyMessage("gatt $address", sessions[address]?.owner))
        }
        val transport = when (args.optString("transport", "auto")) {
            "br_edr" -> BluetoothDevice.TRANSPORT_BREDR
            "le" -> BluetoothDevice.TRANSPORT_LE
            else -> BluetoothDevice.TRANSPORT_AUTO
        }
        val phy = if (args.has("phy_mask")) args.getInt("phy_mask") else BluetoothDevice.PHY_LE_1M_MASK
        val gatt = try {
            device.connectGatt(context, args.optBoolean("auto_connect"), session, transport, phy, handler)
        } catch (t: Throwable) {
            sessions.remove(address)
            DeviceBridge.popKind("connected")
            throw t
        }
        session.gatt = gatt
        val ok = session.await(timeout)
        if (!ok || session.state != BluetoothProfile.STATE_CONNECTED) {
            sessions.remove(address)
            gatt.close()
            DeviceBridge.popKind("connected")
            return DeviceJson.err("failed", "connect failed state=${session.state} status=${session.status}")
        }
        return DeviceJson.ok(
            "connected $address",
            JSONObject().put("address", address).put("connection_state", session.state).put("gatt_status", session.status),
        )
    }

    @SuppressLint("MissingPermission")
    private fun discover(address: String, timeout: Long): JSONObject {
        val session = need(address)
        session.prepare()
        if (session.gatt?.discoverServices() != true) return DeviceJson.err("failed", "discoverServices rejected")
        session.await(timeout)
        return list(address).putExtraStatus(session)
    }

    @SuppressLint("MissingPermission")
    private fun list(address: String): JSONObject {
        val gatt = need(address).gatt ?: throw IllegalStateException("no gatt")
        val services = JSONArray()
        for (service in gatt.services) {
            val chars = JSONArray()
            for (ch in service.characteristics) {
                val descs = JSONArray()
                for (d in ch.descriptors) {
                    descs.put(JSONObject()
                        .put("uuid", d.uuid.toString())
                        .put("permissions", d.permissions)
                        .put("value_hex", d.value?.let { DeviceJson.bytesToHex(it) } ?: JSONObject.NULL))
                }
                chars.put(JSONObject()
                    .put("uuid", ch.uuid.toString())
                    .put("instance_id", ch.instanceId)
                    .put("properties", ch.properties)
                    .put("permissions", ch.permissions)
                    .put("write_type", ch.writeType)
                    .put("descriptors", descs))
            }
            services.put(JSONObject()
                .put("uuid", service.uuid.toString())
                .put("instance_id", service.instanceId)
                .put("type", if (service.type == android.bluetooth.BluetoothGattService.SERVICE_TYPE_PRIMARY) "primary" else "secondary")
                .put("characteristics", chars))
        }
        return DeviceJson.ok("services ${services.length()}", JSONObject().put("address", address).put("services", services))
    }

    @SuppressLint("MissingPermission")
    private fun requestMtu(address: String, mtu: Int, timeout: Long): JSONObject {
        val session = need(address)
        session.prepare()
        if (session.gatt?.requestMtu(mtu) != true) return DeviceJson.err("failed", "requestMtu rejected")
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("mtu", session.mtu))
    }

    @SuppressLint("MissingPermission")
    private fun priority(address: String, name: String): JSONObject {
        val p = when (name) {
            "high" -> BluetoothGatt.CONNECTION_PRIORITY_HIGH
            "low_power" -> BluetoothGatt.CONNECTION_PRIORITY_LOW_POWER
            else -> BluetoothGatt.CONNECTION_PRIORITY_BALANCED
        }
        val ok = need(address).gatt?.requestConnectionPriority(p) == true
        return if (ok) DeviceJson.ok("priority $name", JSONObject().put("address", address).put("priority", name))
        else DeviceJson.err("failed", "requestConnectionPriority rejected")
    }

    @SuppressLint("MissingPermission")
    private fun phy(address: String, args: JSONObject, timeout: Long): JSONObject {
        val session = need(address)
        session.prepare()
        val tx = if (args.has("tx_phy")) args.getInt("tx_phy") else BluetoothDevice.PHY_LE_1M_MASK
        val rx = if (args.has("rx_phy")) args.getInt("rx_phy") else tx
        val options = if (args.has("phy_options")) args.getInt("phy_options") else BluetoothDevice.PHY_OPTION_NO_PREFERRED
        session.gatt?.setPreferredPhy(tx, rx, options)
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("tx_phy", session.txPhy).put("rx_phy", session.rxPhy))
    }

    @SuppressLint("MissingPermission")
    private fun readPhy(address: String, timeout: Long): JSONObject {
        val session = need(address)
        session.prepare()
        session.gatt?.readPhy()
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("tx_phy", session.txPhy).put("rx_phy", session.rxPhy))
    }

    @SuppressLint("MissingPermission")
    private fun readRssi(address: String, timeout: Long): JSONObject {
        val session = need(address)
        session.prepare()
        if (session.gatt?.readRemoteRssi() != true) return DeviceJson.err("failed", "readRemoteRssi rejected")
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("rssi", session.rssi))
    }

    @SuppressLint("MissingPermission")
    private fun readChar(address: String, args: JSONObject, timeout: Long): JSONObject {
        val session = need(address)
        val ch = findChar(session, args)
        session.prepare()
        if (session.gatt?.readCharacteristic(ch) != true) return DeviceJson.err("failed", "readCharacteristic rejected")
        session.await(timeout)
        val data = JSONObject().put("value_hex", session.value?.let { DeviceJson.bytesToHex(it) })
        return gattOk(address, session, data)
    }

    @SuppressLint("MissingPermission")
    private fun writeChar(address: String, args: JSONObject, timeout: Long): JSONObject {
        val session = need(address)
        val ch = findChar(session, args)
        val bytes = DeviceJson.hexToBytes(args.optString("value_hex"))
        val writeType = when (args.optString("write_type", "default")) {
            "no_response" -> BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            "signed" -> BluetoothGattCharacteristic.WRITE_TYPE_SIGNED
            else -> BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        }
        session.prepare()
        val started = if (Build.VERSION.SDK_INT >= 33) {
            session.gatt?.writeCharacteristic(ch, bytes, writeType) == BluetoothGatt.GATT_SUCCESS
        } else {
            @Suppress("DEPRECATION")
            ch.writeType = writeType
            @Suppress("DEPRECATION")
            ch.value = bytes
            @Suppress("DEPRECATION")
            session.gatt?.writeCharacteristic(ch) == true
        }
        if (!started) return DeviceJson.err("failed", "writeCharacteristic rejected")
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("length", bytes.size))
    }

    @SuppressLint("MissingPermission")
    private fun readDesc(address: String, args: JSONObject, timeout: Long): JSONObject {
        val session = need(address)
        val desc = findDesc(session, args)
        session.prepare()
        if (session.gatt?.readDescriptor(desc) != true) return DeviceJson.err("failed", "readDescriptor rejected")
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("value_hex", session.value?.let { DeviceJson.bytesToHex(it) }))
    }

    @SuppressLint("MissingPermission")
    private fun writeDesc(address: String, args: JSONObject, timeout: Long, value: ByteArray? = null): JSONObject {
        val session = need(address)
        val desc = findDesc(session, args)
        val bytes = value ?: DeviceJson.hexToBytes(args.optString("value_hex"))
        session.prepare()
        val started = if (Build.VERSION.SDK_INT >= 33) {
            session.gatt?.writeDescriptor(desc, bytes) == BluetoothGatt.GATT_SUCCESS
        } else {
            @Suppress("DEPRECATION")
            desc.value = bytes
            @Suppress("DEPRECATION")
            session.gatt?.writeDescriptor(desc) == true
        }
        if (!started) return DeviceJson.err("failed", "writeDescriptor rejected")
        session.await(timeout)
        return gattOk(address, session, JSONObject().put("length", bytes.size))
    }

    @SuppressLint("MissingPermission")
    private fun subscribe(address: String, args: JSONObject, timeout: Long, enable: Boolean = true): JSONObject {
        val session = need(address)
        val ch = findChar(session, args)
        session.gatt?.setCharacteristicNotification(ch, enable)
        val cccd = ch.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"))
            ?: return DeviceJson.err("invalid_argument", "characteristic has no CCCD")
        val indicate = args.optString("notification", "notify") == "indicate"
        val value = when {
            !enable -> BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            indicate -> BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
            else -> BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        }
        val wrote = writeDesc(address, args.put("descriptor_uuid", cccd.uuid.toString()), timeout, value)
        if (!wrote.optBoolean("ok")) return wrote
        val wait = if (args.has("subscribe_wait_ms")) args.getLong("subscribe_wait_ms") else 0L
        if (wait > 0) Thread.sleep(wait)
        val queued = JSONArray()
        val q = notes[address]
        while (q != null && q.isNotEmpty()) queued.put(q.poll())
        return DeviceJson.ok(
            if (enable) "subscribed" else "unsubscribed",
            JSONObject().put("address", address).put("notifications", queued).put("gatt_status", session.status),
        )
    }

    @SuppressLint("MissingPermission")
    private fun bond(context: Context, address: String, args: JSONObject, timeout: Long): JSONObject {
        if (args.optString("transport", "auto") != "auto") {
            throw UnsupportedOperationException("unsupported_api: BluetoothDevice.createBond(transport) is not in the public SDK")
        }
        ensureBondReceiver(context)
        val dev = device(address)
        val latch = CountDownLatch(1)
        bondLatch.set(latch)
        val started = dev.createBond()
        if (!started) return DeviceJson.err("failed", "createBond rejected")
        latch.await(timeout, TimeUnit.MILLISECONDS)
        return DeviceJson.ok("bond_state=${dev.bondState}", JSONObject().put("address", address).put("bond_state", dev.bondState))
    }

    @SuppressLint("MissingPermission")
    private fun fetchUuids(address: String): JSONObject {
        val dev = device(address)
        dev.fetchUuidsWithSdp()
        val arr = JSONArray()
        dev.uuids?.forEach { arr.put(it.uuid.toString()) }
        return DeviceJson.ok("uuids ${arr.length()}", JSONObject().put("uuids", arr).put("bond_state", dev.bondState))
    }

    private fun status(address: String): JSONObject {
        val session = sessions[address]
        val queued = JSONArray()
        val q = notes[address]
        while (q != null && q.isNotEmpty()) queued.put(q.poll())
        val data = JSONObject()
            .put("address", address)
            .put("connected", session?.state == BluetoothProfile.STATE_CONNECTED)
            .put("connection_state", session?.state ?: BluetoothProfile.STATE_DISCONNECTED)
            .put("mtu", session?.mtu)
            .put("rssi", session?.rssi)
            .put("tx_phy", session?.txPhy)
            .put("rx_phy", session?.rxPhy)
            .put("notifications", queued)
        return DeviceJson.ok("status $address", data)
    }

    private fun need(address: String, agent: String = ""): GattSession {
        val session = sessions[address] ?: throw IllegalStateException("not connected to $address")
        if (agent.isNotEmpty()) {
            val who = DeviceBridge.agentLabel(agent)
            if (session.owner != who) throw DeviceBridge.busy("gatt $address", session.owner)
        }
        return session
    }

    private fun withSession(address: String, agent: String, timeout: Long, block: () -> JSONObject): JSONObject {
        val session = need(address, agent)
        if (!session.opLock.tryLock(timeout.coerceAtLeast(1L), TimeUnit.MILLISECONDS)) {
            throw DeviceBridge.busy("gatt $address", session.owner)
        }
        try {
            return block()
        } finally {
            session.opLock.unlock()
        }
    }

    @SuppressLint("MissingPermission")
    private fun device(address: String): BluetoothDevice {
        val session = sessions[address]
        if (session?.gatt?.device != null) return session.gatt!!.device
        throw IllegalStateException("not connected to $address")
    }

    private fun findChar(session: GattSession, args: JSONObject): BluetoothGattCharacteristic {
        val gatt = session.gatt ?: throw IllegalStateException("no gatt")
        val su = parseUuid(args.getString("service_uuid"))
        val cu = parseUuid(args.getString("characteristic_uuid"))
        val sInst = if (args.has("service_instance_id")) args.getInt("service_instance_id") else -1
        val cInst = if (args.has("characteristic_instance_id")) args.getInt("characteristic_instance_id") else -1
        val services = gatt.services.filter { it.uuid == su && (sInst < 0 || it.instanceId == sInst) }
        for (service in services) {
            val found = service.characteristics.firstOrNull { it.uuid == cu && (cInst < 0 || it.instanceId == cInst) }
            if (found != null) return found
        }
        throw IllegalArgumentException("characteristic $cu not found")
    }

    private fun findDesc(session: GattSession, args: JSONObject): BluetoothGattDescriptor {
        val ch = if (args.has("characteristic_uuid")) findChar(session, args) else {
            throw IllegalArgumentException("characteristic_uuid is required")
        }
        val du = parseUuid(args.getString("descriptor_uuid"))
        return ch.descriptors.firstOrNull { it.uuid == du } ?: throw IllegalArgumentException("descriptor $du not found")
    }

    private fun gattOk(address: String, session: GattSession, extra: JSONObject): JSONObject {
        extra.put("address", address).put("gatt_status", session.status).put("connection_state", session.state)
        val ok = session.status == BluetoothGatt.GATT_SUCCESS || session.status == -1
        return if (ok) DeviceJson.ok("gatt_status=${session.status}", extra)
        else DeviceJson.err("failed", "gatt_status=${session.status}").put("data", extra)
    }

    private fun JSONObject.putExtraStatus(session: GattSession): JSONObject {
        optJSONObject("data")?.put("gatt_status", session.status)
        return this
    }

    @SuppressLint("MissingPermission")
    private fun ensureBondReceiver(context: Context) {
        if (bondReceiver) return
        val filter = IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                bondState.set(intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1))
                if (bondState.get() != BluetoothDevice.BOND_BONDING) bondLatch.get()?.countDown()
            }
        }
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        bondReceiver = true
    }

    private class GattSession(val address: String, val owner: String) : BluetoothGattCallback() {
        val opLock = java.util.concurrent.locks.ReentrantLock()
        var gatt: BluetoothGatt? = null
        var state: Int = BluetoothProfile.STATE_DISCONNECTED
        var status: Int = -1
        var mtu: Int = 23
        var rssi: Int = 0
        var txPhy: Int = 0
        var rxPhy: Int = 0
        var value: ByteArray? = null
        private var latch = CountDownLatch(1)

        fun prepare() {
            latch = CountDownLatch(1)
            status = -1
        }

        fun await(timeout: Long): Boolean = latch.await(timeout, TimeUnit.MILLISECONDS).also { if (!it) status = -2 }

        private fun done() { latch.countDown() }

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            this.status = status
            state = newState
            if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                sessions.remove(address)
                DeviceBridge.popKind("connected")
            }
            done()
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            this.status = status
            done()
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            this.mtu = mtu
            this.status = status
            done()
        }

        override fun onPhyUpdate(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
            this.txPhy = txPhy
            this.rxPhy = rxPhy
            this.status = status
            done()
        }

        override fun onPhyRead(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
            this.txPhy = txPhy
            this.rxPhy = rxPhy
            this.status = status
            done()
        }

        override fun onReadRemoteRssi(gatt: BluetoothGatt, rssi: Int, status: Int) {
            this.rssi = rssi
            this.status = status
            done()
        }

        @Deprecated("Used below API 33")
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (Build.VERSION.SDK_INT >= 33) return
            value = characteristic.value
            this.status = status
            done()
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            this.value = value
            this.status = status
            done()
        }

        @Deprecated("Used below API 33")
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            this.status = status
            done()
        }

        @Deprecated("Used below API 33")
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onDescriptorRead(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (Build.VERSION.SDK_INT >= 33) return
            value = descriptor.value
            this.status = status
            done()
        }

        override fun onDescriptorRead(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int, value: ByteArray) {
            this.value = value
            this.status = status
            done()
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            this.status = status
            done()
        }

        @Deprecated("Used below API 33")
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (Build.VERSION.SDK_INT >= 33) return
            pushNote(characteristic.uuid, characteristic.instanceId, characteristic.value)
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            pushNote(characteristic.uuid, characteristic.instanceId, value)
        }

        private fun pushNote(uuid: UUID, instanceId: Int, bytes: ByteArray?) {
            val q = notes.getOrPut(address) { ConcurrentLinkedQueue() }
            q.add(JSONObject()
                .put("uuid", uuid.toString())
                .put("instance_id", instanceId)
                .put("value_hex", bytes?.let { DeviceJson.bytesToHex(it) } ?: "")
                .put("timestamp_ms", System.currentTimeMillis()))
        }
    }
}

private fun parseUuid(raw: String): UUID {
    val t = raw.trim().lowercase()
    return when {
        t.length == 4 -> UUID.fromString("0000$t-0000-1000-8000-00805f9b34fb")
        t.length == 8 && !t.contains('-') -> UUID.fromString("$t-0000-1000-8000-00805f9b34fb")
        else -> UUID.fromString(t)
    }
}

@SuppressLint("MissingPermission")
private fun scanJson(result: ScanResult, includeRaw: Boolean): JSONObject {
    val device = result.device
    val record = result.scanRecord
    val o = JSONObject()
        .put("address", device.address)
        .put("name", device.name)
        .put("type", device.type)
        .put("bond_state", runCatching { device.bondState }.getOrDefault(-1))
        .put("rssi", result.rssi)
        .put("timestamp_nanos", result.timestampNanos)
        .put("is_connectable", result.isConnectable)
    if (Build.VERSION.SDK_INT >= 26) {
        o.put("primary_phy", result.primaryPhy)
        o.put("secondary_phy", result.secondaryPhy)
        o.put("advertising_sid", result.advertisingSid)
        o.put("tx_power", result.txPower)
        o.put("periodic_advertising_interval", result.periodicAdvertisingInterval)
        o.put("is_legacy", result.isLegacy)
        o.put("data_status", result.dataStatus)
    }
    if (Build.VERSION.SDK_INT >= 30) o.put("alias", device.alias)
    if (record != null) {
        val services = JSONArray()
        record.serviceUuids?.forEach { services.put(it.uuid.toString()) }
        val serviceData = JSONObject()
        record.serviceData?.forEach { (uuid, bytes) -> serviceData.put(uuid.uuid.toString(), DeviceJson.bytesToHex(bytes)) }
        val mfg = JSONObject()
        val rawMfg = record.manufacturerSpecificData
        if (rawMfg != null) {
            for (i in 0 until rawMfg.size()) mfg.put(rawMfg.keyAt(i).toString(), DeviceJson.bytesToHex(rawMfg.valueAt(i)))
        }
        o.put("scan_record", JSONObject()
            .put("advertise_flags", record.advertiseFlags)
            .put("device_name", record.deviceName)
            .put("tx_power_level", record.txPowerLevel)
            .put("service_uuids", services)
            .put("service_data", serviceData)
            .put("manufacturer_data", mfg)
            .put("bytes_hex", if (includeRaw) record.bytes?.let { DeviceJson.bytesToHex(it) } else JSONObject.NULL))
    }
    return o
}

private fun scanSettings(o: JSONObject?): ScanSettings {
    val b = ScanSettings.Builder()
    val s = o ?: return b.build()
    b.setScanMode(when (s.optString("scan_mode", "balanced")) {
        "low_power" -> ScanSettings.SCAN_MODE_LOW_POWER
        "low_latency" -> ScanSettings.SCAN_MODE_LOW_LATENCY
        "opportunistic" -> ScanSettings.SCAN_MODE_OPPORTUNISTIC
        else -> ScanSettings.SCAN_MODE_BALANCED
    })
    b.setCallbackType(when (s.optString("callback_type", "all_matches")) {
        "first_match" -> ScanSettings.CALLBACK_TYPE_FIRST_MATCH
        "match_lost" -> ScanSettings.CALLBACK_TYPE_MATCH_LOST
        else -> ScanSettings.CALLBACK_TYPE_ALL_MATCHES
    })
    b.setMatchMode(when (s.optString("match_mode", "aggressive")) {
        "sticky" -> ScanSettings.MATCH_MODE_STICKY
        else -> ScanSettings.MATCH_MODE_AGGRESSIVE
    })
    b.setNumOfMatches(when (s.optString("match_num", "max")) {
        "one" -> ScanSettings.MATCH_NUM_ONE_ADVERTISEMENT
        "few" -> ScanSettings.MATCH_NUM_FEW_ADVERTISEMENT
        else -> ScanSettings.MATCH_NUM_MAX_ADVERTISEMENT
    })
    if (s.has("report_delay_ms")) b.setReportDelay(s.getLong("report_delay_ms"))
    if (s.has("phy")) {
        b.setPhy(when (s.getString("phy")) {
            "le_coded" -> BluetoothDevice.PHY_LE_CODED
            "all_supported" -> ScanSettings.PHY_LE_ALL_SUPPORTED
            else -> BluetoothDevice.PHY_LE_1M
        })
    }
    if (s.has("legacy")) b.setLegacy(s.getBoolean("legacy"))
    return b.build()
}

private fun scanFilters(arr: JSONArray?): List<ScanFilter> {
    if (arr == null || arr.length() == 0) return emptyList()
    val out = ArrayList<ScanFilter>(arr.length())
    for (i in 0 until arr.length()) {
        val o = arr.getJSONObject(i)
        val b = ScanFilter.Builder()
        if (o.has("device_name")) b.setDeviceName(o.getString("device_name"))
        if (o.has("device_address")) b.setDeviceAddress(o.getString("device_address"))
        if (o.has("service_uuid")) {
            val uuid = ParcelUuid(parseUuid(o.getString("service_uuid")))
            if (o.has("service_uuid_mask")) b.setServiceUuid(uuid, ParcelUuid(parseUuid(o.getString("service_uuid_mask"))))
            else b.setServiceUuid(uuid)
        }
        if (o.has("service_data_uuid")) {
            val uuid = ParcelUuid(parseUuid(o.getString("service_data_uuid")))
            val data = o.optString("service_data").let { if (it.isEmpty()) null else DeviceJson.hexToBytes(it) }
            val mask = o.optString("service_data_mask").let { if (it.isEmpty()) null else DeviceJson.hexToBytes(it) }
            if (data != null && mask != null) b.setServiceData(uuid, data, mask)
            else if (data != null) b.setServiceData(uuid, data)
            else b.setServiceData(uuid, null)
        }
        if (o.has("manufacturer_id")) {
            val id = o.getInt("manufacturer_id")
            val data = o.optString("manufacturer_data").let { if (it.isEmpty()) null else DeviceJson.hexToBytes(it) }
            val mask = o.optString("manufacturer_data_mask").let { if (it.isEmpty()) null else DeviceJson.hexToBytes(it) }
            if (data != null && mask != null) b.setManufacturerData(id, data, mask)
            else if (data != null) b.setManufacturerData(id, data)
            else b.setManufacturerData(id, byteArrayOf())
        }
        if (o.has("solicitation_uuid")) {
            if (Build.VERSION.SDK_INT < 29) {
                throw UnsupportedOperationException("unsupported_api: solicitation_uuid requires API 29")
            }
            val uuid = ParcelUuid(parseUuid(o.getString("solicitation_uuid")))
            if (o.has("solicitation_uuid_mask")) b.setServiceSolicitationUuid(uuid, ParcelUuid(parseUuid(o.getString("solicitation_uuid_mask"))))
            else b.setServiceSolicitationUuid(uuid)
        }
        if (Build.VERSION.SDK_INT >= 33 && o.has("advertising_data_type")) {
            val type = o.getInt("advertising_data_type")
            val data = o.optString("advertising_data").let { if (it.isEmpty()) byteArrayOf() else DeviceJson.hexToBytes(it) }
            val mask = o.optString("advertising_data_mask").let { if (it.isEmpty()) null else DeviceJson.hexToBytes(it) }
            if (data.isNotEmpty() || mask != null) {
                b.setAdvertisingDataTypeWithData(type, data, mask ?: ByteArray(data.size))
            } else {
                b.setAdvertisingDataType(type)
            }
        }
        out.add(b.build())
    }
    return out
}
