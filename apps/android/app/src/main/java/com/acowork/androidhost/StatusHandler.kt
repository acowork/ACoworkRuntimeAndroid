package com.acowork.androidhost

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.camera2.CameraManager
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.media.MicrophoneInfo
import android.os.Build
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

object StatusHandler {
    fun query(context: Context, workDir: String, args: JSONObject): JSONObject {
        val wanted = HashSet<String>()
        val sections = args.optJSONArray("sections")
        if (sections == null || sections.length() == 0) {
            wanted.addAll(listOf("permissions", "features", "cameras", "audio_devices", "microphones", "bluetooth", "usb", "bridge"))
        } else {
            for (i in 0 until sections.length()) wanted.add(sections.getString(i))
        }
        val data = JSONObject().put("sdk_int", Build.VERSION.SDK_INT)
        if ("permissions" in wanted) data.put("permissions", permissions(context))
        if ("features" in wanted) data.put("features", features(context))
        if ("cameras" in wanted) data.put("cameras", cameras(context))
        if ("audio_devices" in wanted) data.put("audio_devices", audioDevices(context))
        if ("microphones" in wanted) data.put("microphones", microphones(context))
        if ("bluetooth" in wanted) data.put("bluetooth", bluetooth(context))
        if ("usb" in wanted) data.put("usb", usb(context))
        if ("bridge" in wanted) data.put("bridge", DeviceBridge.snapshot())
        return DeviceJson.finish("device status", data, workDir, args.optString("output").ifBlank { null })
    }

    private fun permissions(context: Context): JSONObject {
        val names = DevicePermissions.declared()
        val o = JSONObject()
        for (name in names) {
            val granted = ContextCompat.checkSelfPermission(context, name) == PackageManager.PERMISSION_GRANTED
            o.put(name, granted)
        }
        return o
    }

    private fun features(context: Context): JSONObject {
        val pm = context.packageManager
        val names = listOf(
            PackageManager.FEATURE_CAMERA,
            PackageManager.FEATURE_CAMERA_FRONT,
            PackageManager.FEATURE_CAMERA_AUTOFOCUS,
            PackageManager.FEATURE_CAMERA_FLASH,
            PackageManager.FEATURE_MICROPHONE,
            PackageManager.FEATURE_BLUETOOTH,
            PackageManager.FEATURE_BLUETOOTH_LE,
            PackageManager.FEATURE_USB_HOST,
            PackageManager.FEATURE_AUDIO_LOW_LATENCY,
            PackageManager.FEATURE_AUDIO_PRO,
        )
        val o = JSONObject()
        for (name in names) o.put(name, pm.hasSystemFeature(name))
        return o
    }

    private fun cameras(context: Context): JSONArray {
        val manager = context.getSystemService(CameraManager::class.java)
        val arr = JSONArray()
        for (id in manager.cameraIdList) {
            val chars = runCatching { manager.getCameraCharacteristics(id) }.getOrNull()
            val item = JSONObject().put("camera_id", id)
            if (chars != null) item.put("characteristics", CameraRequests.readCharacteristics(chars))
            arr.put(item)
        }
        return arr
    }

    private fun audioDevices(context: Context): JSONArray {
        val am = context.getSystemService(AudioManager::class.java)
        val arr = JSONArray()
        for (device in am.getDevices(AudioManager.GET_DEVICES_ALL)) {
            arr.put(JSONObject()
                .put("id", device.id)
                .put("type", device.type)
                .put("type_name", audioTypeName(device.type))
                .put("product_name", device.productName)
                .put("address", device.address)
                .put("is_source", device.isSource)
                .put("is_sink", device.isSink)
                .put("channel_counts", JSONArray(device.channelCounts.toList()))
                .put("channel_masks", JSONArray(device.channelMasks.toList()))
                .put("channel_index_masks", JSONArray(device.channelIndexMasks.toList()))
                .put("encodings", JSONArray(device.encodings.toList()))
                .put("sample_rates", JSONArray(device.sampleRates.toList())))
        }
        return arr
    }

    private fun microphones(context: Context): JSONArray {
        if (Build.VERSION.SDK_INT < 28) return JSONArray()
        val am = context.getSystemService(AudioManager::class.java)
        val arr = JSONArray()
        val mics: List<MicrophoneInfo> = runCatching { am.microphones }.getOrDefault(emptyList())
        for (mic in mics) {
            arr.put(JSONObject()
                .put("id", mic.id)
                .put("type", mic.type)
                .put("address", mic.address)
                .put("location", mic.location)
                .put("group", mic.group)
                .put("index_in_the_group", mic.indexInTheGroup)
                .put("sensitivity", mic.sensitivity)
                .put("directionality", mic.directionality)
                .put("frequency_response", JSONArray().apply {
                    mic.frequencyResponse?.forEach { pair ->
                        put(JSONArray().put(pair.first).put(pair.second))
                    }
                })
                .put("orientation", JSONArray().apply {
                    val o = mic.orientation
                    if (o != null) put(o.x).put(o.y).put(o.z)
                })
                .put("channel_mapping", JSONArray().apply {
                    mic.channelMapping?.forEach { pair ->
                        put(JSONObject().put("channel", pair.first).put("mapping", pair.second.toString()))
                    }
                }))
        }
        return arr
    }

    private fun bluetooth(context: Context): JSONObject {
        val adapter = context.getSystemService(android.bluetooth.BluetoothManager::class.java).adapter
        if (adapter == null) return JSONObject().put("present", false)
        val o = JSONObject()
            .put("present", true)
            .put("enabled", adapter.isEnabled)
            .put("state", adapter.state)
            .put("name", runCatching { adapter.name }.getOrNull())
            .put("le_supported", context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE))
        val bonded = JSONArray()
        val devices = runCatching { adapter.bondedDevices }.getOrNull()
        if (devices == null) {
            o.put("bonded_error", "permission_required")
        } else {
            for (device in devices) {
                val uuids = JSONArray()
                runCatching { device.uuids }?.getOrNull()?.forEach { uuids.put(it.uuid.toString()) }
                bonded.put(JSONObject()
                    .put("address", device.address)
                    .put("name", runCatching { device.name }.getOrNull())
                    .put("alias", if (Build.VERSION.SDK_INT >= 30) runCatching { device.alias }.getOrNull() else null)
                    .put("type", device.type)
                    .put("bond_state", device.bondState)
                    .put("uuids", uuids))
            }
        }
        o.put("bonded", bonded)
        return o
    }

    private fun usb(context: Context): JSONObject {
        val usb = context.getSystemService(android.hardware.usb.UsbManager::class.java)
        val devices = JSONArray()
        for (device in usb.deviceList.values) {
            var hid = device.deviceClass == android.hardware.usb.UsbConstants.USB_CLASS_HID
            if (!hid) {
                for (i in 0 until device.interfaceCount) {
                    if (device.getInterface(i).interfaceClass == android.hardware.usb.UsbConstants.USB_CLASS_HID) hid = true
                }
            }
            if (!hid) continue
            devices.put(JSONObject()
                .put("device_id", device.deviceId)
                .put("device_name", device.deviceName)
                .put("vendor_id", device.vendorId)
                .put("product_id", device.productId)
                .put("has_permission", usb.hasPermission(device))
                .put("product", runCatching { device.productName }.getOrNull())
                .put("manufacturer", runCatching { device.manufacturerName }.getOrNull()))
        }
        return JSONObject().put("host_feature", context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)).put("devices", devices)
    }

    private fun audioTypeName(type: Int): String = when (type) {
        AudioDeviceInfo.TYPE_BUILTIN_MIC -> "builtin_mic"
        AudioDeviceInfo.TYPE_BUILTIN_SPEAKER -> "builtin_speaker"
        AudioDeviceInfo.TYPE_WIRED_HEADSET -> "wired_headset"
        AudioDeviceInfo.TYPE_WIRED_HEADPHONES -> "wired_headphones"
        AudioDeviceInfo.TYPE_BLUETOOTH_SCO -> "bluetooth_sco"
        AudioDeviceInfo.TYPE_BLUETOOTH_A2DP -> "bluetooth_a2dp"
        AudioDeviceInfo.TYPE_USB_DEVICE -> "usb_device"
        AudioDeviceInfo.TYPE_USB_HEADSET -> "usb_headset"
        else -> type.toString()
    }
}

object DevicePermissions {
    const val EXTRA_PERMISSION = "com.acowork.androidhost.EXTRA_PERMISSION"
    const val EXTRA_USB_DEVICE = "com.acowork.androidhost.EXTRA_USB_DEVICE"
    const val EXTRA_SCREEN = "com.acowork.androidhost.EXTRA_SCREEN"

    fun declared(): List<String> {
        val names = mutableListOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.POST_NOTIFICATIONS,
        )
        if (Build.VERSION.SDK_INT >= 31) {
            names.add(Manifest.permission.BLUETOOTH_SCAN)
            names.add(Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            names.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        return names
    }

    fun bleScan(): List<String> =
        if (Build.VERSION.SDK_INT >= 31) {
            listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    fun bleConnect(): List<String> =
        if (Build.VERSION.SDK_INT >= 31) listOf(Manifest.permission.BLUETOOTH_CONNECT) else emptyList()

    fun firstMissing(context: Context, perms: List<String>): String? =
        perms.firstOrNull {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }

    fun required(context: Context, permission: String): JSONObject {
        notify(context, permission, null)
        return DeviceJson.err(
            "permission_required",
            "Grant $permission from the ACowork Host notification, then retry.",
        )
    }

    fun usb(context: Context, deviceName: String) {
        notify(context, null, deviceName, null)
    }

    fun requiredAccessibility(context: Context): JSONObject {
        notifyAccessibility(context)
        return DeviceJson.err(
            "permission_required",
            "Enable the ACowork Host accessibility service in Android Settings, then retry. The app cannot turn this on by itself.",
        )
    }

    fun requiredProjection(context: Context): JSONObject {
        notifyProjection(context)
        return DeviceJson.err(
            "permission_required",
            "Grant screen capture from the ACowork Host notification, then retry. Needed for screenshots when Accessibility takeScreenshot is unavailable.",
        )
    }

    fun notifyAccessibility(context: Context) = notify(context, null, null, "accessibility")

    fun notifyProjection(context: Context) = notify(context, null, null, "projection")

    private fun notify(context: Context, permission: String?, usbDevice: String?, screen: String? = null) {
        val channel = "acowork_device"
        if (Build.VERSION.SDK_INT >= 26) {
            val mgr = context.getSystemService(android.app.NotificationManager::class.java)
            if (mgr.getNotificationChannel(channel) == null) {
                mgr.createNotificationChannel(
                    android.app.NotificationChannel(channel, "ACowork device access", android.app.NotificationManager.IMPORTANCE_HIGH),
                )
            }
        }
        val open = android.content.Intent(context, MainActivity::class.java).apply {
            flags = android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP or android.content.Intent.FLAG_ACTIVITY_NEW_TASK
            if (permission != null) putExtra(EXTRA_PERMISSION, permission)
            if (usbDevice != null) putExtra(EXTRA_USB_DEVICE, usbDevice)
            if (screen != null) putExtra(EXTRA_SCREEN, screen)
        }
        val pi = android.app.PendingIntent.getActivity(
            context,
            (permission ?: usbDevice ?: screen ?: "device").hashCode(),
            open,
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE,
        )
        val text = when {
            screen == "accessibility" -> "Enable ACowork screen control"
            screen == "projection" -> "Allow screen capture"
            usbDevice != null -> "USB device needs permission"
            permission != null -> "Allow $permission"
            else -> "Device permission needed"
        }
        val notification = androidx.core.app.NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("ACowork device tool")
            .setContentText(text)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        androidx.core.app.NotificationManagerCompat.from(context).notify(text.hashCode(), notification)
    }
}
