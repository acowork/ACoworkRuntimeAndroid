package com.acowork.androidhost

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.DisplayMetrics
import android.os.Build.VERSION_CODES
import android.view.Display
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * One computer-use-style tool: observe the screen and act on it.
 *
 * Gestures and the UI tree need [HostAccessibilityService]. Screenshots use
 * AccessibilityService.takeScreenshot on API 30+, otherwise MediaProjection.
 */
object AndroidUseHandler {
    private val projectionLock = Any()
    private var projection: MediaProjection? = null

    fun hasProjection(): Boolean = synchronized(projectionLock) { projection != null }

    fun onProjectionResult(context: Context, resultCode: Int, data: Intent?) {
        if (resultCode != Activity.RESULT_OK || data == null) return
        val mgr = context.getSystemService(MediaProjectionManager::class.java)
        synchronized(projectionLock) {
            runCatching { projection?.stop() }
            projection = mgr.getMediaProjection(resultCode, data)
            projection?.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() {
                    synchronized(projectionLock) {
                        if (projection != null) projection = null
                    }
                }
            }, Handler(Looper.getMainLooper()))
        }
    }

    fun handle(context: Context, workDir: String, args: JSONObject, agent: String): JSONObject {
        val op = args.optString("op").ifBlank { "status" }
        if (op == "status") return status(context, workDir, args)
        if (!DeviceBridge.tryAcquireScreen(agent)) {
            return DeviceJson.err("busy", DeviceBridge.busyMessage("screen", DeviceBridge.screenHolder()))
        }
        return try {
            when (op) {
                "screenshot" -> screenshot(context, workDir, args, includeTree = args.optBoolean("include_tree", false))
                "snapshot" -> snapshot(context, workDir, args)
                "tap", "long_press", "swipe", "drag", "gesture", "type", "node", "global" ->
                    act(context, workDir, args, op)
                else -> throw IllegalArgumentException("unknown op $op")
            }
        } finally {
            DeviceBridge.releaseScreen()
        }
    }

    fun status(context: Context, workDir: String, args: JSONObject): JSONObject {
        val data = JSONObject()
            .put("accessibility_enabled", accessibilityEnabled(context))
            .put("accessibility_connected", HostAccessibilityService.connected())
            .put("media_projection_granted", hasProjection())
            .put("screenshot_api", if (Build.VERSION.SDK_INT >= 30) "accessibility_takeScreenshot" else "media_projection")
            .put("sdk_int", Build.VERSION.SDK_INT)
            .put("displays", displays(context))
        return DeviceJson.finish("android_use status", data, workDir, args.optString("output").ifBlank { null })
    }

    private fun act(context: Context, workDir: String, args: JSONObject, op: String): JSONObject {
        val service = requireService(context) ?: return DevicePermissions.requiredAccessibility(context)
        val actionResult = runOnService(service, 20_000) { svc ->
            when (op) {
                "tap" -> gestureTap(svc, context, args, longPress = false)
                "long_press" -> gestureTap(svc, context, args, longPress = true)
                "swipe", "drag" -> gestureSwipe(svc, context, args)
                "gesture" -> gestureCustom(svc, context, args)
                "type" -> typeText(svc, args)
                "node" -> nodeAction(svc, args)
                "global" -> globalAction(svc, args)
                else -> throw IllegalArgumentException("unknown op $op")
            }
        }
        if (!actionResult.optBoolean("ok", true) && actionResult.has("error_code")) return actionResult
        val wait = args.optInt("wait_ms", 250).coerceIn(0, 5_000)
        if (wait > 0) Thread.sleep(wait.toLong())
        val includeShot = when {
            args.has("include_screenshot") -> args.optBoolean("include_screenshot")
            else -> true
        }
        if (!includeShot) {
            return DeviceJson.ok(actionResult.optString("content", op), actionResult.optJSONObject("data") ?: actionResult)
        }
        val shot = screenshot(context, workDir, args, includeTree = args.optBoolean("include_tree", false))
        if (!shot.optBoolean("ok")) return shot
        val data = shot.optJSONObject("data") ?: JSONObject()
        data.put("action", actionResult.optJSONObject("data") ?: actionResult)
        return DeviceJson.ok("$op + screenshot", data)
    }

    private fun screenshot(context: Context, workDir: String, args: JSONObject, includeTree: Boolean): JSONObject {
        val bmp = captureBitmap(context, args) ?: return captureError(context)
        val quality = args.optInt("jpeg_quality", 80).coerceIn(1, 100)
        val maxEdge = args.optInt("max_edge", 1280)
        val scaled = scale(bmp, maxEdge)
        if (scaled !== bmp) bmp.recycle()
        val file = DeviceJson.captureFile(workDir, args.optString("output_path").ifBlank { null }, "jpg")
        FileOutputStream(file).use { out ->
            if (!scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)) {
                scaled.recycle()
                return DeviceJson.err("failed", "JPEG compress failed")
            }
        }
        val data = DeviceJson.fileMeta(file)
            .put("width", scaled.width)
            .put("height", scaled.height)
            .put("display", displayInfo(context, args.optInt("display_id", Display.DEFAULT_DISPLAY)))
        scaled.recycle()
        if (includeTree) {
            val service = HostAccessibilityService.instance
            if (service != null) {
                data.put("tree", runOnService(service, 8_000) { dumpWindows(it, args) })
            }
        }
        return DeviceJson.ok("screenshot ${file.name}", data)
    }

    private fun snapshot(context: Context, workDir: String, args: JSONObject): JSONObject {
        val service = requireService(context) ?: return DevicePermissions.requiredAccessibility(context)
        val tree = runOnService(service, 8_000) { dumpWindows(it, args) }
        val data = JSONObject()
            .put("display", displayInfo(context, args.optInt("display_id", Display.DEFAULT_DISPLAY)))
            .put("tree", tree)
        return DeviceJson.finish("window snapshot", data, workDir, args.optString("output").ifBlank { null })
    }

    private fun captureError(context: Context): JSONObject {
        if (!HostAccessibilityService.connected() && !accessibilityEnabled(context)) {
            return DevicePermissions.requiredAccessibility(context)
        }
        if (Build.VERSION.SDK_INT < 30 && !hasProjection()) {
            return DevicePermissions.requiredProjection(context)
        }
        if (Build.VERSION.SDK_INT >= 30 && !HostAccessibilityService.connected()) {
            return DevicePermissions.requiredAccessibility(context)
        }
        if (!hasProjection()) return DevicePermissions.requiredProjection(context)
        return DeviceJson.err("failed", "screenshot failed")
    }

    private fun captureBitmap(context: Context, args: JSONObject): Bitmap? {
        val displayId = args.optInt("display_id", Display.DEFAULT_DISPLAY)
        if (Build.VERSION.SDK_INT >= 30) {
            val service = HostAccessibilityService.instance
            if (service != null) {
                takeScreenshotA11y(service, displayId)?.let { return it }
            }
        }
        return takeScreenshotProjection(context, args)
    }

    @android.annotation.TargetApi(VERSION_CODES.R)
    private fun takeScreenshotA11y(service: HostAccessibilityService, displayId: Int): Bitmap? {
        if (Build.VERSION.SDK_INT < 30) return null
        val latch = CountDownLatch(1)
        val bmp = AtomicReference<Bitmap?>()
        service.mainHandler.post {
            service.takeScreenshot(
                displayId,
                { r -> r.run() },
                object : AccessibilityService.TakeScreenshotCallback {
                    override fun onSuccess(screenshot: AccessibilityService.ScreenshotResult) {
                        val hw = screenshot.hardwareBuffer
                        val wrapped = Bitmap.wrapHardwareBuffer(hw, screenshot.colorSpace)
                        bmp.set(wrapped?.copy(Bitmap.Config.ARGB_8888, false))
                        wrapped?.recycle()
                        hw.close()
                        latch.countDown()
                    }

                    override fun onFailure(errorCode: Int) {
                        latch.countDown()
                    }
                },
            )
        }
        latch.await(8, TimeUnit.SECONDS)
        return bmp.get()
    }

    private fun takeScreenshotProjection(context: Context, args: JSONObject): Bitmap? {
        val proj = synchronized(projectionLock) { projection } ?: run {
            DevicePermissions.notifyProjection(context)
            return null
        }
        val metrics = displayMetrics(context, args.optInt("display_id", Display.DEFAULT_DISPLAY))
        val width = metrics.widthPixels
        val height = metrics.heightPixels
        val dpi = metrics.densityDpi
        DeviceBridge.pushKind("projection")
        val reader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
        var display: VirtualDisplay? = null
        return try {
            val latch = CountDownLatch(1)
            val imageRef = AtomicReference<Image?>()
            reader.setOnImageAvailableListener({
                imageRef.compareAndSet(null, reader.acquireLatestImage())
                latch.countDown()
            }, DeviceBridge.handler)
            display = proj.createVirtualDisplay(
                "acowork-screen",
                width,
                height,
                dpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                reader.surface,
                null,
                DeviceBridge.handler,
            )
            if (!latch.await(8, TimeUnit.SECONDS)) return null
            val image = imageRef.get() ?: return null
            image.use { imageToBitmap(it, width, height) }
        } finally {
            display?.release()
            reader.close()
            DeviceBridge.popKind("projection")
        }
    }

    private fun imageToBitmap(image: Image, width: Int, height: Int): Bitmap {
        val plane = image.planes[0]
        val buffer = plane.buffer
        val pixelStride = plane.pixelStride
        val rowStride = plane.rowStride
        val rowPadding = rowStride - pixelStride * width
        val full = Bitmap.createBitmap(width + rowPadding / pixelStride, height, Bitmap.Config.ARGB_8888)
        full.copyPixelsFromBuffer(buffer)
        val cropped = Bitmap.createBitmap(full, 0, 0, width, height)
        if (cropped !== full) full.recycle()
        return cropped
    }

    private fun scale(src: Bitmap, maxEdge: Int): Bitmap {
        if (maxEdge <= 0) return src
        val long = maxOf(src.width, src.height)
        if (long <= maxEdge) return src
        val scale = maxEdge.toFloat() / long
        return Bitmap.createScaledBitmap(
            src,
            (src.width * scale).toInt().coerceAtLeast(1),
            (src.height * scale).toInt().coerceAtLeast(1),
            true,
        )
    }

    private fun gestureTap(service: HostAccessibilityService, context: Context, args: JSONObject, longPress: Boolean): JSONObject {
        val metrics = displayMetrics(context, args.optInt("display_id", Display.DEFAULT_DISPLAY))
        val x = coord(args, "x", metrics.widthPixels)
        val y = coord(args, "y", metrics.heightPixels)
        val duration = args.optInt("duration_ms", if (longPress) 700 else 50).coerceIn(1, 10_000)
        dispatch(service, listOf(stroke(listOf(x to y), 0L, duration.toLong())))
        return DeviceJson.ok(
            if (longPress) "long_press" else "tap",
            JSONObject().put("x", x).put("y", y).put("duration_ms", duration),
        )
    }

    private fun gestureSwipe(service: HostAccessibilityService, context: Context, args: JSONObject): JSONObject {
        val metrics = displayMetrics(context, args.optInt("display_id", Display.DEFAULT_DISPLAY))
        val x = coord(args, "x", metrics.widthPixels)
        val y = coord(args, "y", metrics.heightPixels)
        val x2 = coord(args, "x2", metrics.widthPixels)
        val y2 = coord(args, "y2", metrics.heightPixels)
        val duration = args.optInt("duration_ms", 300).coerceIn(50, 15_000)
        dispatch(service, listOf(stroke(listOf(x to y, x2 to y2), 0L, duration.toLong())))
        return DeviceJson.ok("swipe", JSONObject().put("x", x).put("y", y).put("x2", x2).put("y2", y2).put("duration_ms", duration))
    }

    private fun gestureCustom(service: HostAccessibilityService, context: Context, args: JSONObject): JSONObject {
        val metrics = displayMetrics(context, args.optInt("display_id", Display.DEFAULT_DISPLAY))
        val strokesArg = args.optJSONArray("strokes") ?: throw IllegalArgumentException("strokes is required")
        val max = GestureDescription.getMaxStrokeCount()
        if (strokesArg.length() > max) throw IllegalArgumentException("at most $max strokes")
        val strokes = ArrayList<GestureDescription.StrokeDescription>()
        for (i in 0 until strokesArg.length()) {
            val s = strokesArg.getJSONObject(i)
            val pts = s.optJSONArray("points") ?: throw IllegalArgumentException("stroke.points is required")
            val points = ArrayList<Pair<Float, Float>>()
            for (p in 0 until pts.length()) {
                val pt = pts.getJSONObject(p)
                points.add(
                    coord(pt, "x", metrics.widthPixels) to coord(pt, "y", metrics.heightPixels),
                )
            }
            val start = s.optInt("start_ms", 0).coerceIn(0, 60_000)
            val duration = s.optInt("duration_ms", 100).coerceIn(1, 15_000)
            strokes.add(stroke(points, start.toLong(), duration.toLong()))
        }
        dispatch(service, strokes)
        return DeviceJson.ok("gesture", JSONObject().put("strokes", strokesArg.length()))
    }

    private fun stroke(points: List<Pair<Float, Float>>, startMs: Long, durationMs: Long): GestureDescription.StrokeDescription {
        if (points.isEmpty()) throw IllegalArgumentException("stroke needs points")
        val path = Path()
        path.moveTo(points[0].first, points[0].second)
        for (i in 1 until points.size) path.lineTo(points[i].first, points[i].second)
        if (points.size == 1) path.lineTo(points[0].first + 1f, points[0].second)
        return GestureDescription.StrokeDescription(path, startMs, durationMs)
    }

    private fun dispatch(service: HostAccessibilityService, strokes: List<GestureDescription.StrokeDescription>) {
        val builder = GestureDescription.Builder()
        for (s in strokes) builder.addStroke(s)
        val desc = builder.build()
        val latch = CountDownLatch(1)
        val ok = AtomicBoolean(false)
        val posted = CountDownLatch(1)
        service.mainHandler.post {
            val accepted = service.dispatchGesture(
                desc,
                object : AccessibilityService.GestureResultCallback() {
                    override fun onCompleted(gestureDescription: GestureDescription?) {
                        ok.set(true)
                        latch.countDown()
                    }
                    override fun onCancelled(gestureDescription: GestureDescription?) {
                        latch.countDown()
                    }
                },
                null,
            )
            if (!accepted) latch.countDown()
            posted.countDown()
        }
        posted.await(2, TimeUnit.SECONDS)
        if (!latch.await(15, TimeUnit.SECONDS) || !ok.get()) {
            throw IllegalStateException("gesture cancelled or timed out")
        }
    }

    private fun typeText(service: HostAccessibilityService, args: JSONObject): JSONObject {
        val text = args.optString("text")
        if (text.isEmpty() && !args.has("text")) throw IllegalArgumentException("text is required")
        val node = findNode(service, args) ?: focusedEditable(service)
            ?: throw IllegalArgumentException("no focused editable node; pass view_id or text selector")
        return try {
            val argsBundle = android.os.Bundle()
            argsBundle.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
            val ok = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, argsBundle)
            if (!ok) throw IllegalStateException("ACTION_SET_TEXT was rejected")
            DeviceJson.ok("type", JSONObject().put("text_length", text.length).put("view_id", node.viewIdResourceName ?: JSONObject.NULL))
        } finally {
            node.recycle()
        }
    }

    private fun nodeAction(service: HostAccessibilityService, args: JSONObject): JSONObject {
        val actionName = args.optString("action").ifBlank { "click" }
        val node = findNode(service, args) ?: throw IllegalArgumentException("no node matched the selector")
        return try {
            val ok = when (actionName) {
                "click" -> node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                "long_click" -> node.performAction(AccessibilityNodeInfo.ACTION_LONG_CLICK)
                "focus" -> node.performAction(AccessibilityNodeInfo.ACTION_FOCUS)
                "clear_focus" -> node.performAction(AccessibilityNodeInfo.ACTION_CLEAR_FOCUS)
                "select" -> node.performAction(AccessibilityNodeInfo.ACTION_SELECT)
                "copy" -> node.performAction(AccessibilityNodeInfo.ACTION_COPY)
                "cut" -> node.performAction(AccessibilityNodeInfo.ACTION_CUT)
                "paste" -> node.performAction(AccessibilityNodeInfo.ACTION_PASTE)
                "scroll_forward" -> node.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
                "scroll_backward" -> node.performAction(AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
                "expand" -> node.performAction(AccessibilityNodeInfo.ACTION_EXPAND)
                "collapse" -> node.performAction(AccessibilityNodeInfo.ACTION_COLLAPSE)
                "dismiss" -> node.performAction(AccessibilityNodeInfo.ACTION_DISMISS)
                "clear" -> node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, android.os.Bundle().apply {
                    putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "")
                })
                "set_text" -> {
                    val text = args.optString("text")
                    node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, android.os.Bundle().apply {
                        putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
                    })
                }
                "ime_enter" -> {
                    if (Build.VERSION.SDK_INT < 30) {
                        throw UnsupportedOperationException("unsupported_api: ACTION_IME_ENTER needs API 30")
                    }
                    node.performAction(0x00400000) // ACTION_IME_ENTER, API 30
                }
                else -> throw IllegalArgumentException("unknown node action $actionName")
            }
            if (!ok) throw IllegalStateException("node action $actionName was rejected")
            DeviceJson.ok(
                "node $actionName",
                JSONObject()
                    .put("action", actionName)
                    .put("view_id", node.viewIdResourceName ?: JSONObject.NULL)
                    .put("class_name", node.className ?: JSONObject.NULL)
                    .put("bounds", boundsJson(node)),
            )
        } finally {
            node.recycle()
        }
    }

    private fun globalAction(service: HostAccessibilityService, args: JSONObject): JSONObject {
        val name = args.optString("action").ifBlank { args.optString("global") }.ifBlank { "back" }
        val code = when (name) {
            "back" -> AccessibilityService.GLOBAL_ACTION_BACK
            "home" -> AccessibilityService.GLOBAL_ACTION_HOME
            "recents" -> AccessibilityService.GLOBAL_ACTION_RECENTS
            "notifications" -> AccessibilityService.GLOBAL_ACTION_NOTIFICATIONS
            "quick_settings" -> AccessibilityService.GLOBAL_ACTION_QUICK_SETTINGS
            "power_dialog" -> AccessibilityService.GLOBAL_ACTION_POWER_DIALOG
            "split_screen" -> {
                if (Build.VERSION.SDK_INT < 24) throw UnsupportedOperationException("unsupported_api: GLOBAL_ACTION_TOGGLE_SPLIT_SCREEN needs API 24")
                AccessibilityService.GLOBAL_ACTION_TOGGLE_SPLIT_SCREEN
            }
            "lock_screen" -> {
                if (Build.VERSION.SDK_INT < 28) throw UnsupportedOperationException("unsupported_api: GLOBAL_ACTION_LOCK_SCREEN needs API 28")
                AccessibilityService.GLOBAL_ACTION_LOCK_SCREEN
            }
            "take_screenshot" -> {
                if (Build.VERSION.SDK_INT < 28) throw UnsupportedOperationException("unsupported_api: GLOBAL_ACTION_TAKE_SCREENSHOT needs API 28")
                AccessibilityService.GLOBAL_ACTION_TAKE_SCREENSHOT
            }
            "dismiss_notification_shade" -> {
                if (Build.VERSION.SDK_INT < 31) throw UnsupportedOperationException("unsupported_api: GLOBAL_ACTION_DISMISS_NOTIFICATION_SHADE needs API 31")
                15
            }
            else -> throw IllegalArgumentException("unknown global action $name")
        }
        val ok = service.performGlobalAction(code)
        if (!ok) throw IllegalStateException("global action $name was rejected")
        return DeviceJson.ok("global $name", JSONObject().put("action", name))
    }

    private fun findNode(service: HostAccessibilityService, args: JSONObject): AccessibilityNodeInfo? {
        val selector = selectorOf(args) ?: return null
        val roots = roots(service)
        val matches = ArrayList<AccessibilityNodeInfo>()
        try {
            for (root in roots) collectMatches(root, selector, matches)
            val index = selector.optInt("index", 0)
            if (index < 0 || index >= matches.size) {
                matches.forEach { it.recycle() }
                return null
            }
            val chosen = matches[index]
            matches.forEachIndexed { i, n -> if (i != index) n.recycle() }
            return chosen
        } finally {
            roots.forEach { it.recycle() }
        }
    }

    private fun focusedEditable(service: HostAccessibilityService): AccessibilityNodeInfo? {
        val roots = roots(service)
        try {
            for (root in roots) {
                findFocused(root)?.let { return it }
            }
            return null
        } finally {
            roots.forEach { it.recycle() }
        }
    }

    private fun findFocused(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        if (node.isFocused && node.isEditable) return AccessibilityNodeInfo.obtain(node)
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val found = findFocused(child)
            child.recycle()
            if (found != null) return found
        }
        return null
    }

    private fun collectMatches(node: AccessibilityNodeInfo, selector: JSONObject, out: MutableList<AccessibilityNodeInfo>) {
        if (matches(node, selector)) out.add(AccessibilityNodeInfo.obtain(node))
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectMatches(child, selector, out)
            child.recycle()
        }
    }

    private fun selectorOf(args: JSONObject): JSONObject? {
        args.optJSONObject("selector")?.let { return it }
        val o = JSONObject()
        for (key in listOf("view_id", "class_name", "text_contains", "content_description")) {
            val v = args.optString(key)
            if (v.isNotBlank()) o.put(key, v)
        }
        for (key in listOf("clickable", "editable", "focused", "scrollable")) {
            if (args.has(key)) o.put(key, args.optBoolean(key))
        }
        if (args.has("index")) o.put("index", args.optInt("index"))
        return if (o.length() == 0) null else o
    }

    private fun matches(node: AccessibilityNodeInfo, selector: JSONObject): Boolean {
        selector.optString("view_id").takeIf { it.isNotBlank() }?.let {
            if (node.viewIdResourceName != it) return false
        }
        selector.optString("class_name").takeIf { it.isNotBlank() }?.let {
            if (node.className?.toString() != it) return false
        }
        selector.optString("text").takeIf { it.isNotBlank() }?.let {
            if (node.text?.toString() != it) return false
        }
        selector.optString("text_contains").takeIf { it.isNotBlank() }?.let {
            if (node.text?.toString()?.contains(it) != true) return false
        }
        selector.optString("content_description").takeIf { it.isNotBlank() }?.let {
            if (node.contentDescription?.toString() != it) return false
        }
        if (selector.has("clickable") && node.isClickable != selector.optBoolean("clickable")) return false
        if (selector.has("editable") && node.isEditable != selector.optBoolean("editable")) return false
        if (selector.has("focused") && node.isFocused != selector.optBoolean("focused")) return false
        if (selector.has("scrollable") && node.isScrollable != selector.optBoolean("scrollable")) return false
        return selector.has("view_id") || selector.has("class_name") || selector.has("text") ||
            selector.has("text_contains") || selector.has("content_description") ||
            selector.has("clickable") || selector.has("editable") || selector.has("focused") ||
            selector.has("scrollable")
    }

    private fun roots(service: HostAccessibilityService): List<AccessibilityNodeInfo> {
        val out = ArrayList<AccessibilityNodeInfo>()
        val windows = runCatching { service.windows }.getOrNull()
        if (windows != null) {
            for (w in windows) {
                w.root?.let { out.add(it) }
                w.recycle()
            }
        }
        if (out.isEmpty()) {
            service.rootInActiveWindow?.let { out.add(it) }
        }
        return out
    }

    private fun dumpWindows(service: HostAccessibilityService, args: JSONObject): JSONObject {
        val maxNodes = args.optInt("max_nodes", 200).coerceIn(1, 2_000)
        val maxDepth = args.optInt("max_depth", 24).coerceIn(1, 64)
        val remaining = AtomicInteger(maxNodes)
        val windowsJson = JSONArray()
        val windows = runCatching { service.windows }.getOrNull()
        if (windows != null && windows.isNotEmpty()) {
            for (w in windows) {
                windowsJson.put(dumpWindow(w, remaining, maxDepth))
                w.recycle()
            }
        } else {
            val root = service.rootInActiveWindow
            if (root != null) {
                windowsJson.put(JSONObject().put("active", true).put("root", dumpNode(root, 0, remaining, maxDepth)))
                root.recycle()
            }
        }
        return JSONObject().put("truncated", remaining.get() <= 0).put("windows", windowsJson)
    }

    private fun dumpWindow(window: AccessibilityWindowInfo, remaining: AtomicInteger, maxDepth: Int): JSONObject {
        val o = JSONObject()
            .put("id", window.id)
            .put("type", window.type)
            .put("active", window.isActive)
            .put("focused", window.isFocused)
            .put("layer", window.layer)
            .put("title", window.title?.toString() ?: JSONObject.NULL)
        val bounds = android.graphics.Rect()
        window.getBoundsInScreen(bounds)
        o.put("bounds", JSONObject().put("left", bounds.left).put("top", bounds.top).put("right", bounds.right).put("bottom", bounds.bottom))
        val root = window.root
        if (root != null) {
            o.put("root", dumpNode(root, 0, remaining, maxDepth))
            root.recycle()
        }
        return o
    }

    private fun dumpNode(node: AccessibilityNodeInfo, depth: Int, remaining: AtomicInteger, maxDepth: Int): JSONObject {
        val o = JSONObject()
            .put("class_name", node.className ?: JSONObject.NULL)
            .put("view_id", node.viewIdResourceName ?: JSONObject.NULL)
            .put("text", node.text?.toString() ?: JSONObject.NULL)
            .put("content_description", node.contentDescription?.toString() ?: JSONObject.NULL)
            .put("bounds", boundsJson(node))
            .put("clickable", node.isClickable)
            .put("long_clickable", node.isLongClickable)
            .put("scrollable", node.isScrollable)
            .put("editable", node.isEditable)
            .put("enabled", node.isEnabled)
            .put("focused", node.isFocused)
            .put("selected", node.isSelected)
            .put("checkable", node.isCheckable)
            .put("checked", node.isChecked)
            .put("password", node.isPassword)
            .put("visible", node.isVisibleToUser)
            .put("package_name", node.packageName ?: JSONObject.NULL)
        remaining.decrementAndGet()
        if (depth >= maxDepth || remaining.get() <= 0) return o
        val children = JSONArray()
        for (i in 0 until node.childCount) {
            if (remaining.get() <= 0) break
            val child = node.getChild(i) ?: continue
            children.put(dumpNode(child, depth + 1, remaining, maxDepth))
            child.recycle()
        }
        if (children.length() > 0) o.put("children", children)
        return o
    }

    private fun boundsJson(node: AccessibilityNodeInfo): JSONObject {
        val r = android.graphics.Rect()
        node.getBoundsInScreen(r)
        return JSONObject().put("left", r.left).put("top", r.top).put("right", r.right).put("bottom", r.bottom)
    }

    private fun coord(args: JSONObject, key: String, span: Int): Float {
        if (!args.has(key)) throw IllegalArgumentException("$key is required")
        val raw = args.get(key)
        val value = when (raw) {
            is Number -> raw.toDouble()
            is String -> raw.toDouble()
            else -> throw IllegalArgumentException("$key must be a number")
        }
        val normalized = args.optBoolean("normalized", false)
        return if (normalized) (value * span).toFloat() else value.toFloat()
    }

    private fun displays(context: Context): JSONArray {
        val arr = JSONArray()
        val dm = context.getSystemService(DisplayManager::class.java)
        for (display in dm.displays) {
            arr.put(displayInfo(context, display.displayId))
        }
        return arr
    }

    private fun displayInfo(context: Context, displayId: Int): JSONObject {
        val metrics = displayMetrics(context, displayId)
        return JSONObject()
            .put("display_id", displayId)
            .put("width", metrics.widthPixels)
            .put("height", metrics.heightPixels)
            .put("density_dpi", metrics.densityDpi)
            .put("rotation", rotation(context, displayId))
    }

    private fun displayMetrics(context: Context, displayId: Int): DisplayMetrics {
        val metrics = DisplayMetrics()
        val dm = context.getSystemService(DisplayManager::class.java)
        val display = dm.getDisplay(displayId) ?: dm.getDisplay(Display.DEFAULT_DISPLAY)
        @Suppress("DEPRECATION")
        display.getRealMetrics(metrics)
        return metrics
    }

    private fun rotation(context: Context, displayId: Int): Int {
        val dm = context.getSystemService(DisplayManager::class.java)
        val display = dm.getDisplay(displayId) ?: return 0
        @Suppress("DEPRECATION")
        return display.rotation
    }

    private fun accessibilityEnabled(context: Context): Boolean {
        val expected = "${context.packageName}/${HostAccessibilityService::class.java.name}"
        val enabled = android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        return enabled.split(':').any { it.equals(expected, ignoreCase = true) }
    }

    private fun requireService(context: Context): HostAccessibilityService? {
        val svc = HostAccessibilityService.instance
        if (svc != null) return svc
        if (!accessibilityEnabled(context)) DevicePermissions.notifyAccessibility(context)
        return null
    }

    private fun runOnService(service: HostAccessibilityService, timeoutMs: Long, block: (HostAccessibilityService) -> JSONObject): JSONObject {
        if (Looper.myLooper() == Looper.getMainLooper()) return block(service)
        val latch = CountDownLatch(1)
        val result = AtomicReference<JSONObject>()
        val error = AtomicReference<Throwable?>()
        service.mainHandler.post {
            try {
                result.set(block(service))
            } catch (t: Throwable) {
                error.set(t)
            } finally {
                latch.countDown()
            }
        }
        if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            return DeviceJson.err("failed", "accessibility call timed out")
        }
        error.get()?.let { throw it }
        return result.get() ?: DeviceJson.err("failed", "empty accessibility result")
    }
}
