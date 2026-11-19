package com.acowork.androidhost

import android.graphics.Rect
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.CaptureResult
import android.hardware.camera2.params.ColorSpaceTransform
import android.hardware.camera2.params.MeteringRectangle
import android.hardware.camera2.params.RggbChannelVector
import android.hardware.camera2.params.TonemapCurve
import android.location.Location
import android.os.Build
import android.util.Range
import android.util.Size
import org.json.JSONArray
import org.json.JSONObject

/**
 * Pass-through for the public Camera2 key set at compileSdk 35.
 * Unknown names are [IllegalArgumentException]. A key the running API
 * level does not have is [UnsupportedOperationException].
 */
object CameraRequests {
    fun apply(builder: CaptureRequest.Builder, request: JSONObject?) {
        if (request == null) return
        val names = request.keys()
        while (names.hasNext()) {
            val name = names.next()
            setKey(builder, name, request.get(name))
        }
    }

    fun readResult(result: CaptureResult): JSONObject {
        val out = JSONObject()
        fun <T> put(name: String, key: CaptureResult.Key<T>) {
            try {
                JsonValues.put(out, name, result.get(key))
            } catch (_: Throwable) {
            }
        }
        put("SENSOR_SENSITIVITY", CaptureResult.SENSOR_SENSITIVITY)
        put("SENSOR_EXPOSURE_TIME", CaptureResult.SENSOR_EXPOSURE_TIME)
        put("SENSOR_FRAME_DURATION", CaptureResult.SENSOR_FRAME_DURATION)
        put("SENSOR_TIMESTAMP", CaptureResult.SENSOR_TIMESTAMP)
        put("LENS_FOCAL_LENGTH", CaptureResult.LENS_FOCAL_LENGTH)
        put("LENS_APERTURE", CaptureResult.LENS_APERTURE)
        put("LENS_FOCUS_DISTANCE", CaptureResult.LENS_FOCUS_DISTANCE)
        put("LENS_STATE", CaptureResult.LENS_STATE)
        put("LENS_FILTER_DENSITY", CaptureResult.LENS_FILTER_DENSITY)
        put("CONTROL_AE_MODE", CaptureResult.CONTROL_AE_MODE)
        put("CONTROL_AE_STATE", CaptureResult.CONTROL_AE_STATE)
        put("CONTROL_AF_MODE", CaptureResult.CONTROL_AF_MODE)
        put("CONTROL_AF_STATE", CaptureResult.CONTROL_AF_STATE)
        put("CONTROL_AWB_MODE", CaptureResult.CONTROL_AWB_MODE)
        put("CONTROL_AWB_STATE", CaptureResult.CONTROL_AWB_STATE)
        put("CONTROL_MODE", CaptureResult.CONTROL_MODE)
        put("CONTROL_AE_EXPOSURE_COMPENSATION", CaptureResult.CONTROL_AE_EXPOSURE_COMPENSATION)
        put("CONTROL_AE_LOCK", CaptureResult.CONTROL_AE_LOCK)
        put("CONTROL_AWB_LOCK", CaptureResult.CONTROL_AWB_LOCK)
        put("CONTROL_AE_REGIONS", CaptureResult.CONTROL_AE_REGIONS)
        put("CONTROL_AF_REGIONS", CaptureResult.CONTROL_AF_REGIONS)
        put("CONTROL_AWB_REGIONS", CaptureResult.CONTROL_AWB_REGIONS)
        put("CONTROL_SCENE_MODE", CaptureResult.CONTROL_SCENE_MODE)
        put("CONTROL_EFFECT_MODE", CaptureResult.CONTROL_EFFECT_MODE)
        put("CONTROL_VIDEO_STABILIZATION_MODE", CaptureResult.CONTROL_VIDEO_STABILIZATION_MODE)
        put("FLASH_MODE", CaptureResult.FLASH_MODE)
        put("FLASH_STATE", CaptureResult.FLASH_STATE)
        put("JPEG_ORIENTATION", CaptureResult.JPEG_ORIENTATION)
        put("JPEG_QUALITY", CaptureResult.JPEG_QUALITY)
        put("JPEG_GPS_LOCATION", CaptureResult.JPEG_GPS_LOCATION)
        put("SCALER_CROP_REGION", CaptureResult.SCALER_CROP_REGION)
        put("LENS_OPTICAL_STABILIZATION_MODE", CaptureResult.LENS_OPTICAL_STABILIZATION_MODE)
        put("NOISE_REDUCTION_MODE", CaptureResult.NOISE_REDUCTION_MODE)
        put("EDGE_MODE", CaptureResult.EDGE_MODE)
        put("HOT_PIXEL_MODE", CaptureResult.HOT_PIXEL_MODE)
        put("SHADING_MODE", CaptureResult.SHADING_MODE)
        put("TONEMAP_MODE", CaptureResult.TONEMAP_MODE)
        put("COLOR_CORRECTION_MODE", CaptureResult.COLOR_CORRECTION_MODE)
        put("COLOR_CORRECTION_GAINS", CaptureResult.COLOR_CORRECTION_GAINS)
        put("COLOR_CORRECTION_TRANSFORM", CaptureResult.COLOR_CORRECTION_TRANSFORM)
        put("COLOR_CORRECTION_ABERRATION_MODE", CaptureResult.COLOR_CORRECTION_ABERRATION_MODE)
        put("BLACK_LEVEL_LOCK", CaptureResult.BLACK_LEVEL_LOCK)
        put("STATISTICS_FACE_DETECT_MODE", CaptureResult.STATISTICS_FACE_DETECT_MODE)
        put("STATISTICS_FACES", CaptureResult.STATISTICS_FACES)
        if (Build.VERSION.SDK_INT >= 26) {
            put("CONTROL_ENABLE_ZSL", CaptureResult.CONTROL_ENABLE_ZSL)
        }
        if (Build.VERSION.SDK_INT >= 28) {
            put("DISTORTION_CORRECTION_MODE", CaptureResult.DISTORTION_CORRECTION_MODE)
        }
        if (Build.VERSION.SDK_INT >= 30) {
            put("CONTROL_ZOOM_RATIO", CaptureResult.CONTROL_ZOOM_RATIO)
            put("CONTROL_EXTENDED_SCENE_MODE", CaptureResult.CONTROL_EXTENDED_SCENE_MODE)
        }
        return out
    }

    fun readCharacteristics(chars: CameraCharacteristics): JSONObject {
        val out = JSONObject()
        fun <T> put(name: String, key: CameraCharacteristics.Key<T>) {
            try {
                val value = chars.get(key) ?: return
                if (value is android.hardware.camera2.params.StreamConfigurationMap) {
                    out.put(name, streamMap(value))
                } else {
                    JsonValues.put(out, name, value)
                }
            } catch (_: Throwable) {
            }
        }
        put("LENS_FACING", CameraCharacteristics.LENS_FACING)
        put("SENSOR_ORIENTATION", CameraCharacteristics.SENSOR_ORIENTATION)
        put("SENSOR_INFO_PIXEL_ARRAY_SIZE", CameraCharacteristics.SENSOR_INFO_PIXEL_ARRAY_SIZE)
        put("SENSOR_INFO_ACTIVE_ARRAY_SIZE", CameraCharacteristics.SENSOR_INFO_ACTIVE_ARRAY_SIZE)
        put("SENSOR_INFO_PHYSICAL_SIZE", CameraCharacteristics.SENSOR_INFO_PHYSICAL_SIZE)
        put("SENSOR_INFO_SENSITIVITY_RANGE", CameraCharacteristics.SENSOR_INFO_SENSITIVITY_RANGE)
        put("SENSOR_INFO_EXPOSURE_TIME_RANGE", CameraCharacteristics.SENSOR_INFO_EXPOSURE_TIME_RANGE)
        put("SENSOR_INFO_MAX_FRAME_DURATION", CameraCharacteristics.SENSOR_INFO_MAX_FRAME_DURATION)
        put("SENSOR_INFO_WHITE_LEVEL", CameraCharacteristics.SENSOR_INFO_WHITE_LEVEL)
        put("SENSOR_INFO_COLOR_FILTER_ARRANGEMENT", CameraCharacteristics.SENSOR_INFO_COLOR_FILTER_ARRANGEMENT)
        put("SENSOR_INFO_TIMESTAMP_SOURCE", CameraCharacteristics.SENSOR_INFO_TIMESTAMP_SOURCE)
        put("SENSOR_AVAILABLE_TEST_PATTERN_MODES", CameraCharacteristics.SENSOR_AVAILABLE_TEST_PATTERN_MODES)
        put("LENS_INFO_AVAILABLE_FOCAL_LENGTHS", CameraCharacteristics.LENS_INFO_AVAILABLE_FOCAL_LENGTHS)
        put("LENS_INFO_AVAILABLE_APERTURES", CameraCharacteristics.LENS_INFO_AVAILABLE_APERTURES)
        put("LENS_INFO_MINIMUM_FOCUS_DISTANCE", CameraCharacteristics.LENS_INFO_MINIMUM_FOCUS_DISTANCE)
        put("LENS_INFO_HYPERFOCAL_DISTANCE", CameraCharacteristics.LENS_INFO_HYPERFOCAL_DISTANCE)
        put("LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION", CameraCharacteristics.LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION)
        put("LENS_INFO_FOCUS_DISTANCE_CALIBRATION", CameraCharacteristics.LENS_INFO_FOCUS_DISTANCE_CALIBRATION)
        put("CONTROL_AE_COMPENSATION_RANGE", CameraCharacteristics.CONTROL_AE_COMPENSATION_RANGE)
        put("CONTROL_AE_COMPENSATION_STEP", CameraCharacteristics.CONTROL_AE_COMPENSATION_STEP)
        put("CONTROL_AE_AVAILABLE_MODES", CameraCharacteristics.CONTROL_AE_AVAILABLE_MODES)
        put("CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES", CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES)
        put("CONTROL_AF_AVAILABLE_MODES", CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)
        put("CONTROL_AWB_AVAILABLE_MODES", CameraCharacteristics.CONTROL_AWB_AVAILABLE_MODES)
        put("CONTROL_AVAILABLE_MODES", CameraCharacteristics.CONTROL_AVAILABLE_MODES)
        put("CONTROL_AVAILABLE_SCENE_MODES", CameraCharacteristics.CONTROL_AVAILABLE_SCENE_MODES)
        put("CONTROL_AVAILABLE_EFFECTS", CameraCharacteristics.CONTROL_AVAILABLE_EFFECTS)
        put("CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES", CameraCharacteristics.CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES)
        put("CONTROL_MAX_REGIONS_AE", CameraCharacteristics.CONTROL_MAX_REGIONS_AE)
        put("CONTROL_MAX_REGIONS_AF", CameraCharacteristics.CONTROL_MAX_REGIONS_AF)
        put("CONTROL_MAX_REGIONS_AWB", CameraCharacteristics.CONTROL_MAX_REGIONS_AWB)
        put("FLASH_INFO_AVAILABLE", CameraCharacteristics.FLASH_INFO_AVAILABLE)
        put("SCALER_AVAILABLE_MAX_DIGITAL_ZOOM", CameraCharacteristics.SCALER_AVAILABLE_MAX_DIGITAL_ZOOM)
        put("SCALER_STREAM_CONFIGURATION_MAP", CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        put("SCALER_CROPPING_TYPE", CameraCharacteristics.SCALER_CROPPING_TYPE)
        put("REQUEST_AVAILABLE_CAPABILITIES", CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES)
        put("REQUEST_MAX_NUM_OUTPUT_RAW", CameraCharacteristics.REQUEST_MAX_NUM_OUTPUT_RAW)
        put("REQUEST_MAX_NUM_OUTPUT_PROC", CameraCharacteristics.REQUEST_MAX_NUM_OUTPUT_PROC)
        put("REQUEST_MAX_NUM_OUTPUT_PROC_STALLING", CameraCharacteristics.REQUEST_MAX_NUM_OUTPUT_PROC_STALLING)
        put("REQUEST_MAX_NUM_INPUT_STREAMS", CameraCharacteristics.REQUEST_MAX_NUM_INPUT_STREAMS)
        put("REQUEST_PIPELINE_MAX_DEPTH", CameraCharacteristics.REQUEST_PIPELINE_MAX_DEPTH)
        put("REQUEST_PARTIAL_RESULT_COUNT", CameraCharacteristics.REQUEST_PARTIAL_RESULT_COUNT)
        put("INFO_SUPPORTED_HARDWARE_LEVEL", CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL)
        put("SYNC_MAX_LATENCY", CameraCharacteristics.SYNC_MAX_LATENCY)
        put("NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES", CameraCharacteristics.NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES)
        put("EDGE_AVAILABLE_EDGE_MODES", CameraCharacteristics.EDGE_AVAILABLE_EDGE_MODES)
        put("HOT_PIXEL_AVAILABLE_HOT_PIXEL_MODES", CameraCharacteristics.HOT_PIXEL_AVAILABLE_HOT_PIXEL_MODES)
        put("TONEMAP_AVAILABLE_TONE_MAP_MODES", CameraCharacteristics.TONEMAP_AVAILABLE_TONE_MAP_MODES)
        put("TONEMAP_MAX_CURVE_POINTS", CameraCharacteristics.TONEMAP_MAX_CURVE_POINTS)
        put("COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES", CameraCharacteristics.COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES)
        put("STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES", CameraCharacteristics.STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES)
        put("STATISTICS_INFO_MAX_FACE_COUNT", CameraCharacteristics.STATISTICS_INFO_MAX_FACE_COUNT)
        if (Build.VERSION.SDK_INT >= 28) {
            put("DISTORTION_CORRECTION_AVAILABLE_MODES", CameraCharacteristics.DISTORTION_CORRECTION_AVAILABLE_MODES)
            put("INFO_VERSION", CameraCharacteristics.INFO_VERSION)
        }
        if (Build.VERSION.SDK_INT >= 30) {
            put("CONTROL_ZOOM_RATIO_RANGE", CameraCharacteristics.CONTROL_ZOOM_RATIO_RANGE)
        }
        return out
    }

    private fun setKey(builder: CaptureRequest.Builder, name: String, raw: Any) {
        when (name) {
            "CONTROL_MODE" -> builder.set(CaptureRequest.CONTROL_MODE, DeviceJson.asInt(raw))
            "CONTROL_AE_MODE" -> builder.set(CaptureRequest.CONTROL_AE_MODE, DeviceJson.asInt(raw))
            "CONTROL_AF_MODE" -> builder.set(CaptureRequest.CONTROL_AF_MODE, DeviceJson.asInt(raw))
            "CONTROL_AWB_MODE" -> builder.set(CaptureRequest.CONTROL_AWB_MODE, DeviceJson.asInt(raw))
            "CONTROL_AE_LOCK" -> builder.set(CaptureRequest.CONTROL_AE_LOCK, DeviceJson.asBool(raw))
            "CONTROL_AWB_LOCK" -> builder.set(CaptureRequest.CONTROL_AWB_LOCK, DeviceJson.asBool(raw))
            "CONTROL_AE_EXPOSURE_COMPENSATION" -> builder.set(CaptureRequest.CONTROL_AE_EXPOSURE_COMPENSATION, DeviceJson.asInt(raw))
            "CONTROL_AE_ANTIBANDING_MODE" -> builder.set(CaptureRequest.CONTROL_AE_ANTIBANDING_MODE, DeviceJson.asInt(raw))
            "CONTROL_AE_PRECAPTURE_TRIGGER" -> builder.set(CaptureRequest.CONTROL_AE_PRECAPTURE_TRIGGER, DeviceJson.asInt(raw))
            "CONTROL_AF_TRIGGER" -> builder.set(CaptureRequest.CONTROL_AF_TRIGGER, DeviceJson.asInt(raw))
            "CONTROL_AE_TARGET_FPS_RANGE" -> builder.set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, intRange(raw))
            "CONTROL_AE_REGIONS" -> builder.set(CaptureRequest.CONTROL_AE_REGIONS, regions(raw))
            "CONTROL_AF_REGIONS" -> builder.set(CaptureRequest.CONTROL_AF_REGIONS, regions(raw))
            "CONTROL_AWB_REGIONS" -> builder.set(CaptureRequest.CONTROL_AWB_REGIONS, regions(raw))
            "CONTROL_CAPTURE_INTENT" -> builder.set(CaptureRequest.CONTROL_CAPTURE_INTENT, DeviceJson.asInt(raw))
            "CONTROL_EFFECT_MODE" -> builder.set(CaptureRequest.CONTROL_EFFECT_MODE, DeviceJson.asInt(raw))
            "CONTROL_SCENE_MODE" -> builder.set(CaptureRequest.CONTROL_SCENE_MODE, DeviceJson.asInt(raw))
            "CONTROL_VIDEO_STABILIZATION_MODE" -> builder.set(CaptureRequest.CONTROL_VIDEO_STABILIZATION_MODE, DeviceJson.asInt(raw))
            "CONTROL_POST_RAW_SENSITIVITY_BOOST" -> {
                requireApi(24, name)
                builder.set(CaptureRequest.CONTROL_POST_RAW_SENSITIVITY_BOOST, DeviceJson.asInt(raw))
            }
            "CONTROL_ENABLE_ZSL" -> {
                requireApi(26, name)
                builder.set(CaptureRequest.CONTROL_ENABLE_ZSL, DeviceJson.asBool(raw))
            }
            "CONTROL_ZOOM_RATIO" -> {
                requireApi(30, name)
                builder.set(CaptureRequest.CONTROL_ZOOM_RATIO, DeviceJson.asFloat(raw))
            }
            "CONTROL_EXTENDED_SCENE_MODE" -> {
                requireApi(30, name)
                builder.set(CaptureRequest.CONTROL_EXTENDED_SCENE_MODE, DeviceJson.asInt(raw))
            }
            "CONTROL_SETTINGS_OVERRIDE" -> {
                requireApi(34, name)
                builder.set(CaptureRequest.CONTROL_SETTINGS_OVERRIDE, DeviceJson.asInt(raw))
            }
            "SENSOR_SENSITIVITY" -> builder.set(CaptureRequest.SENSOR_SENSITIVITY, DeviceJson.asInt(raw))
            "SENSOR_EXPOSURE_TIME" -> builder.set(CaptureRequest.SENSOR_EXPOSURE_TIME, DeviceJson.asLong(raw))
            "SENSOR_FRAME_DURATION" -> builder.set(CaptureRequest.SENSOR_FRAME_DURATION, DeviceJson.asLong(raw))
            "SENSOR_TEST_PATTERN_MODE" -> builder.set(CaptureRequest.SENSOR_TEST_PATTERN_MODE, DeviceJson.asInt(raw))
            "SENSOR_PIXEL_MODE" -> {
                requireApi(31, name)
                builder.set(CaptureRequest.SENSOR_PIXEL_MODE, DeviceJson.asInt(raw))
            }
            "LENS_FOCUS_DISTANCE" -> builder.set(CaptureRequest.LENS_FOCUS_DISTANCE, DeviceJson.asFloat(raw))
            "LENS_APERTURE" -> builder.set(CaptureRequest.LENS_APERTURE, DeviceJson.asFloat(raw))
            "LENS_FILTER_DENSITY" -> builder.set(CaptureRequest.LENS_FILTER_DENSITY, DeviceJson.asFloat(raw))
            "LENS_FOCAL_LENGTH" -> builder.set(CaptureRequest.LENS_FOCAL_LENGTH, DeviceJson.asFloat(raw))
            "LENS_OPTICAL_STABILIZATION_MODE" -> builder.set(CaptureRequest.LENS_OPTICAL_STABILIZATION_MODE, DeviceJson.asInt(raw))
            "FLASH_MODE" -> builder.set(CaptureRequest.FLASH_MODE, DeviceJson.asInt(raw))
            "FLASH_STRENGTH_LEVEL" -> {
                requireApi(35, name)
                builder.set(CaptureRequest.FLASH_STRENGTH_LEVEL, DeviceJson.asInt(raw))
            }
            "SCALER_CROP_REGION" -> builder.set(CaptureRequest.SCALER_CROP_REGION, rect(raw))
            "SCALER_ROTATE_AND_CROP" -> {
                requireApi(31, name)
                builder.set(CaptureRequest.SCALER_ROTATE_AND_CROP, DeviceJson.asInt(raw))
            }
            "JPEG_QUALITY" -> builder.set(CaptureRequest.JPEG_QUALITY, DeviceJson.asInt(raw).toByte())
            "JPEG_ORIENTATION" -> builder.set(CaptureRequest.JPEG_ORIENTATION, DeviceJson.asInt(raw))
            "JPEG_THUMBNAIL_QUALITY" -> builder.set(CaptureRequest.JPEG_THUMBNAIL_QUALITY, DeviceJson.asInt(raw).toByte())
            "JPEG_THUMBNAIL_SIZE" -> builder.set(CaptureRequest.JPEG_THUMBNAIL_SIZE, size(raw))
            "JPEG_GPS_LOCATION" -> builder.set(CaptureRequest.JPEG_GPS_LOCATION, location(raw))
            "NOISE_REDUCTION_MODE" -> builder.set(CaptureRequest.NOISE_REDUCTION_MODE, DeviceJson.asInt(raw))
            "EDGE_MODE" -> builder.set(CaptureRequest.EDGE_MODE, DeviceJson.asInt(raw))
            "HOT_PIXEL_MODE" -> builder.set(CaptureRequest.HOT_PIXEL_MODE, DeviceJson.asInt(raw))
            "SHADING_MODE" -> builder.set(CaptureRequest.SHADING_MODE, DeviceJson.asInt(raw))
            "TONEMAP_MODE" -> builder.set(CaptureRequest.TONEMAP_MODE, DeviceJson.asInt(raw))
            "TONEMAP_GAMMA" -> builder.set(CaptureRequest.TONEMAP_GAMMA, DeviceJson.asFloat(raw))
            "TONEMAP_CURVE" -> builder.set(CaptureRequest.TONEMAP_CURVE, tonemap(raw))
            "COLOR_CORRECTION_MODE" -> builder.set(CaptureRequest.COLOR_CORRECTION_MODE, DeviceJson.asInt(raw))
            "COLOR_CORRECTION_GAINS" -> builder.set(CaptureRequest.COLOR_CORRECTION_GAINS, gains(raw))
            "COLOR_CORRECTION_TRANSFORM" -> builder.set(CaptureRequest.COLOR_CORRECTION_TRANSFORM, transform(raw))
            "COLOR_CORRECTION_ABERRATION_MODE" -> builder.set(CaptureRequest.COLOR_CORRECTION_ABERRATION_MODE, DeviceJson.asInt(raw))
            "DISTORTION_CORRECTION_MODE" -> {
                requireApi(28, name)
                builder.set(CaptureRequest.DISTORTION_CORRECTION_MODE, DeviceJson.asInt(raw))
            }
            "STATISTICS_FACE_DETECT_MODE" -> builder.set(CaptureRequest.STATISTICS_FACE_DETECT_MODE, DeviceJson.asInt(raw))
            "STATISTICS_LENS_SHADING_MAP_MODE" -> builder.set(CaptureRequest.STATISTICS_LENS_SHADING_MAP_MODE, DeviceJson.asInt(raw))
            "STATISTICS_HOT_PIXEL_MAP_MODE" -> builder.set(CaptureRequest.STATISTICS_HOT_PIXEL_MAP_MODE, DeviceJson.asBool(raw))
            "BLACK_LEVEL_LOCK" -> builder.set(CaptureRequest.BLACK_LEVEL_LOCK, DeviceJson.asBool(raw))
            else -> throw IllegalArgumentException("unknown CaptureRequest key: $name")
        }
    }

    private fun requireApi(api: Int, name: String) {
        if (Build.VERSION.SDK_INT < api) {
            throw UnsupportedOperationException("unsupported_api: $name requires API $api")
        }
    }

    private fun intRange(raw: Any): Range<Int> {
        val arr = raw as? JSONArray ?: throw IllegalArgumentException("range must be [min, max]")
        return Range(DeviceJson.asInt(arr.get(0)), DeviceJson.asInt(arr.get(1)))
    }

    private fun regions(raw: Any): Array<MeteringRectangle> {
        val arr = raw as? JSONArray ?: throw IllegalArgumentException("regions must be an array")
        return Array(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            val weight = if (o.has("weight")) o.getInt("weight") else MeteringRectangle.METERING_WEIGHT_DONT_CARE
            if (o.has("left")) {
                MeteringRectangle(o.getInt("left"), o.getInt("top"), o.getInt("right") - o.getInt("left"), o.getInt("bottom") - o.getInt("top"), weight)
            } else {
                MeteringRectangle(o.getInt("x"), o.getInt("y"), o.getInt("width"), o.getInt("height"), weight)
            }
        }
    }

    private fun rect(raw: Any): Rect {
        val o = raw as? JSONObject ?: throw IllegalArgumentException("rect must be an object")
        return if (o.has("left")) {
            Rect(o.getInt("left"), o.getInt("top"), o.getInt("right"), o.getInt("bottom"))
        } else {
            val x = o.getInt("x")
            val y = o.getInt("y")
            Rect(x, y, x + o.getInt("width"), y + o.getInt("height"))
        }
    }

    private fun size(raw: Any): Size {
        val o = raw as? JSONObject ?: throw IllegalArgumentException("size must be {width, height}")
        return Size(o.getInt("width"), o.getInt("height"))
    }

    private fun location(raw: Any): Location {
        val o = raw as? JSONObject ?: throw IllegalArgumentException("location must be an object")
        return Location("device-bridge").apply {
            latitude = o.getDouble("latitude")
            longitude = o.getDouble("longitude")
            if (o.has("altitude")) altitude = o.getDouble("altitude")
        }
    }

    private fun gains(raw: Any): RggbChannelVector {
        val arr = raw as? JSONArray ?: throw IllegalArgumentException("COLOR_CORRECTION_GAINS must be [r, gEven, gOdd, b]")
        return RggbChannelVector(arr.getDouble(0).toFloat(), arr.getDouble(1).toFloat(), arr.getDouble(2).toFloat(), arr.getDouble(3).toFloat())
    }

    private fun transform(raw: Any): ColorSpaceTransform {
        val arr = raw as? JSONArray ?: throw IllegalArgumentException("COLOR_CORRECTION_TRANSFORM must be 18 ints")
        val ints = IntArray(18) { DeviceJson.asInt(arr.get(it)) }
        return ColorSpaceTransform(ints)
    }

    private fun tonemap(raw: Any): TonemapCurve {
        val o = raw as? JSONObject ?: throw IllegalArgumentException("TONEMAP_CURVE must be {red, green, blue}")
        fun channel(name: String): FloatArray {
            val arr = o.getJSONArray(name)
            return FloatArray(arr.length()) { DeviceJson.asFloat(arr.get(it)) }
        }
        return TonemapCurve(channel("red"), channel("green"), channel("blue"))
    }

    private fun streamMap(map: android.hardware.camera2.params.StreamConfigurationMap): JSONObject {
        val formats = intArrayOf(
            android.graphics.ImageFormat.JPEG,
            android.graphics.ImageFormat.YUV_420_888,
            android.graphics.ImageFormat.RAW_SENSOR,
            android.graphics.ImageFormat.PRIVATE,
        )
        val outputs = JSONArray()
        for (fmt in formats) {
            val sizes = runCatching { map.getOutputSizes(fmt) }.getOrNull() ?: continue
            val sizeArr = JSONArray()
            for (s in sizes) {
                val min = runCatching { map.getOutputMinFrameDuration(fmt, s) }.getOrDefault(0L)
                val stall = runCatching { map.getOutputStallDuration(fmt, s) }.getOrDefault(0L)
                sizeArr.put(JSONObject()
                    .put("width", s.width)
                    .put("height", s.height)
                    .put("min_frame_duration_ns", min)
                    .put("stall_ns", stall))
            }
            outputs.put(JSONObject().put("format", fmt).put("sizes", sizeArr))
        }
        return JSONObject().put("outputs", outputs)
    }
}
