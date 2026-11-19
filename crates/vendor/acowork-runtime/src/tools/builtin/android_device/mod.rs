//! Android-only device tools. Registered only when `ACOWORK_DEVICE_BRIDGE`
//! is set. The schema is the public Android SDK surface; skills teach usage.
//!
//! Hardware runs in the app process. This module sends one JSON request
//! over the bridge and, for `android_photo`, attaches a downscaled preview.

use std::path::Path;
use std::time::Duration;

use acowork_android::device::{self, DeviceRequest, PROTOCOL_VERSION};
use acowork_core::error::Result;
use acowork_core::providers::traits::{ContentPart, ImageUrlPart};
use acowork_core::tools::traits::{Tool, ToolContext, ToolResult, ToolSpec};
use async_trait::async_trait;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::agent::attachment_to_image::build_data_url;

/// Build the eight device tools. Caller has already checked the bridge env.
pub fn tools() -> Vec<std::sync::Arc<dyn Tool>> {
    device::TOOL_NAMES
        .iter()
        .copied()
        .map(|name| std::sync::Arc::new(AndroidDeviceTool { name }) as std::sync::Arc<dyn Tool>)
        .collect()
}

struct AndroidDeviceTool {
    name: &'static str,
}

impl AndroidDeviceTool {
    fn spec_value(&self) -> ToolSpec {
        ToolSpec {
            name: self.name.to_string(),
            description: description(self.name).to_string(),
            input_schema: schema(self.name),
        }
    }
}

#[async_trait]
impl Tool for AndroidDeviceTool {
    fn spec(&self) -> ToolSpec {
        self.spec_value()
    }

    async fn execute(&self, params: Value, work_dir: Option<&str>) -> Result<ToolResult> {
        let ctx = ToolContext {
            work_dir: work_dir.map(str::to_string),
            ..ToolContext::default()
        };
        self.execute_with_context(params, &ctx).await
    }

    async fn execute_with_context(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let name = self.name;
        let params = params.clone();
        let work_dir = ctx.work_dir.clone().unwrap_or_default();
        let agent_id = ctx.session_id.clone().unwrap_or_default();
        let joined = tokio::task::spawn_blocking(move || invoke(name, params, work_dir, agent_id))
            .await
            .map_err(|e| acowork_core::error::AcoworkError::Tool(e.to_string()))?;
        Ok(joined)
    }
}

fn invoke(tool: &str, args: Value, work_dir: String, agent_id: String) -> ToolResult {
    let Some((sock, token)) = device::bridge_endpoint() else {
        return fail(
            "bridge_unavailable",
            "ACOWORK_DEVICE_BRIDGE is not set; device tools are not connected to the host app",
        );
    };
    let req = DeviceRequest {
        v: PROTOCOL_VERSION,
        id: Uuid::new_v4().to_string(),
        token,
        tool: tool.to_string(),
        agent_id,
        work_dir,
        args,
    };
    let timeout = call_timeout(tool, &req.args);
    match device::call(&sock, &req, timeout) {
        Ok(resp) => to_result(tool, resp),
        Err(e) => fail("bridge_unavailable", &e.to_string()),
    }
}

fn call_timeout(tool: &str, args: &Value) -> Duration {
    let duration_ms = args.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let wait_ms = args
        .get("subscribe_wait_ms")
        .or_else(|| args.get("timeout_ms"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let scan_ms = if tool == "android_ble_scan" {
        args.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(10_000)
    } else {
        0
    };
    let play_wait = matches!(
        (tool, args.get("op").and_then(|v| v.as_str())),
        ("android_audio_play", Some("play_and_wait")) | ("android_audio_play", None)
    );
    let mut ms = 30_000u64
        .saturating_add(duration_ms)
        .saturating_add(wait_ms)
        .saturating_add(scan_ms)
        .saturating_add(15_000);
    if play_wait {
        ms = ms.max(600_000);
    }
    // Stay under the agent loop's 10 minute tool timeout.
    Duration::from_millis(ms.min(590_000))
}

fn to_result(tool: &str, resp: device::DeviceResponse) -> ToolResult {
    if !resp.ok {
        let code = resp.error_code.unwrap_or_else(|| "failed".into());
        let message = resp.error.unwrap_or(resp.content);
        return fail(&code, &message);
    }
    let data_text = serde_json::to_string(&resp.data).unwrap_or_else(|_| "{}".into());
    let content = if resp.content.is_empty() {
        data_text
    } else if data_text.len() > 16 * 1024 {
        resp.content
    } else {
        format!("{}\n{data_text}", resp.content)
    };
    let mut result = ToolResult {
        ok: true,
        content,
        content_parts: None,
        error: None,
        token_usage: None,
    };
    if tool == "android_photo" {
        if let Some(part) = preview_part(&resp.data) {
            result.content_parts = Some(vec![part]);
        }
    }
    result
}

fn fail(code: &str, message: &str) -> ToolResult {
    let text = if message.is_empty() {
        code.to_string()
    } else if message.starts_with(code) {
        message.to_string()
    } else {
        format!("{code}: {message}")
    };
    ToolResult {
        ok: false,
        content: text.clone(),
        content_parts: None,
        error: Some(text),
        token_usage: None,
    }
}

/// Downscale the captured JPEG so the model can see it without a second tool call.
fn preview_part(data: &Value) -> Option<ContentPart> {
    let path = data.get("path")?.as_str()?;
    let img = image::ImageReader::open(Path::new(path)).ok()?.decode().ok()?;
    let (w, h) = (img.width(), img.height());
    let long = w.max(h).max(1);
    let scale = if long > 512 { 512.0 / long as f32 } else { 1.0 };
    let out_w = ((w as f32) * scale).round().max(1.0) as u32;
    let out_h = ((h as f32) * scale).round().max(1.0) as u32;
    let resized = if scale < 1.0 {
        img.resize(out_w, out_h, image::imageops::FilterType::Triangle)
    } else {
        img
    };
    let mut jpeg = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut jpeg);
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, 80)
        .encode_image(&resized)
        .ok()?;
    let url = build_data_url("image/jpeg", &jpeg);
    Some(ContentPart::ImageUrl {
        image_url: ImageUrlPart {
            url,
            detail: Some("low".into()),
            width: Some(resized.width()),
            height: Some(resized.height()),
        },
    })
}

fn description(name: &str) -> &'static str {
    match name {
        "android_device_status" => {
            "Read phone hardware and permission state. No side effects and no permission prompt. sections selects permissions, features, cameras (full CameraCharacteristics), audio_devices, microphones, bluetooth, usb, bridge (inflight calls and exclusive holders). Defaults to all sections."
        }
        "android_photo" => {
            "Capture one JPEG with Camera2. lens_facing defaults to back. capture_request keys are public CaptureRequest.Key names and override jpeg_quality, jpeg_orientation, and location. Returns the file path, the CaptureResult, and a small preview image."
        }
        "android_video_record" => {
            "Record video with MediaRecorder and a Camera2 record template. op is start, stop, or status. duration_ms records and returns in one call. max_duration_ms defaults to 600000; 0 means no limit. capture_request uses the same keys as android_photo."
        }
        "android_audio_record" => {
            "Record audio. Compressed containers use MediaRecorder; wav and raw_pcm use AudioRecord. op is start, stop, or status, unless duration_ms is set. audio_source, encoding, channel_mask, and effects (aec, ns, agc) follow the public AudioRecord / MediaRecorder fields."
        }
        "android_audio_play" => {
            "Play an audio file under the agent work directory with MediaPlayer. op is play_and_wait, start, pause, resume, stop, seek, or status. audio_attributes, playback speed, pitch, seek_mode, and preferred_device_id are the public player fields."
        }
        "android_ble_scan" => {
            "BLE scan via BluetoothLeScanner.startScan. settings maps to ScanSettings.Builder and filters maps to ScanFilter.Builder. Multiple filters are OR, matching the platform. Returns each ScanResult and ScanRecord, including raw advertising bytes when include_raw is true."
        }
        "android_ble_gatt" => {
            "BLE GATT client. op matches the public BluetoothGatt methods: connect, disconnect, close, discover_services, list, request_mtu, request_connection_priority, set_preferred_phy, read_phy, read_rssi, read, write, read_descriptor, write_descriptor, subscribe, unsubscribe, create_bond, fetch_uuids, get_bond_state, status. Write length is the negotiated MTU."
        }
        "android_usb_hid" => {
            "USB host for a device that has a HID interface (class 3). op is list, open, close, claim, release, set_configuration, set_interface, control_transfer, transfer, or get_raw_descriptors. control_transfer takes the public UsbDeviceConnection.controlTransfer arguments. This does not make the phone a USB gadget."
        }
        _ => "Android device tool",
    }
}

fn schema(name: &str) -> Value {
    match name {
        "android_device_status" => json!({
            "type": "object",
            "properties": {
                "sections": {
                    "type": "array",
                    "description": "Subset of permissions, features, cameras, audio_devices, microphones, bluetooth, usb, bridge. Default: all.",
                    "items": { "type": "string" }
                },
                "output": { "type": "string", "enum": ["inline", "file"], "description": "inline returns JSON in the tool result when it fits. file writes the JSON under device-captures. Default: inline, spilling to a file past the result budget." }
            }
        }),
        "android_photo" => json!({
            "type": "object",
            "properties": {
                "camera_id": { "type": "string", "description": "CameraManager camera id. Default: the camera matching lens_facing." },
                "lens_facing": { "type": "string", "enum": ["back", "front", "external"], "description": "Used when camera_id is omitted. Default back." },
                "template": { "type": "string", "enum": ["still", "manual", "preview"], "description": "CameraDevice template. Default still (TEMPLATE_STILL_CAPTURE)." },
                "output_path": { "type": "string", "description": "JPEG path. Relative paths are under the agent work dir. Default: device-captures/<id>.jpg." },
                "output": { "type": "string", "enum": ["inline", "file"] },
                "warmup_frames": { "type": "integer", "description": "Repeating-request frames before the still capture so AE/AF can settle. Default: a few frames for auto focus, 0 for template=manual." },
                "jpeg_quality": { "type": "integer", "description": "JPEG_QUALITY 1-100. Default 95. Overridden by capture_request.JPEG_QUALITY." },
                "jpeg_orientation": { "type": "integer", "description": "JPEG_ORIENTATION in degrees. Default: derived from SENSOR_ORIENTATION and lens facing." },
                "location": { "type": "object", "description": "JPEG_GPS_LOCATION. Fields latitude, longitude, altitude (optional, meters).", "properties": { "latitude": { "type": "number" }, "longitude": { "type": "number" }, "altitude": { "type": "number" } } },
                "capture_request": {
                    "type": "object",
                    "description": "Map of public CaptureRequest.Key names to values. Applied after the convenience fields, so it wins on conflict. Unknown keys return invalid_argument. Keys the device API level lacks return unsupported_api. Groups: CONTROL_* (AE/AF/AWB mode and lock, exposure compensation, regions, precapture and AF trigger, target FPS, zoom, scene, effect, video stabilization, capture intent, ZSL, extended scene mode), SENSOR_* (sensitivity, exposure time, frame duration, test pattern), LENS_* (focus distance, aperture, focal length, filter density, optical stabilization), FLASH_MODE, SCALER_CROP_REGION, JPEG_*, NOISE_REDUCTION_MODE, EDGE_MODE, HOT_PIXEL_MODE, SHADING_MODE, TONEMAP_*, COLOR_CORRECTION_*, DISTORTION_CORRECTION_MODE, STATISTICS_FACE_DETECT_MODE and the related statistics mode switches. Regions are arrays of {x,y,width,height,weight}. Ranges are [min,max]. Rects are {left,top,right,bottom}.",
                    "additionalProperties": true
                }
            }
        }),
        "android_video_record" => json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": ["start", "stop", "status"], "description": "Omit op and pass duration_ms to record and return in one call. start begins a session; stop finalizes it." },
                "camera_id": { "type": "string" },
                "lens_facing": { "type": "string", "enum": ["back", "front", "external"] },
                "template": { "type": "string", "enum": ["record", "manual", "preview"], "description": "Default record (TEMPLATE_RECORD)." },
                "duration_ms": { "type": "integer", "description": "When set, one call records this long and returns." },
                "output_format": { "type": "string", "enum": ["mpeg_4", "webm", "three_gpp"], "description": "MediaRecorder.OutputFormat. Default mpeg_4." },
                "video_encoder": { "type": "string", "description": "MediaRecorder.VideoEncoder name: default, h263, h264, hevc, mpeg_4_sp, vp8, vp9, av1, dolby_vision. Default h264." },
                "audio_encoder": { "type": "string", "description": "MediaRecorder.AudioEncoder name: default, amr_nb, amr_wb, aac, he_aac, aac_eld, vorbis, opus. Default aac." },
                "camcorder_profile": { "type": "string", "description": "CamcorderProfile quality name, including time-lapse and high-speed names (QUALITY_720P, QUALITY_1080P, QUALITY_2160P, QUALITY_HIGH, QUALITY_LOW, QUALITY_TIME_LAPSE_1080P, QUALITY_HIGH_SPEED_HIGH, ...). Explicit fields below override the profile." },
                "video_size": { "type": "object", "properties": { "width": { "type": "integer" }, "height": { "type": "integer" } } },
                "video_bit_rate": { "type": "integer" },
                "video_frame_rate": { "type": "integer" },
                "capture_rate": { "type": "number", "description": "MediaRecorder.setCaptureRate. Used for time-lapse." },
                "orientation_hint": { "type": "integer" },
                "audio_enabled": { "type": "boolean", "description": "Default true. Requires RECORD_AUDIO when true." },
                "audio_source": { "type": "string", "description": "MediaRecorder.AudioSource: default, mic, camcorder, voice_recognition, voice_communication, unprocessed, voice_performance, voice_uplink, voice_downlink, voice_call. Default camcorder." },
                "audio_sample_rate": { "type": "integer" },
                "audio_bit_rate": { "type": "integer" },
                "audio_channels": { "type": "integer" },
                "output_path": { "type": "string" },
                "max_duration_ms": { "type": "integer", "description": "setMaxDuration. Default 600000. 0 means no limit." },
                "max_file_size_bytes": { "type": "integer", "description": "setMaxFileSize. 0 means no limit." },
                "location": { "type": "object", "properties": { "latitude": { "type": "number" }, "longitude": { "type": "number" }, "altitude": { "type": "number" } } },
                "preferred_device_id": { "type": "integer", "description": "AudioDeviceInfo id. setPreferredDevice, API 28+." },
                "privacy_sensitive": { "type": "boolean", "description": "setPrivacySensitive, API 30+." },
                "capture_request": { "type": "object", "description": "Same CaptureRequest map as android_photo, on TEMPLATE_RECORD.", "additionalProperties": true },
                "output": { "type": "string", "enum": ["inline", "file"] }
            }
        }),
        "android_audio_record" => json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": ["start", "stop", "status"] },
                "duration_ms": { "type": "integer", "description": "When set, record this long in one call." },
                "container": { "type": "string", "enum": ["aac_m4a", "amr_nb", "amr_wb", "opus", "wav", "raw_pcm"], "description": "aac_m4a, amr_*, opus use MediaRecorder. wav and raw_pcm use AudioRecord. Default aac_m4a. opus requires API 29." },
                "audio_source": { "type": "string", "description": "default, mic, camcorder, voice_recognition, voice_communication, unprocessed, voice_performance (API 29), voice_uplink, voice_downlink, voice_call. Default mic." },
                "sample_rate": { "type": "integer", "description": "Hz. Default 44100 for PCM, encoder default for compressed." },
                "encoding": { "type": "string", "enum": ["pcm_8bit", "pcm_16bit", "pcm_float", "pcm_24bit", "pcm_32bit"], "description": "PCM encoding. pcm_24bit and pcm_32bit require API 31. Default pcm_16bit." },
                "channel_mask": { "description": "Integer AudioFormat channel mask, or \"mono\" / \"stereo\". Default mono." },
                "channel_index_mask": { "type": "integer", "description": "AudioFormat channel index mask." },
                "buffer_size_bytes": { "type": "integer" },
                "bit_rate": { "type": "integer", "description": "Compressed bit rate." },
                "max_duration_ms": { "type": "integer", "description": "Default 600000 for an open-ended start. 0 means no limit." },
                "max_file_size_bytes": { "type": "integer" },
                "preferred_device_id": { "type": "integer" },
                "privacy_sensitive": { "type": "boolean", "description": "API 30+." },
                "audio_session_id": { "type": "integer", "description": "Not accepted. AudioRecord.Builder has no public setSessionId. The assigned id is returned on the result." },
                "effects": {
                    "type": "object",
                    "description": "Enable AcousticEchoCanceler, NoiseSuppressor, AutomaticGainControl when the device offers them. PCM only; the result reports which ones actually enabled.",
                    "properties": {
                        "aec": { "type": "boolean" },
                        "ns": { "type": "boolean" },
                        "agc": { "type": "boolean" }
                    }
                },
                "output_path": { "type": "string" },
                "output": { "type": "string", "enum": ["inline", "file"] }
            }
        }),
        "android_audio_play" => json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "enum": ["play_and_wait", "start", "pause", "resume", "stop", "seek", "status"], "description": "Default play_and_wait. loop=true is rejected for play_and_wait." },
                "path": { "type": "string", "description": "File inside the agent work directory." },
                "audio_attributes": {
                    "type": "object",
                    "description": "AudioAttributes. usage: media, game, voice_communication, alarm, notification, assistance, assistant, notification_ringtone, notification_event, unknown. content_type: music, speech, movie, sonification, unknown. flags: array of audibility_enforced, hw_av_sync, low_latency. capture_policy: all, none, system (API 29).",
                    "properties": {
                        "usage": { "type": "string" },
                        "content_type": { "type": "string" },
                        "flags": { "type": "array", "items": { "type": "string" } },
                        "capture_policy": { "type": "string" }
                    }
                },
                "stream_type": { "type": "string", "description": "Legacy setAudioStreamType: music, voice_call, ring, alarm, notification, system, dtmf, accessibility. Ignored when audio_attributes is set." },
                "volume": { "type": "number", "description": "0 to 1, both channels." },
                "left_volume": { "type": "number" },
                "right_volume": { "type": "number" },
                "loop": { "type": "boolean" },
                "seek_ms": { "type": "integer" },
                "seek_mode": { "type": "string", "enum": ["previous_sync", "next_sync", "closest_sync", "closest"], "description": "MediaPlayer.seekTo mode. Default closest." },
                "playback_speed": { "type": "number", "description": "PlaybackParams speed. Default 1." },
                "pitch": { "type": "number", "description": "PlaybackParams pitch. Default 1." },
                "audio_fallback_mode": { "type": "string", "enum": ["default", "mute", "fail"], "description": "PlaybackParams audio fallback mode." },
                "preferred_device_id": { "type": "integer", "description": "Output AudioDeviceInfo id. API 28+." },
                "audio_session_id": { "type": "integer" },
                "aux_effect_id": { "type": "integer", "description": "attachAuxEffect id." },
                "aux_effect_send_level": { "type": "number", "description": "setAuxEffectSendLevel." }
            },
            "required": ["path"]
        }),
        "android_ble_scan" => json!({
            "type": "object",
            "properties": {
                "duration_ms": { "type": "integer", "description": "Default 10000." },
                "include_raw": { "type": "boolean", "description": "Include ScanRecord bytes as hex. Default true." },
                "output": { "type": "string", "enum": ["inline", "file"] },
                "settings": {
                    "type": "object",
                    "description": "ScanSettings.Builder. scan_mode: low_power, balanced, low_latency, opportunistic. callback_type: all_matches, first_match, match_lost. match_mode: aggressive, sticky. match_num: one, few, max. report_delay_ms, phy (le_1m, le_coded, all_supported), legacy (boolean).",
                    "additionalProperties": true
                },
                "filters": {
                    "type": "array",
                    "description": "ScanFilter.Builder list. Filters are OR. Each item may set device_name, device_address, service_uuid, service_uuid_mask, service_data_uuid, service_data (hex), service_data_mask (hex), manufacturer_id, manufacturer_data (hex), manufacturer_data_mask (hex), solicitation_uuid, solicitation_uuid_mask, advertising_data_type (API 33), advertising_data (hex), advertising_data_mask (hex).",
                    "items": { "type": "object", "additionalProperties": true }
                }
            }
        }),
        "android_ble_gatt" => json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "description": "connect, disconnect, close, discover_services, list, request_mtu, request_connection_priority, set_preferred_phy, read_phy, read_rssi, read, write, read_descriptor, write_descriptor, subscribe, unsubscribe, create_bond, fetch_uuids, get_bond_state, status." },
                "address": { "type": "string", "description": "Bluetooth MAC address." },
                "auto_connect": { "type": "boolean", "description": "connectGatt autoConnect. Default false." },
                "transport": { "type": "string", "enum": ["auto", "br_edr", "le"], "description": "connectGatt transport. Default auto. create_bond only accepts auto; createBond(int) is not a public method." },
                "phy_mask": { "type": "integer", "description": "PHY bitmask for connect: 1 le_1m, 2 le_2m, 4 le_coded. Default PHY_LE_1M_MASK." },
                "phy_options": { "type": "integer", "description": "connectGatt has no public phy options argument. A non-zero value returns unsupported_api. Use set_preferred_phy." },
                "timeout_ms": { "type": "integer", "description": "How long to wait for the GATT callback. Default 10000." },
                "service_uuid": { "type": "string" },
                "service_instance_id": { "type": "integer" },
                "characteristic_uuid": { "type": "string" },
                "characteristic_instance_id": { "type": "integer" },
                "descriptor_uuid": { "type": "string" },
                "value_hex": { "type": "string", "description": "Bytes to write. Length is limited by the negotiated ATT MTU, not by this tool." },
                "write_type": { "type": "string", "enum": ["default", "no_response", "signed"], "description": "BluetoothGattCharacteristic write type. Default default." },
                "mtu": { "type": "integer", "description": "requestMtu value." },
                "priority": { "type": "string", "enum": ["balanced", "high", "low_power"], "description": "requestConnectionPriority." },
                "tx_phy": { "type": "integer" },
                "rx_phy": { "type": "integer" },
                "notification": { "type": "string", "enum": ["notify", "indicate"], "description": "Which CCCD value subscribe writes. Default notify." },
                "subscribe_wait_ms": { "type": "integer", "description": "How long subscribe collects notifications before returning. Further notifications are buffered for op=status." }
            },
            "required": ["op", "address"]
        }),
        "android_usb_hid" => json!({
            "type": "object",
            "properties": {
                "op": { "type": "string", "description": "list, open, close, claim, release, set_configuration, set_interface, control_transfer, transfer, get_raw_descriptors." },
                "device_id": { "type": "integer", "description": "UsbDevice.getDeviceId." },
                "device_name": { "type": "string", "description": "UsbDevice.getDeviceName, for example /dev/bus/usb/001/002." },
                "vendor_id": { "type": "integer" },
                "product_id": { "type": "integer" },
                "serial": { "type": "string" },
                "interface_id": { "type": "integer" },
                "alternate_setting": { "type": "integer" },
                "force_claim": { "type": "boolean", "description": "UsbDeviceConnection.claimInterface force. Default true." },
                "idle_timeout_ms": { "type": "integer", "description": "Release the interface after this idle time. Default 60000. 0 holds until close." },
                "configuration_id": { "type": "integer" },
                "request_type": { "type": "integer", "description": "controlTransfer requestType." },
                "request": { "type": "integer", "description": "controlTransfer request. HID GET_REPORT is 0x01, SET_REPORT is 0x09, SET_IDLE is 0x0A, SET_PROTOCOL is 0x0B." },
                "value": { "type": "integer", "description": "controlTransfer value. For HID reports this is (reportType << 8) | reportId." },
                "index": { "type": "integer", "description": "controlTransfer index. Usually the interface number." },
                "data_hex": { "type": "string", "description": "OUT payload. Empty for IN transfers." },
                "length": { "type": "integer", "description": "Transfer length in bytes. Required for IN when data_hex is empty. USB wLength is 16-bit; larger bulk reads are allowed up to 1MB." },
                "timeout_ms": { "type": "integer", "description": "Transfer timeout. Default 1000." },
                "endpoint_address": { "type": "integer", "description": "UsbEndpoint address, direction included." },
                "endpoint_number": { "type": "integer" },
                "direction": { "type": "string", "enum": ["in", "out"], "description": "Used with endpoint_number when endpoint_address is omitted." },
                "output": { "type": "string", "enum": ["inline", "file"], "description": "Where to put raw descriptors and transfer bytes." }
            },
            "required": ["op"]
        }),
        _ => json!({"type": "object"}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_tools_and_each_schema_names_itself() {
        let built = tools();
        assert_eq!(built.len(), 8);
        for tool in built {
            let spec = tool.spec();
            assert!(device::TOOL_NAMES.contains(&spec.name.as_str()));
            assert!(spec.description.len() > 40);
            assert_eq!(spec.input_schema["type"], "object");
        }
    }

    #[test]
    fn missing_bridge_is_an_error_result_not_a_panic() {
        // Safety: tests in this process may run in parallel. Only assert the
        // error shape when the variable is unset, which is the CI default.
        if device::bridge_active() {
            return;
        }
        let result = invoke(
            "android_device_status",
            json!({}),
            "/tmp/work".into(),
            "s".into(),
        );
        assert!(!result.ok);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("bridge_unavailable"), "{err}");
    }
}
