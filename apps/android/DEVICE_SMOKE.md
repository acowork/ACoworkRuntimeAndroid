# APK device smoke (BLA-AL00, no root)

Date: 2026-11-18 · serial used only locally (not committed).

## Safe connectivity (do not steal desktop `:19900`)

Desktop Node already owns `127.0.0.1:19900`. **Never** `adb forward tcp:19900`.

Phone → PC Gateway only:

```powershell
adb reverse tcp:19876 tcp:19876
adb reverse tcp:19875 tcp:19875
# leave `adb forward` empty
```

## Commands

```powershell
adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd version

adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd probe

adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd start `
  --es gateway http://127.0.0.1:19876 --es name apk-bla-al00

adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd status

adb logcat -d | findstr ACoworkHost
```

## Results (this session)

| Check | Result |
|---|---|
| Install + native load | `acowork-android-ffi 0.1.0` |
| Probe | `profile=apk-sandbox`, caps include `control_plane` / `process` |
| Foreground service | `isForeground=true` |
| Engine packaged | `libacowork_engine.so` under `nativeLibraryDir` |
| MQTT enroll (via reverse) | `enrolled=true`, node_id assigned |
| `adb forward` to 19900 | **forbidden** — conflicts with desktop Node |

Gateway HTTP `/api/nodes` needs auth; enroll proof is the APK status JSON `enrolled=true`.

## Device tools

The host process listens on `{filesDir}/acowork/device-bridge.sock` while the foreground service is up. The engine only sees the eight `android_*` tools when that bridge published `device-bridge.token`.

1. Settings → **Allow device capabilities**. Grant camera and microphone.
2. From an enrolled agent, call `android_photo` with `{}` and `android_audio_record` with `{"duration_ms": 1000}`.
3. Both calls should return `ok` and a file under `{work_dir}/device-captures/`.
4. Revoke camera (or run before granting). `android_photo` must return `error_code=permission_required`, not an empty success. A high-importance notification deep-links back to the grant button.
5. `android_device_status` must not prompt and must not claim the camera, the microphone, BLE, or USB.
