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

The host process listens on `{filesDir}/acowork/device-bridge.sock` while the foreground service is up. The engine registers the `android_*` tools in the phone runtime (including `android_use`).

1. Settings → **Allow device capabilities**. Grant camera and microphone.
2. From an enrolled agent, call `android_photo` with `{}` and `android_audio_record` with `{"duration_ms": 1000}`.
3. Both calls should return `ok` and a file under `{work_dir}/device-captures/`.
4. Revoke camera (or run before granting). `android_photo` must return `error_code=permission_required`, not an empty success. A high-importance notification deep-links back to the grant button.
5. `android_device_status` must not prompt and must not claim the camera, the microphone, BLE, or USB.

## android_use (screen)

1. Settings → **Enable screen control** → turn on **ACowork Host** in Accessibility. On Android 10 also tap the screen-capture notification once if a screenshot is needed.
2. `android_use` `{"op":"status"}` returns `accessibility_connected` without prompting.
3. `{"op":"screenshot"}` returns a JPEG under `device-captures/` and a preview content part.
4. `{"op":"tap","x":0.5,"y":0.5,"normalized":true}` should succeed only with accessibility on; otherwise `permission_required`.
5. With accessibility off, screenshot/tap must not succeed silently.

## Agents → 详情页（会话历史）

一级页点任意 agent 进入二级页，页面只读，数据来自 `{filesDir}/acowork/agents/{instanceId}/memory/private.sqlite`
的 `sessions` 表（设计见 [../../docs/design/zh/android-agent-sessions.md](../../docs/design/zh/android-agent-sessions.md)）。

| Check | Result |
|---|---|
| 点 Agents 行进入详情页 | 头部为 agent 名 · 包名 · `Running`/`Stopped` |
| 会话行 | `<title or Untitled session>` / `<相对时间> · <N> msg`，最近活动在最前 |
| 空态（agent 未在手机上对话过） | `No sessions yet. This agent has not chatted on this phone.`，底部 `no sessions` |
| 读失败 | `Cannot read the session store: <原因>`（择中可复制），**不是**空列表 |
| 已卸载但目录在 | 头部 `<instanceId> · not installed`，会话照常显示 |
| Refresh / 左上返回 | 重新读盘；返回 Agents 页 |

会话历史的检查不需要 host 在跑（agent 停着也读得到盘上的记录）。

## Root (Magisk / KSU — same APK)

Root is a probed host profile of this APK. There is no extra root binary. The Runtime process stays `untrusted_app`; privileged commands go through Magisk/KSU `su -c`.

1. Magisk/KSU: grant `com.acowork.androidhost` (or tap **Request Magisk / KSU root** and accept the prompt; up to 60s).
2. **Stop** then **Start host** so the start probe (500 ms) sees uid 0. Status JSON: `profile=root-shell`, `su_granted=true`.
3. Optional: **Dangerous mode** for system-partition writes. Session-only — off when the host stops, never persisted. Restart running agents after toggling.

```powershell
adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd request_root

adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd dangerous --es on 1

adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd status
```

`ps -Z` of `libacowork_engine.so` must stay `untrusted_app` even when `profile=root-shell`.
