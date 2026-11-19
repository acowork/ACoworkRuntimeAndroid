# ACowork Android Host APK

Independent **Node host** app (`com.acowork.androidhost`) — not the main-repo
mobile **client**. See [ADR-AND-004](../../docs/adr/zh/ADR-AND-004-independent-apk-deliverable.md).

## Layout

| Path | Role |
|---|---|
| `app/` | Kotlin UI + foreground service |
| `../../crates/acowork-android-ffi` | JNI `cdylib` → `libacowork_android_ffi.so` |
| `filesDir/acowork/` | Scoped storage home (identity, packages, HostConfig) |

## Prerequisites

- Android SDK (`ANDROID_HOME`)
- NDK **26.1.10909125** (e.g. `$ANDROID_HOME/ndk/26.1.10909125`)
- **JDK 17** with `jlink` (`JAVA_HOME`) — Temurin/OpenJDK works; some IDE JBRs omit `jlink` and break AGP
- Rust target: `rustup target add aarch64-linux-android`

## Build native library

From repo root (PowerShell) — use the helper so `zstd-sys` and friends get the
NDK sysroot (linker alone is not enough on Windows):

```powershell
. .\scripts\android-ndk-env.ps1
cargo build -p acowork-android-ffi --release --target aarch64-linux-android
# then copy, or:
cd apps/android
./gradlew cargoNdkArm64
```

Copy lands in `app/src/main/jniLibs/arm64-v8a/libacowork_android_ffi.so`
(gitignored `*.so` — rebuild locally).

## Build / install APK

```powershell
$env:JAVA_HOME = "<JDK 17+>"   # e.g. Android Studio / IntelliJ JBR
$env:ANDROID_HOME = "D:\Android\Sdk"
cd apps/android
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## What works in this slice

- Foreground service + notification keep-alive
- Connectivity callback → native MQTT re-start
- Probe summary / node status via JNI
- Node enroll (C1) over MQTT; Gateway control `ping` / `start` / `stop` / `install` / `uninstall` handled in FFI
- Packaged engine: `libacowork_engine.so` (CLI `acowork-android` as jniLibs binary)
- Root-shell is the same APK + Magisk/KSU grant (no extra bin). **Request Magisk / KSU root**, then Stop/Start host. **Dangerous mode** is a session switch for system writes and is never persisted.
- Agents page → per-agent **detail page** with its session history (newest activity
  first, title / relative time / message count — the desktop list's fields). Read-only:
  see [docs/design/zh/android-agent-sessions.md](../../docs/design/zh/android-agent-sessions.md)
- adb smoke without unlocking UI: see [DEVICE_SMOKE.md](DEVICE_SMOKE.md)

**Do not** `adb forward tcp:19900` while a desktop Node is using that port — use `adb reverse` for `:19875`/`:19876` only.

## Package identity

`applicationId` = `com.acowork.androidhost` — deliberately distinct from any
upstream mobile client package.
