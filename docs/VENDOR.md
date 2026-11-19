# Vendored / ported upstream sources

This repository is an **independent** Android Node+Runtime (ADR-AND-003): it does
**not** path- or git-depend on upstream crates. Behavior is **copied** from the
sibling ACowork monorepo and adapted here.

## Snapshot

| Field | Value |
|---|---|
| Upstream repo | `E:/projects/tranxon/ACowork` (local sibling) |
| Upstream commit | `c9d2827101c7ac0c823b2f3188e170d0c1908762` (2026-11-18) |
| Layout | `crates/vendor/{acowork-core,acowork-memory,acowork-sqlite,acowork-mcp,acowork-mqtt-session,acowork-runtime}` |

Re-copy with a fresh tree sync from `ACowork/core/<crate>` into `crates/vendor/<crate>` when upgrading; keep this table updated.

## Closure

| Local path | Upstream | Notes |
|---|---|---|
| `crates/vendor/acowork-core` | `core/acowork-core` | Protocol, tools traits, logging |
| `crates/vendor/acowork-memory` | `core/acowork-memory` | Required by sqlite; memory **service** binary unused by Android host |
| `crates/vendor/acowork-sqlite` | `core/acowork-sqlite` | Conversation / session sidecars |
| `crates/vendor/acowork-mcp` | `core/acowork-mcp` | MCP client |
| `crates/vendor/acowork-mqtt-session` | `core/acowork-mqtt-session` | MQTT session lifecycle |
| `crates/vendor/acowork-runtime` | `core/acowork-runtime` | Full agent engine; feature `android-host` routes shell via `ExecutionBackend` |
| `crates/acowork-android/src/node/package.rs` | node `install.rs` + `download_package` | `.agent` ZIP install (also kept for Node inventory without linking vendor node) |
| `crates/acowork-android/proto/node_control.proto` | subset of `mqtt_payload.proto` | Node control plane field numbers |

**Not vendored** (on purpose): `acowork-gateway`, `acowork-node`, `acowork-user`, `acowork-vault`, `acowork-sign`, `acowork-embed`, `acowork-lsp-relay`, `acowork-eval`.

## Android adaptations inside vendored runtime

- `platform.rs`: detect Termux/Android; register `bash` + `ash` tools
- `tools/builtin/shell.rs` + `android_exec.rs` (`android-host`): shell → `acowork_android::host::ExecutionBackend`
- Dev/integration tests that need Gateway/eval removed or gated (`upstream-gateway-tests`)

## Explicitly unsupported / feature-off

| Item | Reason |
|---|---|
| `wasm-tools` / Wasmtime | Not an Android NDK delivery target |
| PowerShell / Git Bash tools | Desktop-only; not registered on Android |
| `codebase` / LSP tool | Upstream already unregistered; no Android LSP relay |
| Gateway-broker unit tests | Gateway not in this workspace |
| `acowork-sign` hard verify | Soft-accept unsigned packages (same Phase-1 stance) |

## Node-side thin package path

`acowork-android` still owns MQTT enroll, reverse proxy, and `.agent` inventory so the Node role does not pull the entire Runtime into every probe binary. The Runtime role (`acowork-android runtime`) links `acowork-runtime` with `android-host`.

## APK host packaging

| Piece | Path |
|---|---|
| JNI bridge | `crates/acowork-android-ffi` → `libacowork_android_ffi.so` |
| Gradle app | `apps/android` (`com.acowork.androidhost`) |
| NDK | 26.1.10909125, target `aarch64-linux-android` / abi `arm64-v8a` |
| Env helper | `scripts/android-ndk-env.ps1` (CC + sysroot for cc-rs crates) |

Scoped home on device: `Context.getFilesDir()/acowork`. See `apps/android/README.md`.
