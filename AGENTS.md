# AGENTS.md — ACoworkRuntimeAndroid

## Overview

Android port of the ACowork **Node Agent + Runtime** tiers: a phone/tablet hosts agents,
enrolls with an existing Gateway, and is a first-class cluster member — not a thin client.
Two deliverables from one engine: the CLI (`acowork-android`, Termux) and the host APK
(`com.acowork.androidhost`, foreground service + JNI). Upstream platform repo:
[ACowork](https://github.com/acowork/ACowork) — this repo is intentionally independent of it
([ADR-AND-003](docs/adr/zh/ADR-AND-003-independent-engine-and-spawn-contract.md)).

README.md and docs/ carry the background; when this file contradicts an ADR, the ADR wins.

## Build & Test

Host-side (any OS, no Android toolchain needed):

```bash
cargo build
cargo test                                        # unit + contract + conformance + ground truth
cargo clippy --all-targets -- -D warnings         # must be warning-free
cargo fmt --check
```

The rules layer must also build bare-metal (R12, not optional):

```bash
cargo build  -p acowork-platform-contract --no-default-features --target riscv32imc-unknown-none-elf
cargo clippy -p acowork-platform-contract --no-default-features --target riscv32imc-unknown-none-elf -- -D warnings
```

APK — one command, owns toolchain discovery, Rust cross-compile, mksh, Gradle, signing:

```bash
./dev/android/build_android.sh [--release] [--install]      # Linux / macOS
.\dev\android\build_android.ps1 [-Release] [-Install]       # Windows
```

Requirements: NDK **26.1.10909125**, JDK 17 **with `jlink`**, and the `aarch64-linux-android`
rustup target. Known traps and the keystore policy:
[dev/android/README.md](dev/android/README.md). The `.sh` and the `.ps1` are twins by contract —
change a step in one, change it in the other.

## Release

[`VERSION`](VERSION) is the single source of truth: it feeds `versionName`/`versionCode` in
[apps/android/app/build.gradle.kts](apps/android/app/build.gradle.kts), and the tag must match it.

1. Land the change on `main`, tag it (`git tag -a vX.Y.Z`), push the tag. A tag containing `-`
   (e.g. `v0.2.0-rc1`) is published as a pre-release.
2. `.github/workflows/release.yml` runs three jobs:
   - **verify** — `dev/android/check_exec_bits.sh` (every tracked file starting with `#!` must be
     recorded executable), tag matches `VERSION`, version declarations agree.
   - **build** — SDK and NDK at the local build's pins, plus build-tools 35.0.0 / android-35,
     and mksh R57 cross-built. Cross-compiles the FFI cdylib and the CLI for
     `aarch64-linux-android`, stages both into `jniLibs` (the CLI is copied as
     `libacowork_engine.so` so AGP extracts it with the executable bit), restores the keystore
     from secrets into `keystore.properties`, runs `:app:assembleRelease`, then verifies with
     `apksigner verify`, and packs the asset with `SHA256SUMS.txt`.
   - **publish** — notes generated from the commit log, uploaded as a **draft** GitHub Release
     (`ACoworkNode-<version>-arm64-v8a.apk`).
3. A human publishes. Open the draft, install the CI-built APK on a device and confirm the node
   enrolls before clicking publish: the CI artifact is not the local build, and a device check is
   the only evidence that counts.

Secrets: `ACOWORK_KEYSTORE_BASE64` (the `.jks`, base64), `ACOWORK_KEYSTORE_PASSWORD`,
`ACOWORK_KEY_ALIAS`, `ACOWORK_KEY_PASSWORD`.

When a run fails, fix it on `main`, merge, and **move the tag**: delete it locally and on the
remote, re-create it at the new main, push. Re-running an attempt re-tests the same broken
commit.

Traps already paid for — do not repay them:

- `setup-android` must stay **v4+**: v3 installs the legacy `tools` package, which is gone from
  the SDK repository, so the job dies before anything is built.
- A missing exec bit is invisible on Windows (`core.fileMode` is false) and is exit 126 on Linux.
  The verify job checks the mode git recorded, not the one on disk.
- `Cargo.lock` is tracked, so it must be a lock that has actually been built: a fresh resolve can
  pair crates that cannot compile (`calamine` 0.26.1 needs `zip` < 2.5 — pinned 2.4.2). CI does
  not pass `--locked`, so a manifest/lock disagreement re-resolves silently instead of failing.
- Missing signing material makes the release APK **unsigned rather than failing** the build;
  `apksigner verify` is what catches it. Keep that step.

## Project Structure

```
crates/
  acowork-platform-contract/  # platform-neutral rules (R1–R13), serde-only, no_std + alloc
  acowork-android/            # Android facts: host probe / ExecutionBackend / capability gate,
                              # node half (EngineSpec, ProcessTable, enroll), device tools
  acowork-android-cli/        # one binary, two roles: `serve` (Node) / `runtime` (Runtime)
  acowork-android-ffi/        # JNI cdylib for the APK
  vendor/                     # copied Runtime closure from upstream core/ (see below)
apps/android/                 # host APK (Gradle + Kotlin foreground service)
docs/adr/zh/                  # ADR-AND-001..004 — decisions bind the code
docs/{design,plan,review}/zh/ # design notes, plans, readiness assessments
dev/android/                  # build & release automation
scripts/                      # sync-vendor.ps1, android-ndk-env.ps1
```

Dependency direction: `cli` / `ffi` → `acowork-android` → `platform-contract` (+ `vendor/*`
for the Runtime role).

## Vendored Crates

`crates/vendor/*` is a **snapshot copy** of upstream `core/` crates (current base and patch
notes: [docs/VENDOR.md](docs/VENDOR.md)).

- Do not fix a bug only here: fix upstream, re-sync with `scripts/sync-vendor.ps1`, then re-apply
  the Android adaptations listed in VENDOR.md (`platform.rs`, `shell.rs` / `android_exec.rs`,
  `android-host` feature) — a clean overwrite erases them.
- Update the snapshot table in `docs/VENDOR.md` in the same commit as a re-sync.
- `tests/` dirs of vendored crates are dropped on sync (they need Gateway/eval); don't re-add.

## Security Model (non-negotiable)

- **The Runtime never runs as root.** Escalation happens per tool call inside the execution
  backend, gated by session approval.
- **Root is not a boolean**: it is decomposed into approvable capabilities
  (`android:shell:read`, `android:fs:system`, …), each audited; destructive operations
  (`dd` to a block device, partition writes) are refused by default.
- A command the classifier says changes state is never run without approval — the refusal paths
  in `crates/acowork-android/src/host/` are product surface, name them, don't bypass them.

## Conventions

- Commits follow Conventional Commits, English, one-line subject: `feat(android): …` /
  `fix(host): …` / `docs: …` / `chore(vendor): …` — scopes in use: `android`, `host`, `ci`,
  `vendor`, `docs`.
- Design docs / ADRs are Chinese (source of truth); Rust code comments MUST be English.
- The conformance suite [crates/acowork-android/tests/rules_conformance.rs](crates/acowork-android/tests/rules_conformance.rs)
  is the artifact a second platform port copies; keep rules testable there, not Android-only.

## Rules (Do NOT)

- Do NOT act before the user confirms your plan.
- Do NOT guess: a root cause needs a log, `device_probe` / `acowork-host` output or a failing
  regression test. A model of a device is not a device.
- Do NOT add Android/std dependencies to `acowork-platform-contract` — it must keep building
  for `riscv32imc-unknown-none-elf`.
- Do NOT edit vendored crate behavior without recording it in `docs/VENDOR.md` — an unrecorded
  patch is lost on the next sync.
- Do NOT commit keystores, passwords, `.so` artifacts (`jniLibs` is rebuilt locally) or
  `keystore.properties`.
- Do NOT wrap file paths in quotes — use Markdown links relative to the working directory.
- Do NOT run grep in the repo root; `target/`, `build/` and `apps/android/build/` are huge.
