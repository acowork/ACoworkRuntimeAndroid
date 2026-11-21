# dev/android/

Build and release automation for **ACoworkNode** — the Android *Node host* app
(`com.acowork.androidhost`). This is not the main repo's mobile **client**;
see [ADR-AND-004](../../docs/adr/zh/ADR-AND-004-independent-apk-deliverable.md).

| script | what it does |
|---|---|
| [`build_android.sh`](build_android.sh) | **Linux / macOS — start here.** Toolchain discovery → Rust cross-compile → packaged shell → Gradle assemble → optional device install. |
| [`build_android.ps1`](build_android.ps1) | **Windows — start here.** The PowerShell twin of the `.sh`; same steps, same flags. |
| [`build_ash.sh`](build_ash.sh) | Cross-compiles the packaged POSIX shell (mksh R57) for arm64-v8a. Called by the build scripts. |
| [`setup_keystore.sh`](setup_keystore.sh) | Creates the local signing keystore. **The keystore never enters the repository.** |

## The one-command build

```bash
# Linux / macOS
./dev/android/build_android.sh                    # debug APK
./dev/android/build_android.sh --release          # release APK
./dev/android/build_android.sh --release --install

# Windows
.\dev\android\build_android.ps1                   # debug APK
.\dev\android\build_android.ps1 -Release
.\dev\android\build_android.ps1 -Release -Install
```

The `.sh` and `.ps1` are twins **by contract, not by shared code** — the two
implement the same five steps, and when you change a step in one you change
the other.

| flag | `.sh` | `.ps1` |
|---|---|---|
| release build | `--release` | `-Release` |
| install on the device | `--install` | `-Install` |
| reuse the existing `jniLibs` | `--skip-native` | `-SkipNative` |
| signing keystore | `--keystore <path>` | `-Keystore <path>` |
| keystore / key password | `--keystore-pass`, `--key-pass` | `-KeystorePassword`, `-KeyPassword` |
| key alias | `--key-alias` | `-KeyAlias` |
| version override | `--version` | `-Version` |

### What the build actually does

1. **Locates the toolchain** — Android SDK, NDK `26.1.10909125`, and a JDK 17
   that ships `jlink`.
2. **Resolves the version** from the repo-root [`VERSION`](../../VERSION) file.
3. **Cross-compiles the native artifacts**:
   - `cargo build -p acowork-android-ffi -p acowork-android-cli --release
     --target aarch64-linux-android`
   - the packaged POSIX shell (see below)
   - both are copied into `app/src/main/jniLibs/arm64-v8a/`
4. **Assembles** the APK with Gradle, signing the release variant when a
   keystore is configured.
5. **Installs** on the connected device when asked, and reports the signature
   state so an unsigned APK is never mistaken for a signed one.

## Three things that will bite you

### The linker alone is not enough

The Rust crates depend on `zstd-sys` and `rusqlite`, which compile C sources
with `cc-rs`. Setting only the *linker* makes the build fail with:

```
fatal error: 'string.h' file not found
```

The C compiler needs the NDK **sysroot** as well. The build scripts export the
whole set:

```
CC_aarch64_linux_android          = <ndk>/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android26-clang
CXX_aarch64_linux_android         = .../aarch64-linux-android26-clang++
AR_aarch64_linux_android          = .../llvm-ar
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = .../aarch64-linux-android26-clang
CFLAGS_aarch64_linux_android      = --sysroot=<ndk>/toolchains/llvm/prebuilt/<host>/sysroot
CXXFLAGS_aarch64_linux_android    = --sysroot=...
```

`scripts/android-ndk-env.ps1` sets the same variables for interactive use on
Windows; the build scripts set them for every platform so that local and CI
builds cannot drift apart.

### The JDK needs `jlink`

AGP's `JdkImageTransform` calls `jlink` to build the `android.jar` system
module image. IDE runtimes — the IntelliJ JBR, some Android Studio builds —
omit it, and the build dies with:

```
jlink executable .../jbr/bin/jlink.exe does not exist
```

A **global** `~/.gradle/gradle.properties` often pins `org.gradle.java.home` to
exactly such a runtime, and that setting outranks `JAVA_HOME`. The build
scripts detect this case and override it for the invocation, so you do not
have to edit your global Gradle config.

### `bash` on Windows is not necessarily Git Bash

On a machine with WSL enabled, PowerShell resolves a bare `bash` to
`C:\WINDOWS\system32\bash.exe` — that is WSL, which mounts this drive at
`/mnt/e`, not `/e`. The script then cannot find its own sibling file:

```
/bin/bash: /e/projects/.../dev/android/build_ash.sh: No such file or directory
```

Two separate path defects hide behind that one message, and both are worth
knowing because each looks like the other:

- PowerShell hands native arguments over verbatim, so a Windows path reaches
  bash with backslashes intact, and bash reads them as escapes —
  `E:\dev\android\build_ash.sh` arrives as `E:devandroidbuild_ash.sh`.
- `ANDROID_NDK_HOME` in Windows form survives MSYS's own file tests, so
  `[ -f "$CC" ]` passes, and the failure only surfaces when mksh's `Build.sh`
  runs `$CC` in a command position.

`build_android.ps1` therefore locates Git Bash from the git installation
instead of trusting `PATH`, and `build_ash.sh` normalises every incoming path
through `cygpath -u`. The normalisation lives in `build_ash.sh` rather than in
its caller so that a CI shell, the bash twin, and a hand-run invocation are all
safe without having to remember the rule.

## The packaged shell (`libacowork_ash.so`)

The app needs a shell it is *allowed* to execute. On a device with Enforcing
SELinux an `untrusted_app` cannot exec `/system/bin/sh` (`shell_exec`), which
is why in-app probes used to collapse to the `apk-sandbox` profile and every
ash tool call failed. The workaround is to package a shell as a `jniLib`, so
Android extracts it into `nativeLibraryDir` with the `+x` bit.

That shell is **mksh R57** (MirBSD KSH). It is a third-party binary and is
therefore **not committed** — it is cross-compiled from a pinned upstream
commit by [`build_ash.sh`](build_ash.sh) and lands in the git-ignored
`build/android/`.

| | |
|---|---|
| upstream | <https://github.com/mirbsd/mksh> |
| pinned commit | `1050c2e888252178108786881f59ebd87aa69e72` (`bump`, 2019-03-01) |
| version string | `KSH_VERSION=@(#)MIRBSD KSH R57 2019/03/01 Android` |
| target | `aarch64-linux-android`, 16 KB page alignment |

The build script verifies that version string after building, so a drifting
pin fails the build instead of shipping a different shell.

## Signing

**The keystore never enters the repository.** It is the app's upgrade identity:
losing it means the app can never be updated in place, and leaking it means
anyone can sign an update the device will accept.

### Configure it

```bash
./dev/android/setup_keystore.sh
# -> keys/acoworknode.jks   (git-ignored) — the signing identity, created once
# -> keystore.properties    (git-ignored) — the per-machine binding to the build
```

The passwords are prompted for and never taken as arguments, so they do not land
in the shell history or the process list.

The script then checks that the two files really are readable only by you, and
says so when they are not. On Windows that check cannot be about POSIX mode
bits: MSYS `chmod 600` is advisory, and a file it reports as `644` — or even as
`600` — can still be readable by every local account through an inherited NTFS
ACE. So `harden()` inspects the ACL with `icacls` and, when it finds a
group-inherited entry, prints the command that actually closes it:

```bat
icacls keys\acoworknode.jks /inheritance:r /grant:r "%USERNAME%:F"
```

Run that on a copy the first time. A mistyped principal there removes your own
access too, and `icacls <file> /reset` is the only way back — which is a poor
way to lose a keystore you cannot regenerate.

**Re-running the script where a keystore already exists is the normal thing to
do** — on a fresh clone, or after moving to another machine. It verifies the
alias really is inside that keystore and then rewrites only the binding. It
never regenerates the identity: a second key would break in-place upgrades for
every device that already runs the app, and a script that quietly did so would
be the worst kind of build tool.

### Other ways to bind the build

Either write `keystore.properties` in the repo root by hand (git-ignored):

```properties
acowork.keystoreFile=keys/acoworknode.jks
acowork.keystorePassword=<store password>
acowork.keyAlias=acoworknode
acowork.keyPassword=<key password>
```

…or export the environment variables:

```bash
export ACOWORK_KEYSTORE_FILE=keys/acoworknode.jks
export ACOWORK_KEYSTORE_PASSWORD=...
export ACOWORK_KEY_ALIAS=acoworknode
export ACOWORK_KEY_PASSWORD=...
```

…or pass them on the command line for a one-off build:

```bash
./dev/android/build_android.sh --release \
    --keystore keys/acoworknode.jks \
    --keystore-pass "$STORE_PW" --key-alias acoworknode --key-pass "$KEY_PW"
```

The precedence is: Gradle property → `keystore.properties` → environment
variable.

When nothing is configured the release build still succeeds but produces an
**unsigned** APK, and the build script says so explicitly — including which of
the two halves is missing, since "keystore exists, binding does not" is the
usual near-miss and used to report itself as a generic "no keystore". That
silence is deliberate but was not informative enough: an unsigned APK is fine
for a local smoke test, and a release build that quietly produced one for
distribution would be much worse. `apksigner verify` is run on the result either
way, so the artifact's actual state is always in the log.

## Releasing

One thing triggers a release: an annotated `v*` tag. The workflow
([`.github/workflows/release.yml`](../../.github/workflows/release.yml)) builds
the APK, signs it, and publishes a **draft** Release. A maintainer verifies
the assets and presses Publish — nothing reaches users automatically.

```bash
# 1. bump VERSION, commit
echo "0.1.1" > VERSION
git commit -am "release: 0.1.1"

# 2. tag and push
git tag -a v0.1.1 -m "ACoworkNode 0.1.1"
git push origin v0.1.1
```

The `verify` job fails if the tag does not match `VERSION`. The `build` job
runs `apksigner verify` and fails if the signature does not check out — an
unsigned APK never reaches the release assets.

### Repository secrets

The keystore is a **repository secret**, not a file in the tree. Only its
base64 encoding is uploaded to GitHub's encrypted secret store.

| secret | value |
|---|---|
| `ACOWORK_KEYSTORE_BASE64` | `base64 -w0 keys/acoworknode.jks` |
| `ACOWORK_KEYSTORE_PASSWORD` | the keystore password |
| `ACOWORK_KEY_ALIAS` | `acoworknode` |
| `ACOWORK_KEY_PASSWORD` | the key password |

On Linux: `base64 -w0 keys/acoworknode.jks`. On macOS: `base64 < keys/acoworknode.jks | tr -d '\n'`.

A keystore that is ever committed to the tree is **compromised** — rotate it
before the next release.

## Version scheme

[`VERSION`](../../VERSION) is authoritative. The Gradle build derives both
fields from it:

| field | value |
|---|---|
| `versionName` | the file's contents, without a `v` prefix |
| `versionCode` | `major * 1_000_000 + minor * 1_000 + patch` |

The `versionCode` formula keeps room for 999 patches per minor and is
monotonic across a major bump, which is what the package manager requires for
an in-place upgrade.
