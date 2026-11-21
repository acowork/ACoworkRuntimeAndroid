#!/usr/bin/env bash
# build_android.sh - One-command APK build for ACoworkNode (Linux / macOS).
#
# WHY THIS EXISTS
#   Producing the ACoworkNode APK needs five things that live in three
#   different worlds: a Rust cross-compiler, the Android NDK, a C toolchain
#   for the packaged shell, and Gradle. Getting the first three to agree on a
#   sysroot is the part that is easy to get wrong, and this script is where
#   that agreement is encoded:
#
#     1. cargo cross-compiles the FFI library and the engine CLI for
#        aarch64-linux-android. This needs CC/CFLAGS/AR pointing at the NDK
#        sysroot -- NOT just a linker, because zstd-sys and rusqlite compile
#        C sources with cc-rs and fail with "string.h file not found"
#        otherwise.
#     2. mksh R57 is cross-compiled into the packaged POSIX shell
#        (libacowork_ash.so). See build_ash.sh for why the app needs one.
#     3. The Rust artifacts and the packaged shell are copied into jniLibs.
#     4. Gradle assembles the APK, signing the release variant when the
#        keystore is available locally (see --keystore below).
#     5. The APK is optionally installed on the connected device.
#
#   The Windows twin is dev/android/build_android.ps1.
#
# USAGE
#   ./dev/android/build_android.sh                  debug APK (default)
#   ./dev/android/build_android.sh --release        release APK
#   ./dev/android/build_android.sh --release --install
#   ./dev/android/build_android.sh --install        install the debug APK
#   ./dev/android/build_android.sh --skip-native    reuse the existing jniLibs
#   ./dev/android/build_android.sh --keystore <path>  release signing keystore
#   ./dev/android/build_android.sh --keystore-pass <pw> / --key-pass <pw>
#   ./dev/android/build_android.sh --key-alias <alias>
#
# Requires: bash, git, cargo + the aarch64-linux-android target, a JDK 17 that
# ships jlink (Temurin works; some IDE JBRs omit jlink and break AGP), the
# Android SDK, and the NDK 26.1.10909125.

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
BUILD_TYPE="debug"
INSTALL=0
SKIP_NATIVE=0
KEYSTORE=""
KEYSTORE_PASS=""
KEY_PASS=""
KEY_ALIAS=""
VERSION_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --release)       BUILD_TYPE="release" ;;
        --debug)         BUILD_TYPE="debug" ;;
        --install)       INSTALL=1 ;;
        --skip-native)   SKIP_NATIVE=1 ;;
        --keystore)      KEYSTORE="${2:?--keystore needs a path}"; shift ;;
        --keystore-pass) KEYSTORE_PASS="${2:?--keystore-pass needs a value}"; shift ;;
        --key-pass)      KEY_PASS="${2:?--key-pass needs a value}"; shift ;;
        --key-alias)     KEY_ALIAS="${2:?--key-alias needs a value}"; shift ;;
        --version)       VERSION_OVERRIDE="${2:?--version needs a value}"; shift ;;
        -h|--help)       sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
ANDROID_DIR="$REPO_ROOT/apps/android"
NDK_VERSION="26.1.10909125"
CARGO_TARGET="aarch64-linux-android"

if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_OFF=""
fi
info() { echo "${C_CYAN}$*${C_OFF}"; }
ok()   { echo "${C_GREEN}$*${C_OFF}"; }
warn() { echo "${C_YELLOW}$*${C_OFF}" >&2; }
die()  { echo "${C_RED}$*${C_OFF}" >&2; exit 1; }

echo "========================================"
echo "ACoworkNode — Android build"
echo "  build type : $BUILD_TYPE"
echo "  repo       : $REPO_ROOT"
echo "========================================"
echo ""

# ── 1. Toolchain discovery ────────────────────────────────────────────────────
info "[1/5] Locating the toolchain"

# ANDROID_HOME / ANDROID_SDK_ROOT, then the usual per-user locations.
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    case "$(uname -s)" in
        Darwin*) SDK="$HOME/Library/Android/sdk" ;;
        *)       SDK="$HOME/Android/Sdk" ;;
    esac
fi
[ -d "$SDK" ] || die "Android SDK not found — set ANDROID_HOME (looked at '$SDK')"

NDK_HOME="${ANDROID_NDK_HOME:-$SDK/ndk/$NDK_VERSION}"
[ -d "$NDK_HOME" ] || die "NDK $NDK_VERSION not found at $NDK_HOME"

case "$(uname -s)" in
    Linux*)  HOST_TAG="linux-x86_64" ;;
    Darwin*) HOST_TAG="darwin-x86_64" ;;
    MINGW*|MSYS*|CYGWIN*) HOST_TAG="windows-x86_64" ;;
    *) die "unsupported host $(uname -s)" ;;
esac
PREBUILT="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
[ -d "$PREBUILT" ] || die "NDK prebuilt not found at $PREBUILT"
SYSROOT="$PREBUILT/sysroot"

if [ "$HOST_TAG" = "windows-x86_64" ]; then
    NDK_CC="$PREBUILT/bin/aarch64-linux-android26-clang.cmd"
    NDK_CXX="$PREBUILT/bin/aarch64-linux-android26-clang++.cmd"
    NDK_AR="$PREBUILT/bin/llvm-ar.exe"
else
    NDK_CC="$PREBUILT/bin/aarch64-linux-android26-clang"
    NDK_CXX="$PREBUILT/bin/aarch64-linux-android26-clang++"
    NDK_AR="$PREBUILT/bin/llvm-ar"
fi
[ -f "$NDK_CC" ] || die "NDK clang not found at $NDK_CC"

# The JDK must ship jlink: AGP's JdkImageTransform calls it to build the
# android.jar system module image. IDE runtimes (IntelliJ JBR, some Android
# Studio builds) omit jlink and the build dies with
# "jlink executable ... does not exist".
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/jlink" ]; then
    JDK_HOME="$JAVA_HOME"
elif command -v jlink >/dev/null 2>&1; then
    JDK_HOME="$(dirname "$(dirname "$(command -v jlink)")")"
else
    for candidate in \
        /usr/lib/jvm/temurin-17 /usr/lib/jvm/java-17-openjdk-amd64 \
        /usr/lib/jvm/java-17-openjdk /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home \
        "$HOME/.jdks/temurin-17"; do
        if [ -x "$candidate/bin/jlink" ]; then JDK_HOME="$candidate"; break; fi
    done
fi
[ -n "${JDK_HOME:-}" ] || die "no JDK 17 with jlink found — set JAVA_HOME (Temurin 17 recommended)"

# A global ~/.gradle/gradle.properties often pins org.gradle.java.home to an
# IDE runtime WITHOUT jlink. That setting outranks JAVA_HOME, so the build
# would die with the very jlink error we just worked around. Detect it and
# override it for this invocation only.
GRADLE_USER_PROPS="${GRADLE_USER_HOME:-$HOME/.gradle}/gradle.properties"
if [ -f "$GRADLE_USER_PROPS" ] && grep -q "^[[:space:]]*org\.gradle\.java\.home" "$GRADLE_USER_PROPS"; then
    PINNED="$(grep -m1 "^[[:space:]]*org\.gradle\.java\.home" "$GRADLE_USER_PROPS" | cut -d= -f2- | tr -d '\r')"
    if [ ! -x "$PINNED/bin/jlink" ]; then
        warn "  ~/.gradle pins org.gradle.java.home to '$PINNED' (no jlink) — overriding for this build"
        GRADLE_JAVA_HOME_ARG=(-Dorg.gradle.java.home="$JDK_HOME")
    fi
fi
# shellcheck disable=SC2206
[ -z "${GRADLE_JAVA_HOME_ARG:-}" ] && GRADLE_JAVA_HOME_ARG=()

ok "  SDK   : $SDK"
ok "  NDK   : $NDK_HOME"
ok "  JDK   : $JDK_HOME"

rustup target list --installed 2>/dev/null | grep -qx "$CARGO_TARGET" || {
    info "  installing rust target $CARGO_TARGET"
    rustup target add "$CARGO_TARGET"
}

# ── 2. Version ───────────────────────────────────────────────────────────────
info "[2/5] Resolving the version"
VERSION_FILE="$REPO_ROOT/VERSION"
[ -f "$VERSION_FILE" ] || die "VERSION file missing at $VERSION_FILE"
VERSION="$(cat "$VERSION_FILE" | tr -d '[:space:]')"
if [ -n "$VERSION_OVERRIDE" ]; then VERSION="$VERSION_OVERRIDE"; fi
ok "  version : $VERSION"

# ── 3. Native artifacts ──────────────────────────────────────────────────────
if [ "$SKIP_NATIVE" -eq 0 ]; then
    info "[3/5] Cross-compiling the native artifacts"

    # These exports are the whole point of the script: cc-rs compiles C sources
    # for zstd-sys / rusqlite, so it needs the NDK sysroot, not just a linker.
    export ANDROID_NDK_HOME="$NDK_HOME"
    export CC_aarch64_linux_android="$NDK_CC"
    export CXX_aarch64_linux_android="$NDK_CXX"
    export AR_aarch64_linux_android="$NDK_AR"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_CC"
    export CFLAGS_aarch64_linux_android="--sysroot=$SYSROOT"
    export CXXFLAGS_aarch64_linux_android="--sysroot=$SYSROOT"

    ( cd "$REPO_ROOT" && cargo build \
        -p acowork-android-ffi \
        -p acowork-android-cli \
        --release \
        --target "$CARGO_TARGET" )

    JNI_DIR="$ANDROID_DIR/app/src/main/jniLibs/arm64-v8a"
    mkdir -p "$JNI_DIR"
    cp "$REPO_ROOT/target/$CARGO_TARGET/release/libacowork_android_ffi.so" "$JNI_DIR/"
    # The CLI is packaged as lib*.so so AGP extracts it with the +x bit into
    # nativeLibraryDir, where it can be spawned.
    cp "$REPO_ROOT/target/$CARGO_TARGET/release/acowork-android" "$JNI_DIR/libacowork_engine.so"
    ok "  copied libacowork_android_ffi.so + libacowork_engine.so"

    # The packaged POSIX shell (see build_ash.sh for the SELinux reason).
    bash "$SCRIPT_DIR/build_ash.sh"
    cp "$REPO_ROOT/build/android/libacowork_ash.so" "$JNI_DIR/"
    ok "  copied libacowork_ash.so"
else
    info "[3/5] Reusing the existing jniLibs (--skip-native)"
fi

# ── 4. Assemble ──────────────────────────────────────────────────────────────
info "[4/5] Assembling the $BUILD_TYPE APK"
cd "$ANDROID_DIR"

export JAVA_HOME="$JDK_HOME"
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"

GRADLE_ARGS=()
if [ "$BUILD_TYPE" = "release" ]; then
    GRADLE_ARGS+=(":app:assembleRelease")
else
    GRADLE_ARGS+=(":app:assembleDebug")
fi

if [ -n "$KEYSTORE" ]; then
    [ -f "$KEYSTORE" ] || die "keystore not found at $KEYSTORE"
    # The keystore stays on disk; only the path and the passwords are passed
    # to Gradle. Gradle's own signing block reads them from properties.
    GRADLE_ARGS+=("-Pacowork.keystoreFile=$KEYSTORE")
    [ -n "$KEYSTORE_PASS" ] && GRADLE_ARGS+=("-Pacowork.keystorePassword=$KEYSTORE_PASS")
    [ -n "$KEY_ALIAS" ] && GRADLE_ARGS+=("-Pacowork.keyAlias=$KEY_ALIAS")
    [ -n "$KEY_PASS" ] && GRADLE_ARGS+=("-Pacowork.keyPassword=$KEY_PASS")
    ok "  signing with $KEYSTORE"
elif [ -f "$REPO_ROOT/keystore.properties" ]; then
    ok "  signing with the local keystore.properties"
elif [ "$BUILD_TYPE" = "release" ]; then
    warn "  no signing configuration — the release APK will be UNSIGNED"
    # The common near-miss: the keystore exists but the per-machine binding
    # does not, so say which of the two steps is actually missing.
    if compgen -G "$REPO_ROOT/keys/*.jks" >/dev/null 2>&1 || compgen -G "$REPO_ROOT/keys/*.keystore" >/dev/null 2>&1; then
        warn "  a keystore IS present in keys/ but keystore.properties is absent -"
        warn "  bind it with: ./dev/android/setup_keystore.sh"
    else
        warn "  create one with: ./dev/android/setup_keystore.sh (or pass --keystore)"
    fi
fi

GRADLE_ARGS+=("-Pacowork.version=$VERSION")
./gradlew "${GRADLE_ARGS[@]}" "${GRADLE_JAVA_HOME_ARG[@]}"

OUT_DIR="$ANDROID_DIR/app/build/outputs/apk/$BUILD_TYPE"
APK="$(find "$OUT_DIR" -name '*.apk' -print -quit 2>/dev/null || true)"
[ -n "$APK" ] || die "no APK produced in $OUT_DIR"
ok "  APK: $APK ($(du -h "$APK" | cut -f1))"

# Report the signing state, so an unsigned artifact is never mistaken for a
# signed one. `apksigner verify` is the authority.
#
# NOTE: an APK signed with the v2/v3 schemes carries NO META-INF/*.RSA entry
# (that is the v1/JAR scheme), so "is there a .RSA file" is NOT a valid
# signing check - it reports "absent" for a correctly signed APK.
if [ "$BUILD_TYPE" = "release" ]; then
    # apksigner is `apksigner.bat` on Windows and a plain script elsewhere.
    APKSIGNER="$(find "$SDK/build-tools" \( -name apksigner -o -name apksigner.bat \) -type f 2>/dev/null | sort -V | tail -1 || true)"
    if [ -z "$APKSIGNER" ]; then
        warn "  apksigner not found — cannot verify the signature"
    elif "$APKSIGNER" verify --print-certs "$APK" > /dev/null 2>&1; then
        ok "  signature: VERIFIED"
        "$APKSIGNER" verify --print-certs "$APK" 2>/dev/null | grep -i "DN:" | head -2 | sed 's/^/    /'
    else
        warn "  signature: NOT VERIFIED (unsigned APK)"
    fi
fi

# ── 5. Install ───────────────────────────────────────────────────────────────
if [ "$INSTALL" -eq 1 ]; then
    info "[5/5] Installing on the connected device"
    ADB="$SDK/platform-tools/adb"
    [ -x "$ADB" ] || die "adb not found at $ADB"
    "$ADB" install -r "$APK"
    # adb's exit code is the only failure signal here.
    ok "  installed"
    echo "  Launch: adb shell monkey -p com.acowork.androidhost -c android.intent.category.LAUNCHER 1"
else
    info "[5/5] Skipping the device install (--install to install)"
fi

echo ""
ok "Done."
