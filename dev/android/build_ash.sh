#!/usr/bin/env bash
# build_ash.sh - Cross-compile the packaged POSIX shell (mksh R57) for arm64-v8a.
#
# WHY THIS EXISTS
#   The Android host needs a shell it is ALLOWED to execute. On a device with
#   Enforcing SELinux, an untrusted_app cannot exec /system/bin/sh (shell_exec),
#   which is why in-app probes used to collapse to the apk-sandbox profile and
#   every ash tool call failed. The workaround is to package a shell as a
#   jniLib so Android extracts it into nativeLibraryDir with the +x bit, where
#   the app may execute it.
#
#   The packaged shell is mksh R57 (MirBSD KSH), cross-compiled for Android.
#   It is a THIRD-PARTY binary: it is never committed to this repository
#   (it lands in the git-ignored build/ directory) and is rebuilt from a
#   pinned upstream commit so the build is reproducible.
#
#   Upstream: https://github.com/mirbsd/mksh
#   Pinned commit: 1050c2e888252178108786881f59ebd87aa69e72 ("bump", 2019-03-01)
#     -> the exact release whose version string the shipped binary reports:
#        KSH_VERSION=@(#)MIRBSD KSH R57 2019/03/01 Android
#
# USAGE
#   ./dev/android/build_ash.sh              build into build/android/
#   ./dev/android/build_ash.sh --skip-build reuse an existing build/android/libacowork_ash.so
#
# Requires: git, and the Android NDK (ANDROID_NDK_HOME or ANDROID_HOME/ndk/<ver>).

set -euo pipefail

SKIP_BUILD=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1 ;;
        -h|--help)    sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$REPO_ROOT/build/android"
OUT_BIN="$OUT_DIR/libacowork_ash.so"

MKSH_COMMIT="1050c2e888252178108786881f59ebd87aa69e72"
MKSH_REPO="https://github.com/mirbsd/mksh.git"
NDK_VERSION="26.1.10909125"

if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_OFF=""
fi
info() { echo "${C_CYAN}$*${C_OFF}"; }
ok()   { echo "${C_GREEN}$*${C_OFF}"; }
warn() { echo "${C_YELLOW}$*${C_OFF}" >&2; }
die()  { echo "${C_RED}$*${C_OFF}" >&2; exit 1; }

if [ "$SKIP_BUILD" -eq 1 ]; then
    [ -f "$OUT_BIN" ] || die "no $OUT_BIN to reuse"
    ok "Reusing $OUT_BIN"
    exit 0
fi

# ── Toolchain ────────────────────────────────────────────────────────────────
# A non-bash caller (the PowerShell build script, a CI shell) hands over
# ANDROID_NDK_HOME in Windows form. mksh's Build.sh then runs $CC in a command
# position, where bash reads its backslashes as escapes: 'D:\ndk\26.1' turns
# into 'D:ndk261'. MSYS converts paths for its own file tests, so the toolchain
# LOOKS valid right up until the compile step fails. Normalise once, here, so
# every caller is safe.
to_posix() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        # No MSYS helper means Linux/macOS, where the path is already POSIX.
        printf '%s\n' "$1"
    fi
}

NDK_HOME="${ANDROID_NDK_HOME:-}"
if [ -z "$NDK_HOME" ] && [ -n "${ANDROID_HOME:-}" ]; then
    NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
fi
[ -n "$NDK_HOME" ] || die "ANDROID_NDK_HOME not set and no ANDROID_HOME/ndk/$NDK_VERSION"
NDK_HOME="$(to_posix "$NDK_HOME")"
[ -d "$NDK_HOME" ] || die "NDK not found at $NDK_HOME"

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
    CC="$PREBUILT/bin/aarch64-linux-android26-clang.cmd"
    STRIP="$PREBUILT/bin/llvm-strip.exe"
else
    CC="$PREBUILT/bin/aarch64-linux-android26-clang"
    STRIP="$PREBUILT/bin/llvm-strip"
fi
[ -f "$CC" ] || die "NDK clang not found at $CC"

# ── Fetch the pinned upstream source ─────────────────────────────────────────
SRC_DIR="$REPO_ROOT/build/mksh-src"
mkdir -p "$REPO_ROOT/build"
if [ ! -d "$SRC_DIR/.git" ]; then
    info "Cloning mksh (pinned $MKSH_COMMIT)"
    rm -rf "$SRC_DIR"
    git clone --quiet "$MKSH_REPO" "$SRC_DIR"
fi
cd "$SRC_DIR"
git fetch --quiet origin "$MKSH_COMMIT" 2>/dev/null || true
git checkout --quiet --detach "$MKSH_COMMIT" 2>/dev/null || {
    # A shallow clone may not have the commit; deepen and retry.
    git fetch --quiet --unshallow origin 2>/dev/null || git fetch --quiet --depth 200 origin
    git checkout --quiet --detach "$MKSH_COMMIT"
}

# Build.sh parses rlimits.opt and dies on CRLF line endings, which a Windows
# git checkout with core.autocrlf=true produces. Strip them everywhere.
#
# The CR is detected with grep -U: without it, grep treats $'\r' as the two
# characters backslash-r and never matches a real carriage return.
if grep -qU $'\r' rlimits.opt 2>/dev/null; then
    warn "Normalising CRLF line endings (Windows checkout)"
    for f in *.c *.h *.opt *.1 Makefile Build.sh; do
        [ -f "$f" ] && sed -i 's/\r$//' "$f"
    done
fi

# ── Cross-compile ────────────────────────────────────────────────────────────
# TARGET_OS=Android is mksh's own switch for an Android target.
# MKSH_SMALL keeps the binary small; the " Android" version suffix is the
# vendor extension that identifies the build as the Android one.
info "Building mksh R57 for aarch64-linux-android"
export TARGET_OS=Android
export CC="$CC"
export CFLAGS="--sysroot=$SYSROOT -Os -fPIE"
export CPPFLAGS="-DMKSH_SMALL '-DKSH_VERSIONNAME_VENDOR_EXT=\" Android\"'"
export LDFLAGS="-Wl,-z,max-page-size=16384 -pie -Wl,--gc-sections"
sh Build.sh -r > "$REPO_ROOT/build/mksh-build.log" 2>&1 || {
    warn "mksh build failed — see build/mksh-build.log"
    tail -30 "$REPO_ROOT/build/mksh-build.log" >&2
    exit 1
}
[ -f mksh ] || die "mksh binary not produced"

# Android requires 16 KB page alignment on recent targets.
"$STRIP" --strip-all mksh -o mksh.stripped
mkdir -p "$OUT_DIR"
cp mksh.stripped "$OUT_BIN"
chmod +x "$OUT_BIN"
ok "Packaged shell: $OUT_BIN ($(wc -c < "$OUT_BIN") bytes)"

# ── Verify the version string ────────────────────────────────────────────────
# The shipped binary reports "MIRBSD KSH R57 2019/03/01 Android". If this ever
# changes, the APK's shell contract changed with it, so fail loudly.
if ! strings "$OUT_BIN" 2>/dev/null | grep -q "MIRBSD KSH R57"; then
    if ! grep -a -q "MIRBSD KSH R57" "$OUT_BIN"; then
        die "built shell does not report 'MIRBSD KSH R57' — the pinned commit is wrong"
    fi
fi
ok "Version string verified"
