#!/usr/bin/env bash
# setup_keystore.sh - Configure local ACoworkNode signing.
#
# WHY THIS IS A SEPARATE STEP
#   The keystore is the app's identity to the device. Losing it means the app
#   can never be upgraded in place, and publishing it means anyone can sign an
#   update. So it is created ONCE, kept on the maintainer's disk, and never
#   committed.
#
#   Both halves land in git-ignored paths by default (keys/ and
#   keystore.properties), so an accidental `git add -A` cannot commit either.
#
# WHAT IT DOES
#   1. Creates keys/acoworknode.jks, or reuses the one already there. It never
#      regenerates an existing identity - doing that silently breaks in-place
#      upgrades for every device already installed.
#   2. Writes keystore.properties, the per-machine binding that makes a release
#      build signed. Re-running this script on a fresh clone with a keystore you
#      already own is the supported way to restore that binding.
#
# USAGE
#   ./dev/android/setup_keystore.sh                     interactive
#   ./dev/android/setup_keystore.sh --alias acoworknode --out keys/acoworknode.jks
#   ./dev/android/setup_keystore.sh --no-properties     bind via environment vars
#
# The passwords are prompted for (never taken as a command-line argument, so
# they do not land in the shell history or in the process list).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

ALIAS="acoworknode"
OUT=""
KEY_SIZE=2048
VALIDITY=10000
PROPS=""
NO_PROPERTIES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --alias)         ALIAS="${2:?--alias needs a value}"; shift ;;
        --out)           OUT="${2:?--out needs a value}"; shift ;;
        --props)         PROPS="${2:?--props needs a value}"; shift ;;
        --no-properties) NO_PROPERTIES=1 ;;
        --key-size)      KEY_SIZE="${2:?--key-size needs a value}"; shift ;;
        --validity)      VALIDITY="${2:?--validity needs a value}"; shift ;;
        -h|--help)       sed -n '2,27p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$OUT" ]; then
    OUT="$REPO_ROOT/keys/acoworknode.jks"
elif [[ "$OUT" != /* ]]; then
    OUT="$REPO_ROOT/$OUT"
fi

if [ -z "$PROPS" ]; then
    PROPS="$REPO_ROOT/keystore.properties"
elif [[ "$PROPS" != /* ]]; then
    PROPS="$REPO_ROOT/$PROPS"
fi

if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_OFF=""
fi
info() { echo "${C_CYAN}$*${C_OFF}"; }
ok()   { echo "${C_GREEN}$*${C_OFF}"; }
warn() { echo "${C_YELLOW}$*${C_OFF}" >&2; }
die()  { echo "${C_RED}$*${C_OFF}" >&2; exit 1; }

# A file holding a signing password must not be readable by other people.
# Claiming "mode 600" without checking is worse than not claiming it, and on
# Windows the check has to be about the ACL: MSYS chmod is advisory there, so a
# file reported as 600 can still be world-readable through an inherited NTFS
# ACE that grants every local user read.
harden() {
    _f="$1"
    chmod 600 "$_f" 2>/dev/null || true

    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*)
            _w="$(_winpath "$_f")"
            if command -v icacls >/dev/null 2>&1 &&
               icacls "$_w" 2>/dev/null |
                   grep -qE '(BUILTIN\\Users|BUILTIN\\Administrators|Authenticated Users):\(?I\)'; then
                warn "  $_f is readable by every local user (inherited NTFS ACE)."
                warn "  chmod cannot fix that on Windows - the ACL decides. From cmd.exe:"
                warn ""
                warn "    icacls $_w /inheritance:r /grant:r \"%USERNAME%:F\""
                warn ""
                warn "  (Prove it on a copy first: a mistyped principal there can"
                warn "  lock you out of your own keystore.)"
                return 1
            fi
            return 0
            ;;
    esac

    _mode="$(stat -c '%a' "$_f" 2>/dev/null || stat -f '%Lp' "$_f" 2>/dev/null || echo unknown)"
    if [ "$_mode" = "600" ]; then
        return 0
    fi
    warn "  $_f ended up mode $_mode, not 600 - this filesystem ignores POSIX modes."
    return 1
}

# Native form of a path, for the tools of the host OS rather than for bash.
_winpath() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s\n' "$1"
    fi
}

# keystore.properties is read by a JVM, not by bash, so an MSYS path is not
# merely ugly there: Java's File.isAbsolute() wants a drive letter, so
# '/e/projects/...' counts as RELATIVE and Gradle resolves it against the app
# module, yielding 'apps\android\app\e\projects\...'. A repository-relative path
# is correct on every platform, because build.gradle.kts resolves relative
# values against the repository root.
to_props_path() {
    _p="$1"
    case "$_p" in
        "$REPO_ROOT"/*) printf '%s\n' "${_p#"$REPO_ROOT"/}" ;;
        *)
            if command -v cygpath >/dev/null 2>&1; then
                cygpath -w "$_p"
            else
                printf '%s\n' "$_p"
            fi
            ;;
    esac
}

# The keystore is created ONCE and then lives for the app's whole upgrade life.
# The properties file, by contrast, is per-machine: a fresh clone of a repo you
# already have a keystore for needs the binding, not a new identity. So an
# existing keystore is a supported input, never an error - and never something
# this script silently replaces.
REUSED=0
if [ -f "$OUT" ]; then
    REUSED=1
    warn "Using the existing keystore at $OUT (not regenerating it)."
    warn "A new identity here would break in-place upgrades for every installed"
    warn "device. If you truly mean to start over, delete the file first."
fi

# keytool lives in the JDK.
KEYTOOL=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ]; then
    KEYTOOL="$JAVA_HOME/bin/keytool"
elif command -v keytool >/dev/null 2>&1; then
    KEYTOOL="$(command -v keytool)"
else
    for c in "$HOME/.jdks/temurin-17" "/usr/lib/jvm/temurin-17" "/usr/lib/jvm/java-17-openjdk"; do
        [ -x "$c/bin/keytool" ] && KEYTOOL="$c/bin/keytool" && break
    done
fi
[ -n "$KEYTOOL" ] || die "keytool not found - set JAVA_HOME to a JDK"

mkdir -p "$(dirname "$OUT")"

if [ ! -t 0 ]; then
    die "no controlling terminal - this script prompts for passwords. In CI, supply the signing material through the ACOWORK_KEYSTORE_FILE / ACOWORK_KEYSTORE_PASSWORD / ACOWORK_KEY_ALIAS / ACOWORK_KEY_PASSWORD environment variables instead."
fi

info "ACoworkNode signing configuration"
info "  file     : $OUT"
info "  alias    : $ALIAS"
info "  props    : $PROPS"
info ""

# The two passwords are prompted for separately but may be the same value;
# -storepass and -keypass are kept distinct so a keystore with a separate key
# password remains expressible. They are never taken as arguments, so they do
# not land in the shell history or in the process list.
read -rsp "Keystore password: " STORE_PASS; echo
read -rsp "Key password (Enter = same as store): " KEY_PASS; echo
[ -n "$KEY_PASS" ] || KEY_PASS="$STORE_PASS"
[ -n "$STORE_PASS" ] || die "the keystore password must not be empty"

if [ "$REUSED" -eq 0 ]; then
    "$KEYTOOL" -genkeypair \
        -alias "$ALIAS" \
        -keyalg RSA -keysize "$KEY_SIZE" -validity "$VALIDITY" \
        -keystore "$OUT" \
        -storetype JKS \
        -storepass "$STORE_PASS" -keypass "$KEY_PASS" \
        -dname "CN=ACoworkNode, OU=ACowork, O=ACowork, L=Shanghai, ST=Shanghai, C=CN" \
        || die "keytool failed"
    harden "$OUT" || true
    ok "Keystore created: $OUT"
else
    # A wrong password discovered at install time looks like a signing failure
    # in a Gradle stack trace; discover it here, where the message can say what
    # actually happened.
    "$KEYTOOL" -list -keystore "$OUT" -storepass "$STORE_PASS" -alias "$ALIAS" \
        >/dev/null 2>&1 \
        || die "the keystore at $OUT has no alias '$ALIAS' for that password - re-run with the right --alias, or the wrong file"
    ok "Keystore verified: alias '$ALIAS' present"
fi

# ── Bind the identity to the build ───────────────────────────────────────────
# keystore.properties is git-ignored, so writing it is what makes a release
# build signed without ever putting the password in the tree. Leaving it to the
# developer to hand-create meant the failure mode was a silently UNSIGNED
# release APK.
if [ "$NO_PROPERTIES" -eq 1 ]; then
    warn ""
    warn "Not writing $PROPS (--no-properties)."
    warn "Export ACOWORK_KEYSTORE_FILE / ACOWORK_KEYSTORE_PASSWORD /"
    warn "ACOWORK_KEY_ALIAS / ACOWORK_KEY_PASSWORD instead, or release builds"
    warn "will be unsigned."
else
    if [ -f "$PROPS" ]; then
        warn ""
        warn "Replacing the existing $PROPS"
    fi
    umask 077
    PROPS_KEYSTORE="$(to_props_path "$OUT")"
    cat > "$PROPS" <<EOF
# Local ACoworkNode signing configuration - NEVER COMMIT THIS FILE.
# Written by dev/android/setup_keystore.sh; read by apps/android/app/build.gradle.kts.
# keystoreFile is relative to the repository root (absolute also works, but a
# relative path survives a move of the checkout and needs no drive letter).
acowork.keystoreFile=$PROPS_KEYSTORE
acowork.keystorePassword=$STORE_PASS
acowork.keyAlias=$ALIAS
acowork.keyPassword=$KEY_PASS
EOF
    unset STORE_PASS KEY_PASS
    harden "$PROPS" || true
    ok "Wrote $PROPS (git-ignored)"
    ok "  acowork.keystoreFile=$PROPS_KEYSTORE"
fi

warn ""
warn "Keep the keystore and its passwords OFF the git-tracked tree and off any"
warn "shared drive. The keystore is the app's upgrade identity - losing it means"
warn "the app can never be updated in place, and leaking it means anyone can"
warn "sign an update the device will accept."
warn ""
ok "Next: ./dev/android/build_android.sh --release   (or .\\dev\\android\\build_android.ps1 -Release)"
