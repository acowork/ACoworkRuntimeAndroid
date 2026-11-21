#!/usr/bin/env pwsh
# build_android.ps1 - One-command APK build for ACoworkNode (Windows).
#
# This is the PowerShell twin of dev/android/build_android.sh. The two scripts
# implement the SAME contract; the main repo ships the same pair for the same
# reason (a PowerShell install is a second language and a ~200MB dependency for
# a machine that already has bash). When you change a step in one, change the
# other.
#
# Usage:
#   .\dev\android\build_android.ps1                     debug APK (default)
#   .\dev\android\build_android.ps1 -Release
#   .\dev\android\build_android.ps1 -Release -Install
#   .\dev\android\build_android.ps1 -Install
#   .\dev\android\build_android.ps1 -SkipNative
#   .\dev\android\build_android.ps1 -Release -Keystore C:\keys\acoworknode.jks `
#       -KeystorePassword $pw -KeyAlias acoworknode -KeyPassword $pw
#
# Requires: PowerShell 7+, cargo + the aarch64-linux-android target, a JDK 17
# that ships jlink (Temurin works; some IDE JBRs omit jlink and break AGP),
# the Android SDK, and the NDK 26.1.10909125.

[CmdletBinding()]
param(
    [switch] $Release,
    [switch] $Install,
    [switch] $SkipNative,
    [string] $Keystore,
    [string] $KeystorePassword,
    [string] $KeyAlias,
    [string] $KeyPassword,
    [string] $Version
)

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$REPO_ROOT  = Split-Path -Parent (Split-Path -Parent $SCRIPT_DIR)
$ANDROID_DIR = Join-Path $REPO_ROOT "apps\android"
$NDK_VERSION = "26.1.10909125"
$CARGO_TARGET = "aarch64-linux-android"

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }
function Die($m)  { Write-Host $m -ForegroundColor Red; exit 1 }

# Git Bash reads backslashes as escape characters, and PowerShell hands native
# arguments over verbatim, so 'E:\dev\android\build_ash.sh' arrives at bash as
# 'E:devandroidbuild_ash.sh'. Convert to the POSIX form bash can resolve.
function To-BashPath([string] $Path) {
    if (Get-Command cygpath.exe -ErrorAction SilentlyContinue) {
        return ((& cygpath -u $Path) -join '').Trim()
    }
    $posix = $Path -replace '\\', '/'
    if ($posix -match '^([A-Za-z]):/(.*)$') {
        return '/' + $Matches[1].ToLower() + '/' + $Matches[2]
    }
    return $posix
}

# Bare 'bash' resolves to WSL's bash.exe on a machine that has WSL enabled, and
# WSL mounts this drive at /mnt/e rather than /e - so it reports a correctly
# converted path as missing. Locate Git Bash from the git install instead of
# trusting PATH.
function Resolve-GitBash {
    $candidates = @()
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) {
        $cmdDir = Split-Path -Parent $git.Source
        $candidates += (Join-Path $cmdDir "..\bin\bash.exe")
        $candidates += (Join-Path (Split-Path -Parent $cmdDir) "bin\bash.exe")
    }
    $candidates += "C:\Program Files\Git\bin\bash.exe"
    foreach ($c in $candidates) {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($c)
        if (Test-Path $full) { return $full }
    }
    return $null
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ACoworkNode - Android build" -ForegroundColor Cyan
Write-Host ("  build type : " + $(if ($Release) { "release" } else { "debug" })) -ForegroundColor Cyan
Write-Host ("  repo       : " + $REPO_ROOT) -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Toolchain discovery ───────────────────────────────────────────────────
Info "[1/5] Locating the toolchain"

$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
if (-not $sdk) { $sdk = Join-Path $HOME "AppData\Local\Android\Sdk" }
if (-not (Test-Path $sdk)) { Die "Android SDK not found - set ANDROID_HOME (looked at '$sdk')" }

$ndkHome = $env:ANDROID_NDK_HOME
if (-not $ndkHome) { $ndkHome = Join-Path $sdk "ndk\$NDK_VERSION" }
if (-not (Test-Path $ndkHome)) { Die "NDK $NDK_VERSION not found at $ndkHome" }

$prebuilt = Join-Path $ndkHome "toolchains\llvm\prebuilt\windows-x86_64"
if (-not (Test-Path $prebuilt)) { Die "NDK prebuilt not found at $prebuilt" }
$sysroot = Join-Path $prebuilt "sysroot"

# AGP's JdkImageTransform calls jlink to build the android.jar system module
# image. IDE runtimes (IntelliJ JBR, some Android Studio builds) omit jlink and
# the build dies with "jlink executable ... does not exist".
function Find-JdkWithJlink {
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += $env:JAVA_HOME }
    $candidates += (Join-Path $HOME ".jdks\temurin-17")
    $candidates += "C:\Program Files\Eclipse Adoptium"
    $candidates += "C:\Program Files\Android\Android Studio\jbr"
    $candidates += "C:\Program Files\Java"
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "bin\jlink.exe")) { return $c }
    }
    if (Get-Command jlink -ErrorAction SilentlyContinue) {
        return (Split-Path -Parent (Split-Path -Parent (Get-Command jlink).Source))
    }
    return $null
}
$jdkHome = Find-JdkWithJlink
if (-not $jdkHome) { Die "no JDK 17 with jlink found - set JAVA_HOME (Temurin 17 recommended)" }

# A global ~/.gradle/gradle.properties often pins org.gradle.java.home to an
# IDE runtime WITHOUT jlink. That setting outranks JAVA_HOME, so the build
# would die with the very jlink error we just worked around. Detect it and
# override it for this invocation only.
$gradleUserProps = Join-Path ($(if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $HOME ".gradle" })) "gradle.properties"
$gradleJavaHomeArg = @()
if (Test-Path $gradleUserProps) {
    $pinned = (Select-String -Path $gradleUserProps -Pattern '^\s*org\.gradle\.java\.home\s*=' | Select-Object -First 1)
    if ($pinned) {
        $pinnedPath = ($pinned.Line -split '=', 2)[1].Trim()
        if (-not (Test-Path (Join-Path $pinnedPath "bin\jlink.exe"))) {
            Warn "  ~/.gradle pins org.gradle.java.home to '$pinnedPath' (no jlink) - overriding for this build"
            $gradleJavaHomeArg = @("-Dorg.gradle.java.home=$jdkHome")
        }
    }
}

Ok "  SDK   : $sdk"
Ok "  NDK   : $ndkHome"
Ok "  JDK   : $jdkHome"

$installed = rustup target list --installed 2>$null
if ($installed -notcontains $CARGO_TARGET) {
    Info "  installing rust target $CARGO_TARGET"
    rustup target add $CARGO_TARGET
    if ($LASTEXITCODE -ne 0) { Die "rustup target add failed" }
}

# ── 2. Version ───────────────────────────────────────────────────────────────
Info "[2/5] Resolving the version"
$versionFile = Join-Path $REPO_ROOT "VERSION"
if (-not (Test-Path $versionFile)) { Die "VERSION file missing at $versionFile" }
$resolvedVersion = (Get-Content $versionFile -Raw).Trim()
if ($Version) { $resolvedVersion = $Version }
Ok "  version : $resolvedVersion"

# ── 3. Native artifacts ──────────────────────────────────────────────────────
if (-not $SkipNative) {
    Info "[3/5] Cross-compiling the native artifacts"

    # These exports are the whole point of the script: cc-rs compiles C sources
    # for zstd-sys / rusqlite, so it needs the NDK sysroot, not just a linker.
    $env:ANDROID_NDK_HOME = $ndkHome
    $env:CC_aarch64_linux_android  = Join-Path $prebuilt "bin\aarch64-linux-android26-clang.cmd"
    $env:CXX_aarch64_linux_android = Join-Path $prebuilt "bin\aarch64-linux-android26-clang++.cmd"
    $env:AR_aarch64_linux_android  = Join-Path $prebuilt "bin\llvm-ar.exe"
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = Join-Path $prebuilt "bin\aarch64-linux-android26-clang.cmd"
    $env:CFLAGS_aarch64_linux_android  = "--sysroot=$sysroot"
    $env:CXXFLAGS_aarch64_linux_android = "--sysroot=$sysroot"

    Push-Location $REPO_ROOT
    try {
        cargo build -p acowork-android-ffi -p acowork-android-cli --release --target $CARGO_TARGET
        if ($LASTEXITCODE -ne 0) { Die "cargo build failed (exit $LASTEXITCODE)" }
    } finally { Pop-Location }

    $jniDir = Join-Path $ANDROID_DIR "app\src\main\jniLibs\arm64-v8a"
    New-Item -ItemType Directory -Path $jniDir -Force | Out-Null
    Copy-Item -Force (Join-Path $REPO_ROOT "target\$CARGO_TARGET\release\libacowork_android_ffi.so") $jniDir
    # The CLI is packaged as lib*.so so AGP extracts it with the +x bit into
    # nativeLibraryDir, where it can be spawned.
    Copy-Item -Force (Join-Path $REPO_ROOT "target\$CARGO_TARGET\release\acowork-android") (Join-Path $jniDir "libacowork_engine.so")
    Ok "  copied libacowork_android_ffi.so + libacowork_engine.so"

    # The packaged POSIX shell (see build_ash.sh for the SELinux reason).
    # It is built by the bash script on purpose: porting it would mean keeping
    # two copies of the mksh flags in sync, which is how a build script starts
    # lying about what it produces.
    $gitBash = Resolve-GitBash
    if (-not $gitBash) {
        Die "Git Bash not found - build_ash.sh needs it (set PATH or install Git for Windows)"
    }
    & $gitBash (To-BashPath (Join-Path $SCRIPT_DIR "build_ash.sh"))
    if ($LASTEXITCODE -ne 0) { Die "build_ash.sh failed (exit $LASTEXITCODE)" }
    Copy-Item -Force (Join-Path $REPO_ROOT "build\android\libacowork_ash.so") $jniDir
    Ok "  copied libacowork_ash.so"
} else {
    Info "[3/5] Reusing the existing jniLibs (-SkipNative)"
}

# ── 4. Assemble ──────────────────────────────────────────────────────────────
Info "[4/5] Assembling the $(if ($Release) { 'release' } else { 'debug' }) APK"

$env:JAVA_HOME = $jdkHome
$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk

$gradleArgs = @()
if ($Release) { $gradleArgs += ":app:assembleRelease" } else { $gradleArgs += ":app:assembleDebug" }

if ($Keystore) {
    if (-not (Test-Path $Keystore)) { Die "keystore not found at $Keystore" }
    # The keystore stays on disk; only the path and the passwords are passed
    # to Gradle. Gradle's own signing block reads them from properties.
    $gradleArgs += "-Pacowork.keystoreFile=$Keystore"
    if ($KeystorePassword) { $gradleArgs += "-Pacowork.keystorePassword=$KeystorePassword" }
    if ($KeyAlias)         { $gradleArgs += "-Pacowork.keyAlias=$KeyAlias" }
    if ($KeyPassword)      { $gradleArgs += "-Pacowork.keyPassword=$KeyPassword" }
    Ok "  signing with $Keystore"
} elseif (Test-Path (Join-Path $REPO_ROOT "keystore.properties")) {
    Ok "  signing with the local keystore.properties"
} elseif ($Release) {
    Warn "  no signing configuration - the release APK will be UNSIGNED"
    # The common near-miss: the keystore exists but the per-machine binding
    # does not, so say which of the two steps is actually missing.
    # (Get-ChildItem -Include is only applied when -Path carries a wildcard or
    # -Recurse is set, which silently returns nothing for a plain directory -
    # so filter the extension afterwards instead.)
    $keysDir = Join-Path $REPO_ROOT "keys"
    $localKeys = @(
        if (Test-Path $keysDir) {
            Get-ChildItem -LiteralPath $keysDir -File |
                Where-Object { $_.Extension -in ".jks", ".keystore" }
        }
    )
    if ($localKeys.Count -gt 0) {
        Warn "  a keystore IS present in keys\ but keystore.properties is absent -"
        Warn "  bind it with: .\dev\android\setup_keystore.sh"
    } else {
        Warn "  create one with: .\dev\android\setup_keystore.sh (or pass -Keystore)"
    }
}

$gradleArgs += "-Pacowork.version=$resolvedVersion"

Push-Location $ANDROID_DIR
try {
    & .\gradlew @gradleArgs @gradleJavaHomeArg
    if ($LASTEXITCODE -ne 0) { Die "gradle build failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

$buildType = if ($Release) { "release" } else { "debug" }
$outDir = Join-Path $ANDROID_DIR "app\build\outputs\apk\$buildType"
$apk = Get-ChildItem -Path $outDir -Filter *.apk -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $apk) { Die "no APK produced in $outDir" }
Ok ("  APK: " + $apk.FullName + "  (" + [math]::Round($apk.Length/1MB,1) + " MB)")

# Report the signing state, so an unsigned artifact is never mistaken for a
# signed one.
if ($Release) {
    $apksigner = Get-ChildItem -Path (Join-Path $sdk "build-tools") -Filter apksigner.bat -Recurse -ErrorAction SilentlyContinue |
                 Sort-Object FullName | Select-Object -Last 1
    if ($apksigner) {
        & $apksigner.FullName verify --print-certs $apk.FullName | Out-Null
        if ($LASTEXITCODE -eq 0) { Ok "  signature: VERIFIED" }
        else { Warn "  signature: NOT VERIFIED (unsigned APK)" }
    } else {
        Warn "  apksigner not found - cannot verify the signature"
    }
}

# ── 5. Install ───────────────────────────────────────────────────────────────
if ($Install) {
    Info "[5/5] Installing on the connected device"
    $adb = Join-Path $sdk "platform-tools\adb.exe"
    if (-not (Test-Path $adb)) { Die "adb not found at $adb" }
    & $adb install -r $apk.FullName
    if ($LASTEXITCODE -ne 0) { Die "adb install failed (exit $LASTEXITCODE) - the device is still running the PREVIOUS build." }
    Ok "  installed"
    Write-Host "  Launch: adb shell monkey -p com.acowork.androidhost -c android.intent.category.LAUNCHER 1" -ForegroundColor DarkGray
} else {
    Info "[5/5] Skipping the device install (-Install to install)"
}

Write-Host ""
Ok "Done."
