# Set env vars so `cargo build --target aarch64-linux-android` uses the NDK.
# Usage: . .\scripts\android-ndk-env.ps1
param(
    [string]$NdkVersion = "26.1.10909125"
)

$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = "D:\Android\Sdk" }
$ndk = Join-Path $sdk "ndk\$NdkVersion"
if (-not (Test-Path $ndk)) { throw "NDK not found at $ndk" }

$prebuilt = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64"
$clang = Join-Path $prebuilt "bin\aarch64-linux-android26-clang.cmd"
$sysroot = Join-Path $prebuilt "sysroot"

$env:ANDROID_NDK_HOME = $ndk
$env:CC_aarch64_linux_android = $clang
$env:CXX_aarch64_linux_android = (Join-Path $prebuilt "bin\aarch64-linux-android26-clang++.cmd")
$env:AR_aarch64_linux_android = (Join-Path $prebuilt "bin\llvm-ar.exe")
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $clang
$env:CFLAGS_aarch64_linux_android = "--sysroot=$sysroot"
$env:CXXFLAGS_aarch64_linux_android = "--sysroot=$sysroot"

Write-Host "ANDROID_NDK_HOME=$ndk"
Write-Host "CC=$clang"
