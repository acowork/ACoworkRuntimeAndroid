# Re-copy the Runtime dependency closure from a local ACowork checkout.
# Usage: .\scripts\sync-vendor.ps1 [-UpstreamRoot E:\projects\tranxon\ACowork]
param(
    [string]$UpstreamRoot = "E:\projects\tranxon\ACowork"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$core = Join-Path $UpstreamRoot "core"
$destRoot = Join-Path $here "crates\vendor"
$crates = @(
    "acowork-core",
    "acowork-memory",
    "acowork-sqlite",
    "acowork-mcp",
    "acowork-mqtt-session",
    "acowork-runtime"
)

$commit = git -C $UpstreamRoot rev-parse HEAD
$meta = git -C $UpstreamRoot log -1 --format="%h %ci %s"
Write-Host "Upstream: $meta"

foreach ($c in $crates) {
    $src = Join-Path $core $c
    $dst = Join-Path $destRoot $c
    if (-not (Test-Path $src)) { throw "missing $src" }
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse -Force $src $dst
    # Drop integration tests that need gateway/eval
    $tests = Join-Path $dst "tests"
    if (Test-Path $tests) { Remove-Item -Recurse -Force $tests }
    Write-Host "synced $c"
}

Write-Host "Update docs/VENDOR.md commit to: $commit"
Write-Host "Re-apply android-host patches (android_exec.rs, platform.rs, shell.rs, Cargo.toml features) if this was a clean overwrite."
