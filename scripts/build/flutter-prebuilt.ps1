[CmdletBinding()]
param(
    [ValidateSet("windows", "linux", "macos", "android", "ios")]
    [string]$Platform,
    [switch]$Locked
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$Package = Join-Path $Root "apps/rustbox-flutter"
$Manifest = Join-Path $Package "rust/Cargo.toml"
$Native = Join-Path $Package "native"
$CargoArgs = @("build", "--release", "--manifest-path", $Manifest, "--package", "rustbox-flutter-bridge")
if ($Locked) { $CargoArgs += "--locked" }

if (-not $Platform) {
    $Platform = if ($IsWindows) { "windows" } elseif ($IsMacOS) { "macos" } else { "linux" }
}

function Build-Target([string]$Target) {
    & cargo @CargoArgs --target $Target
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed for $Target" }
}

function Copy-Binary([string]$Source, [string]$Destination) {
    $Destination = [System.IO.Path]::GetFullPath($Destination)
    New-Item -ItemType Directory -Force (Split-Path $Destination -Parent) | Out-Null
    Copy-Item -Force -LiteralPath $Source -Destination $Destination
    Write-Host "Prepared $Destination"
}

switch ($Platform) {
    "windows" {
        $Target = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
        $Arch = if ($Target.StartsWith("aarch64")) { "arm64" } else { "x64" }
        Build-Target $Target
        Copy-Binary (Join-Path $Root "target/$Target/release/rustbox_flutter_bridge.dll") (Join-Path $Native "windows/$Arch/rustbox_flutter_bridge.dll")
    }
    "linux" {
        $Target = if ((uname -m) -eq "aarch64") { "aarch64-unknown-linux-gnu" } else { "x86_64-unknown-linux-gnu" }
        $Arch = if ($Target.StartsWith("aarch64")) { "arm64" } else { "x64" }
        Build-Target $Target
        Copy-Binary (Join-Path $Root "target/$Target/release/librustbox_flutter_bridge.so") (Join-Path $Native "linux/$Arch/librustbox_flutter_bridge.so")
    }
    "macos" {
        foreach ($Target in @("aarch64-apple-darwin", "x86_64-apple-darwin")) { Build-Target $Target }
        $Output = Join-Path $Native "macos/librustbox_flutter_bridge.a"
        New-Item -ItemType Directory -Force (Split-Path $Output -Parent) | Out-Null
        & lipo -create `
            (Join-Path $Root "target/aarch64-apple-darwin/release/librustbox_flutter_bridge.a") `
            (Join-Path $Root "target/x86_64-apple-darwin/release/librustbox_flutter_bridge.a") `
            -output $Output
        if ($LASTEXITCODE -ne 0) { throw "lipo failed for macOS" }
    }
    "android" {
        & cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 -o (Join-Path $Native "android") @CargoArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo-ndk Android build failed" }
    }
    "ios" {
        foreach ($Target in @("aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios")) { Build-Target $Target }
        $Work = Join-Path $Root "target/flutter-ios-xcframework"
        New-Item -ItemType Directory -Force $Work | Out-Null
        $Simulator = Join-Path $Work "librustbox_flutter_bridge-simulator.a"
        & lipo -create `
            (Join-Path $Root "target/aarch64-apple-ios-sim/release/librustbox_flutter_bridge.a") `
            (Join-Path $Root "target/x86_64-apple-ios/release/librustbox_flutter_bridge.a") `
            -output $Simulator
        if ($LASTEXITCODE -ne 0) { throw "lipo failed for iOS simulator" }
        $Output = Join-Path $Native "ios/RustboxFlutterBridge.xcframework"
        if (Test-Path $Output) { Remove-Item -Recurse -Force -LiteralPath $Output }
        & xcodebuild -create-xcframework `
            -library (Join-Path $Root "target/aarch64-apple-ios/release/librustbox_flutter_bridge.a") `
            -library $Simulator `
            -output $Output
        if ($LASTEXITCODE -ne 0) { throw "xcodebuild failed for iOS XCFramework" }
    }
}
