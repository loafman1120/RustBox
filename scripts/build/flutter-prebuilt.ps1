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

function Install-Targets([string[]]$Targets) {
    & rustup target add @Targets
    if ($LASTEXITCODE -ne 0) { throw "Failed to install Rust targets: $Targets" }
}

function Copy-Binary([string]$Source, [string]$Destination) {
    $Destination = [System.IO.Path]::GetFullPath($Destination)
    New-Item -ItemType Directory -Force (Split-Path $Destination -Parent) | Out-Null
    Copy-Item -Force -LiteralPath $Source -Destination $Destination
    Write-Host "Prepared $Destination"
}

function Install-Wintun([string]$Arch) {
    $Version = "0.14.1"
    $ExpectedSha256 = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
    $WintunArch = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
    $Cache = Join-Path ([System.IO.Path]::GetTempPath()) "rustbox-wintun-$Version"
    $Archive = Join-Path $Cache "wintun.zip"
    $Extracted = Join-Path $Cache "extracted"
    New-Item -ItemType Directory -Force $Cache | Out-Null
    if (-not (Test-Path -LiteralPath $Archive) -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash -ne $ExpectedSha256) {
        Invoke-WebRequest "https://www.wintun.net/builds/wintun-$Version.zip" -OutFile $Archive
    }
    $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash
    if ($ActualSha256 -ne $ExpectedSha256) {
        throw "Wintun archive checksum mismatch: expected $ExpectedSha256, got $ActualSha256"
    }
    if (Test-Path -LiteralPath $Extracted) {
        Remove-Item -Recurse -Force -LiteralPath $Extracted
    }
    Expand-Archive -LiteralPath $Archive -DestinationPath $Extracted
    $WintunDll = Join-Path $Extracted "wintun/bin/$WintunArch/wintun.dll"
    $Signature = Get-AuthenticodeSignature -LiteralPath $WintunDll
    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Wintun Authenticode signature is not valid: $($Signature.StatusMessage)"
    }
    Copy-Binary `
        $WintunDll `
        (Join-Path $Native "windows/$Arch/wintun.dll")
}

switch ($Platform) {
    "windows" {
        $Target = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
        $Arch = if ($Target.StartsWith("aarch64")) { "arm64" } else { "x64" }
        Install-Targets @($Target)
        Build-Target $Target
        $WatchdogArgs = @("build", "--release", "--package", "rustbox-watchdog", "--target", $Target)
        if ($Locked) { $WatchdogArgs += "--locked" }
        & cargo @WatchdogArgs
        if ($LASTEXITCODE -ne 0) { throw "Watchdog build failed for $Target" }
        Copy-Binary (Join-Path $Root "target/$Target/release/rustbox_flutter_bridge.dll") (Join-Path $Native "windows/$Arch/rustbox_flutter_bridge.dll")
        Copy-Binary (Join-Path $Root "target/$Target/release/rustbox-watchdog.exe") (Join-Path $Native "windows/$Arch/rustbox-watchdog.exe")
        Install-Wintun $Arch
    }
    "linux" {
        $Target = if ((uname -m) -eq "aarch64") { "aarch64-unknown-linux-gnu" } else { "x86_64-unknown-linux-gnu" }
        $Arch = if ($Target.StartsWith("aarch64")) { "arm64" } else { "x64" }
        Install-Targets @($Target)
        Build-Target $Target
        Copy-Binary (Join-Path $Root "target/$Target/release/librustbox_flutter_bridge.so") (Join-Path $Native "linux/$Arch/librustbox_flutter_bridge.so")
    }
    "macos" {
        $env:MACOSX_DEPLOYMENT_TARGET = "11.0"
        $Targets = @("aarch64-apple-darwin", "x86_64-apple-darwin")
        Install-Targets $Targets
        foreach ($Target in $Targets) { Build-Target $Target }
        $Output = Join-Path $Native "macos/librustbox_flutter_bridge.a"
        New-Item -ItemType Directory -Force (Split-Path $Output -Parent) | Out-Null
        & lipo -create `
            (Join-Path $Root "target/aarch64-apple-darwin/release/librustbox_flutter_bridge.a") `
            (Join-Path $Root "target/x86_64-apple-darwin/release/librustbox_flutter_bridge.a") `
            -output $Output
        if ($LASTEXITCODE -ne 0) { throw "lipo failed for macOS" }
    }
    "android" {
        Install-Targets @("armv7-linux-androideabi", "aarch64-linux-android", "x86_64-linux-android")
        & cargo ndk -t armeabi-v7a -t arm64-v8a -t x86_64 -o (Join-Path $Native "android") @CargoArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo-ndk Android build failed" }
    }
    "ios" {
        # Keep C/C++ dependencies (notably aws-lc) on the same minimum
        # deployment target as the podspec. Without this, newer Xcode SDKs can
        # emit objects targeting the SDK version while rustc links for iOS 10.
        $env:IPHONEOS_DEPLOYMENT_TARGET = "13.0"
        $Targets = @("aarch64-apple-ios")
        Install-Targets $Targets
        foreach ($Target in $Targets) { Build-Target $Target }
        $Output = Join-Path $Native "ios/RustboxFlutterBridge.xcframework"
        if (Test-Path $Output) { Remove-Item -Recurse -Force -LiteralPath $Output }
        & xcodebuild -create-xcframework `
            -library (Join-Path $Root "target/aarch64-apple-ios/release/librustbox_flutter_bridge.a") `
            -output $Output
        if ($LASTEXITCODE -ne 0) { throw "xcodebuild failed for iOS XCFramework" }
    }
}
