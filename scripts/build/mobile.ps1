#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Build the RustBox FFI library for Android or iOS.
.EXAMPLE
    ./scripts/build/mobile.ps1 -Platform Android
.EXAMPLE
    ./scripts/build/mobile.ps1 -Platform Android -AndroidTargets arm64-v8a,x86_64
.EXAMPLE
    ./scripts/build/mobile.ps1 -Platform IOS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Android", "IOS")]
    [string] $Platform,

    [string[]] $AndroidTargets = @("arm64-v8a", "armeabi-v7a", "x86_64", "x86"),

    [string[]] $IosTargets = @("aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"),

    [ValidateRange(21, 35)]
    [int] $AndroidApi = 21,

    [switch] $Development,

    [switch] $Locked
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")
$Profile = $Development ? "debug" : "release"
$BuildFlag = $Development ? @() : @("--release")
$LockedFlag = $Locked ? @("--locked") : @()

function Require-Command([string] $Name, [string] $Hint) {
    if (-not (Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "$Name was not found. $Hint"
    }
}

Push-Location $RootDir
try {
    Require-Command "cargo" "Install Rust from https://rustup.rs/."

    if ($Platform -eq "Android") {
        Require-Command "cargo-ndk" "Install it with: cargo install cargo-ndk"
        if (-not $env:ANDROID_NDK_HOME -and $env:ANDROID_NDK_LATEST_HOME) {
            $env:ANDROID_NDK_HOME = $env:ANDROID_NDK_LATEST_HOME
        }
        if (-not $env:ANDROID_NDK_HOME -and -not $env:ANDROID_NDK_ROOT) {
            throw "Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to an installed Android NDK."
        }

        $OutputDir = Join-Path $RootDir "dist/android"
        $TargetArgs = [System.Collections.Generic.List[string]]::new()
        foreach ($Target in $AndroidTargets) {
            $TargetArgs.Add("-t")
            $TargetArgs.Add($Target)
        }

        & cargo ndk @TargetArgs -p $AndroidApi -o $OutputDir build -p rustbox-ffi @BuildFlag @LockedFlag
        if ($LASTEXITCODE -ne 0) { throw "Android build failed." }
        Write-Host "Android $Profile libraries: $OutputDir" -ForegroundColor Green
        return
    }

    if (-not $IsMacOS) {
        throw "iOS builds require macOS and Xcode."
    }
    Require-Command "xcodebuild" "Install Xcode and select it with xcode-select."
    Require-Command "lipo" "Install Xcode command-line tools."

    foreach ($Target in $IosTargets) {
        & rustup target add $Target
        if ($LASTEXITCODE -ne 0) { throw "Failed to install Rust target $Target." }
        & cargo build -p rustbox-ffi --target $Target @BuildFlag @LockedFlag
        if ($LASTEXITCODE -ne 0) { throw "iOS build failed for $Target." }
    }

    $DeviceTarget = "aarch64-apple-ios"
    if ($DeviceTarget -notin $IosTargets) {
        throw "iOS packaging requires the device target '$DeviceTarget'."
    }
    $DeviceLibrary = Join-Path $RootDir "target/$DeviceTarget/$Profile/librustbox_ffi.a"
    $SimulatorLibraries = @($IosTargets |
        Where-Object { $_ -in @("aarch64-apple-ios-sim", "x86_64-apple-ios") } |
        ForEach-Object { Join-Path $RootDir "target/$_/$Profile/librustbox_ffi.a" })
    if ($SimulatorLibraries.Count -eq 0) {
        throw "iOS packaging requires at least one simulator target."
    }

    $OutputDir = Join-Path $RootDir "dist/ios"
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $SimulatorLibrary = Join-Path $OutputDir "librustbox_ffi_sim.a"
    if ($SimulatorLibraries.Count -eq 1) {
        Copy-Item $SimulatorLibraries[0] $SimulatorLibrary -Force
    } else {
        & lipo -create @SimulatorLibraries -output $SimulatorLibrary
        if ($LASTEXITCODE -ne 0) { throw "Failed to create the universal iOS simulator library." }
    }

    $Framework = Join-Path $OutputDir "RustBoxFFI.xcframework"
    if (Test-Path $Framework) { Remove-Item -Recurse -Force $Framework }
    & xcodebuild -create-xcframework `
        -library $DeviceLibrary -headers (Join-Path $RootDir "apps/rustbox-ffi/include") `
        -library $SimulatorLibrary -headers (Join-Path $RootDir "apps/rustbox-ffi/include") `
        -output $Framework
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the iOS XCFramework." }
    Write-Host "iOS $Profile XCFramework: $Framework" -ForegroundColor Green
} finally {
    Pop-Location
}
