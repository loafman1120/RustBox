#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [ValidateSet("Desktop", "Android", "IOS")]
    [string] $Platform = "Desktop",
    [switch] $HttpTarget,
    [int] $ListenPort
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")

if ($Platform -ne "Desktop") {
    $Source = Join-Path $RootDir "apps/rustbox-ffi/tests/c/mobile_lifecycle_smoke.c"
    $IncludeDir = Join-Path $RootDir "apps/rustbox-ffi/include"
    $OutputDir = Join-Path $RootDir "target/ci-ffi-mobile-smoke"
    New-Item -ItemType Directory -Force $OutputDir | Out-Null
    Push-Location $RootDir
    try {
        if ($Platform -eq "Android") {
            ./scripts/build/mobile.ps1 -Platform Android -AndroidTargets x86_64 -Locked
            $Prebuilt = Get-ChildItem (Join-Path $env:ANDROID_NDK_HOME "toolchains/llvm/prebuilt") -Directory | Select-Object -First 1
            if (-not $Prebuilt) { throw "Android NDK LLVM toolchain was not found." }
            $Clang = Join-Path $Prebuilt.FullName "bin/x86_64-linux-android21-clang"
            $Executable = Join-Path $OutputDir "ffi-lifecycle"
            & $Clang $Source "-I$IncludeDir" "-L$(Join-Path $RootDir 'dist/android/x86_64')" -lrustbox_ffi -o $Executable
            if ($LASTEXITCODE -ne 0) { throw "Failed to compile Android lifecycle consumer." }
            & adb push $Executable /data/local/tmp/ffi-lifecycle
            & adb push (Join-Path $RootDir "dist/android/x86_64/librustbox_ffi.so") /data/local/tmp/librustbox_ffi.so
            & adb shell chmod 755 /data/local/tmp/ffi-lifecycle
            & adb shell "LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/ffi-lifecycle"
            if ($LASTEXITCODE -ne 0) { throw "Android FFI lifecycle consumer failed." }
            return
        }

        if (-not $IsMacOS) { throw "iOS lifecycle E2E requires macOS and Xcode." }
        ./scripts/build/mobile.ps1 -Platform IOS -IosTargets aarch64-apple-ios,aarch64-apple-ios-sim -Locked
        $Sdk = (& xcrun --sdk iphonesimulator --show-sdk-path).Trim()
        $AppBundle = Join-Path $OutputDir "RustBoxFfiLifecycle.app"
        New-Item -ItemType Directory -Force $AppBundle | Out-Null
        Copy-Item (Join-Path $RootDir "apps/rustbox-ffi/tests/ios/Info.plist") (Join-Path $AppBundle "Info.plist") -Force
        $Executable = Join-Path $AppBundle "ffi-lifecycle-ios"
        $Library = Join-Path $RootDir "target/aarch64-apple-ios-sim/release/librustbox_ffi.a"
        & xcrun --sdk iphonesimulator clang -target arm64-apple-ios13.0-simulator $Source "-I$IncludeDir" $Library -framework Security -framework SystemConfiguration -lresolv -liconv "-isysroot" $Sdk -o $Executable
        if ($LASTEXITCODE -ne 0) { throw "Failed to compile iOS lifecycle consumer." }
        & codesign --force --sign - $AppBundle
        $Device = (& xcrun simctl list devices available -j | ConvertFrom-Json).devices.PSObject.Properties.Value | ForEach-Object { $_ } | Where-Object { $_.name -like "iPhone*" } | Select-Object -First 1
        if (-not $Device) { throw "No available iOS Simulator device was found." }
        & xcrun simctl boot $Device.udid 2>$null
        & xcrun simctl bootstatus $Device.udid -b
        & xcrun simctl install $Device.udid $AppBundle
        & xcrun simctl launch --console --terminate-running-process $Device.udid dev.rustbox.ffi-lifecycle-smoke
        if ($LASTEXITCODE -ne 0) { throw "iOS FFI lifecycle consumer failed." }
        return
    } finally {
        Pop-Location
    }
}

if ($HttpTarget) {
    $Listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, $ListenPort)
    $Listener.Start()
    try {
        while ($true) {
            $Client = $Listener.AcceptTcpClient()
            try {
                $Stream = $Client.GetStream()
                $Reader = [System.IO.StreamReader]::new($Stream)
                $RequestLine = $Reader.ReadLine()
                if ([string]::IsNullOrEmpty($RequestLine)) { continue }
                while (-not [string]::IsNullOrEmpty($Reader.ReadLine())) {}
                $Body = [System.Text.Encoding]::ASCII.GetBytes("rustbox-ffi-http-ok`n")
                $Header = [System.Text.Encoding]::ASCII.GetBytes(
                    "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($Body.Length)`r`nConnection: close`r`n`r`n")
                $Stream.Write($Header, 0, $Header.Length)
                $Stream.Write($Body, 0, $Body.Length)
                $Stream.Flush()
                break
            } finally {
                $Client.Dispose()
            }
        }
    } finally {
        $Listener.Stop()
    }
    exit 0
}

$TargetDir = Join-Path $RootDir "target/debug"
$Source = Join-Path $RootDir "apps/rustbox-ffi/tests/c/dynamic_library_smoke.c"
$IncludeDir = Join-Path $RootDir "apps/rustbox-ffi/include"
$OutputDir = Join-Path $RootDir "target/ci-ffi-smoke"
$Executable = Join-Path $OutputDir $(if ($IsWindows) { "ffi-consumer.exe" } else { "ffi-consumer" })
$ObjectFile = Join-Path $OutputDir "dynamic_library_smoke.obj"
$ResponseFile = Join-Path $OutputDir "response.txt"

function Get-FreeTcpPort {
    $Listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, 0)
    $Listener.Start()
    try { return ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port }
    finally { $Listener.Stop() }
}

function Wait-ForTcpPort([int]$Port) {
    for ($Attempt = 0; $Attempt -lt 100; $Attempt++) {
        $Client = [System.Net.Sockets.TcpClient]::new()
        try {
            $Client.Connect("127.0.0.1", $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 50
        } finally {
            $Client.Dispose()
        }
    }
    throw "HTTP target did not listen on port $Port"
}

New-Item -ItemType Directory -Force $OutputDir | Out-Null

$HttpTargetPort = Get-FreeTcpPort
$ProxyPort = Get-FreeTcpPort
$HttpProcess = $null

Push-Location $RootDir
try {
    cargo build --locked --package rustbox-ffi
    if ($LASTEXITCODE -ne 0) { throw "failed to build rustbox-ffi" }

    if ($IsWindows) {
        $Clang = Get-Command clang -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($Clang) {
            & $Clang.Source $Source "-I$IncludeDir" -DRUSTBOX_SHARED `
                (Join-Path $TargetDir "rustbox_ffi.dll.lib") -o $Executable
        } else {
            $Cl = Get-Command cl -CommandType Application -ErrorAction Stop |
                Select-Object -First 1
            & $Cl.Source /nologo /W4 /DRUSTBOX_SHARED /D_CRT_SECURE_NO_WARNINGS "/I$IncludeDir" $Source `
                "/Fo:$ObjectFile" "/Fe:$Executable" /link (Join-Path $TargetDir "rustbox_ffi.dll.lib")
        }
    } elseif ($IsMacOS) {
        & cc $Source "-I$IncludeDir" "-L$TargetDir" -lrustbox_ffi `
            "-Wl,-rpath,$TargetDir" -o $Executable
    } else {
        & cc $Source "-I$IncludeDir" "-L$TargetDir" -lrustbox_ffi `
            "-Wl,-rpath,$TargetDir" -o $Executable
    }
    if ($LASTEXITCODE -ne 0) { throw "failed to compile the native FFI consumer" }

    if ($IsWindows) {
        $env:PATH = "$TargetDir;$env:PATH"
    }
    $PowerShell = (Get-Process -Id $PID).Path
    $HttpProcess = Start-Process -FilePath $PowerShell -PassThru -NoNewWindow `
        -ArgumentList @("-NoLogo", "-NoProfile", "-File", $PSCommandPath,
            "-HttpTarget", "-ListenPort", "$HttpTargetPort")
    Wait-ForTcpPort $HttpTargetPort

    & $Executable $ProxyPort "http://127.0.0.1:$HttpTargetPort/payload" $ResponseFile
    if ($LASTEXITCODE -ne 0) { throw "native FFI consumer failed" }
} finally {
    if ($null -ne $HttpProcess -and -not $HttpProcess.HasExited) {
        Stop-Process -Id $HttpProcess.Id -Force
        $HttpProcess.WaitForExit()
    }
    Pop-Location
}
