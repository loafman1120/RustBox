#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [switch] $HttpTarget,
    [int] $ListenPort
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

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

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")
$TargetDir = Join-Path $RootDir "target/debug"
$Source = Join-Path $RootDir "crates/rustbox-ffi/tests/c/dynamic_library_smoke.c"
$IncludeDir = Join-Path $RootDir "crates/rustbox-ffi/include"
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
        $Clang = Get-Command clang -CommandType Application -ErrorAction SilentlyContinue
        if ($Clang) {
            & $Clang.Source $Source "-I$IncludeDir" -DRUSTBOX_SHARED `
                (Join-Path $TargetDir "rustbox_ffi.dll.lib") -o $Executable
        } else {
            $Cl = Get-Command cl -CommandType Application -ErrorAction Stop
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
