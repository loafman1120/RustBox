#!/usr/bin/env pwsh
<#
.SYNOPSIS
    gRPC control API external smoke test for RustBox CI.
.DESCRIPTION
    Starts rustbox-app with gRPC control API enabled, then uses grpcurl
    (downloaded & cached) to verify authentication, GetMetrics, and Stop
    by calling real RPCs from outside the process.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")
$WorkDir = if ($env:RUSTBOX_CI_WORK_DIR) { $env:RUSTBOX_CI_WORK_DIR }
           else { Join-Path $RootDir "target/ci-grpc-smoke" }

$GrpcPort = if ($env:RUSTBOX_GRPC_PORT) { [int]$env:RUSTBOX_GRPC_PORT } else { 19090 }
$Token    = if ($env:RUSTBOX_GRPC_TOKEN) { $env:RUSTBOX_GRPC_TOKEN } else { "ci-secret" }
$GrpcurlVersion = "1.9.3"

$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) { $DefaultBin = "$DefaultBin.exe" }
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }

$ProtoDir = Join-Path $RootDir "crates/control/rustbox-control-api/proto"
$HadFailure = $false

function Write-CiLog {
    param([string]$Message)
    Write-Host "[grpc-smoke] $Message"
}

# ── download / cache grpcurl ──
function Get-GrpCurl {
    $cacheDir = if ($env:GRPCURL_CACHE_DIR) { $env:GRPCURL_CACHE_DIR }
                else { Join-Path $RootDir "target/grpcurl-cache" }

    $osArch = if ($IsLinux)   { "linux_x86_64" }
         elseif ($IsMacOS)   { "osx_x86_64" }
         elseif ($IsWindows) { "windows_x86_64" }
         else { throw "unsupported OS for grpcurl" }

    $binName = if ($IsWindows) { "grpcurl.exe" } else { "grpcurl" }
    $cachedBin = Join-Path $cacheDir $binName

    if (Test-Path $cachedBin) {
        Write-CiLog "using cached grpcurl: $cachedBin"
        return $cachedBin
    }

    if ($IsWindows) {
        $archive = Join-Path $cacheDir "grpcurl.zip"
        $url = "https://github.com/fullstorydev/grpcurl/releases/download/v$GrpcurlVersion/grpcurl_${GrpcurlVersion}_${osArch}.zip"
    } else {
        $archive = Join-Path $cacheDir "grpcurl.tar.gz"
        $url = "https://github.com/fullstorydev/grpcurl/releases/download/v$GrpcurlVersion/grpcurl_${GrpcurlVersion}_${osArch}.tar.gz"
    }

    Write-CiLog "downloading grpcurl: $url"
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

    try {
        Invoke-WebRequest -Uri $url -OutFile $archive -MaximumRetryCount 3 -RetryIntervalSec 2

        if ($IsWindows) {
            Expand-Archive -Path $archive -DestinationPath $cacheDir -Force
            $extracted = Get-ChildItem -Path $cacheDir -Filter "grpcurl.exe" -Recurse | Select-Object -First 1
            if (-not $extracted) { throw "grpcurl.exe not found in archive" }
            if ($extracted.FullName -ne $cachedBin) {
                Move-Item -Path $extracted.FullName -Destination $cachedBin -Force
            }
            Get-ChildItem -Path $cacheDir -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            tar -xzf $archive -C $cacheDir grpcurl 2>$null
            & chmod +x $cachedBin 2>$null
        }
    } finally {
        Remove-Item $archive -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $cachedBin)) {
        throw "grpcurl binary not found after extraction: $cachedBin"
    }

    Write-CiLog "grpcurl cached: $cachedBin"
    return $cachedBin
}

# ── wait for tcp port ──
function Wait-ForTcp {
    param([string]$HostName, [int]$Port, [string]$Label, [int]$TimeoutSeconds = 15)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.Connect($HostName, $Port)
            $c.Dispose()
            Write-CiLog "$Label ready on ${HostName}:$Port"
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    throw "$Label did not start on ${HostName}:$Port within ${TimeoutSeconds}s"
}

# ── main ──
try {
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary not found: $BinPath. Run cargo build -p rustbox-app first."
    }

    $GrpcUrl = Get-GrpCurl

    # Helper: invoke grpcurl with proto files (no server reflection needed)
    # Returns merged stdout+stderr as a single string; also sets $LASTEXITCODE
    function Invoke-Grpc {
        $out = & $GrpcUrl -plaintext -import-path $ProtoDir -proto rustbox.control.v1.proto @args 2>&1 | Out-String
        return $out
    }

    function Invoke-SingBoxGrpc {
        $out = & $GrpcUrl -plaintext -import-path $ProtoDir -proto started_service.proto @args 2>&1 | Out-String
        return $out
    }

    $ConfigPath = Join-Path $WorkDir "ci.toml"
    Set-Content -Path $ConfigPath -Encoding utf8 -Value @"
schema_version = 1

[observability]
level = "debug"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:10808"

[[outbounds]]
id = "direct-a"
type = "direct"

[[outbounds]]
id = "direct-b"
type = "direct"

[[outbounds]]
id = "select"
type = "selector"
outbounds = ["direct-a", "direct-b"]
default = "direct-a"

[[routes]]
type = "default"
outbound = "select"
"@

    Write-CiLog "starting rustbox-app with gRPC control API"
    $null = Start-Process -FilePath $BinPath `
        -ArgumentList @("run", "--config", $ConfigPath,
            "--control-grpc", "127.0.0.1:${GrpcPort}",
            "--control-token", $Token) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $WorkDir "rustbox-stdout.log") `
        -RedirectStandardError (Join-Path $WorkDir "rustbox-stderr.log")

    Wait-ForTcp -HostName "127.0.0.1" -Port $GrpcPort -Label "gRPC"

    $svc = "rustbox.control.v1.RustBoxControl"
    $addr = "127.0.0.1:${GrpcPort}"

    # 1) No token → rejected (grpcurl exits != 0)
    Write-CiLog "test: no token"
    $null = Invoke-Grpc $addr ${svc}/GetMetrics
    if ($LASTEXITCODE -eq 0) { throw "FAIL: request without token should be rejected" }

    # 2) Wrong token → rejected
    Write-CiLog "test: wrong token"
    $null = Invoke-Grpc -H "authorization: Bearer wrong" $addr ${svc}/GetMetrics
    if ($LASTEXITCODE -eq 0) { throw "FAIL: request with wrong token should be rejected" }

    # 3) Correct token → GetMetrics returns data
    Write-CiLog "test: GetMetrics"
    $out = Invoke-Grpc -H "authorization: Bearer $Token" $addr ${svc}/GetMetrics
    if ($LASTEXITCODE -ne 0) { throw "FAIL: GetMetrics failed" }
    if ($out -notmatch 'servicesStarted') { throw "FAIL: GetMetrics missing fields" }

    # 4) sing-box-compatible selector RPC succeeds
    Write-CiLog "test: daemon.StartedService/SelectOutbound"
    $out = Invoke-SingBoxGrpc -H "authorization: Bearer $Token" `
        -d '{"groupTag":"select","outboundTag":"direct-b"}' `
        $addr daemon.StartedService/SelectOutbound
    if ($LASTEXITCODE -ne 0) { throw "FAIL: SelectOutbound failed" }

    # 5) Stop → ENGINE_STATE_STOPPING
    Write-CiLog "test: Stop"
    $out = Invoke-Grpc -H "authorization: Bearer $Token" $addr ${svc}/Stop
    if ($LASTEXITCODE -ne 0) { throw "FAIL: Stop failed" }
    if ($out -notmatch 'ENGINE_STATE_STOPPING') { throw "FAIL: Stop wrong state" }

    Write-CiLog "PASSED"
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $script:HadFailure = $true
} finally {
    Get-Process -Name "rustbox-app" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

if ($HadFailure) { exit 1 }
