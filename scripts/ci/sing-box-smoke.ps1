#!/usr/bin/env pwsh
<#
.SYNOPSIS
    sing-box end-to-end smoke test for RustBox CI.
.DESCRIPTION
    Downloads sing-box, starts it as a SOCKS5 proxy, then verifies
    RustBox can route outbound traffic through it.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")
$WorkDir = Join-Path $RootDir "target/ci-singbox-smoke"
$SboxVersion = "1.13.14"

function Write-CiLog {
    param([string]$Message)
    Write-Host "[sing-box-ci] $Message"
}

# ---- Determine sing-box download URL ----
function Get-SingBoxUrl {
    $base = "https://github.com/SagerNet/sing-box/releases/download/v$SboxVersion"

    if ($IsLinux) {
        return "$base/sing-box-$SboxVersion-linux-amd64.tar.gz"
    }
    if ($IsMacOS) {
        # macos-latest is arm64
        return "$base/sing-box-$SboxVersion-darwin-arm64.tar.gz"
    }
    if ($IsWindows) {
        return "$base/sing-box-$SboxVersion-windows-amd64.zip"
    }
    throw "unsupported OS for sing-box smoke test"
}

# ---- Find RustBox binary ----
$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) { $DefaultBin = "$DefaultBin.exe" }
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }

# ---- Find curl ----
function Get-Curl {
    $candidates = @($env:CURL, "curl.exe", "curl")
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    throw "curl not found"
}

try {
    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary not found: $BinPath. Build first."
    }

    $Curl = Get-Curl

    # Prepare work dir
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    $LogsDir = Join-Path $WorkDir "logs"
    $SboxDir = Join-Path $WorkDir "sing-box"
    $WwwDir = Join-Path $WorkDir "www"
    New-Item -ItemType Directory -Path $LogsDir, $SboxDir, $WwwDir -Force | Out-Null

    $Marker = "rustbox-singbox-e2e-ok"
    Set-Content -Path (Join-Path $WwwDir "marker.txt") -Value $Marker -Encoding ascii

    # ---- Download and extract sing-box ----
    $SboxUrl = Get-SingBoxUrl
    $SboxArchive = Join-Path $SboxDir "sing-box-archive"
    Write-CiLog "downloading sing-box from $SboxUrl"
    Invoke-WebRequest -Uri $SboxUrl -OutFile $SboxArchive

    if ($IsWindows) {
        Expand-Archive -Path $SboxArchive -DestinationPath $SboxDir -Force
        $SboxBin = Join-Path $SboxDir "sing-box.exe"
    } else {
        tar -xzf $SboxArchive -C $SboxDir
        $SboxBin = Join-Path $SboxDir "sing-box"
    }

    if (-not (Test-Path $SboxBin)) {
        throw "sing-box binary not found after extraction"
    }

    # Make executable on Unix
    if (-not $IsWindows) {
        & chmod +x $SboxBin
    }

    # ---- Start Python HTTP target ----
    $HttpTargetPort = 18080
    $Python = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $Python) {
        $Python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $Python) {
        throw "python not found"
    }

    Write-CiLog "starting HTTP target on :$HttpTargetPort"
    $TargetProc = Start-Process -FilePath $Python.Source `
        -ArgumentList @("-m", "http.server", "$HttpTargetPort", "--bind", "127.0.0.1", "--directory", $WwwDir) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "http-target.log") `
        -RedirectStandardError (Join-Path $LogsDir "http-target.err.log")

    # Wait for target
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.Connect("127.0.0.1", $HttpTargetPort)
            $c.Dispose()
            Write-CiLog "HTTP target ready"
            break
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }

    # ---- Start sing-box as SOCKS5 server ----
    $SboxMixedPort = 21080
    $SboxConfigPath = Join-Path $WorkDir "sing-box.json"
    @"
{
  "log": { "level": "info", "output": "$($LogsDir.Replace('\', '/'))/sing-box.log" },
  "inbounds": [{
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": $SboxMixedPort
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"@ | Set-Content -Path $SboxConfigPath -Encoding utf8

    Write-CiLog "starting sing-box mixed on :$SboxMixedPort"
    $SboxProc = Start-Process -FilePath $SboxBin `
        -ArgumentList @("run", "-c", $SboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "sing-box-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "sing-box-stderr.log")

    # Wait for sing-box
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $sboxReady = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.Connect("127.0.0.1", $SboxMixedPort)
            $c.Dispose()
            Write-CiLog "sing-box ready"
            $sboxReady = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $sboxReady) {
        throw "sing-box did not start in time"
    }

    # ---- Start RustBox routing through sing-box ----
    $RustboxHttpPort = 28080
    $RustboxConfigPath = Join-Path $WorkDir "rustbox.toml"
    $EventsPath = (Join-Path $LogsDir "rustbox-events.log").Replace("\", "/")
    @"
schema_version = 1

[observability]
level = "debug"
file = "$EventsPath"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:$RustboxHttpPort"

[[outbounds]]
id = "sbox"
type = "socks5"
server = "127.0.0.1"
server_port = $SboxMixedPort

[[routes]]
type = "default"
outbound = "sbox"
"@ | Set-Content -Path $RustboxConfigPath -Encoding utf8

    Write-CiLog "starting rustbox via sing-box route"
    $RustboxProc = Start-Process -FilePath $BinPath `
        -ArgumentList @("run", "--config", $RustboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "rustbox-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "rustbox-stderr.log")

    # Wait for rustbox
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $rustboxReady = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new()
            $c.Connect("127.0.0.1", $RustboxHttpPort)
            $c.Dispose()
            Write-CiLog "rustbox ready"
            $rustboxReady = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $rustboxReady) {
        throw "rustbox did not start in time"
    }

    # ---- Curl through the chain ----
    Write-CiLog "curling through rustbox -> sing-box -> target"
    $CurlLog = Join-Path $LogsDir "curl.log"
    $BodyFile = Join-Path $LogsDir "curl-body.log"

    & $Curl --fail --silent --show-error --verbose `
        --max-time 15 --retry 2 --retry-delay 1 --noproxy "" `
        --proxy "http://127.0.0.1:$RustboxHttpPort" `
        --output $BodyFile `
        "http://127.0.0.1:$HttpTargetPort/marker.txt" 2> $CurlLog

    if ($LASTEXITCODE -ne 0) {
        throw "curl through sing-box chain failed; see $CurlLog"
    }

    $Body = Get-Content -Path $BodyFile -Raw
    if (-not $Body.Contains($Marker)) {
        throw "unexpected response through sing-box chain: $Body"
    }

    # ---- Verify observability ----
    $Events = Get-Content -Path (Join-Path $LogsDir "rustbox-events.log") -Raw
    foreach ($needle in @("connection_accepted", "outbound_connected")) {
        if (-not $Events.Contains($needle)) {
            throw "rustbox events missing '$needle'"
        }
    }

    Write-CiLog "sing-box e2e smoke test PASSED"
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    # cleanup
    Get-Process -Name "sing-box" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -Name "rustbox-app" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -Name "python" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if ($env:RUSTBOX_CI_DUMP_LOGS -eq "1") {
        $logDir = Join-Path $WorkDir "logs"
        if (Test-Path $logDir) {
            Get-ChildItem -Path $logDir | ForEach-Object {
                Write-Host "`n===== $($_.Name) ====="
                Get-Content $_.FullName -ErrorAction SilentlyContinue
            }
        }
    }
}
