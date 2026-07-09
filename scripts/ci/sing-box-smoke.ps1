#!/usr/bin/env pwsh
<#
.SYNOPSIS
    sing-box end-to-end compatibility matrix test for RustBox CI.
.DESCRIPTION
    Downloads sing-box, starts it with the requested inbound type, then
    verifies RustBox can route outbound traffic through it.

    CI matrix parameters (set via env):
      RUSTBOX_SBOX_OUTBOUND = socks5 | http | shadowsocks | anytls
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "../..")
$WorkDir = Join-Path $RootDir "target/ci-singbox-smoke"
$SboxVersion = "1.13.14"
$OutboundType = if ($env:RUSTBOX_SBOX_OUTBOUND) { $env:RUSTBOX_SBOX_OUTBOUND } else { "socks5" }

# Shared test constants
$HttpTargetPort = 18080
$RustboxHttpPort = 28080
$SboxInboundPort = 21080
$Marker = "rustbox-singbox-e2e-ok"
$SsMethod = "aes-128-gcm"
$SsPassword = "test-ss-password-123"
$AnyTlsPassword = "test-anytls-password"

function Write-CiLog {
    param([string]$Message)
    Write-Host "[sing-box-ci/$OutboundType] $Message"
}

# ---- Determine sing-box download URL ----
function Get-SingBoxUrl {
    $base = "https://github.com/SagerNet/sing-box/releases/download/v$SboxVersion"
    if ($IsLinux)   { return "$base/sing-box-$SboxVersion-linux-amd64.tar.gz" }
    if ($IsMacOS)   { return "$base/sing-box-$SboxVersion-darwin-arm64.tar.gz" }
    if ($IsWindows) { return "$base/sing-box-$SboxVersion-windows-amd64.zip" }
    throw "unsupported OS for sing-box smoke test"
}

# ---- Find RustBox binary ----
$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) { $DefaultBin = "$DefaultBin.exe" }
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }

# ---- Find curl ----
function Get-Curl {
    foreach ($c in @($env:CURL, "curl.exe", "curl")) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    throw "curl not found"
}

# ---- Find python ----
function Get-Python {
    foreach ($c in @("python3", "python")) {
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    throw "python not found"
}

# ---- Generate TLS cert for AnyTLS ----
function New-TlsCert {
    param([string]$CertPath, [string]$KeyPath)

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=127.0.0.1", $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
        $san.AddDnsName("localhost")
        $req.CertificateExtensions.Add($san.Build())

        $cert = $req.CreateSelfSigned(
            [System.DateTimeOffset]::UtcNow.AddDays(-1),
            [System.DateTimeOffset]::UtcNow.AddDays(7)
        )
        $certPem = [System.Security.Cryptography.PemEncoding]::WriteString("CERTIFICATE", $cert.RawData)
        $keyPem  = [System.Security.Cryptography.PemEncoding]::WriteString("PRIVATE KEY", $rsa.ExportPkcs8PrivateKey())

        Set-Content -Path $CertPath -Value $certPem -Encoding ascii
        Set-Content -Path $KeyPath  -Value $keyPem  -Encoding ascii
    } finally {
        $rsa.Dispose()
    }
}

# ---- Generate sing-box server config per outbound type ----
function Get-SingBoxConfig {
    param([string]$LogsDir)

    $logsEscaped = $LogsDir.Replace('\', '/')

    switch ($OutboundType) {
        "socks5" {
            return @"
{
  "log": { "level": "info", "output": "$logsEscaped/sing-box.log" },
  "inbounds": [{
    "type": "mixed",
    "tag": "sbox-in",
    "listen": "127.0.0.1",
    "listen_port": $SboxInboundPort
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"@
        }
        "http" {
            return @"
{
  "log": { "level": "info", "output": "$logsEscaped/sing-box.log" },
  "inbounds": [{
    "type": "http",
    "tag": "sbox-in",
    "listen": "127.0.0.1",
    "listen_port": $SboxInboundPort
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"@
        }
        "shadowsocks" {
            return @"
{
  "log": { "level": "info", "output": "$logsEscaped/sing-box.log" },
  "inbounds": [{
    "type": "shadowsocks",
    "tag": "sbox-in",
    "listen": "127.0.0.1",
    "listen_port": $SboxInboundPort,
    "method": "$SsMethod",
    "password": "$SsPassword"
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"@
        }
        "anytls" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{
  "log": { "level": "info", "output": "$logsEscaped/sing-box.log" },
  "inbounds": [{
    "type": "anytls",
    "tag": "sbox-in",
    "listen": "127.0.0.1",
    "listen_port": $SboxInboundPort,
    "password": "$AnyTlsPassword",
    "tls": {
      "enabled": true,
      "certificate_path": "$certPath",
      "key_path": "$keyPath"
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"@
        }
        default { throw "unsupported outbound type: $OutboundType" }
    }
}

# ---- Generate RustBox config per outbound type ----
function Get-RustBoxConfig {
    param([string]$EventsPath)

    $common = @"
schema_version = 1

[observability]
level = "debug"
file = "$EventsPath"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:$RustboxHttpPort"

"@

    switch ($OutboundType) {
        "socks5" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "socks5"
server = "127.0.0.1"
server_port = $SboxInboundPort

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "http" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "http"
server = "127.0.0.1"
server_port = $SboxInboundPort

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "shadowsocks" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "shadowsocks"
server = "127.0.0.1"
server_port = $SboxInboundPort
method = "$SsMethod"
password = "$SsPassword"

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "anytls" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "anytls"
server = "127.0.0.1"
server_port = $SboxInboundPort
password = "$AnyTlsPassword"

[outbounds.tls]
enabled = false

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        default { throw "unsupported outbound type: $OutboundType" }
    }
}

# ---- Main ----
try {
    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary not found: $BinPath. Build first."
    }

    $Curl = Get-Curl
    $Python = Get-Python

    # Prepare work dir
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    $LogsDir = Join-Path $WorkDir "logs"
    $SboxDir = Join-Path $WorkDir "sing-box"
    $WwwDir = Join-Path $WorkDir "www"
    New-Item -ItemType Directory -Path $LogsDir, $SboxDir, $WwwDir -Force | Out-Null

    if ($OutboundType -eq "anytls") {
        $tlsDir = Join-Path $WorkDir "tls"
        New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null
        New-TlsCert -CertPath (Join-Path $tlsDir "cert.pem") -KeyPath (Join-Path $tlsDir "key.pem")
    }

    Set-Content -Path (Join-Path $WwwDir "marker.txt") -Value $Marker -Encoding ascii

    # ---- Download sing-box ----
    $SboxUrl = Get-SingBoxUrl
    $SboxArchive = Join-Path $SboxDir "sing-box-archive"
    Write-CiLog "downloading sing-box"
    Invoke-WebRequest -Uri $SboxUrl -OutFile $SboxArchive

    if ($IsWindows) {
        Expand-Archive -Path $SboxArchive -DestinationPath $SboxDir -Force
        $SboxBin = Join-Path $SboxDir "sing-box.exe"
    } else {
        tar -xzf $SboxArchive -C $SboxDir
        $SboxBin = Join-Path $SboxDir "sing-box"
        & chmod +x $SboxBin
    }
    if (-not (Test-Path $SboxBin)) { throw "sing-box binary not found after extraction" }

    # ---- Start HTTP target ----
    Write-CiLog "starting HTTP target on :$HttpTargetPort"
    $targetProc = Start-Process -FilePath $Python `
        -ArgumentList @("-m", "http.server", "$HttpTargetPort", "--bind", "127.0.0.1", "--directory", $WwwDir) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "http-target.log") `
        -RedirectStandardError (Join-Path $LogsDir "http-target.err.log")

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect("127.0.0.1", $HttpTargetPort); $c.Dispose()
            $ready = $true; break
        } catch { Start-Sleep -Milliseconds 300 }
    }
    if (-not $ready) { throw "HTTP target did not start in time" }

    # ---- Start sing-box ----
    $sboxConfig = Get-SingBoxConfig -LogsDir $LogsDir
    $SboxConfigPath = Join-Path $WorkDir "sing-box.json"
    Set-Content -Path $SboxConfigPath -Value $sboxConfig -Encoding utf8

    Write-CiLog "starting sing-box $OutboundType inbound on :$SboxInboundPort"
    $sboxProc = Start-Process -FilePath $SboxBin `
        -ArgumentList @("run", "-c", $SboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "sing-box-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "sing-box-stderr.log")

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect("127.0.0.1", $SboxInboundPort); $c.Dispose()
            $ready = $true; break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw "sing-box did not start in time" }

    # ---- Start RustBox ----
    $eventsPath = (Join-Path $LogsDir "rustbox-events.log").Replace("\", "/")
    $rustboxConfig = Get-RustBoxConfig -EventsPath $eventsPath
    $RustboxConfigPath = Join-Path $WorkDir "rustbox.toml"
    Set-Content -Path $RustboxConfigPath -Value $rustboxConfig -Encoding utf8

    Write-CiLog "starting rustbox -> sing-box $OutboundType"
    $rustboxProc = Start-Process -FilePath $BinPath `
        -ArgumentList @("run", "--config", $RustboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "rustbox-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "rustbox-stderr.log")

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect("127.0.0.1", $RustboxHttpPort); $c.Dispose()
            $ready = $true; break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw "rustbox did not start in time" }

    # ---- Curl through the chain ----
    Write-CiLog "curling: curl -> rustbox http -> $OutboundType outbound -> sing-box -> target"
    $bodyFile = Join-Path $LogsDir "curl-body.log"
    & $Curl --fail --silent --show-error --verbose `
        --max-time 15 --retry 2 --retry-delay 1 --noproxy "" `
        --proxy "http://127.0.0.1:$RustboxHttpPort" `
        --output $bodyFile `
        "http://127.0.0.1:$HttpTargetPort/marker.txt" 2> (Join-Path $LogsDir "curl.log")

    if ($LASTEXITCODE -ne 0) {
        throw "curl through $OutboundType chain failed"
    }

    $body = Get-Content -Path $bodyFile -Raw
    if (-not $body.Contains($Marker)) {
        throw "unexpected response through $OutboundType chain: $body"
    }

    Write-CiLog "PASSED: rustbox -> sing-box $OutboundType"
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
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
