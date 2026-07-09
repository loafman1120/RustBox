#!/usr/bin/env pwsh
<#
.SYNOPSIS
    sing-box end-to-end outbound compatibility matrix for RustBox CI.
.DESCRIPTION
    Downloads and caches sing-box, starts it with the requested inbound
    type, then verifies RustBox can route outbound traffic through it.

    CI matrix parameter (set via env):
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

$HttpTargetPort = 18080
$RustboxHttpPort = 28080
$SboxInboundPort = 21080
$Marker = "rustbox-singbox-e2e-ok"
$SsMethod = "aes-128-gcm"
$SsPassword = "test-ss-password-123"
$AnyTlsPassword = "test-anytls-password"

function Write-CiLog {
    param([string]$Message)
    Write-Host "[sbox/$OutboundType] $Message"
}

# ---- Resolve sing-box binary (cache-aware) ----
function Get-SingBoxBinary {
    $cacheDir = if ($env:SING_BOX_CACHE_DIR) { $env:SING_BOX_CACHE_DIR }
                else { Join-Path ([System.IO.Path]::GetTempPath()) "rustbox-ci-sing-box" }

    $osArch = if ($IsLinux)   { "linux-amd64" }
         elseif ($IsMacOS)   { "darwin-arm64" }
         elseif ($IsWindows) { "windows-amd64" }
         else { throw "unsupported OS" }

    $binName = if ($IsWindows) { "sing-box.exe" } else { "sing-box" }
    $cachedBin = Join-Path $cacheDir $binName

    if (Test-Path $cachedBin) {
        Write-CiLog "using cached sing-box: $cachedBin"
        return $cachedBin
    }

    # Download
    $base = "https://github.com/SagerNet/sing-box/releases/download/v$SboxVersion"
    $asset = "sing-box-$SboxVersion-$osArch"
    if ($IsWindows) { $asset = "$asset.zip" } else { $asset = "$asset.tar.gz" }
    $url = "$base/$asset"

    Write-CiLog "downloading sing-box: $url"
    $archive = Join-Path $cacheDir "sing-box-download"
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $archive

    # Extract
    if ($IsWindows) {
        Expand-Archive -Path $archive -DestinationPath $cacheDir -Force
        # Windows zip may have sing-box.exe at root or in a subdir
        $extracted = Get-ChildItem -Path $cacheDir -Filter "sing-box.exe" -Recurse | Select-Object -First 1
        if (-not $extracted) { throw "sing-box.exe not found in archive" }
        Move-Item -Path $extracted.FullName -Destination $cachedBin -Force
    } else {
        tar -xzf $archive -C $cacheDir
        # tarball may have a root directory; find the binary regardless
        $extracted = Get-ChildItem -Path $cacheDir -Filter "sing-box" -Recurse | Select-Object -First 1
        if (-not $extracted) { throw "sing-box binary not found in archive" }
        Move-Item -Path $extracted.FullName -Destination $cachedBin -Force
        & chmod +x $cachedBin 2>$null
    }

    Remove-Item -Path $archive -Force -ErrorAction SilentlyContinue
    # Clean up any leftover subdirectory from extraction
    Get-ChildItem -Path $cacheDir -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Write-CiLog "sing-box cached at: $cachedBin"
    return $cachedBin
}

# ---- Helpers ----
$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) { $DefaultBin = "$DefaultBin.exe" }
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }

function Get-Curl {
    foreach ($c in @($env:CURL, "curl.exe", "curl")) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    throw "curl not found"
}

function Get-Python {
    foreach ($c in @("python3", "python")) {
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    throw "python not found"
}

function New-TlsCert {
    param([string]$CertPath, [string]$KeyPath)

    $keyFile = Join-Path $WorkDir "tls/temp.key"
    $certFile = Join-Path $WorkDir "tls/temp.crt"

    # Prefer openssl on Unix, fall back to .NET APIs
    $openssl = Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($openssl) {
        $null = & $openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile `
            -days 7 -nodes -subj "/CN=127.0.0.1" `
            -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "openssl cert generation failed" }
        Copy-Item $certFile $CertPath
        Copy-Item $keyFile $KeyPath
        Remove-Item $keyFile, $certFile -Force -ErrorAction SilentlyContinue
        return
    }

    # .NET fallback
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

function Get-SingBoxConfig {
    param([string]$LogsDir)
    $logsEscaped = $LogsDir.Replace('\', '/')

    switch ($OutboundType) {
        "socks5" {
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"mixed","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "http" {
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"http","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "shadowsocks" {
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"shadowsocks","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"method":"$SsMethod","password":"$SsPassword"}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "anytls" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"anytls","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"password":"$AnyTlsPassword","tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        default { throw "unsupported outbound type: $OutboundType" }
    }
}

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
server = "127.0.0.1:$SboxInboundPort"

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
server = "127.0.0.1:$SboxInboundPort"

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
server = "127.0.0.1:$SboxInboundPort"
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
server = "127.0.0.1:$SboxInboundPort"
password = "$AnyTlsPassword"

[outbounds.tls]
enabled = true
# The smoke test generates a short-lived self-signed certificate.
insecure = true

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        default { throw "unsupported outbound type: $OutboundType" }
    }
}

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
            Start-Sleep -Milliseconds 300
        }
    }
    throw "$Label did not start on ${HostName}:$Port within ${TimeoutSeconds}s"
}

# ---- Main ----
try {
    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary not found: $BinPath. Build first."
    }

    $Curl = Get-Curl
    $Python = Get-Python
    $SboxBin = Get-SingBoxBinary

    # Prepare work dir
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    $LogsDir = Join-Path $WorkDir "logs"
    $WwwDir = Join-Path $WorkDir "www"
    New-Item -ItemType Directory -Path $LogsDir, $WwwDir -Force | Out-Null

    if ($OutboundType -eq "anytls") {
        $tlsDir = Join-Path $WorkDir "tls"
        New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null
        Write-CiLog "generating TLS certificate"
        New-TlsCert -CertPath (Join-Path $tlsDir "cert.pem") -KeyPath (Join-Path $tlsDir "key.pem")
    }

    Set-Content -Path (Join-Path $WwwDir "marker.txt") -Value $Marker -Encoding ascii

    # ---- Start HTTP target ----
    Write-CiLog "starting HTTP target on :$HttpTargetPort"
    $null = Start-Process -FilePath $Python `
        -ArgumentList @("-m", "http.server", "$HttpTargetPort", "--bind", "127.0.0.1", "--directory", $WwwDir) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "http-target.log") `
        -RedirectStandardError (Join-Path $LogsDir "http-target.err.log")
    Wait-ForTcp "127.0.0.1" $HttpTargetPort "HTTP target"

    # ---- Start sing-box ----
    $sboxConfig = Get-SingBoxConfig -LogsDir $LogsDir
    $SboxConfigPath = Join-Path $WorkDir "sing-box.json"
    Set-Content -Path $SboxConfigPath -Value $sboxConfig -Encoding utf8

    Write-CiLog "starting sing-box $OutboundType inbound on :$SboxInboundPort"
    $null = Start-Process -FilePath $SboxBin `
        -ArgumentList @("run", "-c", $SboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "sing-box-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "sing-box-stderr.log")
    Wait-ForTcp "127.0.0.1" $SboxInboundPort "sing-box"

    # ---- Start RustBox ----
    $eventsPath = (Join-Path $LogsDir "rustbox-events.log").Replace("\", "/")
    $rustboxConfig = Get-RustBoxConfig -EventsPath $eventsPath
    $RustboxConfigPath = Join-Path $WorkDir "rustbox.toml"
    Set-Content -Path $RustboxConfigPath -Value $rustboxConfig -Encoding utf8

    Write-CiLog "starting rustbox -> sing-box $OutboundType"
    $null = Start-Process -FilePath $BinPath `
        -ArgumentList @("run", "--config", $RustboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "rustbox-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "rustbox-stderr.log")
    Wait-ForTcp "127.0.0.1" $RustboxHttpPort "rustbox"

    # ---- Curl ----
    Write-CiLog "curling: curl -> rustbox -> $OutboundType -> sing-box -> target"
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
