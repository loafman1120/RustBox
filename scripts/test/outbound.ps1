#!/usr/bin/env pwsh
<#
.SYNOPSIS
    sing-box end-to-end outbound compatibility matrix for RustBox CI.
.DESCRIPTION
    Downloads and caches sing-box, starts it with the requested inbound
    type, then verifies RustBox can route outbound traffic through it.

    CI matrix parameter (set via env):
      RUSTBOX_SBOX_OUTBOUND = socks5 | http | shadowsocks | anytls | vmess | vless | trojan |
                               hysteria2 | tuic | naive | shadowtls | wireguard
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
$VmUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
$VlUuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
$TrojanPassword = "test-trojan-password"
$Hysteria2Password = "test-hysteria2-password"
$TuicUuid = "2dd61d93-75d8-4da4-ac0e-6aece7eac365"
$TuicPassword = "test-tuic-password"
$NaiveUsername = "rustbox"
$NaivePassword = "test-naive-password"
$ShadowTlsPassword = "test-shadowtls-password"
$ShadowTlsCoverPort = 21081
$WireGuardClientPrivateKey = $null
$WireGuardClientPublicKey = $null
$WireGuardServerPrivateKey = $null
$WireGuardServerPublicKey = $null
$SupportsUdp = $OutboundType -notin @("http", "naive", "shadowtls")
$HttpTargetProcess = $null
$SboxProcess = $null
$RustboxProcess = $null
$HadFailure = $false

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

function New-WireGuardKeyPair {
    param([string]$SingBoxBinary)

    $lines = @(& $SingBoxBinary generate wg-keypair 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw "sing-box WireGuard key generation failed: $($lines -join ' ')"
    }
    $privateLine = $lines | Where-Object { $_ -match "(?i)private" } | Select-Object -First 1
    $publicLine = $lines | Where-Object { $_ -match "(?i)public" } | Select-Object -First 1
    $keyPattern = "[A-Za-z0-9+/]{43}="
    $privateKey = [regex]::Match([string]$privateLine, $keyPattern).Value
    $publicKey = [regex]::Match([string]$publicLine, $keyPattern).Value
    if (-not $privateKey -or -not $publicKey) {
        throw "unexpected sing-box WireGuard keypair output: $($lines -join ' ')"
    }
    return @{ PrivateKey = $privateKey; PublicKey = $publicKey }
}

function Assert-IndependentSingBoxPeer {
    param([string]$SingBoxBinary)

    $lines = @(& $SingBoxBinary version 2>&1 | ForEach-Object { $_.ToString() })
    $identity = $lines -join "`n"
    if ($LASTEXITCODE -ne 0 -or $identity -notmatch "(?im)^sing-box version $([regex]::Escape($SboxVersion))$") {
        throw "E2E peer must be independent sing-box $SboxVersion, got: $($lines -join ' ')"
    }
    Write-CiLog "verified independent peer identity: sing-box $SboxVersion"
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
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"anytls","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"name":"rustbox","password":"$AnyTlsPassword"}],"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "vmess" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"vmess","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"uuid":"$VmUuid","alterId":0}],"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "vless" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"vless","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"uuid":"$VlUuid"}],"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "trojan" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"trojan","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"password":"$TrojanPassword"}],"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "hysteria2" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"hysteria2","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"up_mbps":100,"down_mbps":100,"users":[{"name":"rustbox","password":"$Hysteria2Password"}],"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "tuic" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"tuic","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"name":"rustbox","uuid":"$TuicUuid","password":"$TuicPassword"}],"congestion_control":"cubic","tls":{"enabled":true,"alpn":["h3"],"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "naive" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"naive","tag":"sbox-in","network":"tcp","listen":"127.0.0.1","listen_port":$SboxInboundPort,"users":[{"username":"$NaiveUsername","password":"$NaivePassword"}],"tls":{"enabled":true,"alpn":["h2"],"certificate_path":"$certPath","key_path":"$keyPath"}}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "shadowtls" {
            $certPath = (Join-Path $WorkDir "tls/cert.pem").Replace('\', '/')
            $keyPath  = (Join-Path $WorkDir "tls/key.pem").Replace('\', '/')
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"inbounds":[{"type":"http","tag":"cover","listen":"127.0.0.1","listen_port":$ShadowTlsCoverPort,"tls":{"enabled":true,"certificate_path":"$certPath","key_path":"$keyPath"}},{"type":"socks","tag":"shadow-inner"},{"type":"shadowtls","tag":"sbox-in","listen":"127.0.0.1","listen_port":$SboxInboundPort,"detour":"shadow-inner","version":3,"users":[{"name":"rustbox","password":"$ShadowTlsPassword"}],"handshake":{"server":"127.0.0.1","server_port":$ShadowTlsCoverPort},"strict_mode":true}],"outbounds":[{"type":"direct","tag":"direct"}]}
"@
        }
        "wireguard" {
            if (-not $WireGuardClientPublicKey -or -not $WireGuardServerPrivateKey) {
                throw "WireGuard keys were not initialized"
            }
            return @"
{"log":{"level":"info","output":"$logsEscaped/sing-box.log"},"endpoints":[{"type":"wireguard","tag":"sbox-in","address":["10.77.0.1/32"],"private_key":"$WireGuardServerPrivateKey","listen_port":$SboxInboundPort,"peers":[{"public_key":"$WireGuardClientPublicKey","allowed_ips":["10.77.0.2/32"]}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
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
output = "console-and-file"
file = "$EventsPath"

[[inbounds]]
id = "mixed"
type = "mixed"
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
        "vmess" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "vmess"
server = "127.0.0.1:$SboxInboundPort"
uuid = "$VmUuid"
security = "auto"
alter_id = 0

[outbounds.tls]
enabled = true
insecure = true

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "vless" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "vless"
server = "127.0.0.1:$SboxInboundPort"
uuid = "$VlUuid"

[outbounds.tls]
enabled = true
insecure = true

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "trojan" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "trojan"
server = "127.0.0.1:$SboxInboundPort"
password = "$TrojanPassword"

[outbounds.tls]
enabled = true
insecure = true

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "hysteria2" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "hysteria2"
server = "127.0.0.1:$SboxInboundPort"
password = "$Hysteria2Password"
server_name = "localhost"
insecure = true
up_mbps = 100
down_mbps = 100

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "tuic" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "tuic"
server = "127.0.0.1:$SboxInboundPort"
uuid = "$TuicUuid"
password = "$TuicPassword"
heartbeat = "5s"

[outbounds.tls]
enabled = true
server_name = "localhost"
insecure = true
alpn = ["h3"]

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "naive" {
            return $common + @"

[[outbounds]]
id = "sbox"
type = "naive"
server = "127.0.0.1:$SboxInboundPort"
username = "$NaiveUsername"
password = "$NaivePassword"

[outbounds.tls]
enabled = true
server_name = "localhost"
insecure = true
alpn = ["h2"]

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "shadowtls" {
            return $common + @"

[[outbounds]]
id = "shadow"
type = "shadowtls"
server = "127.0.0.1:$SboxInboundPort"
version = 3
password = "$ShadowTlsPassword"

[outbounds.tls]
enabled = true
server_name = "localhost"
insecure = true

[[outbounds]]
id = "sbox"
type = "socks5"
server = "127.0.0.1:$SboxInboundPort"
dial = { detour = "shadow" }

[[routes]]
type = "default"
outbound = "sbox"
"@
        }
        "wireguard" {
            if (-not $WireGuardClientPrivateKey -or -not $WireGuardServerPublicKey) {
                throw "WireGuard keys were not initialized"
            }
            return $common + @"

[[outbounds]]
id = "sbox"
type = "wireguard"
addresses = ["10.77.0.2/32"]
private_key = "$WireGuardClientPrivateKey"
mtu = 1408

[[outbounds.peers]]
server = "127.0.0.1:$SboxInboundPort"
public_key = "$WireGuardServerPublicKey"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = "5s"

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

function Wait-ForDatagramServer {
    param([System.Diagnostics.Process]$Process, [string]$Label)

    Start-Sleep -Seconds 1
    if ($Process.HasExited) {
        throw "$Label exited before accepting traffic (exit code $($Process.ExitCode))"
    }
    Write-CiLog "$Label is running; readiness will be proven by the external protocol handshake"
}

function Start-HttpTarget {
    param([int]$Port, [string]$Body, [string]$LogsDir)

    $params = @{
        FilePath = (Get-Process -Id $PID).Path
        ArgumentList = @(
            "-NoLogo", "-NoProfile", "-File", (Join-Path $PSScriptRoot "http_target.ps1"),
            "-Port", $Port, "-Body", $Body
        )
        PassThru = $true
        RedirectStandardOutput = Join-Path $LogsDir "http-target.log"
        RedirectStandardError = Join-Path $LogsDir "http-target.err.log"
    }
    if ($IsWindows) { $params.WindowStyle = "Hidden" }
    return Start-Process @params
}

function Read-Exact {
    param([System.IO.Stream]$Stream, [int]$Length)

    $result = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($result, $offset, $Length - $offset)
        if ($read -eq 0) { throw "SOCKS5 control stream closed" }
        $offset += $read
    }
    return $result
}

function Read-SocksEndpoint {
    param([System.IO.Stream]$Stream, [byte]$AddressType)

    switch ($AddressType) {
        1 { $address = [System.Net.IPAddress]::new((Read-Exact $Stream 4)) }
        4 { $address = [System.Net.IPAddress]::new((Read-Exact $Stream 16)) }
        3 {
            $nameLength = (Read-Exact $Stream 1)[0]
            $name = [System.Text.Encoding]::ASCII.GetString((Read-Exact $Stream $nameLength))
            $address = [System.Net.Dns]::GetHostAddresses($name)[0]
        }
        default { throw "unsupported SOCKS5 address type $AddressType" }
    }
    $portBytes = Read-Exact $Stream 2
    $port = ([int]$portBytes[0] -shl 8) -bor $portBytes[1]
    return [System.Net.IPEndPoint]::new($address, $port)
}

function Invoke-Socks5UdpProbe {
    param([string]$ProxyHost, [int]$ProxyPort)

    $control = [System.Net.Sockets.TcpClient]::new()
    $echo = $null
    $client = $null
    try {
        $control.Connect($ProxyHost, $ProxyPort)
        $control.ReceiveTimeout = 10000
        $control.SendTimeout = 10000
        $stream = $control.GetStream()
        $stream.Write([byte[]](5, 1, 0))
        $negotiation = Read-Exact $stream 2
        if ($negotiation[0] -ne 5 -or $negotiation[1] -ne 0) {
            throw "SOCKS5 proxy rejected no-auth negotiation"
        }

        $stream.Write([byte[]](5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
        $reply = Read-Exact $stream 4
        if ($reply[0] -ne 5 -or $reply[1] -ne 0 -or $reply[2] -ne 0) {
            throw "SOCKS5 UDP associate failed with reply $($reply[1])"
        }
        $relay = Read-SocksEndpoint $stream $reply[3]
        if ($relay.Address.Equals([System.Net.IPAddress]::Any) -or
            $relay.Address.Equals([System.Net.IPAddress]::IPv6Any)) {
            $relay = [System.Net.IPEndPoint]::new(
                [System.Net.Dns]::GetHostAddresses($ProxyHost)[0],
                $relay.Port
            )
        }

        $echo = [System.Net.Sockets.UdpClient]::new(
            [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0)
        )
        $client = [System.Net.Sockets.UdpClient]::new(
            [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0)
        )
        $echo.Client.ReceiveTimeout = 10000
        $client.Client.ReceiveTimeout = 10000
        $echoEndpoint = [System.Net.IPEndPoint]$echo.Client.LocalEndPoint
        $payload = [System.Text.Encoding]::ASCII.GetBytes("ping")
        $request = [byte[]]::new(10 + $payload.Length)
        $request[3] = 1
        [System.Net.IPAddress]::Loopback.GetAddressBytes().CopyTo($request, 4)
        $request[8] = [byte]($echoEndpoint.Port -shr 8)
        $request[9] = [byte]($echoEndpoint.Port -band 0xff)
        $payload.CopyTo($request, 10)
        $null = $client.Send($request, $request.Length, $relay)

        $echoPeer = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $received = $echo.Receive([ref]$echoPeer)
        $echoResponse = [System.Text.Encoding]::ASCII.GetBytes(
            "pong:$([System.Text.Encoding]::ASCII.GetString($received))"
        )
        $null = $echo.Send($echoResponse, $echoResponse.Length, $echoPeer)

        $relayPeer = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $response = $client.Receive([ref]$relayPeer)
        if ($response.Length -lt 10 -or $response[0] -ne 0 -or $response[1] -ne 0 -or
            $response[2] -ne 0 -or $response[3] -ne 1) {
            throw "invalid SOCKS5 UDP response header"
        }
        $sourceAddress = [System.Net.IPAddress]::new($response[4..7])
        $sourcePort = ([int]$response[8] -shl 8) -bor $response[9]
        $responseBody = [System.Text.Encoding]::ASCII.GetString($response[10..($response.Length - 1)])
        if (-not $sourceAddress.Equals([System.Net.IPAddress]::Loopback) -or
            $sourcePort -ne $echoEndpoint.Port -or $responseBody -ne "pong:ping") {
            throw "unexpected SOCKS5 UDP response: source=${sourceAddress}:$sourcePort body=$responseBody"
        }
    } finally {
        if ($client) { $client.Dispose() }
        if ($echo) { $echo.Dispose() }
        $control.Dispose()
    }
}

# ---- Main ----
try {
    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary not found: $BinPath. Build first."
    }

    $Curl = Get-Curl
    $SboxBin = Get-SingBoxBinary
    Assert-IndependentSingBoxPeer -SingBoxBinary $SboxBin

    if ($OutboundType -eq "wireguard") {
        Write-CiLog "generating independent WireGuard peer keypairs with sing-box"
        $clientKeys = New-WireGuardKeyPair -SingBoxBinary $SboxBin
        $serverKeys = New-WireGuardKeyPair -SingBoxBinary $SboxBin
        $WireGuardClientPrivateKey = $clientKeys.PrivateKey
        $WireGuardClientPublicKey = $clientKeys.PublicKey
        $WireGuardServerPrivateKey = $serverKeys.PrivateKey
        $WireGuardServerPublicKey = $serverKeys.PublicKey
    }

    if ($env:RUSTBOX_E2E_UDP) {
        $expectedUdp = $env:RUSTBOX_E2E_UDP -eq "1"
        if ($expectedUdp -ne $SupportsUdp) {
            throw "CI UDP expectation does not match ${OutboundType}: expected=$expectedUdp supported=$SupportsUdp"
        }
    }

    # Prepare work dir
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    $LogsDir = Join-Path $WorkDir "logs"
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null

    if ($OutboundType -in @("anytls", "vmess", "vless", "trojan", "hysteria2", "tuic", "naive", "shadowtls")) {
        $tlsDir = Join-Path $WorkDir "tls"
        New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null
        Write-CiLog "generating TLS certificate"
        New-TlsCert -CertPath (Join-Path $tlsDir "cert.pem") -KeyPath (Join-Path $tlsDir "key.pem")
    }

    # ---- Start HTTP target ----
    Write-CiLog "starting HTTP target on :$HttpTargetPort"
    $HttpTargetProcess = Start-HttpTarget -Port $HttpTargetPort -Body $Marker -LogsDir $LogsDir
    Wait-ForTcp "127.0.0.1" $HttpTargetPort "HTTP target"

    # ---- Start sing-box ----
    $sboxConfig = Get-SingBoxConfig -LogsDir $LogsDir
    $SboxConfigPath = Join-Path $WorkDir "sing-box.json"
    Set-Content -Path $SboxConfigPath -Value $sboxConfig -Encoding utf8

    Write-CiLog "starting independent sing-box $SboxVersion peer for $OutboundType on :$SboxInboundPort"
    $SboxProcess = Start-Process -FilePath $SboxBin `
        -ArgumentList @("run", "-c", $SboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "sing-box-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "sing-box-stderr.log")
    if ($OutboundType -in @("hysteria2", "tuic", "wireguard")) {
        Wait-ForDatagramServer -Process $SboxProcess -Label "sing-box"
    } else {
        Wait-ForTcp "127.0.0.1" $SboxInboundPort "sing-box"
    }

    # ---- Start RustBox ----
    $eventsPath = (Join-Path $LogsDir "rustbox-events.log").Replace("\", "/")
    $rustboxConfig = Get-RustBoxConfig -EventsPath $eventsPath
    $RustboxConfigPath = Join-Path $WorkDir "rustbox.toml"
    Set-Content -Path $RustboxConfigPath -Value $rustboxConfig -Encoding utf8

    Write-CiLog "starting rustbox -> sing-box $OutboundType"
    $RustboxProcess = Start-Process -FilePath $BinPath `
        -ArgumentList @("run", "--config", $RustboxConfigPath) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogsDir "rustbox-stdout.log") `
        -RedirectStandardError (Join-Path $LogsDir "rustbox-stderr.log")
    Wait-ForTcp "127.0.0.1" $RustboxHttpPort "rustbox"

    # ---- Curl ----
    # Session-oriented protocols get three sequential requests so the test
    # exercises reuse/multiplexing rather than only the initial stream.
    $requestCount = if ($OutboundType -in @("anytls", "hysteria2", "tuic", "naive")) { 3 } else { 1 }
    for ($request = 1; $request -le $requestCount; $request++) {
        Write-CiLog "curling ${request}/${requestCount}: curl -> rustbox -> $OutboundType -> sing-box -> target"
        $bodyFile = Join-Path $LogsDir "curl-body-$request.log"
        $curlLog = Join-Path $LogsDir "curl-$request.log"
        & $Curl --fail --silent --show-error --verbose `
            --max-time 15 --retry 2 --retry-delay 1 --noproxy "" `
            --proxy "http://127.0.0.1:$RustboxHttpPort" `
            --output $bodyFile `
            "http://127.0.0.1:$HttpTargetPort/marker.txt?request=$request" 2> $curlLog

        if ($LASTEXITCODE -ne 0) {
            throw "request $request through $OutboundType chain failed"
        }

        $body = Get-Content -Path $bodyFile -Raw
        if (-not $body.Contains($Marker)) {
            throw "request $request returned unexpected response through $OutboundType chain: $body"
        }
    }

    if ($SupportsUdp) {
        Write-CiLog "probing UDP: SOCKS5 UDP -> rustbox -> $OutboundType -> sing-box -> echo"
        Invoke-Socks5UdpProbe -ProxyHost "127.0.0.1" -ProxyPort $RustboxHttpPort
        Write-CiLog "UDP probe passed"
    } else {
        Write-CiLog "UDP probe not applicable: $OutboundType outbound is stream-only"
    }

    Write-CiLog "PASSED: $requestCount TCP request(s), rustbox -> sing-box $OutboundType"
} catch {
    $HadFailure = $true
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    foreach ($process in @($HttpTargetProcess, $SboxProcess, $RustboxProcess)) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }

    if ($HadFailure -or $env:RUSTBOX_CI_DUMP_LOGS -eq "1") {
        $logDir = Join-Path $WorkDir "logs"
        if (Test-Path $logDir) {
            Get-ChildItem -Path $logDir | ForEach-Object {
                Write-Host "`n===== $($_.Name) ====="
                Get-Content $_.FullName -ErrorAction SilentlyContinue
            }
        }
    }
}
