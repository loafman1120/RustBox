Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkDir = if ($env:RUSTBOX_CI_WORK_DIR) {
    $env:RUSTBOX_CI_WORK_DIR
} else {
    Join-Path $RootDir "target/ci-proxy-smoke"
}

$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) {
    $DefaultBin = "$DefaultBin.exe"
}
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }

$HttpProxyPort = if ($env:RUSTBOX_HTTP_PROXY_PORT) { [int]$env:RUSTBOX_HTTP_PROXY_PORT } else { 18080 }
$SocksProxyPort = if ($env:RUSTBOX_SOCKS_PROXY_PORT) { [int]$env:RUSTBOX_SOCKS_PROXY_PORT } else { 1080 }
$MixedProxyPort = if ($env:RUSTBOX_MIXED_PROXY_PORT) { [int]$env:RUSTBOX_MIXED_PROXY_PORT } else { 2080 }
$HttpTargetPort = if ($env:RUSTBOX_HTTP_TARGET_PORT) { [int]$env:RUSTBOX_HTTP_TARGET_PORT } else { 19080 }
$HttpsTargetPort = if ($env:RUSTBOX_HTTPS_TARGET_PORT) { [int]$env:RUSTBOX_HTTPS_TARGET_PORT } else { 19443 }

$Marker = "rustbox-ci-proxy-smoke-ok"
$CurlLogIndex = 0
$HadFailure = $false
$Processes = New-Object System.Collections.Generic.List[System.Diagnostics.Process]

function Write-CiLog {
    param([string]$Message)
    Write-Host "[rustbox-ci] $Message"
}

function Get-ExecutableCommand {
    param(
        [string[]]$Candidates,
        [string[]]$ProbeArguments
    )

    foreach ($Candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($Candidate)) {
            continue
        }

        $Command = Get-Command $Candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $Command) {
            continue
        }

        & $Command.Source @ProbeArguments *> $null
        if ($LASTEXITCODE -eq 0) {
            return $Command.Source
        }
    }

    throw "required executable not found: $($Candidates -join ', ')"
}

function Convert-ToTomlPath {
    param([string]$Path)
    return $Path.Replace("\", "/")
}

function New-CiTlsCertificate {
    param(
        [string]$CertPath,
        [string]$KeyPath
    )

    # Prefer openssl on Unix, fall back to .NET APIs
    $openssl = Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($openssl) {
        $keyFile = Join-Path ([System.IO.Path]::GetTempPath()) "rustbox-ci-tls-key.pem"
        $certFile = Join-Path ([System.IO.Path]::GetTempPath()) "rustbox-ci-tls-cert.pem"
        $null = & $openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile `
            -days 7 -nodes -subj "/CN=127.0.0.1" `
            -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "openssl cert generation failed" }
        Copy-Item $certFile $CertPath
        Copy-Item $keyFile $KeyPath
        Remove-Item $keyFile, $certFile -Force -ErrorAction SilentlyContinue
        return
    }

    $Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=127.0.0.1",
            $Rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $San = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $San.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
        $San.AddDnsName("localhost")
        $Request.CertificateExtensions.Add($San.Build())

        $Cert = $Request.CreateSelfSigned(
            [System.DateTimeOffset]::UtcNow.AddDays(-1),
            [System.DateTimeOffset]::UtcNow.AddDays(7)
        )
        $CertPem = [System.Security.Cryptography.PemEncoding]::WriteString("CERTIFICATE", $Cert.RawData)
        $KeyPem = [System.Security.Cryptography.PemEncoding]::WriteString("PRIVATE KEY", $Rsa.ExportPkcs8PrivateKey())

        Set-Content -Path $CertPath -Value $CertPem -Encoding ascii
        Set-Content -Path $KeyPath -Value $KeyPem -Encoding ascii
    } finally {
        $Rsa.Dispose()
    }
}

function Start-LoggedProcess {
    param(
        [string]$Label,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$StdoutPath,
        [string]$StderrPath
    )

    $Params = @{
        FilePath = $FilePath
        ArgumentList = $ArgumentList
        RedirectStandardOutput = $StdoutPath
        RedirectStandardError = $StderrPath
        PassThru = $true
        WorkingDirectory = $RootDir
    }
    if ($IsWindows) {
        $Params.WindowStyle = "Hidden"
    }

    Write-CiLog "start $Label`: $FilePath $($ArgumentList -join ' ')"
    $Process = Start-Process @Params
    $Processes.Add($Process)
    Start-Sleep -Milliseconds 250
    if ($Process.HasExited) {
        throw "$Label exited before becoming ready with code $($Process.ExitCode); command=$FilePath $($ArgumentList -join ' ')"
    }
    return $Process
}

function Wait-ForTcp {
    param(
        [string]$HostName,
        [int]$Port,
        [string]$Label
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds(20)
    $LastError = $null
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Client = [System.Net.Sockets.TcpClient]::new()
        try {
            $Client.Connect($HostName, $Port)
            if ($Client.Connected) {
                Write-CiLog "$Label is listening on ${HostName}:$Port"
                return
            }
        } catch {
            $LastError = $_.Exception.GetBaseException().Message
        } finally {
            $Client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }

    throw "timed out waiting for $Label on ${HostName}:$Port; last_error=$LastError"
}

function Invoke-CurlBodyCheck {
    param(
        [string]$Label,
        [string[]]$CurlArguments
    )

    $script:CurlLogIndex += 1
    $SafeLabel = $Label -replace "[^A-Za-z0-9._-]", "_"
    $CurlLog = Join-Path $LogsDir "curl-$CurlLogIndex-$SafeLabel.log"
    $HeaderLog = Join-Path $LogsDir "curl-$CurlLogIndex-$SafeLabel.headers.log"
    $BodyFile = Join-Path $LogsDir "curl-$CurlLogIndex-$SafeLabel.body.log"

    Write-CiLog "curl check: $Label"
    & $CurlExe `
        --fail --silent --show-error --verbose `
        --max-time 15 --retry 2 --retry-delay 1 --noproxy "" `
        --dump-header $HeaderLog `
        --output $BodyFile `
        @CurlArguments 2> $CurlLog

    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $Label; see $CurlLog"
    }

    $Body = Get-Content -Path $BodyFile -Raw
    if (-not $Body.Contains($Marker)) {
        throw "unexpected response for $Label`: $Body"
    }
}

function Stop-CiProcesses {
    foreach ($Process in $Processes) {
        try {
            if ($Process -and -not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
        }
    }
}

function Show-CiLogs {
    if (-not (Test-Path $LogsDir)) {
        return
    }

    Get-ChildItem -Path $LogsDir -Filter "*.log" | Sort-Object Name | ForEach-Object {
        Write-Host ""
        Write-Host "===== $($_.FullName) ====="
        Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
    }
}

$LogsDir = Join-Path $WorkDir "logs"
$WwwDir = Join-Path $WorkDir "www"
$TlsDir = Join-Path $WorkDir "tls"

try {
    $PythonExe = Get-ExecutableCommand -Candidates @($env:PYTHON, "python3", "python") -ProbeArguments @("--version")
    $CurlExe = Get-ExecutableCommand -Candidates @($env:CURL, "curl.exe", "curl") -ProbeArguments @("--version")

    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary is missing: $BinPath; run `cargo build -p rustbox-app` first"
    }

    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $LogsDir, $WwwDir, $TlsDir -Force | Out-Null
    Set-Content -Path (Join-Path $WwwDir "rustbox-ci.txt") -Value $Marker -Encoding ascii

    Start-LoggedProcess `
        -Label "http target" `
        -FilePath $PythonExe `
        -ArgumentList @("-m", "http.server", "$HttpTargetPort", "--bind", "127.0.0.1", "--directory", $WwwDir) `
        -StdoutPath (Join-Path $LogsDir "http-target.log") `
        -StderrPath (Join-Path $LogsDir "http-target.err.log") | Out-Null
    Wait-ForTcp -HostName "127.0.0.1" -Port $HttpTargetPort -Label "http target"

    $CertPath = Join-Path $TlsDir "cert.pem"
    $KeyPath = Join-Path $TlsDir "key.pem"
    New-CiTlsCertificate -CertPath $CertPath -KeyPath $KeyPath

    $HttpsTargetScript = Join-Path $WorkDir "https-target.py"
    Set-Content -Path $HttpsTargetScript -Encoding utf8 -Value @"
import functools
import http.server
import ssl
import sys

directory, port, cert_file, key_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_file, key_file)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"@
    Start-LoggedProcess `
        -Label "https target" `
        -FilePath $PythonExe `
        -ArgumentList @($HttpsTargetScript, $WwwDir, "$HttpsTargetPort", $CertPath, $KeyPath) `
        -StdoutPath (Join-Path $LogsDir "https-target.log") `
        -StderrPath (Join-Path $LogsDir "https-target.err.log") | Out-Null
    Wait-ForTcp -HostName "127.0.0.1" -Port $HttpsTargetPort -Label "https target"

    $EventsPath = Convert-ToTomlPath (Join-Path $LogsDir "rustbox-events.log")
    $ConfigPath = Join-Path $WorkDir "rustbox-ci.toml"
    Set-Content -Path $ConfigPath -Encoding utf8 -Value @"
schema_version = 1

[observability]
level = "debug"
file = "$EventsPath"

[[inbounds]]
id = "http"
type = "http-connect"
listen = "127.0.0.1:$HttpProxyPort"

[[inbounds]]
id = "socks"
type = "socks5"
listen = "127.0.0.1:$SocksProxyPort"

[[inbounds]]
id = "mixed"
type = "mixed"
listen = "127.0.0.1:$MixedProxyPort"

[[outbounds]]
id = "direct"
type = "direct"

[[routes]]
type = "default"
outbound = "direct"
"@

    Start-LoggedProcess `
        -Label "rustbox" `
        -FilePath $BinPath `
        -ArgumentList @("run", "--config", $ConfigPath) `
        -StdoutPath (Join-Path $LogsDir "rustbox-stdout.log") `
        -StderrPath (Join-Path $LogsDir "rustbox-stderr.log") | Out-Null

    Wait-ForTcp -HostName "127.0.0.1" -Port $HttpProxyPort -Label "http inbound"
    Wait-ForTcp -HostName "127.0.0.1" -Port $SocksProxyPort -Label "socks5 inbound"
    Wait-ForTcp -HostName "127.0.0.1" -Port $MixedProxyPort -Label "mixed inbound"

    Invoke-CurlBodyCheck `
        -Label "http inbound -> direct outbound -> local HTTP target" `
        -CurlArguments @("--proxy", "http://127.0.0.1:$HttpProxyPort", "http://127.0.0.1:$HttpTargetPort/rustbox-ci.txt")

    Invoke-CurlBodyCheck `
        -Label "http CONNECT inbound -> direct outbound -> local HTTPS target" `
        -CurlArguments @("--insecure", "--proxy", "http://127.0.0.1:$HttpProxyPort", "https://127.0.0.1:$HttpsTargetPort/rustbox-ci.txt")

    Invoke-CurlBodyCheck `
        -Label "socks5 inbound -> direct outbound -> local HTTPS target" `
        -CurlArguments @("--insecure", "--socks5-hostname", "127.0.0.1:$SocksProxyPort", "https://127.0.0.1:$HttpsTargetPort/rustbox-ci.txt")

    Invoke-CurlBodyCheck `
        -Label "mixed inbound as HTTP proxy -> direct outbound -> local HTTP target" `
        -CurlArguments @("--proxy", "http://127.0.0.1:$MixedProxyPort", "http://127.0.0.1:$HttpTargetPort/rustbox-ci.txt")

    Invoke-CurlBodyCheck `
        -Label "mixed inbound as SOCKS5 proxy -> direct outbound -> local HTTPS target" `
        -CurlArguments @("--insecure", "--socks5-hostname", "127.0.0.1:$MixedProxyPort", "https://127.0.0.1:$HttpsTargetPort/rustbox-ci.txt")

    if ($env:RUSTBOX_CI_EXTERNAL -eq "1") {
        Write-CiLog "optional external egress check is enabled"
        & $CurlExe `
            --fail --silent --show-error --verbose `
            --max-time 20 --retry 2 --retry-delay 1 --noproxy "" `
            --dump-header (Join-Path $LogsDir "curl-external-egress.headers.log") `
            --proxy "http://127.0.0.1:$HttpProxyPort" `
            --head "https://example.com/" `
            --output (Join-Path $LogsDir "curl-external-egress.body.log") `
            2> (Join-Path $LogsDir "curl-external-egress.log")
        if ($LASTEXITCODE -ne 0) {
            throw "external egress curl check failed"
        }
    } else {
        Write-CiLog "optional external egress check is disabled; set RUSTBOX_CI_EXTERNAL=1 to enable it"
    }

    $Events = Get-Content -Path (Join-Path $LogsDir "rustbox-events.log") -Raw
    foreach ($Needle in @("connection_accepted", "route_selected", "outbound_connected outbound=1", "traffic_recorded")) {
        if (-not $Events.Contains($Needle)) {
            throw "observability log is missing `$Needle`: $Needle"
        }
    }

    Write-CiLog "proxy smoke test passed"
} catch {
    Write-Error $_
    $script:HadFailure = $true
} finally {
    Stop-CiProcesses
    if ($env:RUSTBOX_CI_DUMP_LOGS -eq "1") {
        Show-CiLogs
    }
}

if ($HadFailure) {
    exit 1
}
