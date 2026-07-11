param(
    [switch]$MockSocksServer,
    [int]$ListenPort = 19081,
    [string]$Marker = "rustbox-ci-tun-smoke-ok"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-Exact {
    param([System.IO.Stream]$Stream, [int]$Length)
    $Buffer = [byte[]]::new($Length)
    $Offset = 0
    while ($Offset -lt $Length) {
        $Read = $Stream.Read($Buffer, $Offset, $Length - $Offset)
        if ($Read -eq 0) { throw "connection closed after $Offset of $Length bytes" }
        $Offset += $Read
    }
    return $Buffer
}

function Start-MockSocksServer {
    $Listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        $ListenPort
    )
    $Listener.Start()
    Write-Output "READY 127.0.0.1:$ListenPort"
    try {
        while ($true) {
            $Client = $Listener.AcceptTcpClient()
            try {
                $Client.ReceiveTimeout = 15000
                $Client.SendTimeout = 15000
                $Stream = $Client.GetStream()

                $Greeting = Read-Exact $Stream 2
                if ($Greeting[0] -ne 5) { throw "unsupported SOCKS version $($Greeting[0])" }
                $Methods = Read-Exact $Stream $Greeting[1]
                if (-not ($Methods -contains 0)) {
                    $Stream.Write([byte[]](5, 255))
                    throw "client did not offer SOCKS5 no-auth"
                }
                $Stream.Write([byte[]](5, 0))

                $Request = Read-Exact $Stream 4
                if ($Request[0] -ne 5 -or $Request[1] -ne 1 -or $Request[2] -ne 0) {
                    throw "only SOCKS5 CONNECT is supported"
                }
                switch ($Request[3]) {
                    1 {
                        $Address = [System.Net.IPAddress]::new((Read-Exact $Stream 4)).ToString()
                    }
                    3 {
                        $NameLength = (Read-Exact $Stream 1)[0]
                        $Address = [System.Text.Encoding]::ASCII.GetString((Read-Exact $Stream $NameLength))
                    }
                    4 {
                        $Address = [System.Net.IPAddress]::new((Read-Exact $Stream 16)).ToString()
                    }
                    default { throw "unsupported SOCKS5 address type $($Request[3])" }
                }
                $PortBytes = Read-Exact $Stream 2
                $TargetPort = ([int]$PortBytes[0] -shl 8) -bor $PortBytes[1]
                Write-Output "CONNECT ${Address}:$TargetPort"

                $Stream.Write([byte[]](5, 0, 0, 1, 127, 0, 0, 1, 0, 0))

                $RequestBytes = [System.Collections.Generic.List[byte]]::new()
                $Window = ""
                while ($RequestBytes.Count -lt 16384 -and $Window -ne "`r`n`r`n") {
                    $Byte = $Stream.ReadByte()
                    if ($Byte -lt 0) { break }
                    $RequestBytes.Add([byte]$Byte)
                    $Window = ($Window + [char]$Byte)
                    if ($Window.Length -gt 4) { $Window = $Window.Substring($Window.Length - 4) }
                }
                if ($Window -ne "`r`n`r`n") { throw "HTTP request header was not received" }

                $Body = "$Marker`n"
                $BodyLength = [System.Text.Encoding]::ASCII.GetByteCount($Body)
                $Response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $BodyLength`r`nConnection: close`r`n`r`n$Body"
                $ResponseBytes = [System.Text.Encoding]::ASCII.GetBytes($Response)
                $Stream.Write($ResponseBytes, 0, $ResponseBytes.Length)
                $Stream.Flush()
                Write-Output "RESPONDED $Marker"
            } catch {
                Write-Error "mock connection failed: $($_.Exception.GetBaseException().Message)"
            } finally {
                $Client.Dispose()
            }
        }
    } finally {
        $Listener.Stop()
    }
}

if ($MockSocksServer) {
    Start-MockSocksServer
    exit 0
}

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkDir = if ($env:RUSTBOX_CI_WORK_DIR) { $env:RUSTBOX_CI_WORK_DIR } else { Join-Path $RootDir "target/ci-tun-smoke" }
$LogsDir = Join-Path $WorkDir "logs"
$ConfigPath = Join-Path $WorkDir "rustbox.toml"
$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) { $DefaultBin = "$DefaultBin.exe" }
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }
$TargetAddress = "198.18.0.2"
$Processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Wait-ForLog {
    param(
        [string]$Path,
        [string]$Pattern,
        [string]$Label,
        [System.Diagnostics.Process]$Process
    )
    $Deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $Deadline) {
        if ((Test-Path $Path) -and (Select-String -Path $Path -Pattern $Pattern -Quiet)) {
            Write-Host "[tun-smoke] $Label ready"
            return
        }
        if ($Process -and $Process.HasExited) {
            throw "$Label exited before becoming ready with code $($Process.ExitCode)"
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timed out waiting for $Label; expected '$Pattern' in $Path"
}

function Start-LoggedProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$Stdout, [string]$Stderr)
    $Params = @{
        FilePath = $FilePath
        ArgumentList = $Arguments
        RedirectStandardOutput = $Stdout
        RedirectStandardError = $Stderr
        WorkingDirectory = $RootDir
        PassThru = $true
    }
    if ($IsWindows) { $Params.WindowStyle = "Hidden" }
    $Process = Start-Process @Params
    $Processes.Add($Process)
    return $Process
}

function Stop-CiProcesses {
    foreach ($Process in $Processes) {
        try {
            if ($Process -and -not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

try {
    if (-not (Test-Path $BinPath)) { throw "RustBox binary not found: $BinPath" }
    $Curl = (Get-Command @("curl.exe", "curl") -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    $Pwsh = (Get-Process -Id $PID).Path

    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $LogsDir -ItemType Directory -Force | Out-Null

    $MockOut = Join-Path $LogsDir "mock-socks.log"
    $MockErr = Join-Path $LogsDir "mock-socks-error.log"
    $MockProcess = Start-LoggedProcess $Pwsh @("-NoLogo", "-NoProfile", "-File", $PSCommandPath, "-MockSocksServer", "-ListenPort", "$ListenPort", "-Marker", $Marker) $MockOut $MockErr
    Wait-ForLog $MockOut "READY 127.0.0.1:$ListenPort" "mock SOCKS5" $MockProcess

    @"
schema_version = 1

[observability]
level = "debug"

[[inbounds]]
id = "tun"
type = "tun"
interface_name = "rustbox-ci"
addresses = ["172.18.0.1/30"]
mtu = 1500
auto_route = true
strict_route = true
route_excludes = ["127.0.0.0/8"]
platform_http_proxy = false
auto_redirect = false

[[outbounds]]
id = "mock"
type = "socks5"
server = "127.0.0.1:$ListenPort"

[[routes]]
type = "default"
outbound = "mock"
"@ | Set-Content -Path $ConfigPath -Encoding ascii

    $RustboxOut = Join-Path $LogsDir "rustbox.log"
    $RustboxErr = Join-Path $LogsDir "rustbox-error.log"
    $RustboxProcess = Start-LoggedProcess $BinPath @("run", "--config", $ConfigPath) $RustboxOut $RustboxErr
    Wait-ForLog $RustboxErr "configured proxy graph started" "RustBox TUN" $RustboxProcess

    $BodyPath = Join-Path $LogsDir "curl.body.log"
    $CurlErr = Join-Path $LogsDir "curl.log"
    & $Curl --fail --silent --show-error --verbose --max-time 15 --noproxy "*" --output $BodyPath "http://${TargetAddress}/rustbox-tun-ci" 2> $CurlErr
    if ($LASTEXITCODE -ne 0) { throw "curl failed; see $CurlErr" }
    $Body = Get-Content $BodyPath -Raw
    if (-not $Body.Contains($Marker)) { throw "unexpected response body: $Body" }
    Wait-ForLog $MockOut "CONNECT ${TargetAddress}:80" "expected SOCKS target"
    Wait-ForLog $MockOut "RESPONDED $Marker" "mock response"
    Write-Host "[tun-smoke] PASSED: TUN -> SOCKS5 -> fixed response"
} finally {
    Stop-CiProcesses
    if ($env:RUSTBOX_CI_DUMP_LOGS -eq "1") {
        Get-ChildItem $LogsDir -Filter "*.log" -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
            Write-Host "`n===== $($_.FullName) ====="
            Get-Content $_.FullName -ErrorAction SilentlyContinue
        }
    }
}
