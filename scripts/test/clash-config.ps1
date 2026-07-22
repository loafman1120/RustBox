Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkDir = if ($env:RUSTBOX_CI_WORK_DIR) {
    $env:RUSTBOX_CI_WORK_DIR
} else {
    Join-Path $RootDir "target/ci-clash-config"
}
$DefaultBin = Join-Path $RootDir "target/debug/rustbox-app"
if ($IsWindows) {
    $DefaultBin = "$DefaultBin.exe"
}
$BinPath = if ($env:RUSTBOX_BIN) { $env:RUSTBOX_BIN } else { $DefaultBin }
$MixedPort = if ($env:RUSTBOX_CLASH_MIXED_PORT) { [int]$env:RUSTBOX_CLASH_MIXED_PORT } else { 21890 }
$TargetPort = if ($env:RUSTBOX_CLASH_TARGET_PORT) { [int]$env:RUSTBOX_CLASH_TARGET_PORT } else { 21980 }
$Marker = "rustbox-ci-clash-config-ok"
$Processes = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$HadFailure = $false

function Write-CiLog {
    param([string]$Message)
    Write-Host "[rustbox-clash-ci] $Message"
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
        throw "$Label exited early with code $($Process.ExitCode)"
    }
    return $Process
}

function Wait-ForTcp {
    param([int]$Port, [string]$Label)

    $Deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Client = [System.Net.Sockets.TcpClient]::new()
        try {
            $Client.Connect("127.0.0.1", $Port)
            if ($Client.Connected) {
                Write-CiLog "$Label is listening on 127.0.0.1:$Port"
                return
            }
        } catch {
        } finally {
            $Client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }
    throw "timed out waiting for $Label on 127.0.0.1:$Port"
}

function Invoke-ProxyCheck {
    param([string]$Label, [string[]]$ProxyArguments, [string]$LogName)

    $BodyPath = Join-Path $LogsDir "$LogName.body.log"
    $ErrorPath = Join-Path $LogsDir "$LogName.curl.log"
    Write-CiLog $Label
    & $CurlExe --fail --silent --show-error --verbose --max-time 15 --retry 2 `
        --retry-delay 1 --noproxy "" --output $BodyPath @ProxyArguments `
        "http://127.0.0.1:$TargetPort/" 2> $ErrorPath
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $Label; see $ErrorPath"
    }
    $Body = Get-Content -Path $BodyPath -Raw
    if (-not $Body.Contains($Marker)) {
        throw "unexpected body for $Label`: $Body"
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
    if (Test-Path $LogsDir) {
        Get-ChildItem -Path $LogsDir -Filter "*.log" | Sort-Object Name | ForEach-Object {
            Write-Host ""
            Write-Host "===== $($_.FullName) ====="
            Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
        }
    }
}

$LogsDir = Join-Path $WorkDir "logs"

try {
    if (-not (Test-Path $BinPath)) {
        throw "RustBox binary is missing: $BinPath"
    }
    $ResolvedRoot = [System.IO.Path]::GetFullPath($RootDir)
    $ResolvedWork = [System.IO.Path]::GetFullPath($WorkDir)
    if (-not $ResolvedWork.StartsWith($ResolvedRoot + [System.IO.Path]::DirectorySeparatorChar)) {
        throw "RUSTBOX_CI_WORK_DIR must stay inside the workspace"
    }

    $PwshExe = (Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $CurlExe = (Get-Command curl -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

    Remove-Item -LiteralPath $ResolvedWork -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null

    $ConfigPath = Join-Path $WorkDir "mihomo-e2e.yaml"
    Set-Content -Path $ConfigPath -Encoding utf8 -Value @"
mixed-port: $MixedPort
allow-lan: false

proxies:
  - name: unused-ss
    type: ss
    server: 127.0.0.1
    port: 1
    cipher: aes-128-gcm
    password: test-password

proxy-groups:
  - name: proxy
    type: select
    proxies: [DIRECT, unused-ss]

rules:
  - IP-CIDR,127.0.0.0/8,proxy,no-resolve
  - MATCH,DIRECT
"@

    Start-LoggedProcess `
        -Label "HTTP target" `
        -FilePath $PwshExe `
        -ArgumentList @("-NoLogo", "-NoProfile", "-File", (Join-Path $PSScriptRoot "http_target.ps1"), "-Port", "$TargetPort", "-Body", $Marker) `
        -StdoutPath (Join-Path $LogsDir "target.log") `
        -StderrPath (Join-Path $LogsDir "target.err.log") | Out-Null
    Wait-ForTcp -Port $TargetPort -Label "HTTP target"

    Start-LoggedProcess `
        -Label "RustBox from Clash YAML" `
        -FilePath $BinPath `
        -ArgumentList @("run", "--config", $ConfigPath) `
        -StdoutPath (Join-Path $LogsDir "rustbox.log") `
        -StderrPath (Join-Path $LogsDir "rustbox.err.log") | Out-Null
    Wait-ForTcp -Port $MixedPort -Label "Clash mixed-port"

    Invoke-ProxyCheck `
        -Label "Clash mixed-port HTTP -> selector -> DIRECT -> local target" `
        -ProxyArguments @("--proxy", "http://127.0.0.1:$MixedPort") `
        -LogName "http"
    Invoke-ProxyCheck `
        -Label "Clash mixed-port SOCKS5 -> selector -> DIRECT -> local target" `
        -ProxyArguments @("--socks5-hostname", "127.0.0.1:$MixedPort") `
        -LogName "socks5"

    Write-CiLog "Clash configuration E2E passed"
} catch {
    Write-Error $_
    $script:HadFailure = $true
} finally {
    Stop-CiProcesses
    if ($HadFailure -or $env:RUSTBOX_CI_DUMP_LOGS -eq "1") {
        Show-CiLogs
    }
}

if ($HadFailure) {
    exit 1
}
