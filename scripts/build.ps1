#!/usr/bin/env pwsh
<#
.SYNOPSIS
    RustBox build & CI script for PowerShell 7+.
.DESCRIPTION
    Builds rustbox-app and runs checks, tests, lints, format verification,
    and documentation.  Designed for both local development and CI.
.PARAMETER Release
    Build in release mode (--release).
.PARAMETER Target
    Build for a specific target triple (e.g. x86_64-pc-windows-msvc).
.PARAMETER Features
    Comma-separated list of features to enable.
.PARAMETER NoDefaultFeatures
    Do not include default features (if any).
.PARAMETER Locked
    Pass --locked to cargo (verify Cargo.lock is up to date).
.PARAMETER Package
    Package to operate on (default: rustbox-app). Ignored when -AllTargets is set.
.PARAMETER Clean
    Remove the target directory before building.
.PARAMETER Build
    Run cargo build (default when no other action is selected).
.PARAMETER Check
    Run cargo check (fast compile check, no codegen).
.PARAMETER Test
    Run cargo test.
.PARAMETER Clippy
    Run cargo clippy with -D warnings.
.PARAMETER Fmt
    Run cargo fmt --check (verify formatting).
.PARAMETER Doc
    Run cargo doc with -D warnings.
.PARAMETER AllTargets
    Operate on the entire workspace with --all-targets (where applicable).
.EXAMPLE
    .\scripts\build.ps1
    Builds debug binary for rustbox-app.
.EXAMPLE
    .\scripts\build.ps1 -Release
    Builds release binary.
.EXAMPLE
    .\scripts\build.ps1 -Test -AllTargets
    Runs all workspace tests (all targets).
.EXAMPLE
    .\scripts\build.ps1 -Fmt -Clippy -Test -AllTargets
    CI-style: format check + lint + full test suite.
.EXAMPLE
    .\scripts\build.ps1 -Doc -AllTargets
    Builds workspace documentation, failing on warnings.
#>
[CmdletBinding(DefaultParameterSetName = "Build")]
param(
    # --- Global options ---
    [Parameter(ParameterSetName = "Build")]
    [switch] $Release,

    [Parameter(ParameterSetName = "Build")]
    [string] $Target,

    [Parameter(ParameterSetName = "Build")]
    [string] $Features,

    [Parameter(ParameterSetName = "Build")]
    [switch] $NoDefaultFeatures,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Locked,

    [Parameter(ParameterSetName = "Build")]
    [string] $Package = "rustbox-app",

    # --- Actions ---
    [Parameter(ParameterSetName = "Build")]
    [switch] $Clean,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Build,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Check,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Test,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Clippy,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Fmt,

    [Parameter(ParameterSetName = "Build")]
    [switch] $Doc,

    [Parameter(ParameterSetName = "Build")]
    [switch] $AllTargets
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")

# ----------------
# Helpers
# ----------------

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Green
}

function Get-Cargo {
    $cargo = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $cargo) {
        throw "cargo not found. Ensure Rust toolchain is installed and on PATH."
    }
    return $cargo.Source
}

function Build-CargoArgs {
    param(
        [string]$Command,
        [switch]$IncludeAllTargets
    )

    $cargoArgs = [System.Collections.Generic.List[string]]::new()

    if ($Locked) {
        $cargoArgs.Add("--locked")
    }

    if ($Command -notin @("clean", "fmt", "doc")) {
        if ($AllTargets) {
            if ($IncludeAllTargets) {
                $cargoArgs.Add("--workspace")
                $cargoArgs.Add("--all-targets")
            } else {
                $cargoArgs.Add("--workspace")
            }
        } else {
            $cargoArgs.Add("--package")
            $cargoArgs.Add($Package)
        }
    }

    if ($Command -notin @("clean", "fmt")) {
        if ($Features) {
            $cargoArgs.Add("--features")
            $cargoArgs.Add($Features)
        }
        if ($NoDefaultFeatures) {
            $cargoArgs.Add("--no-default-features")
        }
    }

    if ($Release -and $Command -notin @("check", "clippy", "clean", "fmt")) {
        $cargoArgs.Add("--release")
    }

    if ($Target) {
        $cargoArgs.Add("--target")
        $cargoArgs.Add($Target)
    }

    return $cargoArgs.ToArray()
}

# ----------------
# Main
# ----------------

try {
    $Cargo = Get-Cargo

    Push-Location $RootDir

    $hasAction = $Check -or $Test -or $Clippy -or $Fmt -or $Doc -or $Build
    if (-not $hasAction) {
        $Build = $true
    }

    # --- Clean ---
    if ($Clean) {
        Write-Step "Cleaning target directory"
        & $Cargo clean @(Build-CargoArgs "clean")
        Write-Host ""
    }

    # --- Format ---
    if ($Fmt) {
        Write-Step "Checking formatting (cargo fmt --check)"
        $fmtArgs = [System.Collections.Generic.List[string]]::new()
        $fmtArgs.Add("fmt")
        $fmtArgs.Add("--all")
        $fmtArgs.Add("--check")

        & $Cargo @fmtArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo fmt --check failed." }
        Write-Pass "Formatting OK"
    }

    # --- Check ---
    if ($Check) {
        Write-Step "Running cargo check"
        & $Cargo check @(Build-CargoArgs "check")
        if ($LASTEXITCODE -ne 0) { throw "cargo check failed." }
        Write-Pass "cargo check passed"
    }

    # --- Clippy ---
    if ($Clippy) {
        Write-Step "Running cargo clippy"
        $clippyArgs = [System.Collections.Generic.List[string]]::new()
        $clippyArgs.Add("clippy")

        if ($Locked) { $clippyArgs.Add("--locked") }

        if ($AllTargets) {
            $clippyArgs.Add("--workspace")
            $clippyArgs.Add("--all-targets")
        } else {
            $clippyArgs.Add("--package")
            $clippyArgs.Add($Package)
        }

        if ($Features)          { $clippyArgs.Add("--features");          $clippyArgs.Add($Features) }
        if ($NoDefaultFeatures) { $clippyArgs.Add("--no-default-features") }
        if ($Release)           { $clippyArgs.Add("--release") }
        if ($Target)            { $clippyArgs.Add("--target");            $clippyArgs.Add($Target) }

        $clippyArgs.Add("--")
        $clippyArgs.Add("-D")
        $clippyArgs.Add("warnings")

        & $Cargo @clippyArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }
        Write-Pass "clippy passed"
    }

    # --- Doc ---
    if ($Doc) {
        Write-Step "Building docs (cargo doc)"

        $docArgs = [System.Collections.Generic.List[string]]::new()
        $docArgs.Add("doc")
        if ($Locked) { $docArgs.Add("--locked") }
        if ($AllTargets) {
            $docArgs.Add("--workspace")
        } else {
            $docArgs.Add("--package")
            $docArgs.Add($Package)
        }
        $docArgs.Add("--no-deps")
        if ($Release) { $docArgs.Add("--release") }

        $origDocFlags = $env:RUSTDOCFLAGS
        try {
            $env:RUSTDOCFLAGS = "-D warnings $origDocFlags".TrimEnd()
            & $Cargo @docArgs
            if ($LASTEXITCODE -ne 0) { throw "cargo doc failed." }
        } finally {
            $env:RUSTDOCFLAGS = $origDocFlags
        }

        Write-Pass "docs built"
    }

    # --- Test ---
    if ($Test) {
        $desc = $AllTargets ? "workspace (all targets)" : $Package
        Write-Step "Running cargo test ($desc)"
        & $Cargo test @(Build-CargoArgs "test" -IncludeAllTargets)
        if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }
        Write-Pass "All tests passed"
    }

    # --- Build ---
    if ($Build) {
        $profile = $Release ? "release" : "debug"
        Write-Step "Building $Package ($profile)"

        & $Cargo build @(Build-CargoArgs "build")
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed." }

        $binDir = Join-Path $RootDir "target" $profile
        $binName = $IsWindows ? "$Package.exe" : $Package
        $binPath = Join-Path $binDir $binName

        Write-Pass "Build succeeded"
        Write-Host "   Binary: $binPath" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Pop-Location -ErrorAction SilentlyContinue
}
