#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Verifies that every RustBox workspace package is covered by the unsafe-code policy.
.DESCRIPTION
    Production packages must inherit `[workspace.lints]`, which forbids unsafe
    code. The generated Flutter FFI bridge is the only approved package-level
    exception and must explicitly declare `unsafe_code = "allow"`. Operating
    system target selection must remain inside `crates/platform`.
#>
[CmdletBinding()]
param(
    [switch] $Locked
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Resolve-Path (Join-Path $PSScriptRoot "../..")
$metadataArgs = @("metadata", "--no-deps", "--format-version", "1")
if ($Locked) {
    $metadataArgs += "--locked"
}

Push-Location $root
try {
    $metadataJson = & cargo @metadataArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed"
    }
    $metadata = $metadataJson | ConvertFrom-Json
    $approvedExceptions = @{
        "rustbox-flutter-bridge" = "generated Flutter FFI bridge"
    }
    $failures = [System.Collections.Generic.List[string]]::new()

    foreach ($package in $metadata.packages) {
        $manifest = Get-Content -Raw -LiteralPath $package.manifest_path
        if ($approvedExceptions.ContainsKey($package.name)) {
            if ($manifest -notmatch '(?ms)^\[lints\.rust\]\s*.*?^unsafe_code\s*=\s*"allow"\s*$') {
                $failures.Add(
                    "$($package.name): approved exception must explicitly set unsafe_code = `"allow`""
                )
            }
            continue
        }

        if ($manifest -notmatch '(?ms)^\[lints\]\s*^workspace\s*=\s*true\s*$') {
            $failures.Add(
                "$($package.name): $($package.manifest_path) must contain [lints] workspace = true"
            )
        }
    }

    foreach ($exception in $approvedExceptions.Keys) {
        if ($exception -notin $metadata.packages.name) {
            $failures.Add("stale unsafe-code exception: $exception")
        }
    }

    $portableRoots = @(
        (Join-Path $root "apps"),
        (Join-Path $root "crates")
    )
    $platformRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $root "crates/platform")
    )
    $targetOsFiles = Get-ChildItem -LiteralPath $portableRoots -Recurse -File |
        Where-Object {
            ($_.Extension -eq ".rs" -or $_.Name -eq "Cargo.toml") -and
            -not $_.FullName.StartsWith(
                $platformRoot + [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        } |
        Select-String -Pattern "target_os"
    foreach ($match in $targetOsFiles) {
        $relative = [System.IO.Path]::GetRelativePath($root, $match.Path)
        $failures.Add(
            "OS target selection must live in crates/platform: $relative`:$($match.LineNumber)"
        )
    }

    if ($failures.Count -ne 0) {
        $failures | ForEach-Object { Write-Error $_ }
        throw "workspace architecture policy is incomplete"
    }

    Write-Host (
        "Unsafe-code policy covers {0} workspace packages; approved exceptions: {1}." -f
            $metadata.packages.Count,
            ($approvedExceptions.Keys -join ", ")
    ) -ForegroundColor Green
    Write-Host "OS target selection is confined to crates/platform." -ForegroundColor Green
} finally {
    Pop-Location -ErrorAction SilentlyContinue
}
