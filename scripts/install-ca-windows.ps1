<#
.SYNOPSIS
    Import the SNI Frontend CA certificate into the Windows trust store.

.DESCRIPTION
    Adds ca/ca.crt to the Local Machine Trusted Root Certification Authorities
    store so browsers and tools on this machine trust every certificate the
    frontend issues. Run from an elevated (Administrator) PowerShell prompt.

.PARAMETER CertPath
    Path to the CA certificate. Defaults to ca\ca.crt relative to this script's
    parent directory.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-ca-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$CertPath = (Join-Path $PSScriptRoot '..\ca\ca.crt')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $CertPath)) {
    throw "CA certificate not found at '$CertPath'. Start the frontend once to generate it."
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent() `
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    throw 'This script must run as Administrator to write to the machine root store.'
}

$resolved = (Resolve-Path $CertPath).Path
Import-Certificate -FilePath $resolved -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Write-Host "Imported '$resolved' into Local Machine Trusted Root store." -ForegroundColor Green
Write-Host 'Restart your browser for the change to take effect.'
