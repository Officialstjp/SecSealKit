<#
.SYNOPSIS
Builds the SecSealKit binary module and prepares it for import.

.DESCRIPTION
This script compiles the C# project and copies the resulting DLL to the module root
so it can be loaded by SecSealKit.psd1.
#>

param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module root is one level up from /scripts/
$moduleRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $moduleRoot 'src\SecSealKit\SecSealKit.csproj'

Write-Host "`nBuilding SecSealKit ($Configuration)..." -ForegroundColor Cyan

# Build the project
dotnet build $projectPath -c $Configuration --nologo

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

# Copy DLL to module root
$dllSource = Join-Path $moduleRoot "src\SecSealKit\bin\$Configuration\netstandard2.0\SecSealKit.dll"
$dllDest = Join-Path $moduleRoot 'SecSealKit.dll'

if (Test-Path $dllSource) {
    Copy-Item $dllSource $dllDest -Force
    Write-Host "+ Copied SecSealKit.dll to module root" -ForegroundColor Green
} else {
    throw "Build output not found: $dllSource"
}

Write-Host "+ Build complete!`n" -ForegroundColor Green
Write-Host "To test, run:" -ForegroundColor Yellow
Write-Host "  Import-Module '$moduleRoot\SecSealKit.psd1' -Force" -ForegroundColor White
Write-Host "  Get-Command -Module SecSealKit`n" -ForegroundColor White
