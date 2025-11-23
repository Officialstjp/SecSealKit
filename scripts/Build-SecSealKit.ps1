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

$moduleRoot = $PSScriptRoot
$projectPath = Join-Path $moduleRoot 'src\SecSealKit\SecSealKit.csproj'
$outputDir = Join-Path $moduleRoot 'bin'

Write-Host "Building SecSealKit ($Configuration)..." -ForegroundColor Cyan

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

Write-Host "+ Build complete. Import with: Import-Module .\SecSealKit.psd1" -ForegroundColor Green
