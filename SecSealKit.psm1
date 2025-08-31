<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# SecSealKit module loader
# - Loads private helpers first
# - Provides backend selection (builtin default, experimental opt-in)
# - Exports public cmdlets and test/benchmark helpers
param (
    #[ValidateSet('builtin','experimental')] # defining ValidateSet here causes "MetadataError: The attribute cannot be added because variable ProviderOverride with value  would no longer be valid."
    [string]$ProviderOverride
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level state
$script:SecSeal_Config = [ordered]@{
	CryptoProvider = if ($env:SECSEALKIT_CRYPTO_PROVIDER) { $env:SECSEALKIT_CRYPTO_PROVIDER }
                     else { 'builtin' }
}

if ($ProviderOverride -and (($ProviderOverride -ne 'builtin') -or ($ProviderOverride -ne 'experimental'))) {
    throw "Unsupported cryptography provider override specificed."
}

function Set-SecSealConfig {
	<#
	.SYNOPSIS
	Set runtime configuration for SecSealKit. Not persisted by default.
	#>
	[CmdletBinding()]
	param(
		[ValidateSet('builtin','experimental')][string]$CryptoProvider
	)
	if ($PSBoundParameters.ContainsKey('CryptoProvider')) { $script:SecSeal_Config.CryptoProvider = $CryptoProvider }
}

function Get-SecSealConfig {
    [CmdletBinding()]
    param()
    $script:SecSeal_Config
}

# Dot-source Private helpers in deterministic order
$moduleRoot = Split-Path -Parent $PSCommandPath
$privateDir = Join-Path $moduleRoot 'private'
$publicDir  = Join-Path $moduleRoot 'public'

# Shared primitives
. (Join-Path $privateDir 'Shared\Utils.ps1')
. (Join-Path $privateDir 'Shared\Envelope.Format.ps1')
. (Join-Path $privateDir 'Shared\SelfTest.ps1')

# Preload backend providers
. (Join-Path $privateDir 'Backends\DotNet\Pbkdf2.DotNet.ps1')
. (Join-Path $privateDir 'Backends\DotNet\AesCbc.DotNet.ps1')
. (Join-Path $privateDir 'Backends\Custom\Pbkdf2.Custom.ps1')
. (Join-Path $privateDir 'Backends\Custom\AesCbc.Custom.ps1')

# default backend selector (cmdlets allow individual override)
. (Join-Path $privateDir 'Crypto.Backend.ps1')

# Providers
. (Join-Path $privateDir 'Shared\DPAPI.ps1')
. (Join-Path $privateDir 'Shared\WSCredMan.ps1')
. (Join-Path $privateDir 'Shared\Passphrase.Providers.ps1')

# Dot-source Public cmdlets
Get-ChildItem -Path $publicDir -Filter '*.ps1' | Sort-Object FullName | ForEach-Object { . $_.FullName }

Export-ModuleMember -Function @(
	'Seal-Secret','Unseal-Secret','Sign-Data','Verify-Data','Rotate-Envelope','Inspect-Envelope',
	'Test-SecSealCrypto','Benchmark-SecSealCrypto','Set-SecSealConfig','Get-SecSealConfig'
)


