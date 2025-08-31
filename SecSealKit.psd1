<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


@{
	# SecSealKit PowerShell Module Manifest
	RootModule        = 'SecSealKit.psm1'
	ModuleVersion     = '0.1.0'
	GUID              = 'c8da6f22-5f84-4f8a-9e58-7f6b3e6b7c9a'
	Author            = 'Stefan Ploch'
	CompanyName       = 'Unknown'
	Copyright         = '(c) 2025 Stefan Ploch. Apache-2.0'
	Description       = 'SecSealKit: Authenticated encryption and digital signatures for Windows PowerShell 5.1. Seal secrets into tamper-evident SCS1 envelopes using AES-256-CBC + HMAC-SHA256.'
	PowerShellVersion = '5.1'
	RequiredModules   = @()
	RequiredAssemblies = @()

	# Explicit exports; keep public surface small and clear.
	FunctionsToExport = @(
		'Seal-Secret',
		'Unseal-Secret',
		'Sign-Data',
		'Verify-Data',
		'Rotate-Envelope',
		'Inspect-Envelope',
		'Set-SecSealConfig',
		'Get-SecSealConfig'
	)
	CmdletsToExport   = @()
	VariablesToExport = @()
	AliasesToExport   = @()

	# Module metadata for PowerShell Gallery
	PrivateData = @{
		PSData = @{
			Tags = @('Security', 'Cryptography', 'Encryption', 'Authentication', 'HMAC', 'AES', 'Secrets', 'Windows', 'PowerShell51')
			LicenseUri = 'https://github.com/OfficialStjp/SecSealKit/blob/main/LICENSE'
			ProjectUri = 'https://github.com/OfficialStjp/SecSealKit'
			# IconUri = 'https://github.com/OfficialStjp/SecSealKit/blob/main/icon.png'
			ReleaseNotes = @'
Initial release of SecSealKit v0.1.0

Features:
- SCS1 authenticated encryption envelopes (AES-256-CBC + HMAC-SHA256)
- SCSIG1 detached signatures (HMAC-SHA256)
- PBKDF2-HMAC-SHA1 key derivation with configurable iterations
- Multiple passphrase sources: DPAPI keyfiles, Windows Credential Manager, SecureString
- Dual crypto backends: production .NET and experimental from-scratch
- Envelope management: seal, unseal, inspect, rotate
- PowerShell 5.1 compatible, Windows-only

Security:
- Encrypt-then-MAC design with constant-time verification
- Domain-separated key derivation (salt || "|scs1|")
- Secure memory clearing where possible
- Default 200k PBKDF2 iterations
'@
			ExternalModuleDependencies = @()
		}
	}

	# Help info
	HelpInfoURI = 'https://github.com/OfficialStjp/SecSealKit/blob/main/docs/'
}

