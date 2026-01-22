<# SPDX-License-Identifier: Apache-2.0 #>
<# Copyright (c) 2025 Stefan Ploch #>



@{
    RootModule        = 'SecSealKit.dll'  # Changed from .psm1
    ModuleVersion     = '0.3.0'           # Updated version
    GUID              = 'c8da6f22-5f84-4f8a-9e58-7f6b3e6b7c9a'
    Author            = 'Stefan Ploch'
    CompanyName       = 'Stefan Ploch'
    Copyright         = '(c) 2025 Stefan Ploch. Apache-2.0'
    Description       = 'SecSealKit: Authenticated encryption for PowerShell 5.1+. Binary module with AES-256-CBC + HMAC-SHA256 SCS1 envelopes.'
    PowerShellVersion = '5.1'

    # Cmdlets are auto-exported from the DLL
    FunctionsToExport = @()
    CmdletsToExport   = @('Protect-Secret', 'Unprotect-Secret', 'Get-EnvelopeMetadata', 'New-Signature', 'Compare-Signature')
    AliasesToExport   = @('Seal-Secret', 'Unseal-Secret', 'Inspect-Envelope', 'Sign-Data', 'Verify-Data')

    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Encryption', 'Cryptography', 'AES', 'HMAC', 'Secrets')
            LicenseUri   = 'https://github.com/OfficialStjp/SecSealKit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/OfficialStjp/SecSealKit'
            ReleaseNotes = @'
v0.3.0 - Hybrid Encryption & Certificate Support

- SCSPK1 hybrid encryption (RSA-OAEP + AES-256-CBC) for certificate-based "sealed secrets"
- New Sign-Data / Verify-Data cmdlets for HMAC-SHA256 integrity checks
- Get-EnvelopeMetadata for inspecting envelopes without decryption
- Auto-discovery of certificates in Windows certificate stores

Full changelog: https://github.com/OfficialStjp/SecSealKit/blob/main/CHANGELOG.md
'@
        }
    }

	# Help info
	HelpInfoURI = 'https://github.com/OfficialStjp/SecSealKit/blob/main/docs/'
}

