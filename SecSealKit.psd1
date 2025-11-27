<# SPDX-License-Identifier: Apache-2.0 #>
<# Copyright (c) 2025 Stefan Ploch #>



@{
    RootModule        = 'SecSealKit.dll'  # Changed from .psm1
    ModuleVersion     = '0.2.0'           # Updated version
    GUID              = 'c8da6f22-5f84-4f8a-9e58-7f6b3e6b7c9a'
    Author            = 'Stefan Ploch'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2025 Stefan Ploch. Apache-2.0'
    Description       = 'SecSealKit: Authenticated encryption for PowerShell 5.1+. Binary module with AES-256-CBC + HMAC-SHA256 SCS1 envelopes.'
    PowerShellVersion = '5.1'

    # Cmdlets are auto-exported from the DLL
    FunctionsToExport = @()
    CmdletsToExport   = @('Protect-Secret', 'Unprotect-Secret', 'Get-EnvelopeMetadata')
    AliasesToExport   = @('Seal-Secret', 'Unseal-Secret', 'Inspect-Envelope')

    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Encryption', 'Cryptography', 'AES', 'HMAC', 'Secrets')
            LicenseUri   = 'https://github.com/OfficialStjp/SecSealKit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/OfficialStjp/SecSealKit'
            ReleaseNotes = @'
v0.2.0 - Binary Module Migration

Changes:
- Migrated to compiled C# binary module for performance and type safety
- Removed experimental crypto backend (security)
- Cmdlet names: Seal-Secret → Protect-Secret (aliases preserved)

Features:
- SCS1 authenticated encryption (AES-256-CBC + HMAC-SHA256)
- PBKDF2-HMAC-SHA1 with 200k default iterations
- Multiple passphrase sources: SecureString, DPAPI keyfiles, CredMan, environment variables
- Constant-time MAC verification
- Best-effort secure memory clearing

Compatibility:
- PowerShell 5.1+ (Windows only)
- SCS1 envelope format unchanged (v0.1 envelopes still work)
'@
        }
    }

	# Help info
	HelpInfoURI = 'https://github.com/OfficialStjp/SecSealKit/blob/main/docs/'
}

