# SecSealKit

> Secure sealing module for credential management from PowerShell 5.1 - Encrypt small secrets with authenticated envelopes

SecSealKit is a high-performance binary PowerShell module for creating encrypted "envelopes" to safely store small secrets and artifacts in repositories or configuration files. Built on compiled C# using .NET Standard 2.0 for speed and reliability, it uses strong authenticated encryption (AES-256-CBC + HMAC-SHA256) with PBKDF2 key derivation. Passphrases are kept out of code via DPAPI keyfiles or Windows Credential Manager.

## Features

- **Binary Module (v0.2+)**: Compiled C# for performance and type safety
- **Authenticated Encryption**: SCS1 envelopes with AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
- **Strong Key Derivation**: PBKDF2-HMAC-SHA1 with configurable iterations (200k default)
- **Secure Passphrase Storage**: DPAPI keyfiles, Windows Credential Manager, SecureString, or environment variables
- **Multiple Input/Output Modes**: String, bytes, files, or pipeline
- **Constant-Time Operations**: Timing-attack resistant MAC verification
- **Best-Effort Memory Safety**: Secure clearing of key material
- **Envelope Inspection**: Metadata viewing without decryption (coming soon: rotation, signatures)
- **PowerShell 5.1+ Compatible**: Windows only (requires DPAPI/CredMan)

## Planned Features:
- (complete Migration) Remaining v0.1 script cmdlets -> Binary cmdlets
- Stronger KDF (Argon 2)
- AES-GCM Support
- ECDSA Digital Signatures
- Certificate Report
- Expanded Envelope Metadata Tags
- Envelope Expiration
- Performance Tools

## Performance
**Measured Metrics:**
Encrypting 10485762 Bytes (10MB) with 200k Iterations:
- v0.1 Cmdlet: 7.5 - 10s
- v0.2 Cmdlet: ~350ms

## Quick Start

### Installation

```powershell
# Build the binary module
.\scripts\Build-SecSealKit.ps1 -Configuration Release

# Import the module
Import-Module .\SecSealKit.psd1 -Force

# Verify installation
Get-Command -Module SecSealKit
```

### Basic Usage

```powershell
# Protect a secret string (encryption)
$securePass = Read-Host -AsSecureString "Enter passphrase"
Protect-Secret -InputString "my-api-key-12345" -OutFile "secret.scs1" -PassphraseSecure $securePass

# Unprotect the secret (decryption)
$secret = Unprotect-Secret -InFile "secret.scs1" -PassphraseSecure $securePass -AsPlainText
Write-Host "Secret: $secret"

# Inspect envelope metadata (without decryption)
Inspect-Envelope -InFile "secret.scs1"
```

### Using DPAPI Keyfiles

```powershell
# Create a DPAPI-protected keyfile (CurrentUser scope)
# (helper cmdlets coming in v0.3)
$keyBytes = [byte[]](1..32)
[System.IO.File]::WriteAllBytes('my-app.key', [System.Security.Cryptography.ProtectedData]::Protect($keyBytes, $null, 'CurrentUser'))

# Protect using the keyfile
Protect-Secret -InputString "database-password" -OutFile "db.scs1" -FromKeyfile "my-app.key"

# Unprotect using the keyfile
$dbpass = Unprotect-Secret -InFile "db.scs1" -FromKeyfile "my-app.key" -AsPlainText
```

### Digital Signatures (Coming in v0.3)

```powershell
# Sign data
Sign-Data -InputString "important document content" -OutFile "document.scsig1" -PassphraseSecure $securePass

# Verify signature
$isValid = Verify-Data -InputString "important document content" -SignatureFile "document.scsig1" -PassphraseSecure $securePass
if ($isValid) { Write-Host "+ Signature valid" } else { Write-Host "! Signature invalid" }
```

## Command Reference

### Core Operations (v0.2)

| Command | Alias | Purpose | Status |
|---------|-------|---------|--------|
| `Protect-Secret` | `Seal-Secret` | Encrypt data into SCS1 envelope | ✅ Available |
| `Unprotect-Secret` | `Unseal-Secret` | Decrypt data from SCS1 envelope | ✅ Available |
| `Inspect-Envelope` | | Display envelope metadata | ✅ Available |

### Coming in v0.3+

| Command | Purpose | Target |
|---------|---------|--------|
| `Sign-Data` | Create detached SCSIG1 signature | v0.3 |
| `Verify-Data` | Verify detached SCSIG1 signature | v0.3 |
| `Rotate-Envelope` | Re-encrypt envelope with new passphrase/iterations | v0.3 |
| `New-SecSealKeyfile` | Create DPAPI-protected keyfiles | v0.3 |

### Passphrase Sources

SecSealKit supports multiple passphrase sources (in order of precedence):

1. **DPAPI Keyfile**: `-FromKeyfile <path>` - DPAPI-protected keyfile
2. **Credential Manager**: `-FromCredMan <name>` - Windows Credential Manager entry
3. **SecureString**: `-PassphraseSecure $secure` - In-memory SecureString
4. **Environment Variable**: `-FromEnv <varname>` - Environment variable (dev only)



## File Formats

### SCS1 Envelope Format

```
SCS1$kdf=PBKDF2-SHA1$iter=200000$salt=<base64>$IV=<base64>$ct=<base64>$mac=<base64>
```

- **kdf**: Key derivation function (PBKDF2-HMAC-SHA1)
- **iter**: PBKDF2 iterations (≥10000, default 200000)
- **salt**: Random salt for KDF (16+ bytes, base64)
- **IV**: AES-CBC initialization vector (16 bytes, base64)
- **ct**: AES-256-CBC ciphertext with PKCS7 padding (base64)
- **mac**: HMAC-SHA256 authentication tag (base64)

### SCSIG1 Signature Format

```
SCSIG1$kdf=PBKDF2-SHA1$iter=200000$salt=<base64>$sig=<base64>
```

- **kdf**: Key derivation function (PBKDF2-HMAC-SHA1)
- **iter**: PBKDF2 iterations for signing key
- **salt**: Random salt for signing key derivation
- **sig**: HMAC-SHA256 signature over payload (32 bytes, base64)

## Security Notes

- **Encrypt-then-MAC**: MAC verification occurs before decryption
- **Domain Separation**: KDF uses salt' = salt || "|scs1|" to prevent key reuse
- **Constant-Time Comparison**: MAC verification uses timing-safe comparison
- **Memory Clearing**: Sensitive buffers are zeroed after use where possible
- **High Iteration Count**: Default 200k PBKDF2 iterations (tunable)
- **No Secret Logging**: Logs contain only non-sensitive metadata

## Use Cases

- **Repository Secrets**: API keys, test credentials, license tokens
- **Configuration**: Small encrypted config fragments for deployment
- **Integrity**: Sign JSON payloads, scripts, or configuration files
- **Bootstrap**: Encrypted secrets unlocked on hosts via DPAPI keyfiles
- **Artifact Protection**: Protect certificate thumbprints, identifiers, etc.

## Examples

### Config file Protection
```powershell
# Server A (Encryption)
$config = @{db_user="sa"; db_pass="secret123"} | ConvertTo-Json
Seal-Secret -InputString $config -OutFile "app.scs1" -FromKeyfile "master.key"

# Server B (Decryption) - needs same keyfile
$config = Unseal-Secret -InFile "app.scs1" -FromKeyfile "master.key" -AsPlainText | ConvertFrom-Json
$dbCred = New-Object PSCredential($config.db_user, (ConvertTo-SecureString $config.db_pass -AsPlainText -Force))
```

### Script Integrity
```powershell
# Developer (Signing)
Sign-Data -InFile "deploy.ps1" -OutFile "deploy.scsig1" -FromCredMan "CodeSigning"

# Production Server (Verification)
$isValid = Verify-Data -InFile "deploy.ps1" -SignatureFile "deploy.scsig1" -FromCredMan "CodeSigning"
if ($isValid) {
    & ".\deploy.ps1"  # Only run if signature valid
} else {
    throw "Script integrity check failed!"
}
```

### Rotating Passphrases

```powershell
# Rotate to new passphrase and higher iterations
$oldPass = Read-Host -AsSecureString "Old passphrase"
$newPass = Read-Host -AsSecureString "New passphrase"

Rotate-Envelope -InFile "old.scs1" -OutFile "new.scs1" `
    -OldPassphraseSecure $oldPass -NewPassphraseSecure $newPass `
    -NewIterations 500000
```

### Bulk Operations

```powershell
# Seal multiple files
Get-ChildItem "*.txt" | ForEach-Object {
    $outFile = $_.BaseName + ".scs1"
    Seal-Secret -InFile $_.FullName -OutFile $outFile -FromKeyfile "master.key"
}

# Verify multiple signatures
$allValid = $true
Get-ChildItem "*.scsig1" | ForEach-Object {
    $dataFile = $_.BaseName
    $valid = Verify-Data -InFile $dataFile -SignatureFile $_.FullName -FromKeyfile "signing.key"
    if (-not $valid) { $allValid = $false; Write-Warning "Invalid: $dataFile" }
}
Write-Host "All signatures valid: $allValid"
```

### Integration with Credential Manager

```powershell
# Store passphrase in Windows Credential Manager
$cred = Get-Credential -UserName "SecSealKit" -Message "Enter sealing passphrase"
cmdkey /generic:"SecSealKit-MyApp" /user:$cred.UserName /pass:$cred.GetNetworkCredential().Password

# Use stored passphrase
Seal-Secret -InputString "sensitive-data" -OutFile "app.scs1" -FromCredMan "SecSealKit-MyApp"
```

## Module Structure

```
SecSealKit/
├── SecSealKit.psd1              # Module manifest (binary module)
├── SecSealKit.dll               # Compiled C# cmdlets
├── src/
│   └── SecSealKit/              # C# source code
│       ├── Cmdlets/             # PowerShell cmdlets
│       ├── Crypto/
│       │   ├── Engines/         # Seal/Unseal engines
│       │   ├── KeyDerivation/   # PBKDF2 implementation
│       │   ├── Ciphers/         # AES-256-CBC
│       │   ├── Authentication/  # HMAC-SHA256
│       │   ├── Formats/         # SCS1 envelope format
│       │   └── Utilities/       # RNG, memory, timing-safe ops
│       └── PassphraseSources/   # KeyFile, CredMan, SecureString
├── scripts/
│   └── Build-SecSealKit.ps1     # Compile script
├── tests/
│   └── Integration.Tests.ps1    # End-to-end tests
└── docs/                        # Architecture and specs
```

## Development

### Building from Source

```powershell
# Prerequisites: .NET SDK 6+ or Visual Studio

# Build Debug version
.\scripts\Build-SecSealKit.ps1 -Configuration Debug

# Build Release version
.\scripts\Build-SecSealKit.ps1 -Configuration Release
```

### Running Tests

```powershell
# Run integration tests
.\tests\Integration.Tests.ps1 -Verbose

# Run with verbose crypto logging
$VerbosePreference = 'Continue'
.\tests\Integration.Tests.ps1
```



## Requirements

### Runtime
- **PowerShell**: Windows PowerShell 5.1 or PowerShell 7+
- **Platform**: Windows only (DPAPI and Windows Credential Manager required)
- **.NET**: .NET Framework 4.7.2+ (for PS 5.1) or .NET Core (for PS 7+)
- **Dependencies**: None - compiled binary module

### Development (building from source)
- **.NET SDK**: 6.0 or later
- **C# 10+** compiler support

## Limitations

- **Platform**: Windows-only (due to DPAPI/CredMan dependencies)
- **Storage**: Not a vault - no central storage or RBAC

## License

Apache-2.0 License. See [LICENSE](LICENSE) for details.

---

**⚠️ Security Notice**: This tool handles sensitive data. Review the code, understand the security model, and test thoroughly before production use. Keep passphrases and keyfiles secure.
