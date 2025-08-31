# SecSealKit

> Secure sealing toolkit for PowerShell 5.1 - Encrypt small secrets with authenticated envelopes

SecSealKit provides a PowerShell 5.1 module for creating encrypted "envelopes" to safely store small secrets and artifacts in repositories or configuration files. It uses strong authenticated encryption (AES-256-CBC + HMAC-SHA256) with PBKDF2 key derivation and keeps passphrases out of repos via DPAPI keyfiles or Windows Credential Manager.

## Features

- **Authenticated Encryption**: SCS1 envelopes with AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
- **Strong Key Derivation**: PBKDF2-HMAC-SHA1 with configurable iterations (200k default)
- **Secure Passphrase Storage**: DPAPI keyfiles, Windows Credential Manager, or SecureString
- **Detached Signatures**: SCSIG1 integrity-only signatures using HMAC-SHA256
- **Envelope Management**: Inspect, rotate, and migrate envelopes
- **Dual Crypto Backends**: Production .NET backend + experimental from-scratch backend
- **PowerShell 5.1 Compatible**: Works on Windows PowerShell 5.1+

## Quick Start

### Installation

```powershell
# Import the module
Import-Module .\SecSealKit.psd1

# Verify installation
Get-Command -Module SecSealKit
```

### Basic Usage

```powershell
# Seal a secret string
$securePass = Read-Host -AsSecureString "Enter passphrase"
Seal-Secret -InputString "my-api-key-12345" -OutFile "secret.scs1" -PassphraseSecure $securePass

# Unseal the secret
$secret = Unseal-Secret -InFile "secret.scs1" -PassphraseSecure $securePass -AsPlainText
Write-Host "Secret: $secret"

# Inspect envelope metadata
Inspect-Envelope -InFile "secret.scs1"
```

### Using DPAPI Keyfiles

```powershell
# Create a DPAPI-protected keyfile (CurrentUser scope)
$keyBytes = New-RandomBytes 32
Write-Keyfile -Path "my-app.key" -KeyBytes $keyBytes

# Seal using the keyfile
Seal-Secret -InputString "database-password" -OutFile "db.scs1" -FromKeyfile "my-app.key"

# Unseal using the keyfile
$dbpass = Unseal-Secret -InFile "db.scs1" -FromKeyfile "my-app.key" -AsPlainText
```

### Digital Signatures

```powershell
# Sign data
Sign-Data -InputString "important document content" -OutFile "document.scsig1" -PassphraseSecure $securePass

# Verify signature
$isValid = Verify-Data -InputString "important document content" -SignatureFile "document.scsig1" -PassphraseSecure $securePass
if ($isValid) { Write-Host "+ Signature valid" } else { Write-Host "! Signature invalid" }
```

## Command Reference

### Core Operations

| Command | Purpose |
|---------|---------|
| `Seal-Secret` | Encrypt data into SCS1 envelope |
| `Unseal-Secret` | Decrypt data from SCS1 envelope |
| `Sign-Data` | Create detached SCSIG1 signature |
| `Verify-Data` | Verify detached SCSIG1 signature |
| `Rotate-Envelope` | Re-encrypt envelope with new passphrase/iterations |
| `Inspect-Envelope` | Display envelope metadata without decrypting |

### Passphrase Sources

SecSealKit supports multiple passphrase sources (in order of precedence):

1. **DPAPI Keyfile**: `-FromKeyfile <path>` - DPAPI-protected keyfile
2. **Credential Manager**: `-FromCredMan <name>` - Windows Credential Manager entry
3. **SecureString**: `-PassphraseSecure $secure` - In-memory SecureString
4. **Environment Variable**: `-FromEnv <varname>` - Environment variable (dev only)

### Backend Selection

```powershell
# Use production .NET backend (default)
Seal-Secret -InputString "data" -OutFile "file.scs1" -CryptoProvider builtin

# Use experimental from-scratch backend (with self-tests)
$env:SECSEALKIT_CRYPTO_SELFTEST = '1'
Seal-Secret -InputString "data" -OutFile "file.scs1" -CryptoProvider experimental
```

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
├── SecSealKit.psd1              # Module manifest
├── SecSealKit.psm1              # Module loader
├── public/                      # Public cmdlets
│   ├── Seal-Secret.ps1
│   ├── Unseal-Secret.ps1
│   ├── Sign-Data.ps1
│   ├── Verify-Data.ps1
│   ├── Rotate-Envelope.ps1
│   └── Inspect-Envelope.ps1
├── private/                     # Internal implementation
│   ├── Crypto.Backend.ps1       # Backend selection
│   ├── Backends/
│   │   ├── DotNet/              # Production .NET crypto
│   │   └── Custom/              # Experimental implementations
│   └── Shared/                  # Common utilities
├── tests/                       # Pester tests
└── docs/                        # Architecture and specs
```

## Development

### Running Tests

```powershell
# Run all tests
Invoke-Pester ".\tests\" -Output Detailed

# Run with experimental backend testing
$env:SECSEALKIT_CRYPTO_SELFTEST = '1'
Invoke-Pester ".\tests\" -Output Detailed
```

### Enabling Debug Logging

```powershell
# Enable verbose output
$VerbosePreference = 'Continue'
Seal-Secret -InputString "test" -OutFile "test.scs1" -PassphraseSecure $pass -Verbose
```

## Requirements

- **PowerShell**: Windows PowerShell 5.1 or later
- **Platform**: Windows (uses DPAPI and Windows Credential Manager)
- **Dependencies**: None beyond .NET Framework (included with PS 5.1)

## Limitations

- **File Size**: Optimized for small payloads (<1 MB)
- **Platform**: Windows-only (due to DPAPI/CredMan dependencies)
- **Storage**: Not a vault - no central storage or RBAC

## License

Apache-2.0 License. See [LICENSE](LICENSE) for details.

---

**⚠️ Security Notice**: This tool handles sensitive data. Review the code, understand the security model, and test thoroughly before production use. Keep passphrases and keyfiles secure.
