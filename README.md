# SecSealKit

[![PSGallery Version](https://img.shields.io/powershellgallery/v/SecSealKit?label=PSGallery)](https://www.powershellgallery.com/packages/SecSealKit)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/SecSealKit)](https://www.powershellgallery.com/packages/SecSealKit)
[![License](https://img.shields.io/github/license/Officialstjp/SecSealKit)](LICENSE)

> Encrypt small secrets into authenticated envelopes — for PowerShell 5.1+

## What is this?

SecSealKit creates encrypted "envelopes" for storing secrets in git repos, config files, or anywhere you'd rather not leave plaintext lying around. Think of it as `gpg --symmetric` but PowerShell-native, with better defaults and no key management headaches.

**The idea:** You have an API key, a database password, or a license token. You want to commit it to your repo (encrypted), deploy it with your configs, or pass it between machines — without building a full secrets vault infrastructure. SecSealKit gives you that.

## Features

- **Authenticated encryption** — AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
- **Hybrid encryption** — RSA-OAEP + AES for certificate-based "sealed secrets"
- **Strong key derivation** — PBKDF2 with 200k iterations by default
- **Flexible passphrase sources** — DPAPI keyfiles, Windows Credential Manager, SecureString, or environment variables
- **Constant-time MAC verification** — resistant to timing attacks
- **Binary module** — compiled C# for speed (.NET Standard 2.0)

### What's coming

- [ ] `Rotate-Envelope` — re-key without exposing plaintext
- [ ] `New-SecSealKeyfile` — helper for DPAPI keyfile creation
- [ ] Argon2 KDF option
- [ ] AES-GCM support
- [ ] SecretManagement vault integration

## Quick Start

### Installation

```powershell
# From PowerShell Gallery (recommended)
Install-Module -Name SecSealKit -Scope CurrentUser

# Or build from source
.\scripts\Build-SecSealKit.ps1 -Configuration Release
Import-Module .\SecSealKit.psd1 -Force
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
$keyBytes = [byte[]](1..32)  # In practice, use a cryptographically random passphrase
[System.IO.File]::WriteAllBytes('my-app.key', [System.Security.Cryptography.ProtectedData]::Protect($keyBytes, $null, 'CurrentUser'))

# Protect using the keyfile
Protect-Secret -InputString "database-password" -OutFile "db.scs1" -FromKeyfile "my-app.key"

# Unprotect using the keyfile
$dbpass = Unprotect-Secret -InFile "db.scs1" -FromKeyfile "my-app.key" -AsPlainText
```

### Using Certificates (Sealed Secrets)

```powershell
# Developer (Encryption) - Needs Public Key (.cer)
$cert = Get-PfxCertificate -FilePath ".\certs\Prod-Web.cer"
Protect-Secret -InputString "db-password" -Certificate $cert -OutFile "db.scspk1"

# Server (Decryption) - Needs Private Key in Machine Store
# The module automatically finds the correct certificate by thumbprint
$secret = Unprotect-Secret -InFile "db.scspk1" -AsPlainText
```

### Digital Signatures (Integrity)

```powershell
# Sign data
Sign-Data -InputString "important document content" -OutFile "document.scsig1" -PassphraseSecure $securePass

# Verify signature
$isValid = Verify-Data -InputString "important document content" -SignatureFile "document.scsig1" -PassphraseSecure $securePass
if ($isValid) { Write-Host "+ Signature valid" } else { Write-Host "! Signature invalid" }
```

## Command Reference

### Available Commands

| Cmdlet | Alias | Purpose |
|--------|-------|---------|
| `Protect-Secret` | `Seal-Secret` | Encrypt data into SCS1 or SCSPK1 envelope |
| `Unprotect-Secret` | `Unseal-Secret` | Decrypt data from envelope |
| `Get-EnvelopeMetadata` | `Inspect-Envelope` | View envelope metadata without decryption |
| `New-Signature` | `Sign-Data` | Create HMAC-SHA256 signature |
| `Compare-Signature` | `Verify-Data` | Verify signature |

### Planned

| Command | Purpose |
|---------|---------|
| `Rotate-Envelope` | Re-encrypt with new passphrase/iterations |
| `New-SecSealKeyfile` | Create DPAPI-protected keyfiles |

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

### SCSPK1 Envelope Format (Hybrid)

```
SCSPK1$kid=<Thumbprint>$ek=<base64>$iv=<base64>$ct=<base64>$mac=<base64>
```

- **kid**: Key ID (Certificate Thumbprint)
- **ek**: Encrypted Session Key (RSA-OAEP-SHA256)
- **iv**: AES-CBC initialization vector
- **ct**: AES-256-CBC ciphertext
- **mac**: HMAC-SHA256 authentication tag

### SCSIG1 Signature Format

```
SCSIG1$kdf=PBKDF2-SHA1$iter=200000$salt=<base64>$sig=<base64>
```

- **kdf**: Key derivation function (PBKDF2-HMAC-SHA1)
- **iter**: PBKDF2 iterations for signing key
- **salt**: Random salt for signing key derivation
- **sig**: HMAC-SHA256 signature over payload (32 bytes, base64)

## Security Notes

The cryptography is intentionally boring:
- **Encrypt-then-MAC** — industry standard, MAC verified before decryption
- **PBKDF2 with 200k iterations** — slow enough to resist brute-force
- **Constant-time comparison** — no timing side-channels
- **Memory clearing** — best-effort zeroing of sensitive buffers

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

### Bulk Operations

```powershell
# Seal multiple files
Get-ChildItem "*.txt" | ForEach-Object {
    $outFile = $_.BaseName + ".scs1"
    Seal-Secret -InFile $_.FullName -OutFile $outFile -FromKeyfile "master.key"
}
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

- **Windows-only** — relies on DPAPI and Windows Credential Manager
- **Not a vault** — no central storage, access control, or audit logs

## Why not just use...?

| Alternative | When to use it instead |
|-------------|------------------------|
| **Azure Key Vault / AWS Secrets Manager** | You need centralized access control, auditing, rotation policies |
| **SecretManagement + SecretStore** | You want a local vault with a consistent API |
| **GPG** | You need cross-platform or asymmetric encryption with key rings |
| **DPAPI directly** | You only need machine/user-bound encryption, no portability |

SecSealKit fits when you want **portable encrypted files** with a simple passphrase, certificate or DPAPI keyfile — no infrastructure, no key servers, just files you can commit, copy, or deploy.

## Changelog

All notable changes to SecSealKit are documented in the [CHANGELOG.md](CHANGELOG.md).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## License

Apache-2.0 License. See [LICENSE](LICENSE) for details.

---

**Found a bug? Have an idea?** [Open an issue](https://github.com/Officialstjp/SecSealKit/issues) — contributions welcome.

**⚠️ Security Notice**: This tool handles sensitive data. Review the code, understand the security model, and test thoroughly before production use.
