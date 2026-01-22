# Changelog

All notable changes to SecSealKit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-01-22

### Added
- CI/CD workflows for GitHub Actions
- PSGallery publishing pipeline
- This changelog

## [0.3.0] - 2025-12-02

### Added
- **SCSPK1 hybrid encryption format** — RSA-OAEP + AES-256-CBC for certificate-based encryption
- `Protect-Secret -Certificate` parameter for public key encryption
- `Unprotect-Secret` auto-discovery of certificates in Windows certificate stores
- `New-Signature` / `Sign-Data` cmdlet for HMAC-SHA256 signatures
- `Compare-Signature` / `Verify-Data` cmdlet for signature verification
- SCSIG1 detached signature format
- `Get-EnvelopeMetadata` / `Inspect-Envelope` cmdlet for viewing envelope metadata

### Changed
- Cmdlets renamed to follow PowerShell conventions (aliases preserved):
  - `Seal-Secret` → `Protect-Secret`
  - `Unseal-Secret` → `Unprotect-Secret`

## [0.2.0] - 2025-11-25

Migrated from PowerShell scripts to a compiled C# binary module.

### Added
- Compiled C# binary module (`SecSealKit.dll`) targeting .NET Standard 2.0
- Constant-time MAC verification to prevent timing attacks
- Best-effort secure memory clearing for sensitive buffers

### Changed
- **Breaking:** Module is now a binary module (requires `SecSealKit.dll`)
- Massive performance improvement: ~350ms vs 7-10s for 10MB files with 200k iterations

### Removed
- Experimental "from-scratch" crypto backend
- `Set-SecSealConfig` and `Get-SecSealConfig` cmdlets
- `-CryptoProvider experimental` parameter

### Security
- Removed custom AES implementation in favor of .NET's audited crypto primitives

## [0.1.0] - 2025-09-01

Initial release. Started as a learning project to understand AES internals.

### Added
- SCS1 authenticated encryption envelope format (AES-256-CBC + HMAC-SHA256)
- SCSIG1 detached signature format (HMAC-SHA256)
- PBKDF2-HMAC-SHA1 key derivation with configurable iterations (200k default)
- Domain-separated key derivation (salt || "|scs1|")
- Multiple passphrase sources:
  - DPAPI-protected keyfiles (`-FromKeyfile`)
  - Windows Credential Manager (`-FromCredMan`)
  - SecureString (`-PassphraseSecure`)
  - Environment variables (`-FromEnv`)
- Cmdlets: `Seal-Secret`, `Unseal-Secret`, `Sign-Data`, `Verify-Data`, `Rotate-Envelope`, `Inspect-Envelope`
- Dual crypto backends:
  - `.NET` — production backend using System.Security.Cryptography
  - `experimental` — from-scratch AES (Galois Field math, S-boxes, MixColumns, ShiftRows), Key Derivation, HMAC implementations

### Notes
- Script-based module (`.psm1`)
- Windows PowerShell 5.1+ only

[0.3.1]: https://github.com/Officialstjp/SecSealKit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Officialstjp/SecSealKit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Officialstjp/SecSealKit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Officialstjp/SecSealKit/releases/tag/v0.1.0
