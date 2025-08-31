---
external help file: SecSealKit-help.xml
Module Name: SecSealKit
online version:
schema: 2.0.0
---

# Sign-Data

## SYNOPSIS
Creates a detached SCSIG1 digital signature for data using HMAC-SHA256.

## SYNTAX

```
Sign-Data
```

## DESCRIPTION
Sign-Data creates an integrity-only signature for arbitrary data without encryption.
The signature uses PBKDF2-HMAC-SHA1 key derivation followed by HMAC-SHA256 signing.
This provides data authentication and integrity verification without confidentiality.

## EXAMPLES

### EXAMPLE 1
```
$secure = Read-Host -AsSecureString "Enter signing passphrase"
Sign-Data -InputString "important document" -OutFile "document.scsig1" -PassphraseSecure $secure
```

Signs a string and writes the signature to a file.

### EXAMPLE 2
```
$signature = Sign-Data -InFile "script.ps1" -FromKeyfile "signing.key" -AsString
```

Signs a PowerShell script using a DPAPI keyfile and returns the signature string.

### EXAMPLE 3
```
Sign-Data -InputBytes $payload -OutFile "payload.scsig1" -FromCredMan "CodeSigning" -Iterations 500000
```

Signs byte data using Credential Manager with high iteration count.

## PARAMETERS

## INPUTS

### String, Byte[], or file path for data to sign.
## OUTPUTS

### SCSIG1 signature string or file.
## NOTES
- Output signatures use SCSIG1 format: SCSIG1$kdf=PBKDF2-SHA1$iter=N$salt=b64$sig=b64
- Signatures are detached and stored separately from the original data
- Same passphrase must be used for both signing and verification
- HMAC-SHA256 provides strong integrity protection with shared key authentication

## RELATED LINKS

[Verify-Data]()

[Seal-Secret]()

