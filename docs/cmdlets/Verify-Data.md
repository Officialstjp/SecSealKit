---
external help file: SecSealKit-help.xml
Module Name: SecSealKit
online version:
schema: 2.0.0
---

# Verify-Data

## SYNOPSIS
Verifies a detached SCSIG1 digital signature against data using HMAC-SHA256.

## SYNTAX

```
Verify-Data
```

## DESCRIPTION
Verify-Data checks the integrity and authenticity of data using a detached SCSIG1 signature
created by Sign-Data.
The function re-derives the signing key using the same passphrase
and compares signatures using constant-time comparison to prevent timing attacks.

## EXAMPLES

### EXAMPLE 1
```
$secure = Read-Host -AsSecureString "Enter signing passphrase"
$isValid = Verify-Data -InputString "important document" -SignatureFile "document.scsig1" -PassphraseSecure $secure
```

Verifies a string against its signature file.

### EXAMPLE 2
```
$verified = Verify-Data -InFile "script.ps1" -Signature $sigString -FromKeyfile "signing.key"
```

Verifies a file against a signature string using a DPAPI keyfile.

### EXAMPLE 3
```
$allValid = Get-ChildItem "*.scsig1" | ForEach-Object {
	$dataFile = $_.BaseName
	Verify-Data -InFile $dataFile -SignatureFile $_.FullName -FromCredMan "CodeSigning"
}
```

Bulk verification of multiple signature files using Credential Manager.

## PARAMETERS

## INPUTS

### String, Byte[], or file path for data to verify, plus signature file or string.
## OUTPUTS

### Boolean indicating whether the signature is valid ($true) or invalid ($false).
## NOTES
- Returns $true if signature is valid, $false if invalid or verification fails
- Uses constant-time comparison to prevent timing attacks
- Same passphrase used for signing must be provided for verification
- Iteration count and salt are read from the signature automatically
- Invalid signatures or wrong passphrases return $false rather than throwing errors

## RELATED LINKS

[Sign-Data]()

[Seal-Secret]()

