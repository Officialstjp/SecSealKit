---
external help file: SecSealKit-help.xml
Module Name: SecSealKit
online version:
schema: 2.0.0
---

# Rotate-Envelope

## SYNOPSIS
Re-encrypts an SCS1 envelope with new passphrase, salt, IV, and optionally new iterations.

## SYNTAX

```
Rotate-Envelope
```

## DESCRIPTION
Rotate-Envelope performs cryptographic rotation of an existing SCS1 envelope by decrypting
with the old credentials and re-encrypting with new credentials.
This enables passphrase
rotation and security parameter updates without exposing plaintext to disk.
The original
plaintext is preserved exactly during the rotation process.

## EXAMPLES

### EXAMPLE 1
```
$oldPass = Read-Host -AsSecureString "Old passphrase"
$newPass = Read-Host -AsSecureString "New passphrase"
Rotate-Envelope -InFile "old.scs1" -OutFile "new.scs1" -OldPassphraseSecure $oldPass -NewPassphraseSecure $newPass
```

Rotates an envelope to use a new passphrase while keeping the same iteration count.

### EXAMPLE 2
```
Rotate-Envelope -InFile "app.scs1" -OutFile "app-new.scs1" -OldFromKeyfile "old.key" -NewFromKeyfile "new.key" -NewIterations 500000
```

Rotates an envelope from one DPAPI keyfile to another with increased iterations.

### EXAMPLE 3
```
Rotate-Envelope -InFile "secret.scs1" -OutFile "secret-rotated.scs1" -OldFromCredMan "OldApp" -NewFromCredMan "NewApp"
```

Rotates using different Credential Manager entries for old and new passphrases.

## PARAMETERS

## INPUTS

### SCS1 envelope file path.
## OUTPUTS

### None. New envelope is written to the specified output file.
## NOTES
- MAC verification is performed on the original envelope before rotation
- New random salt and IV are generated for the rotated envelope
- Original plaintext is never written to disk during rotation
- Useful for regular passphrase rotation and security parameter updates
- Both old and new passphrase sources must be accessible during rotation

## RELATED LINKS

[Seal-Secret]()

[Unseal-Secret]()

