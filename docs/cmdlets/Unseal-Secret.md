---
external help file: SecSealKit-help.xml
Module Name: SecSealKit
online version:
schema: 2.0.0
---

# Unseal-Secret

## SYNOPSIS
Decrypts data from an SCS1 authenticated envelope using AES-256-CBC + HMAC-SHA256.

## SYNTAX

### File
```
Unseal-Secret -InFile <String> [-AsPlainText] [-AsBytes] [-OutFile <String>] [-CryptoProvider <String>]
 [-PassphraseSecure <SecureString>] [-FromCredMan <String>] [-FromKeyfile <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### String
```
Unseal-Secret -Envelope <String> [-AsPlainText] [-AsBytes] [-OutFile <String>] [-CryptoProvider <String>]
 [-PassphraseSecure <SecureString>] [-FromCredMan <String>] [-FromKeyfile <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Unseal-Secret decrypts and authenticates data from an SCS1 envelope created by Seal-Secret.
The function verifies the HMAC-SHA256 authentication tag before attempting decryption,
providing protection against tampering.
Supports multiple output formats and passphrase sources.

## EXAMPLES

### EXAMPLE 1
```
$secure = Read-Host -AsSecureString "Enter passphrase"
$secret = Unseal-Secret -InFile "secret.scs1" -PassphraseSecure $secure -AsPlainText
```

Decrypts an envelope file and returns the content as a string.

### EXAMPLE 2
```
Unseal-Secret -Envelope $envelopeString -FromKeyfile "app.key" -OutFile "decrypted.txt"
```

Decrypts an envelope string using a DPAPI keyfile and writes output to a file.

### EXAMPLE 3
```
$bytes = Unseal-Secret -InFile "data.scs1" -FromCredMan "MyApp-Seal" -AsBytes
```

Decrypts an envelope using Credential Manager and returns raw bytes.

## PARAMETERS

### -InFile
Path to a file containing an SCS1 envelope to decrypt.

```yaml
Type: String
Parameter Sets: File
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Envelope
SCS1 envelope string to decrypt directly (alternative to InFile).

```yaml
Type: String
Parameter Sets: String
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsPlainText
Return decrypted data as a UTF-8 string instead of raw bytes.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -AsBytes
Return decrypted data as a byte array (default behavior).

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutFile
Write decrypted data to the specified file path instead of returning it.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CryptoProvider
Cryptographic backend to use.
'builtin' uses .NET Framework crypto (production default).
'experimental' uses from-scratch implementations with self-testing.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassphraseSecure
SecureString containing the passphrase for key derivation.

```yaml
Type: SecureString
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FromCredMan
Name of a Windows Credential Manager entry containing the passphrase.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FromKeyfile
Path to a DPAPI-protected keyfile containing the passphrase bytes.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### SCS1 envelope string or file path.
## OUTPUTS

### Byte array, string, or file output depending on parameters.
## NOTES
- MAC verification is performed before decryption; tampered envelopes will throw an error
- Same passphrase used for sealing must be provided for unsealing
- Iteration count and salt are read from the envelope automatically
- Decrypted data is returned as bytes by default unless -AsPlainText is specified

## RELATED LINKS

[Seal-Secret]()

[Inspect-Envelope]()

