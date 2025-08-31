---
external help file: SecSealKit-help.xml
Module Name: SecSealKit
online version:
schema: 2.0.0
---

# Seal-Secret

## SYNOPSIS
Encrypts data into an SCS1 authenticated envelope using AES-256-CBC + HMAC-SHA256.

## SYNTAX

### String
```
Seal-Secret -InputString <String> -OutFile <String> [-Iterations <Int32>] [-CryptoProvider <String>]
 [-PassphraseSecure <SecureString>] [-FromCredMan <String>] [-FromKeyfile <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### Bytes
```
Seal-Secret -InputBytes <Byte[]> -OutFile <String> [-Iterations <Int32>] [-CryptoProvider <String>]
 [-PassphraseSecure <SecureString>] [-FromCredMan <String>] [-FromKeyfile <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### File
```
Seal-Secret -InFile <String> -OutFile <String> [-Iterations <Int32>] [-CryptoProvider <String>]
 [-PassphraseSecure <SecureString>] [-FromCredMan <String>] [-FromKeyfile <String>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Seal-Secret encrypts small secrets or data into a tamper-evident SCS1 envelope format.
The envelope uses AES-256-CBC encryption with HMAC-SHA256 authentication and PBKDF2-HMAC-SHA1
key derivation.
Passphrases can be sourced from DPAPI keyfiles, Windows Credential Manager,
or SecureString objects to keep secrets out of source code.

## EXAMPLES

### EXAMPLE 1
```
$secure = Read-Host -AsSecureString "Enter passphrase"
Seal-Secret -InputString "api-key-12345" -OutFile "secret.scs1" -PassphraseSecure $secure
```

Encrypts a string using a passphrase prompt and saves to secret.scs1.

### EXAMPLE 2
```
Seal-Secret -InFile "config.json" -OutFile "config.scs1" -FromKeyfile "app.key" -Iterations 500000
```

Encrypts a configuration file using a DPAPI keyfile with high iteration count.

### EXAMPLE 3
```
Seal-Secret -InputBytes $bytes -OutFile "data.scs1" -FromCredMan "MyApp-Seal" -CryptoProvider experimental
```

Encrypts byte data using a Credential Manager entry and experimental crypto backend.

## PARAMETERS

### -InputString
The string data to encrypt.
Input will be UTF-8 encoded before encryption.

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

### -InputBytes
The raw byte array to encrypt.

```yaml
Type: Byte[]
Parameter Sets: Bytes
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InFile
Path to a file containing data to encrypt.
File contents are read as bytes.

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

### -OutFile
Path where the encrypted SCS1 envelope will be written.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Iterations
Number of PBKDF2 iterations for key derivation.
Default is 200,000.
Higher values
increase security but require more computation time.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 200000
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

### String, Byte[], or file path for data to encrypt.
## OUTPUTS

### None. Encrypted envelope is written to the specified output file.
## NOTES
- Output envelopes use SCS1 format: SCS1$kdf=PBKDF2-SHA1$iter=N$salt=b64$IV=b64$ct=b64$mac=b64
- MAC verification is performed before decryption during unsealing
- Passphrases are cleared from memory after use where possible
- Default 200k iterations provide strong security on modern hardware

## RELATED LINKS

[Unseal-Secret]()

[Inspect-Envelope]()

