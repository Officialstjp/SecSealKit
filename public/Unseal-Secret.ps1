<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Unseal-Secret {
    <#
    .SYNOPSIS
    Decrypts data from an SCS1 authenticated envelope using AES-256-CBC + HMAC-SHA256.

    .DESCRIPTION
    Unseal-Secret decrypts and authenticates data from an SCS1 envelope created by Seal-Secret.
    The function verifies the HMAC-SHA256 authentication tag before attempting decryption,
    providing protection against tampering. Supports multiple output formats and passphrase sources.

    .PARAMETER InFile
    Path to a file containing an SCS1 envelope to decrypt.

    .PARAMETER Envelope
    SCS1 envelope string to decrypt directly (alternative to InFile).

    .PARAMETER AsPlainText
    Return decrypted data as a UTF-8 string instead of raw bytes.

    .PARAMETER AsBytes
    Return decrypted data as a byte array (default behavior).

    .PARAMETER OutFile
    Write decrypted data to the specified file path instead of returning it.

    .PARAMETER CryptoProvider
    Cryptographic backend to use. 'builtin' uses .NET Framework crypto (production default).
    'experimental' uses from-scratch implementations with self-testing.

    .PARAMETER PassphraseSecure
    SecureString containing the passphrase for key derivation.

    .PARAMETER FromCredMan
    Name of a Windows Credential Manager entry containing the passphrase.

    .PARAMETER FromKeyfile
    Path to a DPAPI-protected keyfile containing the passphrase bytes.

    .EXAMPLE
    $secure = Read-Host -AsSecureString "Enter passphrase"
    $secret = Unseal-Secret -InFile "secret.scs1" -PassphraseSecure $secure -AsPlainText

    Decrypts an envelope file and returns the content as a string.

    .EXAMPLE
    Unseal-Secret -Envelope $envelopeString -FromKeyfile "app.key" -OutFile "decrypted.txt"

    Decrypts an envelope string using a DPAPI keyfile and writes output to a file.

    .EXAMPLE
    $bytes = Unseal-Secret -InFile "data.scs1" -FromCredMan "MyApp-Seal" -AsBytes

    Decrypts an envelope using Credential Manager and returns raw bytes.

    .INPUTS
    SCS1 envelope string or file path.

    .OUTPUTS
    Byte array, string, or file output depending on parameters.

    .NOTES
    - MAC verification is performed before decryption; tampered envelopes will throw an error
    - Same passphrase used for sealing must be provided for unsealing
    - Iteration count and salt are read from the envelope automatically
    - Decrypted data is returned as bytes by default unless -AsPlainText is specified

    .LINK
    Seal-Secret
    .LINK
    Inspect-Envelope
    #>
	[CmdletBinding()] param(
		[Parameter(ParameterSetName='File', Mandatory)][string]$InFile,
		[Parameter(ParameterSetName='String', Mandatory)][string]$Envelope,
		[switch]$AsPlainText,
		[switch]$AsBytes,
		[string]$OutFile,
		[ValidateSet('builtin','experimental')][string]$CryptoProvider,
		[SecureString]$PassphraseSecure,
		[string]$FromCredMan,
		[string]$FromKeyfile
	)
	$backend = Resolve-CryptoBackend -Override $CryptoProvider

    $text = if ($PSCmdlet.ParameterSetName -eq 'File') {
        Get-Content -Raw -LiteralPath $InFile
    } else {
        $Envelope
    }

    $obj = ConvertFrom-SCS1Envelope -Envelope $text

    $pass = Resolve-PassphraseBytes -FromKeyfile $FromKeyfile -FromCredMan $FromCredMan -PassphraseSecure $PassphraseSecure
    $dk = & $backend.DeriveKey $pass $($obj.Salt) $($obj.Iterations) 64
    $encKey = New-Object byte[](32)
    $macKey = New-Object byte[](32)
    [Array]::Copy($dk, 0, $encKey, 0, 32)
    [Array]::Copy($dk, 32, $macKey, 0, 32)

    $macInput = Get-SCS1MacInput -Iterations $obj.Iterations -Salt $obj.Salt -InitVector $obj.IV -CipherText $obj.CipherText
    if (-not (& $backend.VerifyMac $macInput $obj.Mac $macKey)) {
        throw 'MAC verification failed'
    }

    $plain = & $backend.Decrypt $obj.CipherText $encKey $obj.IV

    if ($OutFile) {
        [IO.File]::WriteAllBytes((Resolve-Path -LiteralPath $OutFile), $plain) | Out-Null
        return
    }
    if ($AsPlainText) { return [Text.Encoding]::UTF8.GetString($plain) }
    if ($AsBytes) { return $plain }
    return $plain
}

