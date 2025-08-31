<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Seal-Secret {
	<#
	.SYNOPSIS
	Encrypts data into an SCS1 authenticated envelope using AES-256-CBC + HMAC-SHA256.

	.DESCRIPTION
	Seal-Secret encrypts small secrets or data into a tamper-evident SCS1 envelope format.
	The envelope uses AES-256-CBC encryption with HMAC-SHA256 authentication and PBKDF2-HMAC-SHA1
	key derivation. Passphrases can be sourced from DPAPI keyfiles, Windows Credential Manager,
	or SecureString objects to keep secrets out of source code.

	.PARAMETER InputString
	The string data to encrypt. Input will be UTF-8 encoded before encryption.

	.PARAMETER InputBytes
	The raw byte array to encrypt.

	.PARAMETER InFile
	Path to a file containing data to encrypt. File contents are read as bytes.

	.PARAMETER OutFile
	Path where the encrypted SCS1 envelope will be written.

	.PARAMETER Iterations
	Number of PBKDF2 iterations for key derivation. Default is 200,000. Higher values
	increase security but require more computation time.

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
	Seal-Secret -InputString "api-key-12345" -OutFile "secret.scs1" -PassphraseSecure $secure

	Encrypts a string using a passphrase prompt and saves to secret.scs1.

	.EXAMPLE
	Seal-Secret -InFile "config.json" -OutFile "config.scs1" -FromKeyfile "app.key" -Iterations 500000

	Encrypts a configuration file using a DPAPI keyfile with high iteration count.

	.EXAMPLE
	Seal-Secret -InputBytes $bytes -OutFile "data.scs1" -FromCredMan "MyApp-Seal" -CryptoProvider experimental

	Encrypts byte data using a Credential Manager entry and experimental crypto backend.

	.INPUTS
	String, Byte[], or file path for data to encrypt.

	.OUTPUTS
	None. Encrypted envelope is written to the specified output file.

	.NOTES
	- Output envelopes use SCS1 format: SCS1$kdf=PBKDF2-SHA1$iter=N$salt=b64$IV=b64$ct=b64$mac=b64
	- MAC verification is performed before decryption during unsealing
	- Passphrases are cleared from memory after use where possible
	- Default 200k iterations provide strong security on modern hardware

	.LINK
	Unseal-Secret
	.LINK
	Inspect-Envelope
	#>
	[CmdletBinding()] param(
		[Parameter(ParameterSetName='String', Mandatory)][string]$InputString,
		[Parameter(ParameterSetName='Bytes', Mandatory)][byte[]]$InputBytes,
		[Parameter(ParameterSetName='File', Mandatory)][string]$InFile,
		[Parameter(Mandatory)][string]$OutFile,
		[int]$Iterations = 200000,
		[ValidateSet('builtin','experimental')][string]$CryptoProvider,
		[Parameter()][SecureString]$PassphraseSecure,
		[string]$FromCredMan,
		[string]$FromKeyfile
	)
	$backend = Resolve-CryptoBackend -Override $CryptoProvider

    $plain = switch ($PSCmdlet.ParameterSetName) {
        'String' { [Text.Encoding]::UTF8.GetBytes($InputString) }
        'Bytes'  { $InputBytes }
        'File'   { [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InFile)) }
    }

    $salt   = New-RandomBytes 16
    $IV     = New-RandomBytes 16
    $pass   = $Null; $dk     = $Null
    $encKey = $Null; $macKey = $Null
    $ct     = $Null; $mac    = $Null

    try {
    $pass = Resolve-PassphraseBytes -FromKeyfile $FromKeyfile -FromCredMan $FromCredMan -PassphraseSecure $PassphraseSecure
        $dk = & $backend.DeriveKey $pass $salt $Iterations 64
        $encKey = New-Object byte[](32)
        $macKey = New-Object byte[](32)
        [Array]::Copy($dk, 0, $encKey, 0, 32)
        [Array]::Copy($dk, 32, $macKey, 0, 32)

    $ct = & $backend.Encrypt $plain $encKey $IV
    $macInput = Get-SCS1MacInput -Iterations $Iterations -Salt $salt -InitVector $IV -CipherText $ct
    $mac = & $backend.ComputeMac $macInput $macKey

    $envStr = ConvertTo-SCS1Envelope -Iterations $Iterations -Salt $salt -InitVector $IV -CipherText $ct -Mac $mac
    Set-Content -LiteralPath $OutFile -Value $envStr -NoNewline
        Write-Verbose ("Sealed with backend: {0}" -f $backend.Name)
    } finally {
        Clear-Bytes $plain; Clear-Bytes $salt; Clear-Bytes $IV;
        Clear-Bytes $encKey; Clear-Bytes $macKey; Clear-Bytes $ct; Clear-Bytes $mac
    }
}

