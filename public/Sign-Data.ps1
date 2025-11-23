<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Sign-Data {
	<#
	.SYNOPSIS
	Creates a detached SCSIG1 digital signature for data using HMAC-SHA256.

	.DESCRIPTION
	Sign-Data creates an integrity-only signature for arbitrary data without encryption.
	The signature uses PBKDF2-HMAC-SHA1 key derivation followed by HMAC-SHA256 signing.
	This provides data authentication and integrity verification without confidentiality.

	.PARAMETER InputString
	The string data to sign. Input will be UTF-8 encoded before signing.

	.PARAMETER InputBytes
	The raw byte array to sign.

	.PARAMETER InFile
	Path to a file containing data to sign. File contents are read as bytes.

	.PARAMETER OutFile
	Path where the SCSIG1 signature will be written.

	.PARAMETER AsString
	Return the signature as a string instead of writing to a file.

	.PARAMETER Iterations
	Number of PBKDF2 iterations for signing key derivation. Default is 200,000.

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
	$secure = Read-Host -AsSecureString "Enter signing passphrase"
	Sign-Data -InputString "important document" -OutFile "document.scsig1" -PassphraseSecure $secure

	Signs a string and writes the signature to a file.

	.EXAMPLE
	$signature = Sign-Data -InFile "script.ps1" -FromKeyfile "signing.key" -AsString

	Signs a PowerShell script using a DPAPI keyfile and returns the signature string.

	.EXAMPLE
	Sign-Data -InputBytes $payload -OutFile "payload.scsig1" -FromCredMan "CodeSigning" -Iterations 500000

	Signs byte data using Credential Manager with high iteration count.

	.INPUTS
	String, Byte[], or file path for data to sign.

	.OUTPUTS
	SCSIG1 signature string or file.

	.NOTES
	- Output signatures use SCSIG1 format: SCSIG1$kdf=PBKDF2-SHA1$iter=N$salt=b64$sig=b64
	- Signatures are detached and stored separately from the original data
	- Same passphrase must be used for both signing and verification
	- HMAC-SHA256 provides strong integrity protection with shared key authentication
	
	#>
	$backend = Resolve-CryptoBackend -Override $CryptoProvider
	# TODO: derive 32-byte signing key via PBKDF2-HMAC-SHA1; produce SCSIG1 string; write or return
	Write-Verbose ("Using backend: {0}" -f $backend.Name)
	throw 'NotImplemented: signing logic'
}

