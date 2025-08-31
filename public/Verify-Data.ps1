<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Verify-Data {
	<#
	.SYNOPSIS
	Verifies a detached SCSIG1 digital signature against data using HMAC-SHA256.

	.DESCRIPTION
	Verify-Data checks the integrity and authenticity of data using a detached SCSIG1 signature
	created by Sign-Data. The function re-derives the signing key using the same passphrase
	and compares signatures using constant-time comparison to prevent timing attacks.

	.PARAMETER InputString
	The string data to verify. Input will be UTF-8 encoded before verification.

	.PARAMETER InputBytes
	The raw byte array to verify.

	.PARAMETER InFile
	Path to a file containing data to verify. File contents are read as bytes.

	.PARAMETER SignatureFile
	Path to a file containing the SCSIG1 signature to verify against.

	.PARAMETER Signature
	SCSIG1 signature string to verify against (alternative to SignatureFile).

	.PARAMETER CryptoProvider
	Cryptographic backend to use. 'builtin' uses .NET Framework crypto (production default).
	'experimental' uses from-scratch implementations with self-testing.

	.PARAMETER PassphraseSecure
	SecureString containing the passphrase used for signing.

	.PARAMETER FromCredMan
	Name of a Windows Credential Manager entry containing the passphrase.

	.PARAMETER FromKeyfile
	Path to a DPAPI-protected keyfile containing the passphrase bytes.

	.EXAMPLE
	$secure = Read-Host -AsSecureString "Enter signing passphrase"
	$isValid = Verify-Data -InputString "important document" -SignatureFile "document.scsig1" -PassphraseSecure $secure

	Verifies a string against its signature file.

	.EXAMPLE
	$verified = Verify-Data -InFile "script.ps1" -Signature $sigString -FromKeyfile "signing.key"

	Verifies a file against a signature string using a DPAPI keyfile.

	.EXAMPLE
	$allValid = Get-ChildItem "*.scsig1" | ForEach-Object {
		$dataFile = $_.BaseName
		Verify-Data -InFile $dataFile -SignatureFile $_.FullName -FromCredMan "CodeSigning"
	}

	Bulk verification of multiple signature files using Credential Manager.

	.INPUTS
	String, Byte[], or file path for data to verify, plus signature file or string.

	.OUTPUTS
	Boolean indicating whether the signature is valid ($true) or invalid ($false).

	.NOTES
	- Returns $true if signature is valid, $false if invalid or verification fails
	- Uses constant-time comparison to prevent timing attacks
	- Same passphrase used for signing must be provided for verification
	- Iteration count and salt are read from the signature automatically
	- Invalid signatures or wrong passphrases return $false rather than throwing errors

	.LINK
	Sign-Data
	.LINK
	Seal-Secret
	#>
	$backend = Resolve-CryptoBackend -Override $CryptoProvider
	# TODO: parse SCSIG1, re-derive key, verify HMAC constant-time; return boolean or throw on failure
	Write-Verbose ("Using backend: {0}" -f $backend.Name)
	throw 'NotImplemented: verify logic'
}

