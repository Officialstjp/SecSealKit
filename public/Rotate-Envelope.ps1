<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Rotate-Envelope {
	<#
	.SYNOPSIS
	Re-encrypts an SCS1 envelope with new passphrase, salt, IV, and optionally new iterations.

	.DESCRIPTION
	Rotate-Envelope performs cryptographic rotation of an existing SCS1 envelope by decrypting
	with the old credentials and re-encrypting with new credentials. This enables passphrase
	rotation and security parameter updates without exposing plaintext to disk. The original
	plaintext is preserved exactly during the rotation process.

	.PARAMETER InFile
	Path to the existing SCS1 envelope file to rotate.

	.PARAMETER OutFile
	Path where the new rotated envelope will be written.

	.PARAMETER NewIterations
	Number of PBKDF2 iterations for the new envelope. If not specified, uses the
	iteration count from the original envelope.

	.PARAMETER CryptoProvider
	Cryptographic backend to use. 'builtin' uses .NET Framework crypto (production default).
	'experimental' uses from-scratch implementations with self-testing.

	.PARAMETER OldPassphraseSecure
	SecureString containing the passphrase for decrypting the original envelope.

	.PARAMETER OldFromCredMan
	Name of a Windows Credential Manager entry containing the old passphrase.

	.PARAMETER OldFromKeyfile
	Path to a DPAPI-protected keyfile containing the old passphrase bytes.

	.PARAMETER NewPassphraseSecure
	SecureString containing the passphrase for encrypting the new envelope.

	.PARAMETER NewFromCredMan
	Name of a Windows Credential Manager entry containing the new passphrase.

	.PARAMETER NewFromKeyfile
	Path to a DPAPI-protected keyfile containing the new passphrase bytes.

	.EXAMPLE
	$oldPass = Read-Host -AsSecureString "Old passphrase"
	$newPass = Read-Host -AsSecureString "New passphrase"
	Rotate-Envelope -InFile "old.scs1" -OutFile "new.scs1" -OldPassphraseSecure $oldPass -NewPassphraseSecure $newPass

	Rotates an envelope to use a new passphrase while keeping the same iteration count.

	.EXAMPLE
	Rotate-Envelope -InFile "app.scs1" -OutFile "app-new.scs1" -OldFromKeyfile "old.key" -NewFromKeyfile "new.key" -NewIterations 500000

	Rotates an envelope from one DPAPI keyfile to another with increased iterations.

	.EXAMPLE
	Rotate-Envelope -InFile "secret.scs1" -OutFile "secret-rotated.scs1" -OldFromCredMan "OldApp" -NewFromCredMan "NewApp"

	Rotates using different Credential Manager entries for old and new passphrases.

	.INPUTS
	SCS1 envelope file path.

	.OUTPUTS
	None. New envelope is written to the specified output file.

	.NOTES
	- MAC verification is performed on the original envelope before rotation
	- New random salt and IV are generated for the rotated envelope
	- Original plaintext is never written to disk during rotation
	- Useful for regular passphrase rotation and security parameter updates
	- Both old and new passphrase sources must be accessible during rotation

	.LINK
	Seal-Secret
	.LINK
	Unseal-Secret
	#>
	$backend = Resolve-CryptoBackend -Override $CryptoProvider
	# TODO: unseal with old, reseal with new; preserve metadata; write OutFile
	Write-Verbose ("Using backend: {0}" -f $backend.Name)
	throw 'NotImplemented: rotate logic'
}

