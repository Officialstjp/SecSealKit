<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Inspect-Envelope {
	<#
	.SYNOPSIS
	Displays metadata and structure information from an SCS1 envelope without decryption.

	.DESCRIPTION
	Inspect-Envelope parses and displays the cryptographic parameters and metadata from
	an SCS1 envelope without requiring the passphrase or performing decryption. This is
	useful for auditing envelope formats, checking iteration counts, and verifying envelope
	integrity before attempting unsealing operations.

	.PARAMETER InFile
	Path to a file containing an SCS1 envelope to inspect.

	.PARAMETER Envelope
	SCS1 envelope string to inspect directly (alternative to InFile).

	.EXAMPLE
	Inspect-Envelope -InFile "secret.scs1"

	Displays metadata for an envelope file including version, iterations, and field lengths.

	.EXAMPLE
	$info = Inspect-Envelope -Envelope $envelopeString
	Write-Host "Iteration count: $($info.Iter)"

	Inspects an envelope string and accesses specific metadata properties.

	.EXAMPLE
	Get-ChildItem "*.scs1" | ForEach-Object {
		$info = Inspect-Envelope -InFile $_.FullName
		Write-Host "$($_.Name): $($info.Version), $($info.Iter) iterations"
	}

	Bulk inspection of multiple envelope files to check their security parameters.

	.INPUTS
	SCS1 envelope string or file path.

	.OUTPUTS
	PSCustomObject with envelope metadata including Version, Iter, SaltLen, IVLen, CtLen, MacLen.

	.NOTES
	- Does not require passphrase or perform any cryptographic operations
	- Useful for auditing and troubleshooting envelope files
	- Validates envelope structure and reports parsing errors
	- Output includes format version, iteration count, and field lengths in bytes
	- Salt and IV lengths should be 16 bytes for SCS1 envelopes

	.LINK
	Seal-Secret
	.LINK
	Unseal-Secret
	#>
	$text = if ($PSCmdlet.ParameterSetName -eq 'File') { Get-Content -Raw -LiteralPath $InFile } else { $Envelope }
	$parsed = ConvertFrom-SCS1Envelope -Envelope $text
	[pscustomobject]@{
		Version   = $parsed.Prefix
		Iter      = $parsed.Iterations
		SaltLen   = $parsed.Salt.Length
		IVLen     = $parsed.IV.Length
		CtLen     = $parsed.CipherText.Length
		MacLen    = $parsed.Mac.Length
	}
}

