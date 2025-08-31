<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

# AES-CBC wrappers (PKCS7 only)
using namespace System.Security.Cryptography

Set-StrictMode -Version Latest

function Invoke-AesCbcEncrypt_DotNet {
    <#
    .SYNOPSIS
    Encrypts data using AES in CBC mode with PKCS7 padding.

    #>
	[CmdletBinding()] param(
		[Parameter(Mandatory)][byte[]]$PlainBytes,
		[Parameter(Mandatory)][byte[]]$Key,
		[Parameter(Mandatory)][byte[]]$InitVector
	)
	$aes = [Aes]::Create()
	try {
		$aes.Mode = [CipherMode]::CBC
		$aes.Padding = [PaddingMode]::PKCS7
		$aes.Key = $Key; $aes.IV = $InitVector
		$enc = $aes.CreateEncryptor(); try { $enc.TransformFinalBlock($PlainBytes,0,$PlainBytes.Length) } finally { $enc.Dispose() }
	} finally { $aes.Dispose() }
}

function Invoke-AesCbcDecrypt_DotNet {
    <#
    .SYNOPSIS
    Decrypts data using AES in CBC mode with PKCS7 padding.

    #>
	[CmdletBinding()] param(
		[Parameter(Mandatory)][byte[]]$CipherBytes,
		[Parameter(Mandatory)][byte[]]$Key,
		[Parameter(Mandatory)][byte[]]$InitVector
	)
	$aes = [Aes]::Create()
	try {
		$aes.Mode = [CipherMode]::CBC
		$aes.Padding = [PaddingMode]::PKCS7
		$aes.Key = $Key; $aes.IV = $InitVector
		$dec = $aes.CreateDecryptor(); try { $dec.TransformFinalBlock($CipherBytes,0,$CipherBytes.Length) } finally { $dec.Dispose() }
	} finally { $aes.Dispose() }
}

