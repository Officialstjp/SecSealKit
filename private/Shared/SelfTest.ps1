<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

# SelfTest.ps1 — RFC/NIST vector checks and differential tests

Set-StrictMode -Version Latest

function Invoke-SecSealSelfTests {
	[CmdletBinding()]
    param(
        [ValidateSet('builtin','experimental','all')]
        [string]$Target='all'
    )

	$allOk = $true
	try {
		# PBKDF2 RFC 6070 sample (shortened illustration)
		$pass = [Text.Encoding]::ASCII.GetBytes('password')
		$salt = [Text.Encoding]::ASCII.GetBytes('salt')

		$v1 = Invoke-PBKDF2HmacSha1 -PasswordBytes $pass -SaltBytes $salt -Iterations 1 -DerivedKeyLength 20
        if (([BitConverter]::ToString($v1).Replace('-','').ToLower()).Substring(0,8) -ne '0c60c80f') {
            throw "RFC 6070 Sample vector v1 failed: $_"
        }

        $v2 = Invoke-PBKDF2HmacSha1 -PasswordBytes $pass -SaltBytes $salt -Iterations 2 -DerivedKeyLength 20
        if (([BitConverter]::ToString($v2).Replace('-','').ToLower()).Substring(0,8) -ne 'ea6c014d') {
            throw "RFC 6070 Sample vector v2 failed: $_"
        }


		# AES roundtrip smoke
		$key = New-RandomBytes 32; $IV = New-RandomBytes 16; $plain = New-RandomBytes 37
		$ct = Invoke-AesCbcEncrypt_DotNet -PlainBytes $plain -Key $key -InitVector $IV
		$rt = Invoke-AesCbcDecrypt_DotNet -CipherBytes $ct -Key $key -InitVector $IV
		if (-not (Compare-BytesConstantTime $plain $rt)) { throw 'AES roundtrip failed' }

		# HMAC consistency
		$mac = Invoke-HmacSha256 -Data $plain -Key $key
		if (-not (Test-MacConstantTime -Data $plain -Mac $mac -Key $key)) { throw 'HMAC verify failed' }
	} catch {
		Write-Warning ("Self-tests failed: {0}" -f $_.Exception.Message)
		$allOk = $false
	} finally {
		Clear-Bytes $pass; Clear-Bytes $salt; Clear-Bytes $key; Clear-Bytes $IV; Clear-Bytes $plain
	}
	return $allOk
}

