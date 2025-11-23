<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# Crypto backend selector and contract (internal)

Set-StrictMode -Version Latest

$script:_backendCache = $null

function Resolve-CryptoBackend {
	<#
	.SYNOPSIS
    Resolve backend based on param/env/config. Defaults to builtin.
	.PARAMETER Override
    Provider name: builtin|experimental
	#>
	[CmdletBinding()]
	param(
        [ValidateSet('builtin','experimental')][string]$Override
    )

	if ($script:_backendCache -ne $null -and [string]::IsNullOrWhiteSpace($Override)) { return $script:_backendCache }

	$provider = if ($Override) { $Override } elseif ($script:SecSeal_Config.CryptoProvider) { $script:SecSeal_Config.CryptoProvider } else { 'builtin' }

    switch ($provider) {
        'builtin' {
            $derive = { param( [byte[]]$pass,[byte[]]$salt,[int]$iter,[int]$dkLen )
                $saltPrime = [Text.Encoding]::ASCII.GetBytes(([Text.Encoding]::ASCII.GetString($salt)) + '|scs1|')
                Invoke-PBKDF2HmacSha1_DotNet -PasswordBytes $pass -SaltBytes $saltPrime -Iterations $iter -DerivedKeyLength $dkLen
            }

            $encrypt = { param( [byte[]]$plain,[byte[]]$key, [byte[]]$InitVector )  Invoke-AesCbcEncrypt_DotNet -PlainBytes $plain -Key $key -InitVector $InitVector }

            $decrypt = { param( [byte[]]$ct,[byte[]]$key,[byte[]]$InitVector )      Invoke-AesCbcDecrypt_DotNet -CipherBytes $ct -Key $key -InitVector $InitVector }

            $mac     = { param( [byte[]]$data,[byte[]]$key )                Invoke-HmacSha256_DotNet -Data $data -Key $key }

            $verify  = { param( [byte[]]$data,[byte[]]$macBytes,[byte[]]$key )
                $calc = Invoke-HmacSha256_DotNet -Data $data -Key $key
                Compare-BytesConstantTime -A $macBytes -B $calc
            }
        }
        'experimental' {
            if ($env:SECSEALKIT_CRYPTO_SELFTEST -eq '1') {
                if (-not (Invoke-SecSealSelfTests -Target 'experimental')) {
                    Write-Warning 'Experimental backend self-tests failed; falling back to builtin.'
                    return (Resolve-CryptoBackend -Override 'builtin')
                }
            }
            $derive = { param( [byte[]]$pass,[byte[]]$salt,[int]$iter,[int]$dkLen )
                $saltPrime = [Text.Encoding]::ASCII.GetBytes(([Text.Encoding]::ASCII.GetString($salt)) + '|scs1|')
                Invoke-PBKDF2HmacSha1_Exp -PasswordBytes $pass -SaltBytes $saltPrime -Iterations $iter -DerivedKeyLength $dkLen
            }

            $encrypt = { param([byte[]]$plain,[byte[]]$key,[byte[]]$InitVector) Invoke-AesCbcEncrypt_Exp -PlainBytes $plain -Key $key -InitVector $InitVector }

            $decrypt = { param([byte[]]$ct,[byte[]]$key,[byte[]]$InitVector)    Invoke-AesCbcDecrypt_Exp -CipherBytes $ct -Key $key -InitVector $InitVector }

            $mac     = { param([byte[]]$data,[byte[]]$key)                      Invoke-HmacSha256_Exp -Data $data -Key $key }

            $verify  = { param([byte[]]$data,[byte[]]$macBytes,[byte[]]$key)
                $calc = Invoke-HmacSha256_Exp -Data $data -Key $key
                Compare-BytesConstantTime -A $macBytes -B $calc
            }
        }
    }

    $backend = [pscustomobject]@{
        Name       = $provider
        DeriveKey  = $derive
        Encrypt    = $encrypt
        Decrypt    = $decrypt
        ComputeMac = $mac
        VerifyMac  = $verify
    }

	if (-not $Override) { $script:_backendCache = $backend }
	return $backend
}
