<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

Set-StrictMode -Version Latest

# TODO: replace with from-scratch AES-CBC. For now, proxy to .NET wrappers to keep tests green.
. "$PSScriptRoot\..\DotNet\AesCbc.DotNet.ps1"

function Invoke-AesCbcEncrypt_Exp { [CmdletBinding()] param([byte[]]$PlainBytes,[byte[]]$Key,[byte[]]$InitVector)
    Invoke-AesCbcEncrypt_DotNet -PlainBytes $PlainBytes -Key $Key -InitVector $InitVector
}
function Invoke-AesCbcDecrypt_Exp { [CmdletBinding()] param([byte[]]$CipherBytes,[byte[]]$Key,[byte[]]$InitVector)
    Invoke-AesCbcDecrypt_DotNet -CipherBytes $CipherBytes -Key $Key -InitVector $InitVector
}
