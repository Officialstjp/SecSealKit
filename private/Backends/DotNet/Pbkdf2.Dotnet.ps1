<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

Set-StrictMode -Version Latest

function Invoke-PBKDF2HmacSha1_DotNet {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][byte[]]$PasswordBytes,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][int]$DerivedKeyLength
    )

    if ($Iterations -lt 1) { throw 'PBKDF2 iterations must be >= 1'}
    $pbkdf2 = New-Object System.Security.Cryptography.RFC2898DeriveBytes($PasswordBytes,$SaltBytes,$Iterations)
    try {
        $pbkdf2.GetBytes($DerivedKeyLength)
    } finally {
        $pbkdf2.Dispose()
    }
}

function Invoke-HmacSha256_DotNet { [CmdletBinding()] param([byte[]]$Data,[byte[]]$Key)
    $h = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { $h.ComputeHash($Data) } finally { $h.Dispose() }
}

function Test-MacConstantTime { [CmdletBinding()] param([byte[]]$Data,[byte[]]$Mac,[byte[]]$Key)
    $calc = Invoke-HmacSha256 -Data $Data -Key $Key
    Compare-BytesConstantTime -A $Mac -B $calc
}
