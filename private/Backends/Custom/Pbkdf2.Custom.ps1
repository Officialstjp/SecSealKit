<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

# PBKDF2 helpers — PS 5.1 friendly

Set-StrictMode -Version Latest

function ConvertTo-BigEndianUint32Bytes_Exp {
    <#
    .SYNOPSIS
    Convert a 32-bit unsigned integer to a big-endian byte array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uint32]$Value
    )

    $bytes = [BitConverter]::GetBytes([uint32]$Value)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $bytes
}


function Invoke-PBKDF2HmacSha1_Exp {
    <#
    .SYNOPSIS
    Invoke PBKDF2-HMAC-SHA1 key derivation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PasswordBytes,
        [Parameter(Mandatory)][byte[]]$SaltBytes,
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][int]$DerivedKeyLength
    )

    if ($Iterations -lt 1) { throw "PDKDF2 iterations must be >= 1" }

    $hashlength     = 20
    $blocks         = [math]::Ceiling($DerivedKeyLength / [double]$hashlength)
    $derivedKey     = New-Object byte[]($DerivedKeyLength)
    $offset         = 0
    $hmac           = [System.Security.Cryptography.HMACSHA1]::new($PasswordBytes)
    try {
        for ($i = 1; $i -le $blocks; $i++) {                                # for every block
            $iterBytes = ConvertTo-BigEndianUint32Bytes -Value $i           # Block index (1-based)
            $msg = New-Object byte[] ($SaltBytes.Length +4)                 # Salt + Block index
            [Array]::Copy($SaltBytes, 0, $msg, 0, $SaltBytes.Length)        # Copy SaltBytes to <msg>
            [Array]::Copy($iterBytes, 0, $msg, $SaltBytes.Length, 4)        # Copy Block index to <msg>
            $curIter = $hmac.ComputeHash($msg)                              # Compute initial hash
            $curIterHash = [byte[]]$curIter.Clone()                         # Clone initial hash
            for ($j = 2; $j -le $Iterations; $j++) {                        # for each iteration
                $curIter = $hmac.ComputeHash($curIter)                      # Compute subsequent hash
                for ($k = 0; $k -lt $curIterHash.Length; $k++) {            # for each byte in the hash
                    $curIterHash[$k] = $curIterHash[$k] -bxor $curIter[$k]  # XOR with current iteration
                }
            }
            $cpyBytes = [Math]::Min($hashLength, $DerivedKeyLength - $offset)   # copy bytes of current block
            [Array]::Copy($curIterHash, 0, $derivedKey, $offset, $cpyBytes)     # to <derivedKey>
            $offset += $cpyBytes
            [Array]::Clear($msg, 0, $msg.Length)                                # Clear message buffer
            [Array]::Clear($iterBytes, 0, $iterBytes.Length)                    # Clear iteration bytes
            [Array]::Clear($curIterHash, 0, $curIterHash.Length)                # Clear current iteration hash
            [Array]::Clear($curIter, 0, $curIter.Length)                        # Clear current iteration
        }
    } finally { try { $hmac.Dispose() } catch {
        Write-Verbose "Failed to dispose HMAC object."
    } }
    [Array]::Clear($PasswordBytes, 0, $PasswordBytes.Length)
    $derivedKey
}

function Invoke-HmacSha256_Exp {
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [byte[]]$Key
    )
    $h = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try {
        $h.ComputeHash($Data)
    } finally {
        $h.Dispose()
    }
}

function Test-MacConstantTime {
    [CmdletBinding()]
    param(
        [byte[]]$Data,
        [byte[]]$Mac,
        [byte[]]$Key
    )

    $calc = Invoke-HmacSha256_Exp -Data $Data -Key $Key
	Compare-BytesConstantTime -A $Mac -B $calc
}

