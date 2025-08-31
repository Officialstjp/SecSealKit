<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

Set-StrictMode -Version Latest

$script:SCS1Prefix = 'SCS1'
$script:SCS1Pattern = '^SCS1\$kdf=PBKDF2-SHA1\$iter=(\d{1,9})\$salt=([A-Za-z0-9+/=]+)\$IV=([A-Za-z0-9+/=]+)\$ct=([A-Za-z0-9+/=]+)\$mac=([A-Za-z0-9+/=]+)$'
$script:SCS1Policy = @{
    MinIterations   = 10000
    MinSaltLenBytes = 16
    MinIVLenBytes   = 16
}

function Get-SCS1MacInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][byte[]]$Salt,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$CipherText
    )
    $saltB64 = ConvertTo-Base64 $Salt
    $ivB64   = ConvertTo-Base64 $InitVector
    $ctB64   = ConvertTo-Base64 $CipherText
    return [Text.Encoding]::ASCII.GetBytes("SCS1`$kdf=PBKDF2-SHA1`$iter=$Iterations`$salt=$saltB64`$IV=$ivB64`$ct=$ctB64")
}

function ConvertTo-SCS1Envelope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][int]$Iterations,
        [Parameter(Mandatory)][byte[]]$Salt,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$CipherText,
        [Parameter(Mandatory)][byte[]]$Mac
    )
    $saltB64 = ConvertTo-Base64 $Salt
    $ivB64   = ConvertTo-Base64 $InitVector
    $ctB64   = ConvertTo-Base64 $CipherText
    $macB64  = ConvertTo-Base64 $Mac
    return "$script:SCS1Prefix`$kdf=PBKDF2-SHA1`$iter=$Iterations`$salt=$saltB64`$IV=$ivB64`$ct=$ctB64`$mac=$macB64"
}

function ConvertFrom-SCS1Envelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Envelope
    )

    if (-not $Envelope -is [string]) { throw "Envelope must be a string" }
    if (-not ($Envelope -match $script:SCS1Pattern))   { throw "Invalid Envelope Format" }

    $iter = [int]$Matches[1]
    $salt = ConvertFrom-Base64 $Matches[2]
    $IV   = ConvertFrom-Base64 $Matches[3]
    $ct   = ConvertFrom-Base64 $Matches[4]
    $mac  = ConvertFrom-Base64 $Matches[5]

    if ($iter -lt $script:SCS1Policy.MinIterations)             { throw 'Iterations below policy minimum' }
    if ($salt.Length -lt $script:SCS1Policy.MinSaltLenBytes)    { throw 'Salt length below policy minimum (min 16 bytes)' }
    if ($IV.Length -ne $script:SCS1Policy.MinIVLenBytes)        { throw 'IV must be 16 bytes' }

    [pscustomobject]@{
        Prefix      = 'SCS1'
        Iterations  = $iter
        Salt        = $salt
        IV          = $IV
        CipherText  = $ct
        Mac         = $mac
    }
}
