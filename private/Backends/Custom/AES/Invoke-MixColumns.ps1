<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


function Invoke-MixColumns {
    <#
    .SYNOPSIS
    Applies the AES MixColumns transformation using GF(2^8) arithmetic

    .DESCRIPTION
    MixColumns provides diffusion by matrix multiplication in GF(2^8).
    Each column is multiplied by the fixed polynomial matrix:

    [02 03 01 01]       [s0]
    [01 02 03 01]   x   [s1] (all operations in GF(2^8))
    [01 01 02 03]       [s2]
    [03 01 01 02]       [s3]

    This ensures that changing one input byte affects all four output bytes,
    providing excellent diffusion properties.

    The coefficients {01, 02, 03} were chosen because:
    - They're efficient
    - They're invertable in GF(2^8)
    - Maximum branch number for optimal diffusion

    .PARAMETER StateMatrix
    The 4x4 state matrix to transform
    #>
    [CmdletBinding()]
    param(
        [byte[][]]$StateMatrix
    )

    # Import
    . "$PSScriptRoot\Multiply-GF256.ps1"

    # The MixColumns transformation matrix
    $mixMatrix = @(
        @(0x02, 0x03, 0x01, 0x01),
        @(0x01, 0x02, 0x03, 0x01),
        @(0x01, 0x01, 0x02, 0x03),
        @(0x03, 0x01, 0x01, 0x02)
    )

    # Create result matrix
    $result = New-Object 'byte[][]' 4
    for ($row = 0; $row -lt 4; $row++) {
        $result[$row] = New-Object byte[] 4
    }

    # Transform each column independently
    for ($col = 0; $col -lt 4; $col++) {
        # Extract the column as a vector
        $column = @(
            $StateMatrix[0][$col],
            $StateMatrix[1][$col],
            $StateMatrix[2][$col],
            $StateMatrix[3][$col]
        )

        # Multiply column by the mix matrix
        for ($row = 0; $row -lt 4; $row++) {
            [byte]$newValue = 0

            # Calculate dot product in GF(2^8)
            for ($i = 0; $i -lt 4; $i++) {
                $product = Multiply-GF256 $mixMatrix[$row][$i] $column[$i]
                $newValue = $newValue -bxor $product  # Addition in GF(2^8) is XOR
            }

            $result[$row][$col] = $newValue
        }

        Write-Verbose "Column $col`: [$($column -join ',')] -> [$($result[0][$col]),$($result[1][$col]),$($result[2][$col]),$($result[3][$col])]"
    }

    return $result
}

function Test-MixColumns {
    <#
    .SYNOPSIS
    Test the MixColumns implementation

    .DESCRIPTION
    Tests the manual implementation against an optional reference
    Defaults to a reference from:
    https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf (page 7)
    #>
    [Cmdletbinding()]
    param()


    $state = @(
        @(0x89, 0xb9, 0x1e, 0x56),
        @(0x3e, 0x5c, 0x8d, 0xf6),
        @(0x79, 0x6d, 0x3e, 0x1c),
        @(0xbb, 0x78, 0x4b, 0x0a)
    )
<#
    $state = @(
        @(0x63, 0xEB, 0x9F, 0xA0),
        @(0x2F, 0x93, 0x92, 0xC0),
        @(0xAF, 0xC7, 0xAB, 0x30),
        @(0xA2, 0x20, 0xCB, 0x2B)
    )#>

    $res = Invoke-MixColumns -StateMatrix $state

    Write-Host "[ $(\\0x $res[0][0]), $(\\0x $res[0][1]), $(\\0x $res[0][2]), $(\\0x $res[0][3]) ]"
    Write-Host "[ $(\\0x $res[1][0]), $(\\0x $res[1][1]), $(\\0x $res[1][2]), $(\\0x $res[1][3]) ]"
    Write-Host "[ $(\\0x $res[2][0]), $(\\0x $res[2][1]), $(\\0x $res[2][2]), $(\\0x $res[2][3]) ]"
    Write-Host "[ $(\\0x $res[3][0]), $(\\0x $res[3][1]), $(\\0x $res[3][2]), $(\\0x $res[3][3]) ]"
}

function Get-Hex {
    [alias("\\0x")]
    param(
        [Parameter(Mandatory)]
        [byte]$Value
    )
    return "$('{0:X2}' -f $Value)"
}
