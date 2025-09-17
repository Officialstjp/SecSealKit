<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
AES ShiftRows Transformation

.DESCRIPTION
Manual implementation of the AES ShiftRows step + educational helpers
#>

function Invoke-ShiftRows {
    <#
    .SYNOPSIS
    Applies the AES ShiftRows transformation for diffusion

    .DESCRIPTION
    ShiftRows provides diffusion by ciclically shifting rows of the state matrix:
    - Row 0: No shift       [a,b,c,d] -> [a,b,c,d]
    - Row 1: Shift 1 Left   [e,f,g,h] -> [f,g,h,e]
    - Row 2: Shift 2 Left   [i,j,k,l] -> [k,l,i,j]
    - Row 3: Shift 3 Left   [m,n,o,p] -> [p,m,n,o]

    This ensures that column-based attacks affect multiple columns after just one round, providing rapid diffusion

    .PARAMETER StateMatrix
    The 4x4 byte matrix representing the current AES state

    .EXAMPLE
    $state = @(
        @(0x01, 0x02, 0x03, 0x04),
        @(0x05, 0x06, 0x07, 0x08),
        @(0x09, 0x0A, 0x0B, 0x0C),
        @(0x0D, 0x0E, 0x0F, 0x10)
    )
    $shifted = Invoke-ShiftRows $state
    # Result: Each row cyclically shifted as described above
    #>

    [CmdletBinding()]
    param(
        [byte[][]]$StateMatrix
    )

    # Create a copy to avoid modifying the original
    $result = New-Object 'byte[][]' 4
    for ($row = 0; $row -lt 4; $row++) {
        $result[$row] = New-Object byte[] 4
    }

    # Apply the shifting pattern
    for ($row = 0; $row -lt 4; $row++) {
        for ($col = 0; $col -lt 4; $col++) {
            # Calculate source column with wrap-around
            $sourceCol = ($col + $row) % 4
            $result[$row][$col] = $StateMatrix[$row][$sourceCol]
        }
    }
    return $result
}
