<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Multiplication in a Galois Field for AES  + educational helpers

.NOTES
This implementation is focussed on showing and understanding the operations, not performance.
#>

[CmdletBinding()]
param(
    [ValidateSet('Test','ShowPoly','Trace')]
    [string]$mode,

    # ShowPoly mode
    [Alias('Pb')]
    [byte]$PolyBytes,

    # Trace-GFMultiplication
    [Alias('A', 'BytesA')]
    [byte]$TraceBytesA = 0x3,
    [Alias('B', 'BytesB')]
    [byte]$TraceBytesB = 0x6E
)

function Multiply-GF256 {
    <#
    .SYNOPSIS
    Multiplies two bytes in Galois Field (2^8) using the AES irreducible polynomial

    .DESCRIPTION
    Implements polynomial multiplication in GF(2^8) with modular reduction
    using the irreducible polynomial x^8 + x^4 + x^3 + x + ^(0x11B)

    This is the mathematical foundation of the AES MixColumns operation. In AES the state is matrix-multiplied with a constant Rijndael-Galois Field
    #>
    param(
        [byte]$A,  # first operand
        [byte]$B   # second operand
    )

    [byte]$result = 0
    [byte]$aCopy = $A # store locally to ensure it doesnt change
    [byte]$bCopy = $B

    # AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
    # In 8-bit arithmetic, this becomes 0x1B (the x^8 term is implicit)
    [byte]$irreducible = 0x1B

    # Peasant multiplication for GF(2^8)
    for ($i = 0; $i -lt 8; $i++) {
        # If the lowest bit of B is set, add A to the result
        # (Addition in GF(2^8) is XOR)
        if ($bCopy -band 1) {
            $result = $result -bxor $aCopy
        }

        # Check if a will overflow when shifted (highest bit set)
        $carry = ($aCopy -band 0x80) -ne 0

        # Shift a left (multiply by x)
        $aCopy = [byte]($aCopy -shl 1)

        # If we had overflow, reduce by the irreducible polynomial
        if ($carry) {
            $aCopy = $aCopy -bxor $irreducible
        }

        # Shift b right for next iteration
        $bCopy = $bCopy -shr 1
    }

    return [byte]$result
}
#
function Test-GFMultiplication {
    # test cases
    $testCases = @(
        @{ A = 0x02; B = 0x87; Expected = 0x15 } # A = x     | A = 00000010 ; B = x^7 + x^2 + x + 1         | B = 10000111 ; Ex = x^4 + x^2 + 1               | 00010101
        @{ A = 0x03; B = 0x6E; Expected = 0xB2 } # A = x + 1 | A = 00000011 ; B = x^6 + x^5 + x^3 + x^2 + x | B = 01101110 ; Ex = x^7 + x^5 + x^4 + x         | 11110101
        @{ A = 0x02; B = 0x6E; Expected = 0xDC } # A = x     | A = 00000010 ; B = x^6 + x^5 + x^2 + x^1 + x | B = 01101110 ; Ex = x^7 + x^6 + x^4 + x^3 + x^2 | 11011100
        # multiplication * 1
        @{ A = 0x01; B = 0x6E; Expected = 0x6E } # A = 1     | A = 00000001 ; B = x^6 + x^5 + x^2 + x^1 + x | B = 01101110 ; Ex = x^6 + x^5 + x^2 + x^1 + x   | 01101110
    )

    Write-Host "GF(2^8) Multiplication Tests"
    Write-Host "============================"

    foreach ($test in $testCases) {
        $result = Multiply-GF256 $test.A $test.B
        $status = if ($result -eq $test.Expected) { "[PASS]" } else { "[FAIL]"}

        # 'x' for multiplication and 'XOR' for addition
        Write-Host "$status 0x$('{0:X2}' -f $test.A) x 0x$('{0:X2}' -f $test.B) = 0x$('{0:X2}' -f $result) (expected 0x$('{0:X2}' -f $test.Expected))"
    }
}

function Show-PolynomialRepresentation {
    param([byte]$Value)

    $terms = @()
    for ($i = 7; $i -ge 0; $i--) {
        if ($Value -band (1 -shl $i)) {
            if ($i -eq 0) { $terms += "1" }
            elseif ($i -eq 1) { $terms += "x" }
            else { $terms += "x^$i" }
        }
    }

    if ($terms.Count -eq 0) { return "0" }
    return $terms -join " + "
}

function Trace-GFMultiplication {
    param(
        [Parameter(Mandatory)][string]$AHex,
        [Parameter(Mandatory)][string]$BHex
    )
    $A = ($AHex -match '^0x') ? [Convert]::ToByte($AHex.Substring(2),16) : [byte]$AHex
    $B = ($BHex -match '^0x') ? [Convert]::ToByte($BHex.Substring(2),16) : [byte]$BHex

    Write-Host ("Parsed A=0x{0:X2}  B=0x{1:X2}" -f $A,$B)
    Write-Host "Multiplying 0x$('{0:X2}' -f $A) x 0x$('{0:X2}' -f $B)"  # Using 'x' instead of ×
    Write-Host "A = $('{0:b8}' -f $A) ($(Show-PolynomialRepresentation $A))"
    Write-Host "B = $('{0:b8}' -f $B) ($(Show-PolynomialRepresentation $B))"
    Write-Host ""

    [byte]$result = 0
    [byte]$aCopy = $A
    [byte]$bCopy = $B
    [byte]$irreducible = 0x1B

    for ($i = 0; $i -lt 8; $i++) {
        Write-Host "--- Iteration $i ---"
        Write-Host "a_copy = 0x$('{0:X2}' -f $aCopy) = $('{0:b8}' -f $aCopy)"
        Write-Host "b_copy = 0x$('{0:X2}' -f $bCopy) = $('{0:b8}' -f $bCopy)"
        Write-Host "result = 0x$('{0:X2}' -f $result) = $('{0:b8}' -f $result)"

        # Check if lowest bit of b is set
        $add_a = $bCopy -band 1
        Write-Host "b_copy & 1 = $add_a"

        if ($add_a) {
            $oldResult = $result
            $result = $result -bxor $aCopy
            Write-Host "  Adding a_copy: 0x$('{0:X2}' -f $oldResult) XOR 0x$('{0:X2}' -f $aCopy) = 0x$('{0:X2}' -f $result)"
        }

        # Check for overflow before shifting
        $carry = $aCopy -band 0x80
        Write-Host "carry (a_copy & 0x80) = 0x$('{0:X2}' -f $carry)"

        # Show the shift operation
        $a_old = $aCopy
        $aCopy = [byte]($aCopy -shl 1)  # Explicit cast to show truncation
        Write-Host "a_copy << 1: 0x$('{0:X2}' -f $a_old) -> 0x$('{0:X2}' -f $aCopy)"

        if ($carry) {
            $old_a = $aCopy
            $aCopy = $aCopy -bxor $irreducible
            Write-Host "  Polynomial reduction: 0x$('{0:X2}' -f $old_a) XOR 0x$('{0:X2}' -f $irreducible) = 0x$('{0:X2}' -f $aCopy)"
        }

        $bCopy = $bCopy -shr 1
        Write-Host ""
    }

    Write-Host "Final result: 0x$('{0:X2}' -f $result)"
    return $result
}

switch($mode) {
    "Test" {
        Test-GFMultiplication
    }
    "ShowPoly" {
        if (!$PolyBytes) {
            Write-Host "Please provide a value for -PolyBytes (-Pb) (Hex)!"
            throw
        }
        Show-PolynomialRepresentation -Value $PolyBytes
    }
    "Trace" {
        if (!$TraceBytesA -or !$TraceBytesB) {
            Write-Host "Please provide values for both -TraceBytesA (-A) and -TraceBytesB (-B)!"
            throw
        }
        Trace-GFMultiplication -AHex $TraceBytesA -BHex $TraceBytesB
    }
}
