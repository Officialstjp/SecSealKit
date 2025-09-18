<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


<#
.SYNOPSIS
Multiplication inverse in a Galois Field for AES  + educational helpers

.NOTES
This implementation is focussed on showing and understanding the operations, not performance.
#>

[CmdletBinding()]
param(
    [ValidateSet('Test','PolyDiv','PolyDeg', 'VerifyInv', 'FindInv', 'Trace')] # trace is just verbose
    [string]$mode,

    # Test requires no parameters
    # PolyDiv mode
    [Alias('Divd')]
    [byte]$Dividend = 0x53,
    [Alias('Divs')]
    [byte]$Divisor = 0xCA,

    # PolyDeg mode
    [Alias('degPoly','degreeValue', 'degVal')]
    [uint16]$Polynomial = 0x11B,

    # VerifyInv mode
    [Alias('vV','verVal','verByte')]
    [byte]$ValueToVerify = 0x53,
    [Alias('vI','verInv','verInverse')]
    [byte]$InverseToVerify = 0xCA,

    # FindInv
    [Alias('Val','Byte', 'V')]
    [byte]$Value = 0x53

    # Trace takes same parameters as FindInv (Value)
)


function Find-MultiplicationInverse-GF256 {
    <#
    .SYNOPSIS
    Finds the multiplication inverse of a byte in GF(2^8)

    .DESCRIPTION
    For any non-zero byte 'a' in GF(2^8), finds byte 'b' such that: a × b ≡ 1 (mod irreducible_polynomial)
    We want to solve: 1 = u×(0x11B) + v×($Value)
    When we find this, 'v' will be our multiplicative inverse

    This is the mathematical foundation for generating the AES S-box.

    .PARAMETER Value
    The byte whose multiplicative inverse we want to find (1-255, not 0)

    .EXAMPLE
    $inverse = Find-MultiplicativeInverse-GF256 0x53
    # Returns the byte that when multiplied by 0x53 in GF(2^8) equals 1
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1,255)] # Explicitly exclude 0x00 - it has no inverse
        [byte]$Value
    )

    # Inverse of 1 is 1
    if($Value -eq 1) { return [byte]1 }

    # Extended Euclidean Algorithm for polynomials in GF(2^8)
    # We're working with the irreducible polynomial: x^8 + x^4 + x^3 + x + 1
    [uint16]$a = 0x11b      # The irreducible polynomial (9 bits)
    [uint16]$b = $Value     # The input value we want to invert

    # Extended Euclidean variables for tracking the linear combination: gcd = u×original_a + v×original_b
    [uint32]$u = 1          # Current coefficient for original_a (0x11B)
    [uint32]$v = 0          # Current coefficient for original_b ($Value)
    [uint32]$s = 0          # Previous coefficient for original_a
    [uint32]$t = 1          # Previous coefficient for original_b

    Write-Verbose "Finding multiplicative inverse of 0x$('{0:X2}' -f $Value) in GF(2^8)"
    Write-Verbose "Initial: a=0x$('{0:X}' -f $a), b=0x$('{0:X}' -f $b)"

    # Continue until b becomes 0 (meaning a contains the GCD)
    while ($b -ne 0) {
        Write-Verbose "--- Loop iteration: a=0x$('{0:X}' -f $a), b=0x$('{0:X}' -f $b) ---"

        # Step 1: Divide a by b to get quotient and remainder
        $divisionResult = Get-PolynomialDivision $a $b
        $quotient = $divisionResult.Quotient
        $remainder = $divisionResult.Remainder

        Write-Verbose "Division: 0x$('{0:X}' -f $a) = 0x$('{0:X}' -f $quotient) × 0x$('{0:X}' -f $b) + 0x$('{0:X}' -f $remainder)"

        # Step 2: Update a and b for next iteration
        $a = $b
        $b = $remainder

        # Step 3: Update coefficients to maintain the linear combination properly
        # Before: gcd = u * original_a + v * original_b
        # After:  gcd = new_u * original_a + new_v * original_b
        $temp_u = $u
        $temp_v = $v

        # Compute new current from (old_u - q * current_u) and (old_v - q * current_v)
        $new_u = $u -bxor (Multiply-PolynomialsGF2 $quotient $s)
        $new_v = $v -bxor (Multiply-PolynomialsGF2 $quotient $t)

        # Rotate pairs: (old, current) = (current, new_current)
        $u = $s
        $v = $t
        $s = $new_u
        $t = $new_v

        Write-Verbose "Coefficient update:"
        Write-Verbose "  u = 0x$('{0:X}' -f $u), v = 0x$('{0:X}' -f $v)"
        Write-Verbose "  s = 0x$('{0:X}' -f $s), t = 0x$('{0:X}' -f $t)"
        Write-Verbose "  Current linear combination: 0x$('{0:X}' -f $a) = (0x$('{0:X}' -f $u))×0x11B + (0x$('{0:X}' -f $v))×0x$('{0:X2}' -f $Value)"
        Write-Verbose ""
    }

    # At this point, 'a' should be 1 (greatest common divisor), and 't' contains our inverse
    if ($a -ne 1) {
        throw "Error: GCD is not 1. Input 0x$('{0:X2}' -f $Value) might not have an inverse."
    }

    # The multiplicative inverse is 'v' reduced to 8 bits
    $inverse = [byte]($v -band 0xFF)

    Write-Verbose "Multiplicative inverse found: 0x$('{0:X2}' -f $inverse)"
    return $inverse
}

function Get-PolynomialDivision {
    <#
    .SYNOPSIS
    Performs polynomial division in GF(2) - division with XOR instead of substraction

    .DESCRIPTION
    Divides one polynomial by another using the same process as long division,
    but with XOR operations instead of subtraction (since we're in GF(2)).

    .EXAMPLE
    # Divide x^3 + x + 1 (0x0B) by x + 1 (0x03)
    $result = Get-PolynomialDivision 0x0B 0x03
    # Returns: @{ Quotient = 0x09; Remainder = 0x02 }
    # Because: (x^3 + x + 1) = (x^2 + 1) × (x + 1) + x
    #>
    param(
        [uint16]$Dividend,   # The polynomial being divided
        [uint16]$Divisor     # The polynomial we're dividing by
    )

    if ($Divisor -eq 0) {
        throw "Cannot divide by zero polynomial"
    }

    [uint16]$quotient = 0
    [uint16]$remainder = $Dividend

    # Find the highest bit position in the divisor
    $divisorDegree = Get-PolynomialDegree $Divisor

    # Perform polynomial long division, continue while the remainder has degree >= divisor degree
    while ($remainder -ne 0 -and (Get-PolynomialDegree $remainder) -ge $divisorDegree) {
        # Calculate how many positions to shift the divisor
        $remainderDegree = Get-PolynomialDegree $remainder
        $shiftAmount = $remainderDegree - $divisorDegree

        # Add x^shift_amount to the quotient (set the corresponding bit)
        $quotientTerm = 1 -shl $shiftAmount
        $quotient = $quotient -bxor $quotientTerm

        # Subtract (XOR) the shifted divisor from the remainder
        $shiftedDivisor = $Divisor -shl $shiftAmount
        $remainder = $remainder -bxor $shiftedDivisor

        Write-Verbose "Division step: quotient_term=0x$('{0:X}' -f $quotientTerm), new_remainder=0x$('{0:X}' -f $remainder)"
    }

    return @{
        Quotient = $quotient
        Remainder = $remainder
    }
}

function Get-PolynomialDegree {
    <#
    .SYNOPSIS
    Returns the degree of a polynomial (position of highest set bit)

    .DESCRIPTION
    In polynomial representation, the degree is the power of the highest term.
    In binary representation, this is the position of the most significant bit.

    .EXAMPLE
    Get-PolynomialDegree 0x0B  # x^3 + x + 1 → degree is 3
    Get-PolynomialDegree 0x03  # x + 1 → degree is 1
    Get-PolynomialDegree 0x01  # 1 → degree is 0
    Get-PolynomialDegree 0x00  # 0 → degree is -1 (undefined)
    #>
    param([uint16]$Polynomial)

    if ($Polynomial -eq 0) {
        return -1  # Degree of zero polynomial is undefined
    }

    # Find the position of the most significant bit
    for ($i = 15; $i -ge 0; $i--) {
        if ($Polynomial -band (1 -shl $i)) {
            return $i
        }
    }
    return -1
}

function Multiply-PolynomialsGF2 {
    <#
    .SYNOPSIS
    Multiplies two polynomials in GF(2) without modular reduction

    .DESCRIPTION
    Performs standard polynomial multiplication where coefficients are in GF(2).
    This means addition is XOR and there are no carries.
    Note: This does NOT perform modular reduction - it's just raw polynomial multiplication.
    #>
    param(
        [uint16]$A,
        [uint16]$B,
        [uint16]$XorWith = 0
    )

    [uint16]$result = 0

    # Standard polynomial multiplication using the distributive property
    # For each bit position in B, if it's set, add A shifted by that position
    for ($i = 0; $i -lt 16; $i++) {
        if ($B -band (1 -shl $i)) {
            $result = $result -bxor ($A -shl $i)
        }
    }

    return $result -bxor $XorWith
}

function Test-MultiplicativeInverses {
    <#
    .SYNOPSIS
    Tests the multiplicative inverse function with known values
    #>
    [CmdletBinding()]
    param()

    Write-Host "Testing Multiplicative Inverses in GF(2^8)"
    Write-Host "==========================================`n"

    # Test some known inverses (these are from AES S-box calculations)
    $test_cases = @(
        @{ Value = 0x01; Expected = 0x01 }   # 1 is its own inverse
        @{ Value = 0x02; Expected = 0x8D }   # 2^(-1) = 141
        @{ Value = 0x03; Expected = 0xF6 }   # 3^(-1) = 246
        @{ Value = 0x53; Expected = 0xCA }   # Random
    )

    foreach ($test in $test_cases) {
        try {
            $val = $test.value
            $computedInverse = Find-MultiplicationInverse-GF256 $val

            . "$PSSCriptRoot\Multiply-GF256.ps1"

            # Verify by multiplying: value x inverse should equal 1
            $verification = Multiply-GF256 $val $computedInverse
            $isCorrect = ($verification -eq 1)

            $status = if ($isCorrect) { "[PASS]" } else { "[FAIL]" }
            $color = if ($isCorrect) { "Green" } else { "Red" }

            Write-Host "$status 0x$('{0:X2}' -f $val)^(-1) = 0x$('{0:X2}' -f $computedInverse)"
            Write-Host "       Verification: 0x$('{0:X2}' -f $val) × 0x$('{0:X2}' -f $computedInverse) = 0x$('{0:X2}' -f $verification)"

            if ($test.Expected -and $computedInverse -ne $test.Expected) {
                Write-Host "       [WARNING] Expected 0x$('{0:X2}' -f $test.Expected), got 0x$('{0:X2}' -f $computedInverse)"
            }

        } catch {
            Write-Host "[ERROR] Failed to compute inverse of 0x$('{0:X2}' -f $val): $($_.Exception.Message)"
        }
        Write-Host ""
    }
}

function Verify-Inverse {
    param([byte]$Value, [byte]$Inverse)

    # Import your working Multiply-GF256 function
    . "$PSScriptRoot\Multiply-GF256.ps1"

    $result = Multiply-GF256 $Value $Inverse

    Write-Host "Verification: 0x$('{0:X2}' -f $Value) × 0x$('{0:X2}' -f $Inverse) = 0x$('{0:X2}' -f $result)"

    if ($result -eq 1) {
        Write-Host "[PASS]: This is the valid multiplicative inverse!" -ForegroundColor Green
    } else {
        Write-Host "[FAIL]: This is not the multiplicative inverse." -ForegroundColor Red
    }

    return ($result -eq 1)
}

# Main execution based on mode
switch ($mode) {
    "Test" {
        Test-MultiplicativeInverses
    }
    "PolyDiv" {
        if (-not $Dividend -or -not $Divisor) {
            Write-Host "Please provide values for both -Dividend (-Divd, -A) and -Divisor (-Divs, -B)!"
            throw
        }
        Write-Host "Polynomial Division: 0x$('{0:X}' -f $Dividend) ÷ 0x$('{0:X}' -f $Divisor)"
        $result = Get-PolynomialDivision -Dividend $Dividend -Divisor $Divisor
        Write-Host "Quotient: 0x$('{0:X}' -f $($result.Quotient)), Remainder: 0x$('{0:X}' -f $($result.Remainder))"
    }
    "PolyDeg" {
        if (-not $Polynomial) {
            Write-Host "Please provide a polynomial value for -Polynomial (-Poly, -Val)!"
            throw
        }
        $degree = Get-PolynomialDegree -Polynomial $Polynomial
        Write-Host "Degree of polynomial 0x$('{0:X}' -f $Polynomial) is $degree"
    }
    "VerifyInv" {
        if (-not $ValueToVerify -or -not $InverseToVerify) {
            Write-Host "Please provide values for both -ValueToVerify (-Val, -V) and -InverseToVerify (-Inv, -I)!"
            throw
        }
        Write-Host "Verifying if 0x$('{0:X2}' -f $InverseToVerify) is the inverse of 0x$('{0:X2}' -f $ValueToVerify)"
        Verify-Inverse -Value $ValueToVerify -Inverse $InverseToVerify
    }
    "FindInv" {
        if (-not $Value) {
            Write-Host "Please provide a value for -Value (-Val, -V) to find its inverse!"
            throw
        }
        $inverse = Find-MultiplicationInverse-GF256 -Value $Value
        Write-Host "Multiplicative inverse of 0x$('{0:X2}' -f $Value) is 0x$('{0:X2}' -f $inverse)"
    }
    "Trace" { # trace is just verbose
        if (-not $Value) {
            Write-Host "Please provide a value for -Value (-Val, -V) to find its inverse!"
            throw
        }
        Find-MultiplicationInverse-GF256 -Value $Value -Verbose
    }
}
