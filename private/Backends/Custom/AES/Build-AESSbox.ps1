<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
.SYNOPSIS
Build S-boxes for subsitution in AES -> Sub Bytes + educational helpers

.NOTES
This implementation is focussed on showing and understanding the operations, not performance.
#>
[CmdletBinding()]
param()

function Build-AESSbox {
    <#
    .SYNOPSIS
    Generates the complete AES S-box using mathematical constrection

    .DESCRIPTION
    This function demonstrates how the AES S-box is mathematically constrcuted:
    1. Find multiplicate inverse in GF(2^8)
    2. Apply the affine transformation (matrix multiplcation + constant)

    This is how the AES designer actually created the S-box values!
    #>
    param()

    # Affine transformation matrix A (8x8 binary matrix)
    $affineMatrix = @(
        @(1,0,0,0,1,1,1,1),     # Row 0 (bit 0 output)
        @(1,1,0,0,0,1,1,1),     # Row 1 (bit 1 output)
        @(1,1,1,0,0,0,1,1),     # Row 2 (bit 2 output)
        @(1,1,1,1,0,0,0,1),     # Row 3 (bit 3 output)
        @(1,1,1,1,1,0,0,0),     # Row 4 (bit 4 output)
        @(0,1,1,1,1,1,0,0),     # Row 5 (bit 5 output)
        @(0,0,1,1,1,1,1,0),     # Row 6 (bit 6 output)
        @(0,0,0,1,1,1,1,1)      # Row 7 (bit 7 output)
    )

    # Affine transformation constant (0x63 in binary)
    $affineConstant = 0x63 # 01100011

    # Create the S-box array (256 entries)
    $sbox = New-Object byte[] 256

    # Generate each S-box entry mathematically
    for ($in = 0; $in -lt 256; $in++) {
        # Step 1: Handle speacial case for 0x00 (has no multiplicative inverse)
        if ($in -eq 0) {
            $inverse = 0 # By convention, inverse of 0 is defined as 0 for S-box
            Write-Verbose "Input is 0 => Inverse 0"
        } else {
            # Step 2: Find multiplicative inverse
            . "$PSSCriptRoot\Find-MultiplicationInverse-GF256.ps1"
            $inverse = Find-MultiplicationInverse-GF256 -Value $in
        }
        # Step 3: Apply affine transformation
        $sboxValue = Apply-AffineTransformation -InputValue $inverse -Matrix $affineMatrix -Constant $affineConstant

        # Store in S-box
        $sbox[$in] = $sboxValue

        Write-Verbose "S[0x$('{0:X2}' -f $in)] = affine(0x$('{0:X2}' -f $inverse)) = 0x$('{0:X2}' -f $sboxValue)"
        # Show progress for first few entries
        if ($in -lt 5 -or $in % 50 -eq 0) {
            Write-Host "S[0x$('{0:X2}' -f $in)] = affine(0x$('{0:X2}' -f $inverse)) = 0x$('{0:X2}' -f $sboxValue)"
        }
    }

    return $sbox
}

function Apply-AffineTransformation {
    <#
    .SYNOPSIS
    Applies the AES affine transfomration: A × input + c

    .DESCRIPTION
    Perfomrs matrix multiplication in GF(2) followed by vector addition.
    This is the second step of AES S-box construction.

    .PARAMETER In
    The byte to transform (usually the multiplicative inverse)

    .PARAMETER Matrix
    The 8x8 affine transfomration matrix

    .PARAMETER Constant
    The constant byte to add (0x63 for AES)
    #>
    [CmdletBinding()]
    param(
        [byte]$InputValue,
        [byte[][]]$Matrix,
        [byte]$Constant
    )

    # Convert input byte to bit array for matrix operations
    # We extract bits from LSB (bit 0) to MSB (bit 7)
    [int[]]$inputBits = @(0,0,0,0,0,0,0,0)  # Pre-initialize for safety

    for ($bitPos = 0; $bitPos -lt 8; $bitPos++) {
        # Extract bit at position $bitPos using shift and mask
        # Example: For input 0x53 (01010011), bit positions yield: [1,1,0,0,1,0,1,0]
        $inputBits[$bitPos] = ($InputValue -shr $bitPos) -band 1
    }

    Write-Verbose "Processing input: 0x$('{0:X2}' -f $InputValue) = $('{0:b8}' -f $InputValue)"
    Write-Verbose "Bit array (LSB→MSB): [$($inputBits -join ',')]"

    # Perform matrix multiplication in GF(2)
    # Each output bit = dot product of matrix row with input vector
    [byte]$result = 0

    for ($outputBit = 0; $outputBit -lt 8; $outputBit++) {
        # Calculate dot product for this output bit position
        [int]$dotProduct = 0

        for ($inputBit = 0; $inputBit -lt 8; $inputBit++) {
            # GF(2) arithmetic: multiplication = AND, addition = XOR
            $matrixElement = $Matrix[$outputBit][$inputBit]
            $inputElement = $inputBits[$inputBit]
            $product = $matrixElement -band $inputElement

            # Accumulate using XOR (addition in GF(2))
            $dotProduct = $dotProduct -bxor $product
        }

        # Set the output bit if dot product is 1
        if ($dotProduct -band 1) {
            $result = $result -bor (1 -shl $outputBit)
        }

        Write-Verbose "  Output bit $outputBit`: dot_product=$dotProduct, result=0x$('{0:X2}' -f $result)"
    }

    # Apply the affine constant (vector addition in GF(2) = XOR)
    $finalResult = $result -bxor $Constant

    Write-Verbose "Matrix result: 0x$('{0:X2}' -f $result) + constant 0x$('{0:X2}' -f $Constant) = 0x$('{0:X2}' -f $finalResult)"

    return [byte]$finalResult
}

function Test-SboxGeneration {
    <#
    .SYNOPSIS
    Tests our S-box generation against known AES S-box values

    .DESCRIPTION
    The official AES S-box has been computed and verified by cryptographers worldwide.
    We can test our implementation against known values to ensure correctness.
    #>

    Write-Host "Testing S-box generation against known AES values..." -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan

    # Generate our S-box using the mathematical construction
    $ourSbox = Build-AESSbox

    # Known AES S-box values for verification (first 16 entries)
    $knownSbox = @(
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,  # S[0x00] to S[0x07]
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76   # S[0x08] to S[0x0F]
    )

    Write-Host "Comparing first 16 S-box entries:" -ForegroundColor Yellow

    $allCorrect = $true
    for ($i = 0; $i -lt 16; $i++) {
        $ourValue = $ourSbox[$i]
        $expectedValue = $knownSbox[$i]
        $isCorrect = ($ourValue -eq $expectedValue)
        $status = if ($isCorrect) { "✅" } else { "❌"; $allCorrect = $false }

        Write-Host "$status S[0x$('{0:X2}' -f $i)] = 0x$('{0:X2}' -f $ourValue) (expected 0x$('{0:X2}' -f $expectedValue))"
    }

    Write-Host ""
    if ($allCorrect) {
        Write-Host "[SUCCESS]: All tested S-box values match the AES standard!" -ForegroundColor Green
    } else {
        Write-Host "[FAILED]  Some values don't match!" -ForegroundColor Red
    }
}

Test-SBoxGeneration
