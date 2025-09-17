<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#
.SYNOPSIS
Build S-boxes for subsitution in AES

.NOTES
This implementation is focussed on showing and understanding the operations, not performance.
#>

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
        Write-Host "In: $In"
        if ($in -eq 0) {
            $inverse = 0 # By convention, inverse of 0 is defined as 0 for S-box
        } else {
            # Step 2: Find multiplicative inverse
            . "$PSSCriptRoot\Find-MultiplicationInverse-GF256.ps1"
            $inverse = Find-MultiplicationInverse-GF256 -Value $in
        }
        Write-Host "Inverse: $Inverse"
        # Step 3: Apply affine transformation
        $sboxValue = Apply-AffineTransformation -in $inverse -Matrix $affineMatrix -Constant $affineConstant

        # Store in S-box
        $sbox[$in] = $sboxValue

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
    param(
        [byte]$In,
        [byte[][]]$Matrix,
        [byte]$Constant
    )
    # Convert the input byte to an array of 8 individual bits
    # Bit 0 is LSB (rightmost), bit 7 is MSB (leftmost)
    [int[]]$inputBits = @(0,0,0,0,0,0,0,0)  # Pre-initialize array

    for ($bitPos = 0; $bitPos -lt 8; $bitPos++) {
        # Extract each bit: shift right by position, then mask with 1
        $inputBits[$bitPos] = ($InputByte -shr $bitPos) -band 1
    }

    Write-Verbose "Input byte 0x$('{0:X2}' -f $InputByte) = $('{0:b8}' -f $InputByte)"
    Write-Verbose "Bit array: [$($inputBits -join ',')] (LSB to MSB)"

    # Perform matrix multiplication in GF(2)
    # Each output bit is the dot product of a matrix row with the input vector
    [byte]$result = 0

    for ($outputBit = 0; $outputBit -lt 8; $outputBit++) {
        # Calculate dot product: matrix_row · input_vector
        # In GF(2), multiplication is AND, addition is XOR
        [int]$dotProduct = 0

        for ($inputBit = 0; $inputBit -lt 8; $inputBit++) {
            # GF(2) multiplication: matrix_element AND input_bit
            $product = $Matrix[$outputBit][$inputBit] -band $inputBits[$inputBit]

            # GF(2) addition: XOR the products together
            $dotProduct = $dotProduct -bxor $product
        }

        # If the dot product is 1, set the corresponding bit in the result
        if ($dotProduct -band 1) {
            $result = $result -bor (1 -shl $outputBit)
        }

        Write-Verbose "Output bit $outputBit`: dot product = $dotProduct, result so far = 0x$('{0:X2}' -f $result)"
    }

    # Step 2: Add the affine constant (XOR in GF(2))
    $finalResult = $result -bxor $Constant

    Write-Verbose "After matrix: 0x$('{0:X2}' -f $result), after adding constant 0x$('{0:X2}' -f $Constant): 0x$('{0:X2}' -f $finalResult)"

    return [byte]$finalResult
}

Build-AESSbox
