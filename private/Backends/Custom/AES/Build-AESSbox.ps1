function Build-AESSbox {
    <#
    .SYNOPSIS
    (Will) Generates the complete AES S-box using mathematical constrection

    .DESCRIPTION
    This function demonstrates how the AES S-box is mathematically constrcuted:
    1. Find multiplicate inverse in GF(2^8)
    2. Apply the affine transformation (matrix multiplcation + constant)

    This is how the AES designer actually created the S-box values!
    #>
    param()
    return
}

function Apply-AffineTransformation {
    <#
    .SYNOPSIS
    Applies the AES affine transfomration: A × input + c

    .DESCRIPTION
    Perfomrs matrix multiplication in GF(2) followed by vector addition.
    This is the second step of AES S-box construction.

    .PARAMETER Input
    The byte to transform (usually the multiplicative inverse)

    .PARAMETER Matrix
    The 8x8 affine transfomration matrix

    .PARAMETER Constant
    The constant byte to add (0x63 for AES)
    #>
    param(
        [byte]$Input,
        [byte[][]]$Matrix,
        [byte]$Constant
    )
    return
}
