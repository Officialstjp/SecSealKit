<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

# DPAPI helpers for keyfile storage (CurrentUser/LocalMachine)

Set-StrictMode -Version Latest

function Get-PassphraseFromSecureString {
    [CmdletBinding()]
    param (
        [SecureString]$Secure
    )

    if (-not $Secure) { return $null }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        [Text.Encoding]::UTF8.GetBytes([RunTime.InteropServices.Marshal]::PtrToStringBSTR($ptr))
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function Get-PassphraseFromEnv {
    [CmdletBinding()]
    param (
        [string]$VarName
    )

    if ([string]::IsNullOrWhiteSpace($VarName)) { return $null }
    $val = [Environment]::GetEnvironmentVariable($VarName, 'Process' )
    if ([string]::IsNullOrEmpty($val)) { return $null }
    [Text.Encoding]::UTF8.GetBytes($val)
}

function Resolve-PassphraseBytes {
    [CmdletBinding()]
    param (
        [string]$FromKeyFile,
        [string]$FromCredMan,
        [SecureString]$PassphraseSecure,
        [string]$FromEnv
    )

    if ($FromKeyFile) {
        return (Read-Keyfile -Path $FromKeyFile)
    }
    if ($FromCredMan) {
        $bytes = (Get-CredManSecretBytes -TargetName $FromCredMan)
        if ($bytes) { return $bytes }
        throw "CredMan entry '$FromCredMan' is empty or not set"
    }
    if ($PassphraseSecure) {
        return (Get-PassphraseFromSecureString -Secure $PassphraseSecure)
    }
    if ($FromEnv) {
        $bytes = Get-PassphraseFromEnv -VarName $FromEnv
        if ($bytes) { return $bytes }
        throw "Env var '$FromEnv' is empty or not set"
    }
    throw "No Passphrase source provided. Specify -FromKeyfile, -FromCredMan, -PassphraseSecure, or -FromEnv."
}

