<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# DPAPI helpers for keyfile storage (CurrentUser/LocalMachine)

Set-StrictMode -Version Latest

function Protect-DpapiBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Plain,
        [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
        [byte[]]$Entropy
    )

    $scopeEnum = if ($scope -eq 'LocalMachine') {
        [System.Security.Cryptography.DataPotectionScope]::LocalMachine
    } else {
        [System.Security.Cryptography.DataPotectionScope]::CurrentUser
    }
    [System.Security.Cryptography.ProtectedData]::Protect($Plain, $Entropy, $scopeEnum)
}

function Unprotect-DpapiBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Protected,
        [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
        [byte[]]$Entropy
    )

    $scopeEnum = if ($Scope -eq 'LocalMachine') {
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    } else {
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    }
    [System.Security.Cryptography.ProtectedData]::Unprotect($Protected, $Entropy, $scopeEnum)
}
function Read-Keyfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $obj = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $scope   = $obj.scope
    $entropy = if ($obj.entropy) {
        [Convert]::FromBase64String($obj.entropy)
    } else { $null }
    $data    = [Convert]::FromBase64String($obj.data)
    Unprotect-DpapiBytes -Protected $data -Scope $scope -Entropy $entropy
}

function Write-Keyfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$PassphraseBytes,
        [ValidateSet('CurrentUser','LocalMachine')][string]$Scope = 'CurrentUser',
        [byte[]]$Entropy
    )
    $prot = Protect-DpapiBytes -Plain $PassphraseBytes -Scope $Scope -Entropy $Entropy

    $obj = [ordered]@{
        ver     = 1
        scope   = $Scope
        entropy = if ($Entropy) { [Convert]::ToBase64String($Entropy) } else { $null }
        data    = [Convert]::ToBase64String($prot)
    } | ConvertTo-Json -Compress

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $obj -NoNewline
}
