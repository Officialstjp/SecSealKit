<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


# Utils.ps1 — Common helpers for SecSealKit

Set-StrictMode -Version Latest

function Write-LogEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Level = 'Info',
        [hashtable]$Data
    )
    try {
        $dir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $entry = [ordered]@{
            ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            event = $Event
            level = $Level
            data = $Data
        } | ConvertTo-Json -Compress
        Add-Content -LiteralPath $script:LogPath -Value $entry
    } catch {
        Write-Verbose "Failed to write log event: $_`n`nEntry: $entry"
    }
}

function New-RandomBytes {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Count
    )
    $bytes = New-Object byte[]($Count)
	[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
	return $bytes
}

function Clear-Bytes {
    param( [byte[]]$b  )
    if ($b) { [Array]::Clear($b,0,$b.Length) }
}

function Join-Ascii {
	param(
        [string[]]$Parts,
        [char]$Sep = '$'
    )
	[Text.Encoding]::ASCII.GetBytes(($Parts -join $Sep))
}

function ConvertTo-Base64 {
    param(
        [byte[]]$Bytes
    )
    [Convert]::ToBase64String($Bytes)
}

function ConvertFrom-Base64 {
    param(
        [string]$Text
    )
    [Convert]::FromBase64String($Text)
}

function Compare-BytesConstantTime {
	[CmdletBinding()]
    param(
        [byte[]]$A,
        [byte[]]$B
    )

	if ($null -eq $A -or $null -eq $B) { return $false }
	if ($A.Length -ne $B.Length) { return $false }

	$acc = 0
	for ($i=0; $i -lt $A.Length; $i++) {
        $acc = $acc -bor ($A[$i] -bxor $B[$i])
    }
	return ($acc -eq 0)
}

function Get-DomainSeparatedSalt {
    param (
        [byte[]]$Salt
    )
    [Text.Encoding]::ASCII.GetBytes(([Text.Encoding]::ASCII.GetString($Salt)) + '|scs1|')
}
