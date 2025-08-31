<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot | Split-Path -Parent
$script:ModulePath = Join-Path $script:ModuleRoot 'SecSealKit.psd1'

Describe "On Module Import" {
    It "loads the Module and all expected commands" {
        $FunctionsToExport = @(
            'Seal-Secret',
            'Unseal-Secret',
            'Sign-Data',
            'Verify-Data',
            'Rotate-Envelope',
            'Inspect-Envelope'
        )
        try {
            $moduleRoot = Split-Path -Parent $PSScriptRoot
            $modulePath = Join-Path $moduleRoot 'SecSealKit.psd1'
            if (-not $modulePath) { throw 'Computed ModulePath is null or empty' }
            $module = Import-Module -Name $modulePath -Force -ErrorAction Stop -PassThru

            if (-not $module) { throw 'Import-Module returned $null' }

            $exportedFunctions = $module.ExportedFunctions.Keys
            foreach ($fn in $FunctionsToExport) {
                $exportedFunctions | Should -Contain $fn
            }
        } catch {
            throw "Failed to import module or verify exports: $($_.Exception.Message)"
        }
    }
}

Describe "SCS1 end-to-end (builtin)" {
    BeforeAll {
        if (-not (Get-Module -ListAvailable | Where-Object { $_.Name -eq 'SecSealKit' })) {
            Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'SecSealKit.psd1') -Force | Out-Null
        }
    }
    It 'seals and unseas a string round-trip' {
        $tmp = Join-Path $env:TEMP ("scs1_{0}.txt" -f ([guid]::NewGuid().ToString('n')))
        $sec = ConvertTo-SecureString -String 'p@ssw0rd' -AsPlainText -Force
        Seal-Secret -InputString 'hello world' -OutFile $tmp -PassphraseSecure $sec -Iterations 50000 -CryptoProvider builtin
        Test-Path $tmp | Should -BeTrue
        $plain = Unseal-Secret -InFile $tmp -PassphraseSecure $sec -AsPlainText -CryptoProvider builtin
        $plain | Should -Be 'hello world'
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
    It "fails MAC verification on tamper" {
        $tmp = Join-Path $env:TEMP ("scs1_{0}.txt" -f ([guid]::NewGuid().ToString('n')))
        $sec = ConvertTo-SecureString -String 'p@ssw0rd' -AsPlainText -Force
        Seal-Secret -InputString 'data' -OutFile $tmp -PassphraseSecure $sec -Iterations 50000 -CryptoProvider builtin
        $envText = Get-Content -Raw -LiteralPath $tmp
        # Tamper: flip last char
        $tampered = $envText.Substring(0, $envText.Length-1) + 'A'
        { Unseal-Secret -Envelope $tampered -PassphraseSecure $sec -CryptoProvider builtin } | Should -Throw
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}
