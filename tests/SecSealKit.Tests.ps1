<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>


Set-StrictMode -Version Latest

$script:ModuleRoot = $PSScriptRoot | Split-Path -Parent
$script:ModulePath = Join-Path $script:ModuleRoot 'SecSealKit.psd1'

Describe "On Module Import" {
    It "loads the Module and all expected commands" {
        # These are aliases that point to the actual cmdlets
        $ExpectedAliases = @(
            'Seal-Secret',
            'Unseal-Secret',
            'Sign-Data',
            'Verify-Data',
            'Inspect-Envelope'
            # Note: Rotate-Envelope planned for v0.4
        )
        try {
            $moduleRoot = Split-Path -Parent $PSScriptRoot
            $modulePath = Join-Path $moduleRoot 'SecSealKit.psd1'
            if (-not $modulePath) { throw 'Computed ModulePath is null or empty' }
            $module = Import-Module -Name $modulePath -Force -ErrorAction Stop -PassThru

            if (-not $module) { throw 'Import-Module returned $null' }

            # Check aliases (Seal-Secret, etc. are aliases to Protect-Secret, etc.)
            $exportedAliases = $module.ExportedAliases.Keys
            foreach ($alias in $ExpectedAliases) {
                $exportedAliases | Should -Contain $alias
            }
        } catch {
            throw "Failed to import module or verify exports: $($_.Exception.Message)"
        }
    }
}

Describe "SCS1 end-to-end" {
    BeforeAll {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $moduleRoot 'SecSealKit.psd1') -Force
    }
    It 'seals and unseals a string round-trip' {
        $tmp = Join-Path $env:TEMP ("scs1_{0}.txt" -f ([guid]::NewGuid().ToString('n')))
        $sec = ConvertTo-SecureString -String 'p@ssw0rd' -AsPlainText -Force
        Seal-Secret -InputString 'hello world' -OutFile $tmp -PassphraseSecure $sec -Iterations 50000
        Test-Path $tmp | Should -BeTrue
        $plain = Unseal-Secret -InFile $tmp -PassphraseSecure $sec -AsPlainText
        $plain | Should -Be 'hello world'
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
    It "fails MAC verification on tamper" {
        $tmp = Join-Path $env:TEMP ("scs1_{0}.txt" -f ([guid]::NewGuid().ToString('n')))
        $sec = ConvertTo-SecureString -String 'p@ssw0rd' -AsPlainText -Force
        Seal-Secret -InputString 'data' -OutFile $tmp -PassphraseSecure $sec -Iterations 50000
        $envText = Get-Content -Raw -LiteralPath $tmp
        # Tamper: flip a character in the middle of the ciphertext
        $parts = $envText.Split('$')
        $ctIndex = ($parts | ForEach-Object { $i = 0 } { if ($_.StartsWith('ct=')) { $i }; $i++ })
        $ct = $parts[$ctIndex].Substring(3)
        $chars = $ct.ToCharArray()
        $chars[20] = if ($chars[20] -eq 'A') { 'B' } else { 'A' }
        $parts[$ctIndex] = "ct=" + ($chars -join '')
        $tampered = $parts -join '$'
        { Unseal-Secret -Envelope $tampered -PassphraseSecure $sec -ErrorAction Stop } | Should -Throw
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}
