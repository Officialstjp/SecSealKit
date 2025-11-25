<#
.SYNOPSIS
End-to-end integration tests for SecSealKit v0.2 binary module.

.DESCRIPTION
Tests all crypto functionality, passphrase providers, and error handling.
#>

param(
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Verbose) { $VerbosePreference = 'Continue' }

$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$modulePath = Join-Path $moduleRoot 'SecSealKit.psd1'

Write-Host "`n=== SecSealKit v0.2 Integration Tests ===" -ForegroundColor Cyan

# Clean import
Remove-Module SecSealKit -ErrorAction SilentlyContinue
Import-Module $modulePath -Force

$testsPassed = 0
$testsFailed = 0

function Test-Case {
    param(
        [string]$Name,
        [scriptblock]$Test
    )

    Write-Host "`n[$Name]" -ForegroundColor Yellow
    try {
        & $Test
        Write-Host "  [+] PASS" -ForegroundColor Green
        $script:testsPassed++
    }
    catch {
        Write-Host "  [!] FAIL: $_" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
        $script:testsFailed++
    }
}

# Test 1: Module loads correctly
Test-Case "Module Import" {
    $cmds = Get-Command -Module SecSealKit
    if ($cmds.Count -lt 2) { throw "Expected at least 2 cmdlets, got $($cmds.Count)" }
    Write-Host "  Found cmdlets: $($cmds.Name -join ', ')"
}

# Test 2: Basic Seal/Unseal with SecureString
Test-Case "Seal/Unseal Round-trip (SecureString)" {
    $secret = "Test-Secret-$(Get-Random)"
    $pass = ConvertTo-SecureString "TestPass123!" -AsPlainText -Force

    # Seal
    $envelope = Protect-Secret -InputString $secret -PassphraseSecure $pass -Verbose:$Verbose
    if ([string]::IsNullOrWhiteSpace($envelope)) { throw "Seal returned empty envelope" }
    if (!$envelope.StartsWith("SCS1`$")) { throw "Invalid envelope format: $($envelope.Substring(0, 35))..." }

    # Unseal
    $decrypted = Unseal-Secret -Envelope $envelope -PassphraseSecure $pass -AsPlainText -Verbose:$Verbose
    if ($decrypted -ne $secret) { throw "Decrypted '$decrypted' != original '$secret'" }
}

# Test 3: File-based operations
Test-Case "Seal/Unseal with Files" {
    $testFile = Join-Path $env:TEMP "secseal_test_$(Get-Random).txt"
    $sealedFile = "$testFile.scs1"
    $unsealedFile = "$testFile.unsealed"

    try {
        $originalContent = "File content test: $(Get-Date)"
        Set-Content -Path $testFile -Value $originalContent -NoNewline

        $pass = ConvertTo-SecureString "FileTest456!" -AsPlainText -Force

        # Seal file
        Protect-Secret -InFile $testFile -OutFile $sealedFile -PassphraseSecure $pass -Verbose:$Verbose
        if (!(Test-Path $sealedFile)) { throw "Sealed file not created" }

        # Unseal file
        Unprotect-Secret -InFile $sealedFile -OutFile $unsealedFile -PassphraseSecure $pass -Verbose:$Verbose
        $decryptedContent = Get-Content -Path $unsealedFile -Raw

        if ($decryptedContent -ne $originalContent) {
            throw "File content mismatch: '$decryptedContent' != '$originalContent'"
        }
    }
    finally {
        Remove-Item $testFile, $sealedFile, $unsealedFile -ErrorAction SilentlyContinue
    }
}

# Test 4: Wrong passphrase detection
Test-Case "MAC Verification (Wrong Passphrase)" {
    $secret = "WrongPassTest"
    $pass1 = ConvertTo-SecureString "CorrectPass" -AsPlainText -Force
    $pass2 = ConvertTo-SecureString "WrongPass" -AsPlainText -Force

    $envelope = Protect-Secret -InputString $secret -PassphraseSecure $pass1

    $failed = $false
    try {
        Unseal-Secret -Envelope $envelope -PassphraseSecure $pass2 -AsPlainText -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -like "*MAC verification failed*") {
            $failed = $true
        }
    }

    if (!$failed) { throw "Wrong passphrase should have triggered MAC verification error" }
}

# Test 5: Tamper detection
Test-Case "Tamper Detection" {
    $secret = "TamperTest"
    $pass = ConvertTo-SecureString "TamperPass" -AsPlainText -Force

    $envelope = Protect-Secret -InputString $secret -PassphraseSecure $pass

    # Tamper with the envelope (flip one character in the ciphertext)
    $parts = $envelope -split '\$'
    $ctIndex = 0..($parts.Count-1) | Where-Object { $parts[$_].StartsWith('ct=') }
    $ct = $parts[$ctIndex].Substring(3)
    $tampered = $ct.ToCharArray()
    $tampered[10] = if ($tampered[10] -eq 'A') { 'B' } else { 'A' }
    $parts[$ctIndex] = "ct=$($tampered -join '')"
    $tamperedEnvelope = $parts -join '$'

    $failed = $false
    try {
        Unseal-Secret -Envelope $tamperedEnvelope -PassphraseSecure $pass -AsPlainText -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -like "*MAC verification failed*") {
            $failed = $true
        }
    }

    if (!$failed) { throw "Tampered envelope should have triggered MAC verification error" }
}

# Test 6: Environment variable passphrase
Test-Case "Environment Variable Passphrase" {
    $envVarName = "SECSEAL_TEST_PASS_$(Get-Random)"
    $envVarValue = "EnvPass$(Get-Random)"

    try {
        [Environment]::SetEnvironmentVariable($envVarName, $envVarValue, 'Process')

        $secret = "EnvVarTest"
        $envelope = Protect-Secret -InputString $secret -FromEnv $envVarName -Verbose:$Verbose
        $decrypted = Unseal-Secret -Envelope $envelope -FromEnv $envVarName -AsPlainText -Verbose:$Verbose

        if ($decrypted -ne $secret) { throw "Env var passphrase failed" }
    }
    finally {
        [Environment]::SetEnvironmentVariable($envVarName, $null, 'Process')
    }
}

# Test 7: Custom iteration count
Test-Case "Custom PBKDF2 Iterations" {
    $secret = "IterationTest"
    $pass = ConvertTo-SecureString "IterPass" -AsPlainText -Force

    $envelope = Protect-Secret -InputString $secret -PassphraseSecure $pass -Iterations 50000 -Verbose:$Verbose

    # Check envelope contains correct iteration count
    if ($envelope -notmatch 'iter=50000') { throw "Envelope doesn't contain iter=50000" }

    $decrypted = Unseal-Secret -Envelope $envelope -PassphraseSecure $pass -AsPlainText -Verbose:$Verbose
    if ($decrypted -ne $secret) { throw "Custom iterations failed" }
}

# Test 8: Binary data handling
Test-Case "Binary Data (Bytes)" {
    $bytes = [byte[]](1..255)
    $pass = ConvertTo-SecureString "BytePass" -AsPlainText -Force

    $envelope = Protect-Secret -InputBytes $bytes -PassphraseSecure $pass -Verbose:$Verbose
    $decrypted = Unseal-Secret -Envelope $envelope -PassphraseSecure $pass -AsBytes -Verbose:$Verbose

    if ($decrypted.Length -ne 255) { throw "Byte length mismatch: $($decrypted.Length) != 255" }
    for ($i = 0; $i -lt 255; $i++) {
        if ($decrypted[$i] -ne ($i + 1)) { throw "Byte mismatch at index $i" }
    }
}

# Summary
Write-Host "`n=== Test Results ===" -ForegroundColor Cyan
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -gt 0) { 'Red' } else { 'Green' })

if ($testsFailed -gt 0) {
    Write-Host "`n´[!!] Some tests failed!" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "`n[++] All tests passed!" -ForegroundColor Green
    exit 0
}
