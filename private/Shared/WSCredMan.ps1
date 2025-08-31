<#
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2025 Stefan Ploch
#>

<#

Add-Type: C:\Projects\coding\Powershell\Modules\STSecSeal\private\Shared\WSCredMan.ps1:11:1
Line |
  11 |  Add-Type -Namespace WinCred -Name Native -MemberDefinition @"
     |  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | (7,6): error CS1513: } expected     {      ^
#>

# WSCredMan.ps1 - Generic read helper for Windows Credential Manager via P/Invoke

Set-StrictMode -Version Latest

if (-not ([System.Management.Automation.PSTypeName]'WinCred.CredMan').Type) {
    Write-Verbose "Loading WinCred.CredMan via Add-Type"
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace WinCred {
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CREDENTIAL {
    public uint Flags;
    public uint Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

public static class CredMan {
    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredReadW(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

    [DllImport("Advapi32.dll", SetLastError=true)]
    public static extern void CredFree([In] IntPtr cred);
}
}
"@
} else {
    Write-Verbose "WinCred.CredMan already loaded"
}

function Get-CredManSecretBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetName
    )

    $ptr = [IntPtr]::Zero
    try {
        $ok = [WinCred.CredMan]::CredReadW($TargetName, 1, 0, [ref]$ptr) # 1 = CRED_TYPE_GENERIC
        if (-not $ok) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "CredReadW failed ($code) for target '$TargetName'"
        }
        $cred = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type]::GetType('WinCred.CREDENTIAL'))
        if ($cred.CredentialBlobSize -eq 0 -or $cred.CredentialBlob -eq [IntPtr]::Zero) { return $null }
        $bytes = New-Object byte[]($cred.CredentialBlobSize)
        [Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $cred.CredentialBlobSize)
        $bytes
    } finally {
        if ($ptr -ne [IntPtr]::Zero) { [WinCred.CredMan]::CredFree($ptr) }
    }
}
