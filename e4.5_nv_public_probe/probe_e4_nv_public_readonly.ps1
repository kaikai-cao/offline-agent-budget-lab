# E4.5 read-only TPM NV metadata inspection.
# Sends TPM2_NV_ReadPublic only. Never sends NV_Read, NV_Write,
# NV_Increment, NV_DefineSpace, NV_UndefineSpace, or Clear.
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this probe from an elevated PowerShell window.'
}

$source = @'
using System;
using System.Runtime.InteropServices;

public static class E45Tbs {
    [StructLayout(LayoutKind.Sequential)]
    public struct TBS_CONTEXT_PARAMS2 {
        public UInt32 version;
        public UInt32 flags;
    }

    [DllImport("tbs.dll", ExactSpelling=true, CallingConvention=CallingConvention.Winapi)]
    public static extern UInt32 Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS2 parameters, out IntPtr context);

    [DllImport("tbs.dll", ExactSpelling=true, CallingConvention=CallingConvention.Winapi)]
    public static extern UInt32 Tbsip_Submit_Command(
        IntPtr context,
        UInt32 locality,
        UInt32 priority,
        [In] byte[] command,
        UInt32 commandSize,
        [Out] byte[] result,
        ref UInt32 resultSize);

    [DllImport("tbs.dll", ExactSpelling=true, CallingConvention=CallingConvention.Winapi)]
    public static extern UInt32 Tbsip_Context_Close(IntPtr context);
}
'@

if (-not ('E45Tbs' -as [type])) { Add-Type -TypeDefinition $source }

function ConvertTo-U16BE([UInt16]$Value) {
    return [byte[]]@([byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF))
}
function ConvertTo-U32BE([UInt32]$Value) {
    return [byte[]]@(
        [byte](($Value -shr 24) -band 0xFF),
        [byte](($Value -shr 16) -band 0xFF),
        [byte](($Value -shr 8) -band 0xFF),
        [byte]($Value -band 0xFF)
    )
}
function Read-U16BE([byte[]]$Buffer, [int]$Offset) {
    return [UInt16](([UInt32]$Buffer[$Offset] -shl 8) -bor [UInt32]$Buffer[$Offset + 1])
}
function Read-U32BE([byte[]]$Buffer, [int]$Offset) {
    $v = ([UInt64]$Buffer[$Offset] -shl 24) -bor
         ([UInt64]$Buffer[$Offset + 1] -shl 16) -bor
         ([UInt64]$Buffer[$Offset + 2] -shl 8) -bor
         [UInt64]$Buffer[$Offset + 3]
    return [UInt32]$v
}
function Get-Hex([byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}
function Get-NvHandleClass([UInt32]$Handle) {
    if ($Handle -ge 0x01400000 -and $Handle -le 0x017FFFFF) { return 'Platform NV range (platform manufacturer namespace)' }
    if ($Handle -ge 0x01800000 -and $Handle -le 0x01BFFFFF) { return 'Owner NV range' }
    if ($Handle -ge 0x01C00000 -and $Handle -le 0x01C07FFF) { return 'TCG-assigned endorsement NV range' }
    if ($Handle -ge 0x01C08000 -and $Handle -le 0x01C0FFFF) { return 'TCG-assigned platform NV range' }
    if ($Handle -ge 0x01C10000 -and $Handle -le 0x01C1FFFF) { return 'Component-OEM NV range' }
    if ($Handle -ge 0x01C20000 -and $Handle -le 0x01C2FFFF) { return 'TPM-OEM NV range' }
    return 'Other/reserved NV handle range; consult current TCG registry'
}

# Handles returned by the user's E4.4 TPM_CAP_HANDLES query. Do not alter them.
$handles = [UInt32[]]@(
    0x01400001, 0x01400002, 0x0140000A,
    0x01410001, 0x01410002, 0x01410003,
    0x01800100, 0x01810008, 0x01820002,
    0x01880001, 0x01880011,
    0x01C00002, 0x01C00016,
    0x01C10102, 0x01C10104, 0x01C101C0
)

Write-Host "`n========== E4.5 TPM NV PUBLIC METADATA PROBE =========="
Write-Host 'Command: TPM2_NV_ReadPublic only.'
Write-Host 'No NV data is read. No NV index is created, deleted, written, or incremented.'
Write-Host 'Existing indices are treated as system/platform state: metadata inspection only.'
Write-Host ("IsAdministrator: {0}" -f $true)

$params = New-Object E45Tbs+TBS_CONTEXT_PARAMS2
$params.version = 2
$params.flags = 4
$context = [IntPtr]::Zero
$createRc = [E45Tbs]::Tbsi_Context_Create([ref]$params, [ref]$context)
Write-Host ("TBS context creation: 0x{0:X8}" -f $createRc)
if ($createRc -ne 0) { throw ("Tbsi_Context_Create failed: 0x{0:X8}" -f $createRc) }

$results = New-Object System.Collections.Generic.List[object]
try {
    foreach ($handle in $handles) {
        # TPM_ST_NO_SESSIONS (0x8001), size=14, TPM_CC_NV_ReadPublic (0x169), nvIndex.
        [byte[]]$command = @(
            0x80, 0x01,
            (ConvertTo-U32BE 14),
            (ConvertTo-U32BE 0x00000169),
            (ConvertTo-U32BE $handle)
        ) | ForEach-Object { $_ }
        # Flatten nested byte arrays safely.
        $flat = New-Object System.Collections.Generic.List[byte]
        foreach ($part in $command) {
            if ($part -is [byte[]]) { $flat.AddRange($part) }
            else { $flat.Add([byte]$part) }
        }
        [byte[]]$commandBytes = $flat.ToArray()
        if ($commandBytes.Length -ne 14) { throw "Internal command construction error: $($commandBytes.Length) bytes" }

        [byte[]]$response = New-Object byte[] 4096
        [UInt32]$responseSize = [UInt32]$response.Length
        $tbsRc = [E45Tbs]::Tbsip_Submit_Command(
            $context, [UInt32]0, [UInt32]200,
            $commandBytes, [UInt32]$commandBytes.Length,
            $response, [ref]$responseSize
        )

        $row = [ordered]@{
            Handle = ('0x{0:X8}' -f $handle)
            HandleClass = Get-NvHandleClass $handle
            TbsReturn = ('0x{0:X8}' -f $tbsRc)
            TpmTag = $null
            TpmResponseCode = $null
            NameAlg = $null
            Attributes = $null
            AuthPolicyDigest = $null
            DataSize = $null
            NvName = $null
            ParseStatus = 'Not parsed'
        }

        if ($tbsRc -ne 0) {
            $row.ParseStatus = 'TBS submission failed; no TPM response parsed'
            $results.Add([pscustomobject]$row)
            continue
        }
        if ($responseSize -lt 10) {
            $row.ParseStatus = "Response too short: $responseSize bytes"
            $results.Add([pscustomobject]$row)
            continue
        }

        $tag = Read-U16BE $response 0
        $declaredSize = Read-U32BE $response 2
        $responseCode = Read-U32BE $response 6
        $row.TpmTag = ('0x{0:X4}' -f $tag)
        $row.TpmResponseCode = ('0x{0:X8}' -f $responseCode)

        if ($declaredSize -gt $responseSize -or $declaredSize -lt 10) {
            $row.ParseStatus = "Invalid TPM response size: declared=$declaredSize actual=$responseSize"
            $results.Add([pscustomobject]$row)
            continue
        }
        if ($responseCode -ne 0) {
            $row.ParseStatus = 'TPM returned an error (for example, index absent or command rejected)'
            $results.Add([pscustomobject]$row)
            continue
        }

        # Response body: TPM2B_NV_PUBLIC, followed by TPM2B_NAME.
        if ($declaredSize -lt 14) {
            $row.ParseStatus = 'Successful TPM response but body is too short'
            $results.Add([pscustomobject]$row)
            continue
        }
        $publicSize = Read-U16BE $response 10
        $publicStart = 12
        $publicEnd = $publicStart + $publicSize
        if ($publicEnd -gt $declaredSize -or $publicSize -lt 14) {
            $row.ParseStatus = 'Malformed TPM2B_NV_PUBLIC size'
            $results.Add([pscustomobject]$row)
            continue
        }

        $nvIndex = Read-U32BE $response $publicStart
        $nameAlg = Read-U16BE $response ($publicStart + 4)
        $attributes = Read-U32BE $response ($publicStart + 6)
        $policySize = Read-U16BE $response ($publicStart + 10)
        $dataSizeOffset = $publicStart + 12 + $policySize
        if (($dataSizeOffset + 2) -gt $publicEnd) {
            $row.ParseStatus = 'Malformed authPolicy/dataSize fields'
            $results.Add([pscustomobject]$row)
            continue
        }
        $dataSize = Read-U16BE $response $dataSizeOffset
        $policy = if ($policySize -gt 0) { [byte[]]$response[($publicStart + 14)..($publicStart + 13 + $policySize)] } else { [byte[]]@() }

        if (($publicEnd + 2) -gt $declaredSize) {
            $row.ParseStatus = 'TPM2B_NAME length missing'
            $results.Add([pscustomobject]$row)
            continue
        }
        $nameSize = Read-U16BE $response $publicEnd
        if (($publicEnd + 2 + $nameSize) -gt $declaredSize) {
            $row.ParseStatus = 'Malformed TPM2B_NAME size'
            $results.Add([pscustomobject]$row)
            continue
        }
        $name = if ($nameSize -gt 0) { [byte[]]$response[($publicEnd + 2)..($publicEnd + 1 + $nameSize)] } else { [byte[]]@() }

        $row.NameAlg = ('0x{0:X4}' -f $nameAlg)
        $row.Attributes = ('0x{0:X8}' -f $attributes)
        $row.AuthPolicyDigest = Get-Hex $policy
        $row.DataSize = $dataSize
        $row.NvName = Get-Hex $name
        $row.ParseStatus = if ($nvIndex -eq $handle) { 'OK' } else { 'Returned NV index does not match queried handle' }
        $results.Add([pscustomobject]$row)
    }
}
finally {
    $closeRc = [E45Tbs]::Tbsip_Context_Close($context)
    Write-Host ("TBS context close: 0x{0:X8}" -f $closeRc)
}

Write-Host "`n========== PER-INDEX RESULTS =========="
$results | Format-List *
Write-Host "`n========== SUMMARY =========="
Write-Host ("Handles queried: {0}" -f $handles.Length)
Write-Host ("TPM_ReadPublic successes: {0}" -f (@($results | Where-Object { $_.ParseStatus -eq 'OK' }).Count))
Write-Host ("TBS errors: {0}" -f (@($results | Where-Object { $_.TbsReturn -ne '0x00000000' }).Count))
Write-Host ("TPM errors: {0}" -f (@($results | Where-Object { $_.TpmResponseCode -and $_.TpmResponseCode -ne '0x00000000' }).Count))
Write-Host "`nNo NV index was modified."
Write-Host "========== END E4.5 PROBE =========="
