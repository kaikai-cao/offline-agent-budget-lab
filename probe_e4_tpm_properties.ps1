# E4.6: Read-only TPM 2.0 property probe through Windows TBS.
# Sends only TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES).
# No NV index is defined, read, written, incremented, or deleted.
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$source = @'
using System;
using System.Runtime.InteropServices;

public static class E46TbsApi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct TBS_CONTEXT_PARAMS2
    {
        public UInt32 version;
        public UInt32 flags;
    }

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    public static extern UInt32 Tbsi_Context_Create(
        ref TBS_CONTEXT_PARAMS2 parameters,
        out IntPtr context);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    public static extern UInt32 Tbsip_Submit_Command(
        IntPtr context,
        UInt32 locality,
        UInt32 priority,
        [In] byte[] command,
        UInt32 commandSize,
        [Out] byte[] result,
        ref UInt32 resultSize);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    public static extern UInt32 Tbsip_Context_Close(IntPtr context);
}
'@

if (-not ('E46TbsApi' -as [type])) {
    Add-Type -TypeDefinition $source
}

function ConvertTo-BE32([uint32] $Value) {
    return [byte[]]@(
        [byte](($Value -shr 24) -band 0xFF),
        [byte](($Value -shr 16) -band 0xFF),
        [byte](($Value -shr 8) -band 0xFF),
        [byte]($Value -band 0xFF)
    )
}

function Read-BE16([byte[]] $Bytes, [int] $Offset) {
    return [uint32]((([uint32]$Bytes[$Offset]) -shl 8) -bor [uint32]$Bytes[$Offset + 1])
}

function Read-BE32([byte[]] $Bytes, [int] $Offset) {
    $v = ([uint64]$Bytes[$Offset] -shl 24) -bor
         ([uint64]$Bytes[$Offset + 1] -shl 16) -bor
         ([uint64]$Bytes[$Offset + 2] -shl 8) -bor
         ([uint64]$Bytes[$Offset + 3])
    return [uint32]$v
}

function New-GetCapabilityCommand([uint32] $Property, [uint32] $PropertyCount) {
    $list = [System.Collections.Generic.List[byte]]::new()
    # TPM_ST_NO_SESSIONS, commandSize=22, TPM_CC_GetCapability
    $list.AddRange([byte[]](0x80, 0x01))
    $list.AddRange([byte[]](ConvertTo-BE32 22))
    $list.AddRange([byte[]](ConvertTo-BE32 0x0000017A))
    # TPM_CAP_TPM_PROPERTIES = 0x00000006
    $list.AddRange([byte[]](ConvertTo-BE32 0x00000006))
    $list.AddRange([byte[]](ConvertTo-BE32 $Property))
    $list.AddRange([byte[]](ConvertTo-BE32 $PropertyCount))
    return $list.ToArray()
}

function Invoke-GetTpmProperty([IntPtr] $Context, [uint32] $Property, [string] $Name) {
    $command = New-GetCapabilityCommand -Property $Property -PropertyCount 1
    [byte[]]$response = New-Object byte[] 4096
    [uint32]$responseSize = $response.Length

    $tbsResult = [E46TbsApi]::Tbsip_Submit_Command(
        $Context, 0, 200, $command, [uint32]$command.Length,
        $response, [ref]$responseSize)

    $tbsHex = '0x{0:X8}' -f $tbsResult
    if ($tbsResult -ne 0) {
        return [pscustomobject]@{
            Name = $Name; RequestedProperty = ('0x{0:X8}' -f $Property)
            TbsReturn = $tbsHex; TpmResponseCode = $null
            ReturnedProperty = $null; Value = $null; Status = 'TBS_ERROR'
        }
    }

    if ($responseSize -lt 19) {
        throw "TPM response too short for ${Name}: $responseSize bytes"
    }

    $tag = Read-BE16 $response 0
    $reportedSize = Read-BE32 $response 2
    $tpmRc = Read-BE32 $response 6
    if ($reportedSize -gt $responseSize -or $reportedSize -lt 10) {
        throw "Invalid TPM response size for ${Name}: reported=$reportedSize actual=$responseSize"
    }

    if ($tpmRc -ne 0) {
        return [pscustomobject]@{
            Name = $Name; RequestedProperty = ('0x{0:X8}' -f $Property)
            TbsReturn = $tbsHex; TpmResponseCode = ('0x{0:X8}' -f $tpmRc)
            ReturnedProperty = $null; Value = $null; Status = 'TPM_ERROR'
        }
    }

    # TPM2_GetCapability response parameters:
    # moreData(1), capability(4), count(4), then count * (property(4), value(4)).
    $moreData = $response[10]
    $capability = Read-BE32 $response 11
    $count = Read-BE32 $response 15
    $expectedSize = 19 + (8 * [int]$count)
    if ($capability -ne 6 -or $count -gt 32 -or $reportedSize -lt $expectedSize) {
        throw "Unexpected TPM_CAP_TPM_PROPERTIES response layout for $Name"
    }

    if ($count -eq 0) {
        return [pscustomobject]@{
            Name = $Name; RequestedProperty = ('0x{0:X8}' -f $Property)
            TbsReturn = $tbsHex; TpmResponseCode = '0x00000000'
            ReturnedProperty = $null; Value = $null; Status = 'NOT_RETURNED'
        }
    }

    $items = @()
    for ($i = 0; $i -lt $count; $i++) {
        $offset = 19 + (8 * $i)
        $items += [pscustomobject]@{
            Property = (Read-BE32 $response $offset)
            Value = (Read-BE32 $response ($offset + 4))
        }
    }

    $exact = $items | Where-Object { $_.Property -eq $Property } | Select-Object -First 1
    if (-not $exact) {
        $first = $items | Select-Object -First 1
        return [pscustomobject]@{
            Name = $Name; RequestedProperty = ('0x{0:X8}' -f $Property)
            TbsReturn = $tbsHex; TpmResponseCode = '0x00000000'
            ReturnedProperty = ('0x{0:X8}' -f $first.Property)
            Value = $first.Value; Status = 'NEXT_PROPERTY_RETURNED_NOT_EXACT'
        }
    }

    return [pscustomobject]@{
        Name = $Name; RequestedProperty = ('0x{0:X8}' -f $Property)
        TbsReturn = $tbsHex; TpmResponseCode = '0x00000000'
        ReturnedProperty = ('0x{0:X8}' -f $exact.Property)
        Value = $exact.Value; Status = 'OK'; MoreData = [bool]($moreData -ne 0)
    }
}

Write-Host '========== E4.6 TPM READ-ONLY PROPERTY PROBE =========='
Write-Host 'Only TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES) commands are sent.'
Write-Host 'No NV index or NV counter is read, created, modified, incremented, or deleted.'

$params = New-Object E46TbsApi+TBS_CONTEXT_PARAMS2
$params.version = 2 # TPM_VERSION_20
$params.flags = 4   # includeTpm20=1; requestRaw=0; includeTpm12=0
$context = [IntPtr]::Zero
$createResult = [E46TbsApi]::Tbsi_Context_Create([ref]$params, [ref]$context)
Write-Host ('TBS context creation: 0x{0:X8}' -f $createResult)
if ($createResult -ne 0) { throw ('Tbsi_Context_Create failed: 0x{0:X8}' -f $createResult) }

$properties = @(
    [pscustomobject]@{ Name='TPM_PT_NV_COUNTERS_MAX'; Id=[uint32]0x00000116; Meaning='Maximum number of defined NV counter indexes' },
    [pscustomobject]@{ Name='TPM_PT_NV_INDEX_MAX'; Id=[uint32]0x00000117; Meaning='Maximum data size of one NV index' },
    [pscustomobject]@{ Name='TPM_PT_ORDERLY_COUNT'; Id=[uint32]0x0000011D; Meaning='Orderly-counter update interval parameter' },
    [pscustomobject]@{ Name='TPM_PT_NV_BUFFER_MAX'; Id=[uint32]0x0000012C; Meaning='Maximum data bytes in one NV read/write/extend/certify command' },
    [pscustomobject]@{ Name='TPM_PT_HR_NV_INDEX'; Id=[uint32]0x00000202; Meaning='Current number of defined NV indexes' },
    [pscustomobject]@{ Name='TPM_PT_NV_COUNTERS'; Id=[uint32]0x0000020A; Meaning='Current number of NV indexes with TPM_NT_COUNTER' },
    [pscustomobject]@{ Name='TPM_PT_NV_COUNTERS_AVAIL'; Id=[uint32]0x0000020B; Meaning='Estimate of additional ORDERLY NV counters; not a general free-counter count' },
    [pscustomobject]@{ Name='TPM_PT_NV_WRITE_RECOVERY'; Id=[uint32]0x00000212; Meaning='Approximate delay before another NV-modifying command is accepted' }
)

$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($property in $properties) {
        $result = Invoke-GetTpmProperty -Context $context -Property $property.Id -Name $property.Name
        $results.Add($result)
    }
}
finally {
    $closeResult = [E46TbsApi]::Tbsip_Context_Close($context)
    Write-Host ('TBS context close: 0x{0:X8}' -f $closeResult)
}

Write-Host "`n========== PROPERTY RESULTS =========="
$results | Format-Table -AutoSize
Write-Host "`n========== PROPERTY DETAILS =========="
for ($i = 0; $i -lt $properties.Count; $i++) {
    [pscustomobject]@{
        Name = $properties[$i].Name
        Meaning = $properties[$i].Meaning
        RequestedProperty = $results[$i].RequestedProperty
        ReturnedProperty = $results[$i].ReturnedProperty
        Value = $results[$i].Value
        Status = $results[$i].Status
        TbsReturn = $results[$i].TbsReturn
        TpmResponseCode = $results[$i].TpmResponseCode
    } | Format-List
}
Write-Host '========== END E4.6 PROBE =========='



