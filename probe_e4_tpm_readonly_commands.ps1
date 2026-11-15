# E4 TPM read-only command probe
# Executes only TPM2_GetCapability commands through TBS.
# It does NOT define/delete NV indices, write NV data, increment counters,
# clear the TPM, or change firmware/Windows configuration.

$ErrorActionPreference = 'Stop'

Write-Host "`n========== E4 TPM READ-ONLY COMMAND PROBE =========="
Write-Host "Commands: TPM2_GetCapability(TPM_CAP_COMMANDS), TPM2_GetCapability(TPM_CAP_HANDLES)"
Write-Host "No TPM NV write or counter increment command is sent."

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "IsAdministrator: $isAdmin"
if (-not $isAdmin) {
    throw 'Run this script from an elevated PowerShell window.'
}

$source = @'
using System;
using System.Runtime.InteropServices;

public static class E4TbsReadOnlyProbe
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

if (-not ('E4TbsReadOnlyProbe' -as [type])) {
    Add-Type -TypeDefinition $source
}

function ConvertTo-U32BE {
    param([Parameter(Mandatory)][UInt32]$Value)
    [UInt64]$v = $Value
    [byte[]]$bytes = @(
        [byte](($v -shr 24) -band 0xFF),
        [byte](($v -shr 16) -band 0xFF),
        [byte](($v -shr 8) -band 0xFF),
        [byte]($v -band 0xFF)
    )
    return ,$bytes
}

function Read-U32BE {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )
    if ($Offset -lt 0 -or ($Offset + 4) -gt $Bytes.Length) {
        throw "TPM response is too short for UInt32 at offset $Offset"
    }
    [UInt64]$v = ([UInt64]$Bytes[$Offset] * 16777216) +
                 ([UInt64]$Bytes[$Offset + 1] * 65536) +
                 ([UInt64]$Bytes[$Offset + 2] * 256) +
                 [UInt64]$Bytes[$Offset + 3]
    return [UInt32]$v
}

function New-TpmGetCapabilityCommand {
    param(
        [Parameter(Mandatory)][UInt32]$Capability,
        [Parameter(Mandatory)][UInt32]$Property,
        [Parameter(Mandatory)][UInt32]$PropertyCount
    )

    # TPM_ST_NO_SESSIONS (0x8001), commandSize=22, TPM_CC_GetCapability (0x17A)
    $list = [System.Collections.Generic.List[byte]]::new()
    $list.AddRange([byte[]]@(0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7A))
    $list.AddRange([byte[]](ConvertTo-U32BE $Capability))
    $list.AddRange([byte[]](ConvertTo-U32BE $Property))
    $list.AddRange([byte[]](ConvertTo-U32BE $PropertyCount))
    return ,$list.ToArray()
}

function Invoke-TpmReadOnlyCommand {
    param(
        [Parameter(Mandatory)][IntPtr]$Context,
        [Parameter(Mandatory)][byte[]]$Command,
        [Parameter(Mandatory)][string]$Name
    )

    [UInt32]$capacity = 4096
    [byte[]]$response = New-Object byte[] ([int]$capacity)
    [UInt32]$locality = 0       # TBS_COMMAND_LOCALITY_ZERO
    [UInt32]$priority = 200     # TBS_COMMAND_PRIORITY_NORMAL
    [UInt32]$commandSize = [UInt32]$Command.Length

    $tbsRc = [E4TbsReadOnlyProbe]::Tbsip_Submit_Command(
        $Context, $locality, $priority, $Command, $commandSize,
        $response, [ref]$capacity)

    $tbsHex = '0x{0:X8}' -f $tbsRc
    Write-Host "`n[$Name] TBS return: $tbsHex"

    if ($tbsRc -ne 0) {
        return [pscustomobject]@{
            Name = $Name; TbsReturn = $tbsHex; TpmResponseCode = $null
            Response = $null; ResponseLength = 0; Error = 'TBS submission failed'
        }
    }

    if ($capacity -lt 10 -or $capacity -gt $response.Length) {
        throw "$Name returned an invalid TPM response length: $capacity"
    }

    [byte[]]$actual = $response[0..([int]$capacity - 1)]
    $tag = ('0x{0:X4}' -f (([UInt32]$actual[0] * 256) + [UInt32]$actual[1]))
    $declaredSize = Read-U32BE -Bytes $actual -Offset 2
    $tpmRc = Read-U32BE -Bytes $actual -Offset 6
    $tpmHex = '0x{0:X8}' -f $tpmRc

    Write-Host "[$Name] TPM response tag: $tag"
    Write-Host "[$Name] TPM response size: $declaredSize"
    Write-Host "[$Name] TPM response code: $tpmHex"

    if ($declaredSize -ne $capacity) {
        throw "$Name response header size ($declaredSize) does not match actual length ($capacity)"
    }

    return [pscustomobject]@{
        Name = $Name; TbsReturn = $tbsHex; TpmResponseCode = $tpmHex
        Response = $actual; ResponseLength = [int]$capacity; Error = $null
    }
}

function Get-CapabilityEntries {
    param(
        [Parameter(Mandatory)][byte[]]$Response,
        [Parameter(Mandatory)][string]$Name
    )

    # Successful no-session GetCapability response:
    # 10-byte header | moreData(1) | capability(4) | count(4) | entries
    if ($Response.Length -lt 19) {
        throw "$Name successful response is too short to contain capability data"
    }

    $moreData = ($Response[10] -ne 0)
    $capability = Read-U32BE -Bytes $Response -Offset 11
    $count = Read-U32BE -Bytes $Response -Offset 15
    [UInt64]$needed = 19 + ([UInt64]$count * 4)
    if ($needed -gt $Response.Length) {
        throw "$Name entry count exceeds the returned response length"
    }

    $entries = [System.Collections.Generic.List[UInt32]]::new()
    for ($i = 0; $i -lt [int]$count; $i++) {
        $entries.Add((Read-U32BE -Bytes $Response -Offset (19 + (4 * $i))))
    }

    return [pscustomobject]@{
        MoreData = $moreData
        Capability = ('0x{0:X8}' -f $capability)
        Count = $count
        Entries = $entries.ToArray()
    }
}

# TPM 2.0 TBS context: version=2, includeTpm20 bit (bit 2) = 1.
$params = New-Object E4TbsReadOnlyProbe+TBS_CONTEXT_PARAMS2
$params.version = 2
$params.flags = 4
$context = [IntPtr]::Zero

try {
    $createRc = [E4TbsReadOnlyProbe]::Tbsi_Context_Create([ref]$params, [ref]$context)
    Write-Host "`nTBS context creation: 0x{0:X8}" -f $createRc
    if ($createRc -ne 0 -or $context -eq [IntPtr]::Zero) {
        throw ('TBS context creation failed: 0x{0:X8}' -f $createRc)
    }

    # Probe 1: TPM_CAP_COMMANDS (0x00000002), beginning at command 0x130.
    # This is read-only and asks which command codes the TPM advertises.
    $commands = New-TpmGetCapabilityCommand -Capability 0x00000002 -Property 0x00000130 -PropertyCount 64
    $commandsResult = Invoke-TpmReadOnlyCommand -Context $context -Command $commands -Name 'TPM_CAP_COMMANDS'

    if ($commandsResult.TpmResponseCode -eq '0x00000000') {
        $commandData = Get-CapabilityEntries -Response $commandsResult.Response -Name 'TPM_CAP_COMMANDS'
        Write-Host "[TPM_CAP_COMMANDS] MoreData: $($commandData.MoreData)"
        Write-Host "[TPM_CAP_COMMANDS] Entry count: $($commandData.Count)"

        $targetCommands = @{
            'TPM_CC_NV_Increment' = [UInt32]0x00000134
            'TPM_CC_NV_Read'      = [UInt32]0x0000014E
            'TPM_CC_NV_ReadPublic'= [UInt32]0x00000169
        }

        foreach ($entry in $targetCommands.GetEnumerator()) {
            $found = $false
            foreach ($attribute in $commandData.Entries) {
                # TPMA_CC.commandIndex occupies the low 16 bits.
                if (($attribute -band [UInt32]0x0000FFFF) -eq $entry.Value) {
                    $found = $true
                    break
                }
            }
            Write-Host ("[Advertised command] {0} ({1}): {2}" -f $entry.Key, ('0x{0:X8}' -f $entry.Value), $found)
        }
    }
    else {
        Write-Host '[TPM_CAP_COMMANDS] TPM did not return success; command support cannot be inferred.'
    }

    # Probe 2: TPM_CAP_HANDLES (0x00000001), first NV-index handle range.
    # This enumerates current NV handles; it does not create or modify them.
    $handles = New-TpmGetCapabilityCommand -Capability 0x00000001 -Property 0x01000000 -PropertyCount 64
    $handlesResult = Invoke-TpmReadOnlyCommand -Context $context -Command $handles -Name 'TPM_CAP_HANDLES_NV'

    if ($handlesResult.TpmResponseCode -eq '0x00000000') {
        $handleData = Get-CapabilityEntries -Response $handlesResult.Response -Name 'TPM_CAP_HANDLES_NV'
        Write-Host "[TPM_CAP_HANDLES_NV] MoreData: $($handleData.MoreData)"
        Write-Host "[TPM_CAP_HANDLES_NV] Current NV handle count returned: $($handleData.Count)"
        if ($handleData.Count -eq 0) {
            Write-Host '[TPM_CAP_HANDLES_NV] No currently defined NV handles were returned in this page.'
        }
        else {
            foreach ($handle in $handleData.Entries) {
                Write-Host ('[NV handle] 0x{0:X8}' -f $handle)
            }
        }
    }
    else {
        Write-Host '[TPM_CAP_HANDLES_NV] TPM did not return success; current NV handles could not be enumerated.'
    }
}
finally {
    if ($context -ne [IntPtr]::Zero) {
        $closeRc = [E4TbsReadOnlyProbe]::Tbsip_Context_Close($context)
        Write-Host ("`nTBS context close: 0x{0:X8}" -f $closeRc)
    }
}

Write-Host "`n========== END E4 READ-ONLY COMMAND PROBE =========="
Write-Host 'Interpretation: TBS submission success and TPM response success are separate checks.'
Write-Host 'TPM_CAP_COMMANDS advertises implementation support; it does NOT prove Windows/TBS will permit a mutating NV command.'
Write-Host 'No NV index was defined, deleted, written, or incremented.'
