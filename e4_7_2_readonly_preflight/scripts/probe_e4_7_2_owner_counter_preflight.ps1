# E4.7.2 read-only preflight for a dedicated Owner NV Counter.
# Sends TPM2_GetCapability and TPM2_NV_ReadPublic only.
# It never defines, writes, increments, undefines, or reads NV data.

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'Run this script from an elevated PowerShell session.'
}

$cs = @'
using System;
using System.Runtime.InteropServices;

public sealed class TbsRawResult
{
    public uint TbsReturnCode { get; set; }
    public byte[] Response { get; set; }
}

public sealed class NvPublicInfo
{
    public uint NvIndex { get; set; }
    public ushort NameAlg { get; set; }
    public uint Attributes { get; set; }
    public string AuthPolicyHex { get; set; }
    public ushort DataSize { get; set; }
    public string NameHex { get; set; }
}

public static class E472Tbs
{
    [StructLayout(LayoutKind.Sequential)]
    private struct TBS_CONTEXT_PARAMS2
    {
        public uint version;
        public uint flags;
    }

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsi_Context_Create(ref TBS_CONTEXT_PARAMS2 parameters, out IntPtr context);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsip_Context_Close(IntPtr context);

    [DllImport("tbs.dll", ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsip_Submit_Command(
        IntPtr context,
        uint locality,
        uint priority,
        [In] byte[] commandBuffer,
        uint commandBufferLength,
        [Out] byte[] resultBuffer,
        ref uint resultBufferLength);

    public static uint OpenContext(out IntPtr context)
    {
        TBS_CONTEXT_PARAMS2 p = new TBS_CONTEXT_PARAMS2();
        p.version = 2; // TBS_CONTEXT_VERSION_TWO
        p.flags = 4;   // TBS_CONTEXT_FLAG_INCLUDE_TPM20
        return Tbsi_Context_Create(ref p, out context);
    }

    public static uint CloseContext(IntPtr context)
    {
        if (context == IntPtr.Zero) return 0;
        return Tbsip_Context_Close(context);
    }

    public static TbsRawResult Submit(IntPtr context, byte[] command)
    {
        byte[] response = new byte[4096];
        uint responseLength = (uint)response.Length;
        uint rc = Tbsip_Submit_Command(context, 0, 200, command, (uint)command.Length, response, ref responseLength);
        if (responseLength > response.Length) throw new InvalidOperationException("TBS returned a response length larger than the supplied buffer.");
        Array.Resize(ref response, (int)responseLength);
        return new TbsRawResult { TbsReturnCode = rc, Response = response };
    }

    private static void PutU16(byte[] b, int o, ushort v)
    {
        b[o] = (byte)(v >> 8); b[o + 1] = (byte)v;
    }

    private static void PutU32(byte[] b, int o, uint v)
    {
        b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v;
    }

    public static byte[] BuildGetCapability(uint capability, uint property, uint propertyCount)
    {
        byte[] b = new byte[22];
        PutU16(b, 0, 0x8001);       // TPM_ST_NO_SESSIONS
        PutU32(b, 2, (uint)b.Length);
        PutU32(b, 6, 0x0000017A);   // TPM_CC_GetCapability
        PutU32(b, 10, capability);
        PutU32(b, 14, property);
        PutU32(b, 18, propertyCount);
        return b;
    }

    public static byte[] BuildNvReadPublic(uint nvIndex)
    {
        byte[] b = new byte[14];
        PutU16(b, 0, 0x8001);       // TPM_ST_NO_SESSIONS
        PutU32(b, 2, (uint)b.Length);
        PutU32(b, 6, 0x00000169);   // TPM_CC_NV_ReadPublic
        PutU32(b, 10, nvIndex);
        return b;
    }

    public static ushort ReadU16(byte[] b, int o)
    {
        if (b == null || o < 0 || o + 2 > b.Length) throw new ArgumentOutOfRangeException("offset");
        return (ushort)(((uint)b[o] << 8) | b[o + 1]);
    }

    public static uint ReadU32(byte[] b, int o)
    {
        if (b == null || o < 0 || o + 4 > b.Length) throw new ArgumentOutOfRangeException("offset");
        return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }

    public static string ToHex(byte[] b, int offset, int length)
    {
        if (b == null || offset < 0 || length < 0 || offset + length > b.Length) throw new ArgumentOutOfRangeException();
        return BitConverter.ToString(b, offset, length).Replace("-", "").ToLowerInvariant();
    }

    public static NvPublicInfo ParseNvReadPublic(byte[] response)
    {
        if (response == null || response.Length < 10) throw new InvalidOperationException("TPM response header is too short.");
        uint size = ReadU32(response, 2);
        uint rc = ReadU32(response, 6);
        if (rc != 0) throw new InvalidOperationException("Cannot parse unsuccessful TPM response.");
        if (size != response.Length || size < 14) throw new InvalidOperationException("Invalid TPM response size.");

        int publicSize = ReadU16(response, 10);
        int publicStart = 12;
        int publicEnd = publicStart + publicSize;
        if (publicEnd + 2 > response.Length) throw new InvalidOperationException("TPM2B_NV_PUBLIC exceeds response bounds.");
        if (publicSize < 12) throw new InvalidOperationException("TPMS_NV_PUBLIC is too short.");

        uint nvIndex = ReadU32(response, publicStart);
        ushort nameAlg = ReadU16(response, publicStart + 4);
        uint attrs = ReadU32(response, publicStart + 6);
        ushort policySize = ReadU16(response, publicStart + 10);
        int policyStart = publicStart + 12;
        int dataSizeOffset = policyStart + policySize;
        if (dataSizeOffset + 2 != publicEnd) throw new InvalidOperationException("Unexpected TPMS_NV_PUBLIC layout.");
        ushort dataSize = ReadU16(response, dataSizeOffset);

        ushort nameSize = ReadU16(response, publicEnd);
        int nameStart = publicEnd + 2;
        if (nameStart + nameSize != response.Length) throw new InvalidOperationException("TPM2B_NAME size does not match response.");

        return new NvPublicInfo
        {
            NvIndex = nvIndex,
            NameAlg = nameAlg,
            Attributes = attrs,
            AuthPolicyHex = ToHex(response, policyStart, policySize),
            DataSize = dataSize,
            NameHex = ToHex(response, nameStart, nameSize)
        };
    }
}
'@

if (-not ('E472Tbs' -as [type])) {
    Add-Type -TypeDefinition $cs -Language CSharp
}

function Format-Hex32([uint32]$Value) {
    return ('0x{0:X8}' -f $Value)
}

function Invoke-TpmCommand([IntPtr]$Context, [byte[]]$Command, [string]$Label) {
    $r = [E472Tbs]::Submit($Context, $Command)
    $obj = [ordered]@{
        Label = $Label
        TbsReturn = (Format-Hex32 $r.TbsReturnCode)
        TpmResponseCode = $null
        Response = $r.Response
    }
    if ($r.TbsReturnCode -eq 0 -and $r.Response.Length -ge 10) {
        $obj.TpmResponseCode = Format-Hex32 ([E472Tbs]::ReadU32($r.Response, 6))
    }
    return [pscustomobject]$obj
}

function Get-CapabilityProperties([IntPtr]$Context, [uint32]$FirstProperty, [uint32]$Count) {
    $result = Invoke-TpmCommand $Context ([E472Tbs]::BuildGetCapability(6, $FirstProperty, $Count)) 'TPM_CAP_TPM_PROPERTIES'
    if ($result.TbsReturn -ne '0x00000000') { throw "TBS failed for TPM_CAP_TPM_PROPERTIES: $($result.TbsReturn)" }
    $b = $result.Response
    if ($b.Length -lt 19 -or [E472Tbs]::ReadU32($b, 6) -ne 0) { throw "TPM_CAP_TPM_PROPERTIES failed: $($result.TpmResponseCode)" }
    $returnedCapability = [E472Tbs]::ReadU32($b, 11)
    if ($returnedCapability -ne 6) { throw 'Unexpected capability selector in TPM response.' }
    $n = [E472Tbs]::ReadU32($b, 15)
    if (19 + (8 * $n) -gt $b.Length) { throw 'TPM property response count exceeds response length.' }
    $map = @{}
    for ($i = 0; $i -lt $n; $i++) {
        $offset = 19 + (8 * $i)
        $property = [E472Tbs]::ReadU32($b, $offset)
        $value = [E472Tbs]::ReadU32($b, $offset + 4)
        $map[$property] = $value
    }
    return $map
}

function Get-AllNvHandles([IntPtr]$Context) {
    $handles = [System.Collections.Generic.List[uint32]]::new()
    [uint32]$start = 0x01000000
    for ($page = 0; $page -lt 16; $page++) {
        $r = Invoke-TpmCommand $Context ([E472Tbs]::BuildGetCapability(1, $start, 64)) 'TPM_CAP_HANDLES'
        if ($r.TbsReturn -ne '0x00000000') { throw "TBS failed for TPM_CAP_HANDLES: $($r.TbsReturn)" }
        $b = $r.Response
        if ($b.Length -lt 19 -or [E472Tbs]::ReadU32($b, 6) -ne 0) { throw "TPM_CAP_HANDLES failed: $($r.TpmResponseCode)" }
        if ([E472Tbs]::ReadU32($b, 11) -ne 1) { throw 'Unexpected capability selector for TPM_CAP_HANDLES.' }
        $more = ($b[10] -ne 0)
        $n = [E472Tbs]::ReadU32($b, 15)
        if (19 + (4 * $n) -gt $b.Length) { throw 'TPM handle count exceeds response length.' }
        if ($n -eq 0 -and $more) { throw 'TPM returned MoreData with an empty handle page.' }
        [uint32]$last = $start
        for ($i = 0; $i -lt $n; $i++) {
            [uint32]$h = [E472Tbs]::ReadU32($b, 19 + (4 * $i))
            if ($h -ge 0x01000000 -and $h -le 0x01FFFFFF) { $handles.Add($h) }
            $last = $h
        }
        if (-not $more) { return $handles.ToArray() }
        if ($last -ge 0x01FFFFFF) { return $handles.ToArray() }
        $start = $last + 1
    }
    throw 'TPM_CAP_HANDLES pagination exceeded the safety limit.'
}

function Read-NvPublic([IntPtr]$Context, [uint32]$Handle) {
    $r = Invoke-TpmCommand $Context ([E472Tbs]::BuildNvReadPublic($Handle)) ('TPM2_NV_ReadPublic ' + (Format-Hex32 $Handle))
    if ($r.TbsReturn -ne '0x00000000') {
        return [pscustomobject]@{ TbsReturn = $r.TbsReturn; TpmResponseCode = $null; Public = $null }
    }
    $b = $r.Response
    if ($b.Length -lt 10) { throw 'TPM NV_ReadPublic response header is too short.' }
    $rc = [E472Tbs]::ReadU32($b, 6)
    if ($rc -ne 0) {
        return [pscustomobject]@{ TbsReturn = $r.TbsReturn; TpmResponseCode = (Format-Hex32 $rc); Public = $null }
    }
    $pub = [E472Tbs]::ParseNvReadPublic($b)
    return [pscustomobject]@{ TbsReturn = $r.TbsReturn; TpmResponseCode = '0x00000000'; Public = $pub }
}

Write-Host '========== E4.7.2 READ-ONLY OWNER COUNTER PREFLIGHT =========='
Write-Host 'Commands: TPM2_GetCapability and TPM2_NV_ReadPublic only.'
Write-Host 'No NV data read; no NV index is defined, changed, incremented, or deleted.'
Write-Host 'Candidate handle: 0x01BFFFFE (Owner NV range).'
Write-Host "IsAdministrator: $isAdmin"

$context = [IntPtr]::Zero
$openRc = [E472Tbs]::OpenContext([ref]$context)
Write-Host ('TBS context creation: ' + (Format-Hex32 $openRc))
if ($openRc -ne 0) { throw ('TBS context creation failed: ' + (Format-Hex32 $openRc)) }

try {
    # Read TPMA_PERMANENT and TPMA_STARTUP_CLEAR.
    $props = Get-CapabilityProperties $context 0x00000200 2
    if (-not $props.ContainsKey([uint32]0x00000200) -or -not $props.ContainsKey([uint32]0x00000201)) {
        throw 'TPM did not return both TPM_PT_PERMANENT and TPM_PT_STARTUP_CLEAR.'
    }
    [uint32]$permanent = $props[[uint32]0x00000200]
    [uint32]$startupClear = $props[[uint32]0x00000201]

    $ownerAuthSet = (($permanent -band 0x00000001) -ne 0)
    $inLockout = (($permanent -band 0x00000200) -ne 0)
    $shEnable = (($startupClear -band 0x00000002) -ne 0)
    $phEnable = (($startupClear -band 0x00000001) -ne 0)
    $phEnableNv = (($startupClear -band 0x00000008) -ne 0)

    Write-Host "`n========== HIERARCHY / PERMANENT STATE =========="
    [pscustomobject]@{
        TPM_PT_PERMANENT = (Format-Hex32 $permanent)
        ownerAuthSet = $ownerAuthSet
        inLockout = $inLockout
        TPM_PT_STARTUP_CLEAR = (Format-Hex32 $startupClear)
        phEnable = $phEnable
        shEnable = $shEnable
        phEnableNV = $phEnableNv
    } | Format-List

    # Re-read known NV handles and compare TPM Names from E4.5.
    $baseline = [ordered]@{
        '0x01400001' = '000bfa5403a66bc97e18bd0afe0225c4ae14b8042f333f9200445877e2cf8f04dabe'
        '0x01400002' = '000b16506bc62a87a1e6bda0abbed6b7f6e3e36e4744f08f52187cad12de90204552'
        '0x0140000A' = '000b36c9f5d797455d000ecf6e4f1f0d991a58d339da9343280b6a60e438bc5e948a'
        '0x01410001' = '000b31be078fc493fa57095b4d041e4b27fefe1e69c4a6543576a37b289c9f2c2b56'
        '0x01410002' = '000b0c141eb1d038579d74843d9734ba22c2c540b8577177826419f4d30bab4c650a'
        '0x01410003' = '000b036b2beeada2ca5b5e21c0117576b961de0f8905b1fab4a7b868de94634edbb4'
        '0x01800100' = '000b8d38b2c5534287a29dceca2118ac4138889e1b9c839944227c5cb996cb6284eb'
        '0x01810008' = '000b0d65170afaf822aa3ff821c6f5fb5f5cea084d7eaba1a4ecf1f264d68d6d1051'
        '0x01820002' = '000bbc81cc49fcf914969cd008c448190026174784f1b76cdb4471dfa6a18398aa27'
        '0x01880001' = '000bd5e41629f4d1ee7b318d4a3e7eae93b0d11e72ffe71e5478f11461c49fa2e6f2'
        '0x01880011' = '000b51a55522eb40aa7f66605334f0814377c886126edb72391675ec8132258398ad'
        '0x01C00002' = '000b9225dc5ee08721240d1ddffd759d33b57e5516fe8fe7e8a9dd5606a7944fb3e3'
        '0x01C00016' = '000b5db4b768ae9225d531436a7f1d36c80fd6f609eff71f049cb0efd0202125cb91'
        '0x01C10102' = '000b9a881750fb31807ef91169ab03b2f2a9b52ffbeb15199b652439bbd55c8c9f7e'
        '0x01C10104' = '000b3eced244b7b3e8333da2a8c55e9a402202e1c445e8d35dee0fc5ee178a055453'
        '0x01C101C0' = '000ba2c2e72c43c119431f57414bb47e879de61f69295df6af451d2994e58025c06f'
    }

    Write-Host "`n========== BASELINE NV NAME COMPARISON =========="
    $baselineResults = foreach ($entry in $baseline.GetEnumerator()) {
        [uint32]$handle = [Convert]::ToUInt32($entry.Key.Substring(2), 16)
        $actual = Read-NvPublic $context $handle
        if ($actual.TbsReturn -ne '0x00000000' -or $actual.TpmResponseCode -ne '0x00000000') {
            [pscustomobject]@{ Handle = $entry.Key; Status = 'READ_ERROR'; TbsReturn = $actual.TbsReturn; TpmResponseCode = $actual.TpmResponseCode; NameMatches = $false }
        } else {
            $match = ($actual.Public.NameHex -eq $entry.Value)
            [pscustomobject]@{ Handle = $entry.Key; Status = 'OK'; TbsReturn = $actual.TbsReturn; TpmResponseCode = $actual.TpmResponseCode; NameMatches = $match }
        }
    }
    $baselineResults | Format-Table -AutoSize

    # Enumerate currently defined NV handles.
    $nvHandles = Get-AllNvHandles $context
    $candidate = [uint32]0x01BFFFFE
    $listed = ($nvHandles -contains $candidate)

    Write-Host "`n========== CANDIDATE HANDLE CHECK =========="
    Write-Host ('Candidate: ' + (Format-Hex32 $candidate))
    Write-Host "Owner range: 0x01800000-0x01BFFFFF (TCG registry convention; actual availability is TPM-specific)."
    Write-Host ('NV handles currently enumerated: ' + $nvHandles.Count)
    Write-Host ('Candidate appears in TPM_CAP_HANDLES: ' + $listed)

    $candidateRead = Read-NvPublic $context $candidate
    Write-Host ('Candidate NV_ReadPublic TBS return: ' + $candidateRead.TbsReturn)
    Write-Host ('Candidate NV_ReadPublic TPM response: ' + [string]$candidateRead.TpmResponseCode)

    $candidateStatus = 'INCONCLUSIVE'
    if ($listed -or $candidateRead.TpmResponseCode -eq '0x00000000') {
        $candidateStatus = 'OCCUPIED'
        if ($candidateRead.Public) {
            $candidateRead.Public | Format-List
        }
    }
    elseif ($candidateRead.TbsReturn -eq '0x00000000' -and $candidateRead.TpmResponseCode -eq '0x0000018B' -and $shEnable) {
        $candidateStatus = 'UNDEFINED_AT_PROBE_TIME'
    }

    $baselinePass = ($baselineResults.Count -eq 16 -and @($baselineResults | Where-Object { -not $_.NameMatches }).Count -eq 0)
    $hierarchyPass = ($shEnable -and -not $inLockout)

    Write-Host "`n========== PREFLIGHT SUMMARY =========="
    [pscustomobject]@{
        BaselineIndexesChecked = $baselineResults.Count
        BaselineNamesUnchanged = $baselinePass
        CandidateHandle = (Format-Hex32 $candidate)
        CandidateStatus = $candidateStatus
        OwnerAuthSet = $ownerAuthSet
        StorageHierarchyEnabled = $shEnable
        TPMInLockout = $inLockout
        HierarchyPreconditionsPass = $hierarchyPass
        ReadOnlyPreflightPass = ($baselinePass -and $candidateStatus -eq 'UNDEFINED_AT_PROBE_TIME' -and $hierarchyPass)
    } | Format-List

    Write-Host 'IMPORTANT: A read-only preflight PASS does not prove NV space is sufficient, prove OwnerAuth is known, or authorize NV_DefineSpace.'
    Write-Host 'No NV index was created, deleted, written, incremented, or data-read.'
}
finally {
    $closeRc = [E472Tbs]::CloseContext($context)
    Write-Host ('TBS context close: ' + (Format-Hex32 $closeRc))
}

Write-Host '========== END E4.7.2 READ-ONLY PREFLIGHT =========='
