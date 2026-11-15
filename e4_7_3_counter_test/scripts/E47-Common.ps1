Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CandidateHandle = [uint32]0x01BFFFFE
$script:CandidateHandleText = '0x01BFFFFE'
$script:ExpectedAttributes = [uint32]0x00040014
$script:ExpectedNameAlg = [uint16]0x000B
$script:ExpectedDataSize = [uint16]8
$script:StateRoot = Join-Path $env:LOCALAPPDATA 'OfflineAgentBudgetLab\E4.7.3'
$script:StatePath = Join-Path $script:StateRoot 'counter-state.json'
$script:AuthPath = Join-Path $script:StateRoot 'counter-auth.dpapi.xml'

$script:BaselineNames = [ordered]@{
    '01400001' = '000bfa5403a66bc97e18bd0afe0225c4ae14b8042f333f9200445877e2cf8f04dabe'
    '01400002' = '000b16506bc62a87a1e6bda0abbed6b7f6e3e36e4744f08f52187cad12de90204552'
    '0140000A' = '000b36c9f5d797455d000ecf6e4f1f0d991a58d339da9343280b6a60e438bc5e948a'
    '01410001' = '000b31be078fc493fa57095b4d041e4b27fefe1e69c4a6543576a37b289c9f2c2b56'
    '01410002' = '000b0c141eb1d038579d74843d9734ba22c2c540b8577177826419f4d30bab4c650a'
    '01410003' = '000b036b2beeada2ca5b5e21c0117576b961de0f8905b1fab4a7b868de94634edbb4'
    '01800100' = '000b8d38b2c5534287a29dceca2118ac4138889e1b9c839944227c5cb996cb6284eb'
    '01810008' = '000b0d65170afaf822aa3ff821c6f5fb5f5cea084d7eaba1a4ecf1f264d68d6d1051'
    '01820002' = '000bbc81cc49fcf914969cd008c448190026174784f1b76cdb4471dfa6a18398aa27'
    '01880001' = '000bd5e41629f4d1ee7b318d4a3e7eae93b0d11e72ffe71e5478f11461c49fa2e6f2'
    '01880011' = '000b51a55522eb40aa7f66605334f0814377c886126edb72391675ec8132258398ad'
    '01C00002' = '000b9225dc5ee08721240d1ddffd759d33b57e5516fe8fe7e8a9dd5606a7944fb3e3'
    '01C00016' = '000b5db4b768ae9225d531436a7f1d36c80fd6f609eff71f049cb0efd0202125cb91'
    '01C10102' = '000b9a881750fb31807ef91169ab03b2f2a9b52ffbeb15199b652439bbd55c8c9f7e'
    '01C10104' = '000b3eced244b7b3e8333da2a8c55e9a402202e1c445e8d35dee0fc5ee178a055453'
    '01C101C0' = '000ba2c2e72c43c119431f57414bb47e879de61f69295df6af451d2994e58025c06f'
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function Initialize-E47Types {
    $type = 'E47TpmNative' -as [type]
    if (-not $type) {
        $source = Join-Path $PSScriptRoot '..\src\E47TpmNative.cs'
        if (-not (Test-Path -LiteralPath $source)) { throw "Missing C# helper: $source" }
        Add-Type -Path $source -ErrorAction Stop
    }
}

function New-TbsContext {
    return [E47TpmNative]::OpenContext()
}

function Close-TbsContext([IntPtr]$Context) {
    if ($Context -ne [IntPtr]::Zero) {
        $rc = [E47TpmNative]::CloseContext($Context)
        if ($rc -ne 0) { Write-Warning ('Tbsip_Context_Close returned 0x{0:X8}' -f $rc) }
    }
}

function Assert-TpmCommandSuccess($Result, [string]$Operation) {
    if ($null -eq $Result) { throw "$Operation returned no result object." }
    if ($Result.TbsReturn -ne 0) {
        throw ('{0}: TBS return 0x{1:X8}. Do not blindly retry a mutating command.' -f $Operation, $Result.TbsReturn)
    }
    if ($Result.TpmResponseCode -ne 0) {
        throw ('{0}: TPM response 0x{1:X8}. Do not blindly retry a mutating command.' -f $Operation, $Result.TpmResponseCode)
    }
}


function Test-TpmCommandAdvertised([IntPtr]$Context, [uint32]$CommandCode) {
    $r = [E47TpmNative]::GetCapability($Context, [uint32]2, $CommandCode, [uint32]1)
    Assert-TpmCommandSuccess $r ('TPM2_GetCapability(TPM_CAP_COMMANDS 0x{0:X8})' -f $CommandCode)
    $more = $false
    $items = [E47TpmNative]::ParseCapabilityCommands($r, [ref]$more)
    if ($items.Count -ne 1) { return $false }
    # TPMA_CC.commandIndex occupies the low 16 bits; remaining bits are command attributes.
    return (($items[0] -band [uint32]0x0000FFFF) -eq ($CommandCode -band [uint32]0x0000FFFF))
}

function Assert-RequiredCounterCommands([IntPtr]$Context) {
    $required = @(
        [pscustomobject]@{ Name = 'TPM2_NV_UndefineSpace'; Code = [uint32]0x00000122 },
        [pscustomobject]@{ Name = 'TPM2_NV_DefineSpace'; Code = [uint32]0x0000012A },
        [pscustomobject]@{ Name = 'TPM2_NV_Increment'; Code = [uint32]0x00000134 },
        [pscustomobject]@{ Name = 'TPM2_NV_Read'; Code = [uint32]0x0000014E },
        [pscustomobject]@{ Name = 'TPM2_NV_ReadPublic'; Code = [uint32]0x00000169 }
    )
    foreach ($entry in $required) {
        if (-not (Test-TpmCommandAdvertised $Context $entry.Code)) {
            throw ('TPM does not advertise required command {0} (0x{1:X8}). Stop before any NV write.' -f $entry.Name, $entry.Code)
        }
        Write-Host ('TPM command advertised: {0}' -f $entry.Name)
    }
}

function Get-TpmHandles([IntPtr]$Context) {
    $r = [E47TpmNative]::GetCapability($Context, [uint32]1, [uint32]0x01000000, [uint32]64)
    Assert-TpmCommandSuccess $r 'TPM2_GetCapability(TPM_CAP_HANDLES)'
    $more = $false
    $items = [E47TpmNative]::ParseCapabilityHandles($r, [ref]$more)
    if ($more) { throw 'TPM returned MoreData=True for the 64-handle request; stop and extend the read-only enumeration.' }
    return ,$items
}

function Get-TpmProperty([IntPtr]$Context, [uint32]$Property) {
    $r = [E47TpmNative]::GetCapability($Context, [uint32]6, $Property, [uint32]1)
    Assert-TpmCommandSuccess $r ('TPM2_GetCapability(property 0x{0:X8})' -f $Property)
    $more = $false
    $value = [E47TpmNative]::ParseSingleTaggedProperty($r, $Property, [ref]$more)
    # MoreData may be TRUE because additional TPM properties follow the requested property.
    # The returned property identifier/value is still valid; do not treat MoreData as failure.
    return [uint32]$value
}

function Get-NvPublic([IntPtr]$Context, [uint32]$Handle) {
    $r = [E47TpmNative]::NvReadPublic($Context, $Handle)
    return $r
}

function Assert-BaselineNames([IntPtr]$Context, [switch]$AllowCandidate) {
    $handles = Get-TpmHandles $Context
    $expectedHandles = @($script:BaselineNames.Keys | ForEach-Object { [Convert]::ToUInt32($_, 16) })
    $expectedCount = $expectedHandles.Count
    if ($AllowCandidate) { $expectedCount++; if ($handles -notcontains $script:CandidateHandle) { throw 'Expected test candidate handle is not present.' } }
    if ($handles.Count -ne $expectedCount) {
        throw ('NV handle count changed: expected {0}, got {1}.' -f $expectedCount, $handles.Count)
    }
    foreach ($key in $script:BaselineNames.Keys) {
        $handle = [Convert]::ToUInt32($key, 16)
        if ($handles -notcontains $handle) { throw "Baseline NV handle 0x$key is missing." }
        $r = Get-NvPublic $Context $handle
        Assert-TpmCommandSuccess $r ('TPM2_NV_ReadPublic(0x{0})' -f $key)
        $pub = [E47TpmNative]::ParseNvReadPublic($r)
        if ($pub.NvIndex -ne $handle -or $pub.NameHex -ne $script:BaselineNames[$key]) {
            throw "Baseline NV Name changed for handle 0x$key. Stop; do not write anything."
        }
    }
    return $handles
}

function Assert-CandidateAbsent([IntPtr]$Context, [uint32[]]$Handles) {
    if ($Handles -contains $script:CandidateHandle) {
        throw 'Candidate NV handle is already present. Refusing to modify or reuse it.'
    }
    $r = Get-NvPublic $Context $script:CandidateHandle
    if ($r.TbsReturn -ne 0) {
        throw ('Candidate NV_ReadPublic TBS failure 0x{0:X8}; availability is inconclusive.' -f $r.TbsReturn)
    }
    if ($r.TpmResponseCode -eq 0) {
        throw 'Candidate handle is already defined. Refusing to overwrite it.'
    }
    if ($r.TpmResponseCode -ne 0x0000008B) {
        throw ('Candidate NV_ReadPublic returned unexpected TPM code 0x{0:X8}; availability is inconclusive.' -f $r.TpmResponseCode)
    }
}

function Assert-HierarchyPreconditions([IntPtr]$Context) {
    $permanent = Get-TpmProperty $Context ([uint32]0x00000200)
    $startup = Get-TpmProperty $Context ([uint32]0x00000201)
    $ownerAuthSet = (($permanent -band 0x1) -ne 0)
    $inLockout = (($permanent -band 0x200) -ne 0)
    $shEnable = (($startup -band 0x2) -ne 0)
    $phEnableNv = (($startup -band 0x8) -ne 0)
    $readOnly = (($startup -band 0x10) -ne 0)

    if ($ownerAuthSet) { throw 'ownerAuthSet=True. OwnerAuth is not assumed to be EmptyAuth; do not attempt DefineSpace.' }
    if ($inLockout) { throw 'TPM is in dictionary-attack lockout. Stop.' }
    if (-not $shEnable) { throw 'Storage hierarchy is disabled. Stop.' }
    if (-not $phEnableNv) { throw 'Platform NV hierarchy is disabled. Stop.' }
    if ($readOnly) { throw 'TPM hierarchies are in read-only mode. Stop.' }

    [pscustomobject]@{
        Permanent = ('0x{0:X8}' -f $permanent)
        StartupClear = ('0x{0:X8}' -f $startup)
        OwnerAuthSet = $ownerAuthSet
        InLockout = $inLockout
        ShEnable = $shEnable
        PhEnableNv = $phEnableNv
        ReadOnly = $readOnly
    }
}

function Get-BootTimeUtc {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    return $os.LastBootUpTime.ToUniversalTime().ToString('o')
}

function Ensure-StateDirectory {
    if (-not (Test-Path -LiteralPath $script:StateRoot)) {
        New-Item -ItemType Directory -Path $script:StateRoot -Force | Out-Null
    }
}

function Save-State($State) {
    Ensure-StateDirectory
    $tmp = $script:StatePath + '.tmp'
    $json = $State | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $script:StatePath -Force
}

function Load-State {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { throw "State file not found: $($script:StatePath)" }
    return (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json -ErrorAction Stop)
}

function New-ProtectedNvAuth([byte[]]$AuthBytes) {
    Ensure-StateDirectory
    if (Test-Path -LiteralPath $script:AuthPath) { throw 'Protected NV auth file already exists. Refusing to overwrite.' }
    $hex = [BitConverter]::ToString($AuthBytes).Replace('-', '')
    $secure = ConvertTo-SecureString -String $hex -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new('E4.7.3-NV-Auth', $secure)
    $credential | Export-Clixml -LiteralPath $script:AuthPath -ErrorAction Stop
    $hex = $null
    $secure = $null
    $credential = $null
}

function Get-ProtectedNvAuth {
    if (-not (Test-Path -LiteralPath $script:AuthPath)) { throw 'Protected NV auth file is missing; do not guess or retry an authorization.' }
    $credential = Import-Clixml -LiteralPath $script:AuthPath -ErrorAction Stop
    if ($credential -isnot [System.Management.Automation.PSCredential]) { throw 'Protected auth file has an unexpected format.' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
    try {
        $hex = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($hex -notmatch '^[0-9A-Fa-f]{64}$') { throw 'Protected auth value is not a 32-byte hex string.' }
        $bytes = New-Object byte[] 32
        for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        return ,$bytes
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $hex = $null
        $credential = $null
    }
}

function Assert-CandidatePublic([IntPtr]$Context, $State, [ValidateSet('Any','Set','Clear')][string]$WrittenExpectation = 'Any') {
    $r = Get-NvPublic $Context $script:CandidateHandle
    Assert-TpmCommandSuccess $r 'TPM2_NV_ReadPublic(candidate)'
    $pub = [E47TpmNative]::ParseNvReadPublic($r)
    if ($pub.NvIndex -ne $script:CandidateHandle) { throw 'NV_ReadPublic returned a different handle.' }

    # TPMA_NV_WRITTEN is dynamic and changes the NV Name after the first successful counter increment.
    # All other attributes remain frozen for this experiment.
    $writtenMask = [uint32]0x20000000
    $stableMask = [Convert]::ToUInt32('DFFFFFFF', 16)
    $isWritten = (($pub.Attributes -band $writtenMask) -ne 0)
    $stableAttributes = [uint32]($pub.Attributes -band $stableMask)
    if ($stableAttributes -ne $script:ExpectedAttributes) {
        throw ('Candidate NV stable attributes mismatch: got 0x{0:X8}.' -f $stableAttributes)
    }
    if ($WrittenExpectation -eq 'Set' -and -not $isWritten) { throw 'Candidate TPMA_NV_WRITTEN is CLEAR but this phase requires it SET.' }
    if ($WrittenExpectation -eq 'Clear' -and $isWritten) { throw 'Candidate TPMA_NV_WRITTEN is SET but this phase requires it CLEAR.' }

    $expectedName = if ($isWritten) { $State.ExpectedWrittenNvName } else { $State.ExpectedNvName }
    if ([string]::IsNullOrWhiteSpace([string]$expectedName)) { throw 'State is missing the expected NV Name for the observed WRITTEN state.' }
    if ($pub.NameHex -ne $expectedName) { throw 'Candidate NV Name mismatch for the observed TPMA_NV_WRITTEN state. Refusing to continue.' }
    if ($pub.NameAlg -ne $script:ExpectedNameAlg -or $pub.DataSize -ne $script:ExpectedDataSize -or $pub.AuthPolicy.Length -ne 0) {
        throw 'Candidate NV public parameters do not match the frozen experiment configuration.'
    }
    return $pub
}

function Read-CandidateCounter([IntPtr]$Context, [byte[]]$AuthBytes) {
    $r = [E47TpmNative]::NvReadCounter($Context, $script:CandidateHandle, $AuthBytes)
    Assert-TpmCommandSuccess $r 'TPM2_NV_Read(candidate counter)'
    return [E47TpmNative]::ParseNvReadCounter($r).ToString([Globalization.CultureInfo]::InvariantCulture)
}

