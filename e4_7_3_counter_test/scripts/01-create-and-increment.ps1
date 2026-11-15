. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types

if ((Test-Path -LiteralPath $script:StatePath) -or (Test-Path -LiteralPath $script:AuthPath)) {
    throw 'A previous E4.7.3 state/auth file already exists. Complete recovery or cleanup before starting another run.'
}

$context = [IntPtr]::Zero
$authBytes = $null
try {
    $context = New-TbsContext
    Write-Host 'TBS context created.'
    Assert-RequiredCounterCommands $context

    $hierarchy = Assert-HierarchyPreconditions $context
    Write-Host 'Hierarchy preconditions:'
    $hierarchy | Format-List

    $handles = Assert-BaselineNames $context
    Write-Host ('Original NV baseline: {0} handles, all Names match E4.5.' -f $handles.Count)
    $nvIndexCountBefore = Get-TpmProperty $context ([uint32]0x00000202)
    $nvCounterCountBefore = Get-TpmProperty $context ([uint32]0x0000020A)
    if ($nvIndexCountBefore -ne 16 -or $nvCounterCountBefore -ne 4) {
        throw ('E4.5/E4.6 baseline count mismatch: HR_NV_INDEX={0}, NV_COUNTERS={1}. Stop.' -f $nvIndexCountBefore, $nvCounterCountBefore)
    }
    Assert-CandidateAbsent $context $handles
    Write-Host ('Candidate {0} is currently undefined (TPM_RC_HANDLE) and absent from TPM_CAP_HANDLES.' -f $script:CandidateHandleText)

    $expectedName = [E47TpmNative]::ComputeExpectedCounterName($script:CandidateHandle, $false)
    $expectedWrittenName = [E47TpmNative]::ComputeExpectedCounterName($script:CandidateHandle, $true)
    Write-Host ('Expected NV Name (WRITTEN=CLEAR): {0}' -f $expectedName)
    Write-Host ('Expected NV Name after first increment (WRITTEN=SET): {0}' -f $expectedWrittenName)
    Write-Host ''
    Write-Host 'This next operation DEFINES a new NV Counter and consumes NV storage.' -ForegroundColor Yellow
    $confirmCreate = Read-Host 'Type exactly CREATE-COUNTER 0x01BFFFFE to continue'
    if ($confirmCreate -cne 'CREATE-COUNTER 0x01BFFFFE') { throw 'Creation was not confirmed; no NV write was sent.' }

    # Create and DPAPI-protect a unique 32-byte index auth value before touching TPM.
    $authBytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($authBytes) } finally { $rng.Dispose() }
    $state = [pscustomobject]@{
        Schema = 'E4.7.3-counter-state-v0.1'
        Handle = $script:CandidateHandleText
        HandleValue = [uint32]$script:CandidateHandle
        NameAlg = 'SHA256'
        Attributes = '0x00040014'
        DataSize = 8
        ExpectedNvName = $expectedName
        ExpectedWrittenNvName = $expectedWrittenName
        CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
        BootTimeBeforeTestUtc = Get-BootTimeUtc
        OwnerAuthSetAtPreflight = $false
        NvIndexCountBefore = $nvIndexCountBefore
        NvCounterCountBefore = $nvCounterCountBefore
        OwnerAuthorizationAssumption = 'EmptyAuth inferred from ownerAuthSet=False since last TPM_Clear; no owner auth change is performed by this package.'
        DefineAttempted = $true
        DefineTbsReturn = $null
        DefineTpmResponseCode = $null
        IncrementAttempted = $false
        IncrementTbsReturn = $null
        IncrementTpmResponseCode = $null
        IncrementCommandSucceeded = $false
        PostIncrementValue = $null
        Status = 'DefineAttempted'
    }
    Save-State $state
    New-ProtectedNvAuth $authBytes

    Write-Host 'Sending TPM2_NV_DefineSpace once...'
    $define = [E47TpmNative]::NvDefineCounter($context, $script:CandidateHandle, $authBytes)
    $state.DefineTbsReturn = ('0x{0:X8}' -f $define.TbsReturn)
    $state.DefineTpmResponseCode = ('0x{0:X8}' -f $define.TpmResponseCode)
    Save-State $state
    Assert-TpmCommandSuccess $define 'TPM2_NV_DefineSpace'

    $pub = Assert-CandidatePublic $context $state -WrittenExpectation Clear
    $nvIndexCountAfter = Get-TpmProperty $context ([uint32]0x00000202)
    $nvCounterCountAfter = Get-TpmProperty $context ([uint32]0x0000020A)
    if ($nvIndexCountAfter -ne 17 -or $nvCounterCountAfter -ne 5) {
        throw ('Post-Define count mismatch: HR_NV_INDEX={0}, NV_COUNTERS={1}. Keep state/auth files and stop.' -f $nvIndexCountAfter, $nvCounterCountAfter)
    }
    $state.Status = 'Created'
    $state.CreatedNvName = $pub.NameHex
    $state.NvIndexCountAfterDefine = $nvIndexCountAfter
    $state.NvCounterCountAfterDefine = $nvCounterCountAfter
    Save-State $state
    Write-Host 'Counter created and NV public area verified.' -ForegroundColor Green
    Write-Host ('Handle: {0}; Name: {1}' -f $script:CandidateHandleText, $pub.NameHex)

    Write-Host ''
    Write-Host 'The next command increments the counter exactly once. It is a persistent TPM write.' -ForegroundColor Yellow
    $confirmIncrement = Read-Host 'Type exactly INCREMENT-ONCE 0x01BFFFFE to continue'
    if ($confirmIncrement -cne 'INCREMENT-ONCE 0x01BFFFFE') {
        $state.Status = 'CreatedNotIncremented'
        Save-State $state
        throw 'Increment was not confirmed. The test NV index remains defined; do not start another run. Use the cleanup procedure only after verifying its Name.'
    }

    # Persist the attempt marker BEFORE submitting the mutating command; this prevents accidental retry after interruption.
    $state.IncrementAttempted = $true
    $state.IncrementAttemptedAtUtc = [DateTime]::UtcNow.ToString('o')
    $state.Status = 'IncrementAttempted'
    Save-State $state

    Write-Host 'Sending TPM2_NV_Increment exactly once...'
    $increment = [E47TpmNative]::NvIncrement($context, $script:CandidateHandle, $authBytes)
    $state.IncrementTbsReturn = ('0x{0:X8}' -f $increment.TbsReturn)
    $state.IncrementTpmResponseCode = ('0x{0:X8}' -f $increment.TpmResponseCode)
    if ($increment.TbsReturn -ne 0 -or $increment.TpmResponseCode -ne 0) {
        $state.Status = 'IncrementOutcomeUncertain'
        Save-State $state
        throw ('TPM2_NV_Increment did not return success (TBS={0}, TPM={1}). DO NOT retry. Preserve state/auth files and inspect the index.' -f $state.IncrementTbsReturn, $state.IncrementTpmResponseCode)
    }
    $state.IncrementCommandSucceeded = $true
    $state.Status = 'IncrementSucceededReadPending'
    Save-State $state

    $writtenPublic = Assert-CandidatePublic $context $state -WrittenExpectation Set
    $state.WrittenNvName = $writtenPublic.NameHex
    Save-State $state
    $counterValue = Read-CandidateCounter $context $authBytes
    $state.PostIncrementValue = $counterValue
    $state.PostIncrementValueCapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    $state.Status = 'ReadyForRebootVerification'
    Save-State $state

    Write-Host ''
    Write-Host 'FIRST PHASE COMPLETE' -ForegroundColor Green
    Write-Host ('Observed counter value after exactly one successful increment: {0}' -f $counterValue)
    Write-Host 'Do NOT expect the value to be 1. TPM NV counters are initialized above previous counter values on that TPM.'
    Write-Host 'Now perform a normal Windows restart. After restart, run scripts\02-verify-after-reboot.ps1.'
    Write-Host ('Protected state directory: {0}' -f $script:StateRoot)
}
finally {
    if ($authBytes) { [Array]::Clear($authBytes, 0, $authBytes.Length) }
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
