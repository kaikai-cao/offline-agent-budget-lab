. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types

$commonText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'E47-Common.ps1') -Raw
if ($commonText -notmatch '(?m)^\s*\$stableMask\s*=\s*\[Convert\]::ToUInt32\(''DFFFFFFF'',\s*16\)\s*$') {
    throw 'E47-Common.ps1 mask fix is not present. Run 00-fix-common-uint32-mask.ps1 first.'
}

$state = Load-State
if ($state.Status -notin @('DefineAttempted', 'CreatedNotIncremented')) {
    throw ("Resume is only allowed from DefineAttempted or CreatedNotIncremented; actual state is '{0}'. Do not retry an increment or define operation." -f $state.Status)
}
if (-not $state.DefineAttempted) { throw 'State does not record a DefineSpace attempt. Stop.' }
if ([string]$state.DefineTbsReturn -cne '0x00000000' -or [string]$state.DefineTpmResponseCode -cne '0x00000000') {
    throw 'Recorded DefineSpace result is not an unambiguous success. Do not retry; inspect current TPM state manually.'
}
if ($state.IncrementAttempted -or $state.IncrementCommandSucceeded -or $state.PostIncrementValue) {
    throw 'An increment attempt or result is already recorded. Do not increment again; use the recovery procedure.'
}
if ([string]$state.Handle -cne $script:CandidateHandleText) { throw 'State handle does not match the frozen candidate.' }
if (-not (Test-Path -LiteralPath $script:AuthPath)) { throw 'Protected NV auth file is missing. Do not guess or regenerate the auth value.' }

$context = [IntPtr]::Zero
$authBytes = $null
try {
    $context = New-TbsContext
    Write-Host 'TBS context created.'

    Assert-RequiredCounterCommands $context
    $hierarchy = Assert-HierarchyPreconditions $context
    Write-Host 'Hierarchy preconditions:'
    $hierarchy | Format-List

    # The candidate is expected to have been created by the previous, interrupted run.
    # Verify the original 16 Names plus the one candidate; do not issue NV_DefineSpace.
    $handles = Assert-BaselineNames $context -AllowCandidate
    Write-Host ('NV handles verified: {0} (16 baseline + candidate).' -f $handles.Count)

    $nvIndexCount = Get-TpmProperty $context ([uint32]0x00000202)
    $nvCounterCount = Get-TpmProperty $context ([uint32]0x0000020A)
    if ($nvIndexCount -ne 17 -or $nvCounterCount -ne 5) {
        throw ('Expected HR_NV_INDEX=17 and NV_COUNTERS=5; got {0} and {1}. Stop without increment.' -f $nvIndexCount, $nvCounterCount)
    }

    $pub = Assert-CandidatePublic $context $state -WrittenExpectation Clear
    if ($pub.NameHex -cne $state.ExpectedNvName) {
        throw 'Candidate Name does not match the pre-increment Name recorded before DefineSpace. Stop.'
    }
    $createdNvNameProperty = $state.PSObject.Properties['CreatedNvName']
if ($null -ne $createdNvNameProperty -and
    -not [string]::IsNullOrWhiteSpace([string]$createdNvNameProperty.Value) -and
    [string]$createdNvNameProperty.Value -cne $pub.NameHex) {
        throw 'Candidate Name differs from the previously recorded creation Name. Stop.'
    }

    $authBytes = Get-ProtectedNvAuth
    if ($authBytes.Length -ne 32) { throw 'Recovered NV auth value has an unexpected length.' }

    $state.Status = 'CreatedNotIncremented'
    $state | Add-Member -MemberType NoteProperty -Name CreatedNvName -Value $pub.NameHex -Force
    $state | Add-Member -MemberType NoteProperty -Name NvIndexCountAfterDefine -Value $nvIndexCount -Force
    $state | Add-Member -MemberType NoteProperty -Name NvCounterCountAfterDefine -Value $nvCounterCount -Force
    $state | Add-Member -MemberType NoteProperty -Name ResumeVerifiedAtUtc -Value ([DateTime]::UtcNow.ToString('o')) -Force
    Save-State $state

    Write-Host 'RECOVERY CHECK PASSED: the counter exists, attributes and Name match, and no increment is recorded.' -ForegroundColor Green
    Write-Host ('Handle: {0}' -f $script:CandidateHandleText)
    Write-Host ('NV Name (WRITTEN=CLEAR): {0}' -f $pub.NameHex)
    Write-Host 'No NV_DefineSpace command was sent by this recovery script.'
    Write-Host ''
    Write-Host 'The next operation sends exactly one TPM2_NV_Increment command.' -ForegroundColor Yellow

    $confirm = Read-Host 'Type exactly INCREMENT-ONCE 0x01BFFFFE to continue'
    if ($confirm -cne 'INCREMENT-ONCE 0x01BFFFFE') {
        Write-Host 'Increment not confirmed. Counter remains defined and unincremented.' -ForegroundColor Yellow
        return
    }

    # Persist the attempt marker before submitting the one mutating command.
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
    Write-Host 'Do NOT assume the value is 1; the TPM counter high-water rule determines the initial value.'
    Write-Host 'Next: perform a normal Windows restart, then run scripts\02-verify-after-reboot.ps1.'
    Write-Host ('Protected state directory: {0}' -f $script:StateRoot)
}
finally {
    if ($authBytes) { [Array]::Clear($authBytes, 0, $authBytes.Length) }
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}

