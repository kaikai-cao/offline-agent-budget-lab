. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types
$state = Load-State
if ($state.Status -notin @('PersistenceVerified','Created','CreatedNotIncremented','PersistenceObservedIncrementOutcomeUncertain','DefineAttempted','IncrementConfirmedNotApplied')) {
    throw "Cleanup is blocked for state '$($state.Status)'. Do not delete an index with unresolved or mismatched state. Review docs first."
}

$context = [IntPtr]::Zero
$authBytes = $null
try {
    $context = New-TbsContext
    $hierarchy = Assert-HierarchyPreconditions $context
    $handles = Assert-BaselineNames $context -AllowCandidate
    if ($handles -notcontains $script:CandidateHandle) { throw 'Candidate handle is not present; nothing will be deleted.' }

    $writtenExpectation = if ($state.Status -in @('PersistenceVerified','PersistenceObservedIncrementOutcomeUncertain')) { 'Set' } else { 'Clear' }
    $pub = Assert-CandidatePublic $context $state -WrittenExpectation $writtenExpectation

    if ($state.Status -in @('PersistenceVerified','PersistenceObservedIncrementOutcomeUncertain')) {
        $authBytes = Get-ProtectedNvAuth
        $currentValue = Read-CandidateCounter $context $authBytes
        if ([string]$currentValue -cne [string]$state.PostIncrementValue) {
            throw 'Counter value no longer matches the verified value. Cleanup refused.'
        }
    }

    Write-Host ('Will remove ONLY NV index {0} with Name {1}.' -f $script:CandidateHandleText, $pub.NameHex) -ForegroundColor Yellow
    Write-Host 'The TPM Owner hierarchy authorization is expected to be EmptyAuth because ownerAuthSet=False was confirmed before creation.'
    $confirm = Read-Host 'Type exactly DELETE-OWN-TEST-INDEX 0x01BFFFFE to continue'
    if ($confirm -cne 'DELETE-OWN-TEST-INDEX 0x01BFFFFE') { throw 'Cleanup was not confirmed; no delete command was sent.' }

    # Persist an attempt marker before the mutating command. Do not blindly retry if its response is lost.
    $state.StatusBeforeUndefine = $state.Status
    $state.UndefineAttempted = $true
    $state.UndefineAttemptedAtUtc = [DateTime]::UtcNow.ToString('o')
    $state.Status = 'UndefineAttempted'
    Save-State $state

    $undefine = [E47TpmNative]::NvUndefineOwner($context, $script:CandidateHandle)
    Assert-TpmCommandSuccess $undefine 'TPM2_NV_UndefineSpace'

    $afterPublic = Get-NvPublic $context $script:CandidateHandle
    if ($afterPublic.TbsReturn -ne 0 -or $afterPublic.TpmResponseCode -ne 0x0000008B) {
        throw ('Post-delete check did not return TPM_RC_HANDLE. TBS=0x{0:X8}; TPM=0x{1:X8}. Keep local auth/state files.' -f $afterPublic.TbsReturn, $afterPublic.TpmResponseCode)
    }
    $afterHandles = Get-TpmHandles $context
    if ($afterHandles -contains $script:CandidateHandle) { throw 'Candidate still appears in TPM_CAP_HANDLES after delete.' }
    $null = Assert-BaselineNames $context
    $nvCount = Get-TpmProperty $context ([uint32]0x00000202)
    $counterCount = Get-TpmProperty $context ([uint32]0x0000020A)
    if ($nvCount -ne 16 -or $counterCount -ne 4) {
        throw ('Post-cleanup count mismatch: HR_NV_INDEX={0}, TPM_PT_NV_COUNTERS={1}. Keep report/state for investigation.' -f $nvCount, $counterCount)
    }

    $report = [pscustomobject]@{
        Result = 'CLEANUP_VERIFIED'
        Handle = $script:CandidateHandleText
        DeletedNvName = $pub.NameHex
        Original16NvNamesUnchanged = $true
        CandidateAbsent = $true
        HrNvIndexAfterCleanup = $nvCount
        NvCountersAfterCleanup = $counterCount
        CompletedAtUtc = [DateTime]::UtcNow.ToString('o')
        Note = 'Deleting an NV Counter index does not reset the TPM-wide counter high-water history.'
    }
    $reportPath = Join-Path $script:StateRoot 'cleanup-report.json'
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8

    if (Test-Path -LiteralPath $script:AuthPath) { Remove-Item -LiteralPath $script:AuthPath -Force }
    if (Test-Path -LiteralPath $script:StatePath) { Remove-Item -LiteralPath $script:StatePath -Force }
    Write-Host 'CLEANUP VERIFIED. Only the dedicated test NV index was deleted.' -ForegroundColor Green
    Write-Host ('Cleanup report: {0}' -f $reportPath)
}
finally {
    if ($authBytes) { [Array]::Clear($authBytes, 0, $authBytes.Length) }
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
