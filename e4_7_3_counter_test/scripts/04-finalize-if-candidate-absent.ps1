. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types
$state = Load-State
if ($state.Status -notin @('PersistenceVerified','PersistenceObservedIncrementOutcomeUncertain','Created','CreatedNotIncremented','DefineAttempted','IncrementConfirmedNotApplied','UndefineAttempted')) {
    throw "Local finalization is blocked for state '$($state.Status)'. Review the report before proceeding."
}
$context = [IntPtr]::Zero
try {
    $context = New-TbsContext
    $null = Assert-HierarchyPreconditions $context
    $handles = Assert-BaselineNames $context
    $candidate = Get-NvPublic $context $script:CandidateHandle
    if ($candidate.TbsReturn -ne 0) {
        throw ('Candidate NV_ReadPublic TBS failure 0x{0:X8}; cannot prove the index is absent.' -f $candidate.TbsReturn)
    }
    if ($candidate.TpmResponseCode -ne 0x0000008B) {
        throw ('Candidate is not confirmed absent; TPM response was 0x{0:X8}. Do not remove local auth/state.' -f $candidate.TpmResponseCode)
    }
    $nvCount = Get-TpmProperty $context ([uint32]0x00000202)
    $counterCount = Get-TpmProperty $context ([uint32]0x0000020A)
    if ($nvCount -ne 16 -or $counterCount -ne 4) {
        throw ('Original inventory count not restored: HR_NV_INDEX={0}, NV_COUNTERS={1}. Keep local files.' -f $nvCount, $counterCount)
    }

    Write-Host 'Read-only verification passed:' -ForegroundColor Green
    Write-Host '  Candidate handle returns TPM_RC_HANDLE.'
    Write-Host '  All original 16 NV Names match the E4.5 baseline.'
    Write-Host '  HR_NV_INDEX=16 and TPM_PT_NV_COUNTERS=4.'
    Write-Host 'This script sends NO TPM mutating command. It only removes local DPAPI/state files.' -ForegroundColor Yellow
    $confirm = Read-Host 'Type exactly FINALIZE-LOCAL-CLEANUP 0x01BFFFFE to continue'
    if ($confirm -cne 'FINALIZE-LOCAL-CLEANUP 0x01BFFFFE') { throw 'Local finalization not confirmed.' }

    $report = [pscustomobject]@{
        Result = 'LOCAL_FINALIZATION_VERIFIED_CANDIDATE_ALREADY_ABSENT'
        Handle = $script:CandidateHandleText
        Original16NvNamesUnchanged = $true
        CandidateAbsent = $true
        HrNvIndex = $nvCount
        NvCounters = $counterCount
        CompletedAtUtc = [DateTime]::UtcNow.ToString('o')
        Note = 'No TPM write command was sent by this finalization script.'
    }
    Ensure-StateDirectory
    $reportPath = Join-Path $script:StateRoot 'local-finalization-report.json'
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    if (Test-Path -LiteralPath $script:AuthPath) { Remove-Item -LiteralPath $script:AuthPath -Force }
    if (Test-Path -LiteralPath $script:StatePath) { Remove-Item -LiteralPath $script:StatePath -Force }
    Write-Host 'LOCAL FINALIZATION VERIFIED. Candidate was already absent; no TPM delete command was sent.' -ForegroundColor Green
    Write-Host ('Report: {0}' -f $reportPath)
}
finally {
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
