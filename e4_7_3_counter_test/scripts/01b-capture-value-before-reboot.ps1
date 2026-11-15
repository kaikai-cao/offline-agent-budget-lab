. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types
$state = Load-State
if (-not $state.IncrementAttempted) { throw 'No increment attempt is recorded. Refusing recovery capture.' }
if ($state.PostIncrementValue) { throw 'A post-increment value is already captured; do not overwrite it.' }
if ($state.Status -notin @('IncrementAttempted','IncrementOutcomeUncertain','IncrementSucceededReadPending')) {
    throw "Recovery capture is not allowed for state '$($state.Status)'."
}

$authBytes = Get-ProtectedNvAuth
$context = [IntPtr]::Zero
try {
    $context = New-TbsContext
    $public = Assert-CandidatePublic $context $state
    $isWritten = (($public.Attributes -band [uint32]0x20000000) -ne 0)
    if ($state.IncrementCommandSucceeded -and -not $isWritten) {
        throw 'Increment was recorded successful but TPMA_NV_WRITTEN is CLEAR. Preserve state and stop.'
    }

    $readResult = [E47TpmNative]::NvReadCounter($context, $script:CandidateHandle, $authBytes)
    if ($readResult.TbsReturn -ne 0) {
        throw ('Recovery NV_Read TBS failure 0x{0:X8}. Preserve state; do not increment again.' -f $readResult.TbsReturn)
    }
    if ($readResult.TpmResponseCode -eq 0x0000014A -and -not $isWritten) {
        # NV_COUNTER is undefined until its first successful NV_Increment. WRITTEN=CLEAR plus
        # TPM_RC_NV_UNINITIALIZED confirms that no successful first increment took effect.
        $state.Status = 'IncrementConfirmedNotApplied'
        $state.UninitializedReadObserved = $true
        $state.RecoveryObservedAtUtc = [DateTime]::UtcNow.ToString('o')
        Save-State $state
        Write-Warning 'TPMA_NV_WRITTEN is CLEAR and NV_Read returned TPM_RC_NV_UNINITIALIZED. No successful first increment is present. Do NOT retry; run 03-cleanup.ps1 to remove only this uninitialized test index.'
        return
    }
    if ($readResult.TpmResponseCode -ne 0) {
        throw ('Recovery NV_Read TPM response 0x{0:X8}. Preserve state; do not increment again.' -f $readResult.TpmResponseCode)
    }
    if (-not $isWritten) {
        throw 'NV_Read succeeded while TPMA_NV_WRITTEN is CLEAR; unexpected state. Preserve index and stop.'
    }

    $value = [E47TpmNative]::ParseNvReadCounter($readResult).ToString([Globalization.CultureInfo]::InvariantCulture)
    $state.PostIncrementValue = $value
    $state.WrittenNvName = $public.NameHex
    $state.PostIncrementValueCapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    $state.Status = if ($state.IncrementCommandSucceeded) { 'ReadyForRebootVerification' } else { 'ValueCapturedButIncrementOutcomeUncertain' }
    Save-State $state
    Write-Host ('Counter value captured before reboot: {0}' -f $value)
    if (-not $state.IncrementCommandSucceeded) {
        Write-Warning 'The increment response was not recorded as successful. This is NOT a clean successful-increment experiment. Do not increment again; you may reboot to test persistence of the captured value, but report the command outcome as uncertain.'
    }
    else {
        Write-Host 'Capture complete. Perform a normal Windows restart, then run 02-verify-after-reboot.ps1.' -ForegroundColor Green
    }
}
finally {
    if ($authBytes) { [Array]::Clear($authBytes, 0, $authBytes.Length) }
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
