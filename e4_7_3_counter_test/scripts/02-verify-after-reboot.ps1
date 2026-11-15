. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types
$state = Load-State
if (-not $state.PostIncrementValue) { throw 'No pre-reboot counter value is recorded. Refusing to claim persistence.' }
if ($state.Status -notin @('ReadyForRebootVerification','ValueCapturedButIncrementOutcomeUncertain')) {
    throw "State '$($state.Status)' is not ready for reboot verification."
}
$currentBoot = Get-BootTimeUtc
$previousBoot = [DateTime]::Parse($state.BootTimeBeforeTestUtc).ToUniversalTime()
$currentBootParsed = [DateTime]::Parse($currentBoot).ToUniversalTime()
if ($currentBootParsed -le $previousBoot) {
    throw 'Windows LastBootUpTime has not advanced. Perform a normal Windows restart before verification.'
}

$authBytes = Get-ProtectedNvAuth
$context = [IntPtr]::Zero
try {
    $context = New-TbsContext
    $public = Assert-CandidatePublic $context $state -WrittenExpectation Set
    if ($state.WrittenNvName -and $public.NameHex -cne $state.WrittenNvName) { throw 'Post-reboot NV Name differs from the captured post-increment Name.' }
    $after = Read-CandidateCounter $context $authBytes
    Write-Host ('Recorded pre-reboot value : {0}' -f $state.PostIncrementValue)
    Write-Host ('Observed post-reboot value: {0}' -f $after)
    if ([string]$after -cne [string]$state.PostIncrementValue) {
        $state.Status = 'PersistenceMismatch'
        $state.PostRebootObservedValue = $after
        $state.PostRebootAtUtc = [DateTime]::UtcNow.ToString('o')
        Save-State $state
        throw 'Counter value changed across reboot. Preserve the index and auth file; do not delete or increment again.'
    }

    $state.PostRebootObservedValue = $after
    $state.PostRebootAtUtc = [DateTime]::UtcNow.ToString('o')
    $state.PostRebootBootTimeUtc = $currentBoot
    if ($state.IncrementCommandSucceeded) {
        $state.Status = 'PersistenceVerified'
        Save-State $state
        Write-Host 'PASS: exact counter value persisted across a Windows restart.' -ForegroundColor Green
    }
    else {
        $state.Status = 'PersistenceObservedIncrementOutcomeUncertain'
        Save-State $state
        Write-Warning 'The counter value persisted, but the increment command response was uncertain. Do not report a clean E4.7.3 increment-success result.'
    }
    Write-Host 'Next: run scripts\03-cleanup.ps1. It will delete only the test index after rechecking its exact NV Name and value.'
}
finally {
    if ($authBytes) { [Array]::Clear($authBytes, 0, $authBytes.Length) }
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
