. (Join-Path $PSScriptRoot 'E47-Common.ps1')
Assert-Elevated
Initialize-E47Types
$state = Load-State
$context = [IntPtr]::Zero
try {
    $context = New-TbsContext
    $null = Assert-HierarchyPreconditions $context
    $handles = Assert-BaselineNames $context
    Assert-CandidateAbsent $context $handles
    Write-Host 'Candidate index is absent and the original 16 NV Names are unchanged.' -ForegroundColor Green
    Write-Host 'This only removes the local DPAPI auth/state files; it sends no TPM write command.'
    $confirm = Read-Host 'Type exactly REMOVE-LOCAL-STATE-ONLY to continue'
    if ($confirm -cne 'REMOVE-LOCAL-STATE-ONLY') { throw 'Local state removal not confirmed.' }
    if (Test-Path -LiteralPath $script:AuthPath) { Remove-Item -LiteralPath $script:AuthPath -Force }
    if (Test-Path -LiteralPath $script:StatePath) { Remove-Item -LiteralPath $script:StatePath -Force }
    Write-Host 'Local state removed. No TPM index was deleted or changed.' -ForegroundColor Green
}
finally {
    if ($context -ne [IntPtr]::Zero) { Close-TbsContext $context }
}
