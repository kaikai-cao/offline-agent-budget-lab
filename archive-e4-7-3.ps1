[CmdletBinding()]
param(
    [string]$RepoRoot = 'D:\Research\offline-agent-budget-lab'
)

$ErrorActionPreference = 'Stop'

function Write-Utf8NoBom {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Content)
    $encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-ReportValue {
    param([Parameter(Mandatory=$true)]$Object, [Parameter(Mandatory=$true)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Cleanup report is missing required field '$Name'." }
    return $property.Value
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$reportSource = Join-Path $env:LOCALAPPDATA 'OfflineAgentBudgetLab\E4.7.3\cleanup-report.json'
$e4Root = Join-Path $RepoRoot 'results\e4'

if (-not (Test-Path -LiteralPath $reportSource -PathType Leaf)) {
    throw "Cleanup report not found: $reportSource. No archive was created."
}

$reportRaw = [System.IO.File]::ReadAllText($reportSource)
$report = $reportRaw | ConvertFrom-Json

# Validate the exact cleanup evidence before writing an archive.
$checks = [ordered]@{
    Result                     = ((Get-ReportValue $report 'Result') -eq 'CLEANUP_VERIFIED')
    Handle                     = ((Get-ReportValue $report 'Handle').ToString().ToUpperInvariant() -eq '0X01BFFFFE')
    DeletedNvName              = ((Get-ReportValue $report 'DeletedNvName').ToString().ToLowerInvariant() -eq '000b667669216ae5f67a6da327553d35f90fbb553944969f5f28921a71532b37b201')
    Original16NvNamesUnchanged = ([bool](Get-ReportValue $report 'Original16NvNamesUnchanged'))
    CandidateAbsent            = ([bool](Get-ReportValue $report 'CandidateAbsent'))
    HrNvIndexAfterCleanup      = ((Get-ReportValue $report 'HrNvIndexAfterCleanup') -eq 16)
    NvCountersAfterCleanup     = ((Get-ReportValue $report 'NvCountersAfterCleanup') -eq 4)
}

$failedChecks = @($checks.GetEnumerator() | Where-Object { -not $_.Value })
if ($failedChecks.Count -gt 0) {
    $names = ($failedChecks | ForEach-Object { $_.Key }) -join ', '
    throw "Cleanup report validation failed for: $names. No archive was created."
}

if (-not (Test-Path -LiteralPath $e4Root -PathType Container)) {
    New-Item -ItemType Directory -Path $e4Root -Force | Out-Null
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$folderName = "E4.7.3-TPM-NV-Counter-Archive-$stamp"
$archiveDir = Join-Path $e4Root $folderName
$evidenceDir = Join-Path $archiveDir 'evidence'
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

# Preserve the exact cleanup report emitted by the cleanup script.
$reportCopy = Join-Path $evidenceDir 'cleanup-report.json'
Copy-Item -LiteralPath $reportSource -Destination $reportCopy

# Capture a non-sensitive state summary only; never copy auth material or DPAPI files.
$stateSource = Join-Path $env:LOCALAPPDATA 'OfflineAgentBudgetLab\E4.7.3\counter-state.json'
$stateSummaryPath = Join-Path $evidenceDir 'counter-state-summary.json'
$stateFields = @(
    'Status', 'IncrementAttempted', 'IncrementCommandSucceeded',
    'IncrementTbsReturn', 'IncrementTpmResponseCode', 'PostIncrementValue',
    'PostIncrementValueCapturedAtUtc', 'WrittenNvName',
    'PostRebootObservedValue', 'PostRebootAtUtc', 'PostRebootBootTimeUtc',
    'StatusBeforeUndefine', 'UndefineAttempted', 'UndefineAttemptedAtUtc'
)
$stateSummaryCreated = $false
if (Test-Path -LiteralPath $stateSource -PathType Leaf) {
    try {
        $state = Get-Content -LiteralPath $stateSource -Raw | ConvertFrom-Json
        $summary = [ordered]@{}
        foreach ($field in $stateFields) {
            $p = $state.PSObject.Properties[$field]
            if ($null -ne $p) { $summary[$field] = $p.Value }
        }
        $summary['SourceFile'] = 'counter-state.json (whitelisted non-secret fields only)'
        $summaryJson = $summary | ConvertTo-Json -Depth 8
        Write-Utf8NoBom -Path $stateSummaryPath -Content $summaryJson
        $stateSummaryCreated = $true
    }
    catch {
        Write-Warning "Could not create optional counter-state summary: $($_.Exception.Message)"
    }
}
else {
    Write-Warning "Optional state file not found; cleanup report and run log will still be archived: $stateSource"
}

$completedUtc = (Get-ReportValue $report 'CompletedAtUtc').ToString()
$log = @"
# E4.7.3 — Real TPM NV Counter Persistence Experiment

- **Experiment date:** 2026-11-13
- **Archive generated (local):** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
- **Cleanup report completion field (UTC):** $completedUtc
- **Repository:** ``D:\Research\offline-agent-budget-lab``
- **Final status:** PASS — experiment completed, test NV index deleted, original NV indexes unchanged.

## 1. Objective

Verify whether a TPM 2.0 NV Counter created for the experiment preserves its exact counter value across one normal Windows restart, then remove only the dedicated test index and verify cleanup.

## 2. Test environment

| Item | Observed configuration |
|---|---|
| System | Dell Pro Tower QCT1250 |
| CPU | Intel Core i7-14700 |
| Motherboard | Dell 0J93GF A03 |
| BIOS | 1.20.0 (2026-10-13) |
| OS | Windows 11 Home Insider Preview, build 26320 |
| TPM manufacturer | NTC |
| TPM device family/version info | NPCT75x / 7.2.5.1 |
| TPM specification | TPM 2.0, TCG spec revision 1.59 |
| Secure Boot | Enabled |

## 3. Test object and configuration

| Item | Value |
|---|---|
| Dedicated test NV index | ``0x01BFFFFE`` |
| NV type | ``TPM_NT_COUNTER`` |
| Name algorithm | SHA-256 (``0x000B``) |
| Data size | 8 bytes |
| NV attributes | ``0x00040014`` |
| Name before first increment (WRITTEN=CLEAR) | ``000b8da67e5ccf4b8541929bea0f0919de2870f54abcb905cdca6d10001f55c173aa`` |
| Name after successful increment (WRITTEN=SET) | ``000b667669216ae5f67a6da327553d35f90fbb553944969f5f28921a71532b37b201`` |

The experiment used the Owner hierarchy to define and later remove the dedicated test index. The pre-creation probe observed ``ownerAuthSet=False``; the cleanup script therefore expected EmptyAuth for the Owner hierarchy, and the cleanup operation completed successfully.

## 4. Execution record

| Stage | Result | Evidence |
|---|---|---|
| Offline command marshalling and parser self-test | PASS | ``00-offline-marshalling-self-test.ps1`` reported all checks PASS, including NV_Read counter value parsing and NV Name handling |
| NV index definition | PASS | ``TPM2_NV_DefineSpace`` succeeded for the dedicated test index |
| First counter increment | PASS | ``TPM2_NV_Increment`` returned TBS status ``0x00000000`` and TPM response code ``0x00000000`` |
| Read before reboot | PASS | ``01b-capture-value-before-reboot.ps1`` recorded counter value **1** |
| Windows restart persistence | PASS | ``02-verify-after-reboot.ps1`` reported pre-reboot value **1**, post-reboot value **1**, and exact value persisted |
| Dedicated index cleanup | PASS | ``03-cleanup.ps1`` reported ``CLEANUP VERIFIED`` |
| Final cleanup evidence | PASS | Candidate absent; original 16 NV Names unchanged; ``HR_NV_INDEX=16``; ``NV_COUNTERS=4`` |

### Key observed command outputs

```text
Counter value captured before reboot: 1
Capture complete. Perform a normal Windows restart, then run 02-verify-after-reboot.ps1.

Recorded pre-reboot value : 1
Observed post-reboot value: 1
PASS: exact counter value persisted across a Windows restart.

CLEANUP VERIFIED. Only the dedicated test NV index was deleted.
```

## 5. Cleanup report verification

The original cleanup report is preserved at ``evidence/cleanup-report.json``. Its validated fields are:

| Field | Value |
|---|---|
| Result | ``CLEANUP_VERIFIED`` |
| Handle | ``0x01BFFFFE`` |
| DeletedNvName | ``000b667669216ae5f67a6da327553d35f90fbb553944969f5f28921a71532b37b201`` |
| Original16NvNamesUnchanged | ``True`` |
| CandidateAbsent | ``True`` |
| HrNvIndexAfterCleanup | ``16`` |
| NvCountersAfterCleanup | ``4`` |
| CompletedAtUtc | ``$completedUtc`` |

## 6. Conclusion

Under this device configuration and test procedure, the TPM NV Counter successfully accepted one increment, returned the value **1**, and preserved that exact value across one normal Windows restart. The dedicated NV index was subsequently deleted, and the cleanup report confirms that the original 16 NV Names remained unchanged.

This is a successful hardware experiment for the tested TPM, index configuration, one increment, and one restart. It is evidence for the persistence behavior of this TPM NV Counter primitive under the tested conditions; it is not a general proof of TPM security or a complete Agent budget-security design.

## 7. Scope and limitations

- One physical TPM device, one NV Counter configuration, one successful increment, and one normal Windows restart were tested.
- This experiment does not establish resistance to a privileged actor able to use Owner or platform authorization to redefine or delete NV state.
- TPM counter persistence alone does not provide exactly-once semantics for an external tool or external side effect.
- This experiment does not prove a complete TEE, secure execution environment, or Agent authorization architecture.
- The cleanup report explicitly notes that deleting an NV Counter index does **not** reset TPM-wide counter high-water history. The active index/counter counts returned to the observed pre-test counts, but that does not mean all TPM-internal historical resource state was reset.

## 8. Final disposition

**E4.7.3 is closed and archived.** No further TPM write, increment, undefine, or cleanup operation is required for this experiment. Future work should treat this result as a measured hardware primitive evaluation, not as an end-to-end security guarantee.
"@

$logPath = Join-Path $archiveDir 'E4.7.3-final-log.md'
Write-Utf8NoBom -Path $logPath -Content $log

# Hash the exact sources relevant to this experiment for reproducibility.
$sourceRelPaths = @(
    'e4_7_3_counter_test\src\E47TpmNative.cs',
    'e4_7_3_counter_test\scripts\00-offline-marshalling-self-test.ps1',
    'e4_7_3_counter_test\scripts\01-create-and-increment.ps1',
    'e4_7_3_counter_test\scripts\01a-resume-after-define.ps1',
    'e4_7_3_counter_test\scripts\01b-capture-value-before-reboot.ps1',
    'e4_7_3_counter_test\scripts\02-verify-after-reboot.ps1',
    'e4_7_3_counter_test\scripts\03-cleanup.ps1',
    'e4_7_3_counter_test\scripts\E47-Common.ps1'
)
$sourceHashes = foreach ($relativePath in $sourceRelPaths) {
    $fullPath = Join-Path $RepoRoot $relativePath
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        $hash = Get-FileHash -LiteralPath $fullPath -Algorithm SHA256
        [pscustomobject]@{
            RelativePath = $relativePath
            SHA256 = $hash.Hash.ToLowerInvariant()
            Present = $true
        }
    }
    else {
        [pscustomobject]@{
            RelativePath = $relativePath
            SHA256 = $null
            Present = $false
        }
    }
}
$sourceHashPath = Join-Path $evidenceDir 'source-file-sha256.json'
Write-Utf8NoBom -Path $sourceHashPath -Content (($sourceHashes | ConvertTo-Json -Depth 5))

$manifest = [ordered]@{
    Experiment = 'E4.7.3 Real TPM NV Counter Persistence'
    ArchiveGeneratedAtLocal = (Get-Date -Format 'o')
    RepositoryRoot = $RepoRoot
    CleanupReportSource = $reportSource
    CleanupReportSHA256 = (Get-FileHash -LiteralPath $reportCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    FinalLogSHA256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant()
    SourceFiles = $sourceHashes
    CounterStateSummaryIncluded = $stateSummaryCreated
    CleanupChecks = $checks
    ArchiveScriptSentTpmCommands = $false
}
$manifestPath = Join-Path $archiveDir 'manifest.json'
Write-Utf8NoBom -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 8)

$zipPath = Join-Path $e4Root ($folderName + '.zip')
Compress-Archive -Path (Join-Path $archiveDir '*') -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host ''
Write-Host 'E4.7.3 archive created successfully.' -ForegroundColor Green
Write-Host "Archive folder: $archiveDir"
Write-Host "ZIP package   : $zipPath"
Write-Host "Cleanup report: $reportCopy"
Write-Host "Final log     : $logPath"
Write-Host "Manifest      : $manifestPath"
Write-Host 'TPM commands sent by this archival script: NONE' -ForegroundColor Cyan
