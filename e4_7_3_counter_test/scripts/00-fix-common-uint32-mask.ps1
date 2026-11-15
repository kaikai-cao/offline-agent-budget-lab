$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'E47-Common.ps1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    throw 'E47-Common.ps1 was not found beside this recovery script.'
}

$content = Get-Content -LiteralPath $commonPath -Raw
$oldLine = '    $stableMask = [uint32]0xDFFFFFFF'
$newLine = '    $stableMask = [Convert]::ToUInt32(''DFFFFFFF'', 16)'

$oldCount = ([regex]::Matches($content, '(?m)^\s*\$stableMask\s*=\s*\[uint32\]0xDFFFFFFF\s*$')).Count
$newMarker = '$stableMask = [Convert]::ToUInt32(''DFFFFFFF'', 16)'
$newCount = ([regex]::Matches($content, '(?m)^\s*\$stableMask\s*=\s*\[Convert\]::ToUInt32\(''DFFFFFFF'',\s*16\)\s*$')).Count

if ($oldCount -eq 1) {
    if (-not $content.Contains($oldLine)) {
        throw 'The exact expected mask line was not found. No file was changed.'
    }
    $content = $content.Replace($oldLine, $newLine)
    Set-Content -LiteralPath $commonPath -Value $content -Encoding utf8
    Write-Host 'Applied the targeted UInt32 mask conversion fix.'
}
elseif ($oldCount -eq 0 -and $newCount -eq 1) {
    Write-Host 'The UInt32 mask conversion fix is already present.'
}
else {
    throw ('Unexpected mask-line count (old={0}, new={1}). No further changes were made.' -f $oldCount, $newCount)
}

# Parse every E4.7.3 PowerShell script before any TPM operation is attempted.
$scriptFiles = Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File
$parseFailures = @()
foreach ($scriptFile in $scriptFiles) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptFile.FullName,
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    if ($parseErrors.Count -gt 0) {
        foreach ($parseError in $parseErrors) {
            $parseFailures += [pscustomobject]@{
                File = $scriptFile.Name
                Line = $parseError.Extent.StartLineNumber
                Message = $parseError.Message
            }
        }
    }
}

if ($parseFailures.Count -gt 0) {
    $parseFailures | Format-Table -AutoSize
    throw 'PowerShell parser validation failed. Do not run the resume script.'
}

Write-Host ('PowerShell parser validation: PASS ({0} scripts)' -f $scriptFiles.Count) -ForegroundColor Green
Write-Host 'No TPM command was sent by this patch script.'
