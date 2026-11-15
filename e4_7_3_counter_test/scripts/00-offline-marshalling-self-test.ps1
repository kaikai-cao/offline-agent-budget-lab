$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\src\E47TpmNative.cs'
if (-not (Test-Path -LiteralPath $source)) { throw "Missing C# helper: $source" }
if (-not ('E47TpmNative' -as [type])) { Add-Type -Path $source -ErrorAction Stop }
$checks = [E47TpmNative]::RunOfflineMarshallingSelfTests()
$checks | ForEach-Object { Write-Host $_ }
Write-Host 'Offline marshalling self-test: PASS' -ForegroundColor Green
Write-Host 'This test does not open TBS and does not send any TPM command.'
