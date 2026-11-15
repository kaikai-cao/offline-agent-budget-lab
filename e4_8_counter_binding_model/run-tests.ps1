$ErrorActionPreference = 'Stop'

Write-Host 'E4.8.1 software-only model tests' -ForegroundColor Cyan
Write-Host 'No TPM/TBS API is used by this test suite.' -ForegroundColor DarkGray

python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) {
    throw "Python unit tests failed with exit code $LASTEXITCODE"
}

Write-Host 'E4.8.1 model tests: PASS' -ForegroundColor Green
