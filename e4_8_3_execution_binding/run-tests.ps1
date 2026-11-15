$ErrorActionPreference = 'Stop'

Write-Host 'Checking cryptography dependency...' -ForegroundColor Cyan
python -c "import cryptography; print('cryptography', cryptography.__version__)"
if ($LASTEXITCODE -ne 0) {
    throw 'cryptography is missing. Run: python -m pip install -r requirements.txt'
}

Write-Host 'Running E4.8.3 tests...' -ForegroundColor Cyan
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) {
    throw 'E4.8.3 test suite failed.'
}
