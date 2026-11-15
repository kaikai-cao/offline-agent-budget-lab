$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) {
    throw "E4.8.2 test suite failed with exit code $LASTEXITCODE"
}
