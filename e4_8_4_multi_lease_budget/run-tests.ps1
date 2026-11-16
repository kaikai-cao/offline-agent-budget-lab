$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) {
    throw "D8.1 test suite failed."
}
