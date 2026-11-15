$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Project virtual environment not found. Run .\run_tests.ps1 first."
}

$env:PYTHONPATH = Join-Path (Get-Location) "src"
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_e1_attacks.py" -v
