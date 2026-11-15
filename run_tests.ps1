$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

$env:PYTHONPATH = Join-Path (Get-Location) "src"
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
