# E4.8.1 — TPM Counter Binding Model

A self-contained, standard-library-only software model for the next offline-agent-budget-lab round.

**Safety:** no TPM/TBS APIs, no hardware commands, no reads/writes to the user's TPM, and no edits to existing project files. Copy this folder into the project root as a new sibling directory.

## Run on Windows PowerShell

From the project root after extracting this folder:

```powershell
Set-Location -LiteralPath "D:\Research\offline-agent-budget-lab"
Set-Location ".\e4_8_counter_binding_model"
python -m unittest discover -s tests -v
```

Or run the included wrapper:

```powershell
.\run-tests.ps1
```

No third-party Python package is required.

## What it tests

- NV_Increment response is modeled as status-only; reading the value is separate.
- Interleaving two increment/read clients can produce duplicate observed sequence values.
- Pre-increment quota checks can overrun under an interleaving.
- Post-increment quota checks fail closed but can burn quota.
- A singleton serialized broker assigns unique sequence values under threads.
- Operation ID replay and request rebinding are checked.
- A pending increment can only be recovered under strict single-intent/exclusive-recovery assumptions.

See `docs/e4-8-protocol-model.md` for assumptions, evidence, and the conclusion boundary.
