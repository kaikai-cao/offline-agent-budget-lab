# E4.8.2 — Durable Single-Writer Broker Model

A self-contained, standard-library-only software experiment for the offline-agent-budget lab.

**Safety boundary:** no TPM/TBS APIs, no hardware writes, no TPM reads, and no edits to E4.7.3 or the existing Agent project. The counter is a JSON-file emulator. SQLite stores the durable journal. A host-local cross-process lock serializes cooperating broker processes.

## Run on Windows PowerShell

From the project root after extracting this folder:

```powershell
Set-Location -LiteralPath "D:\Research\offline-agent-budget-lab\e4_8_2_durable_broker"
python -m unittest discover -s tests -v
```

No third-party Python package is required. Python 3.10+ is recommended.

## What is tested

- Durable replay and request binding across broker reconstruction.
- Recovery after injected crashes following intent, increment, read, and receipt commit.
- Cross-process serialization and duplicate-operation replay.
- Quota exhaustion, out-of-band increments and attribution limits, and stale-journal restoration.

See `docs/e4-8-2-protocol-and-test-plan.md` for the protocol, assumptions, and claim boundaries.
