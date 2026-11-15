E0.2 Local Budget Ledger — overlay package

Extract this ZIP into the existing offline-agent-budget-lab directory.
It adds ledger.py, test_ledger.py and docs/e0.2-local-ledger.md, and updates
src/budget_lab/__init__.py to export the ledger API. Existing E0.1 source,
tests and run_tests.ps1 remain compatible.

Run from the repository root:
    .\run_tests.ps1

The ledger is in-memory and single-process only. It is not anti-rollback,
not crash durable, and not a multi-process/global budget authority.
