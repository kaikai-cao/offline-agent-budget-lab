Offline Agent Budget Lab — E0.4 Root Reconciliation

New files:
  src/budget_lab/reconciliation.py
  tests/test_reconciliation.py
  docs/e0.4-reconciliation.md

Updated files:
  src/budget_lab/issuer.py
  src/budget_lab/receipts.py
  src/budget_lab/__init__.py

Run from the repository root:
  .\run_tests.ps1

E0.4 verifies an Issuer-signed allocation manifest, exact lease-bundle
coverage, terminal operation receipts, per-lease/root-level budget accounting,
and independent trusted chain-head anchors. Missing anchors or unresolved
operations yield INCOMPLETE; invalid evidence or mismatched anchors yield
REJECTED.

Creating the signed allocation manifest freezes further lease issuance in
this E0 run. The trusted chain-head anchor must come from an independent trusted
source. This prototype does not implement a checkpoint registry, durable issuer
state, anti-rollback, TEE, ZK, or cross-process coordination.

Validated test inventory in the build environment:
  E0.1 Issuer:          13
  E0.2 Local ledger:     25
  E0.3 Receipts:         20
  E0.4 Reconciliation:   23
  Total:                 81 passing tests

Build environment: Python 3.13.5, cryptography 46.0.4. The package pins
cryptography 46.0.7 in requirements.txt; run the test script in the target
Windows environment to confirm the pinned dependency there.
