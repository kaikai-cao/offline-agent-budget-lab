Offline Agent Budget Lab — E0.3 Receipt Chain

This overlay adds:
  src/budget_lab/receipts.py
  tests/test_receipts.py
  docs/e0.3-receipts-and-hash-chain.md

It also updates src/budget_lab/__init__.py to export the new API.

Run from the repository root:
  .\run_tests.ps1

E0.3 creates executor-signed assertions for terminal operations and links them
with a SHA-256 hash chain. It does NOT execute tools, provide TEE attestation,
prove external database correctness, guarantee durable logging, or prevent
receipt/ledger rollback. A hash chain alone cannot detect tail truncation
without a trusted checkpoint or trusted complete ledger view.

Expected full suite in this package: 58 tests (13 E0.1 + 25 E0.2 + 20 E0.3).
