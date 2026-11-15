E1.1 — Trusted executor key binding

Purpose
-------
Close the E1-04 trust-substitution gap. The reconciler must not accept a
receipt-verification public key merely because it is carried by the submitted
evidence bundle.

Design
------
BudgetReconciler.reconcile now accepts trusted_executor_keys, a mapping from
lease_id to raw 32-byte Ed25519 public key. This mapping must come from an
independent trusted configuration / registry. The key in LeaseEvidenceBundle
is treated as an untrusted claim and must match the externally pinned key.
If no key is configured, reconciliation returns INCOMPLETE. If the bundle
substitutes a different key, reconciliation returns REJECTED.

Important distinction
---------------------
Do NOT equate lease.holder_public_key with the executor key. The Agent holding
a lease and the trusted execution proxy may be distinct principals. This
patch binds receipts to an independently trusted executor identity; it does
not claim the holder and executor are the same entity.

Run
---
Focused E1 tests:
    .\run_e1_attacks.ps1

Full regression:
    .\run_tests.ps1

Expected:
    E1 focused: 6 tests pass; E1-04 now expects REJECTED.
    Full suite: 90 tests pass.

Trust boundary
--------------
The registry itself is an external trust input. This patch does not implement
secure provisioning, rotation, revocation, remote attestation, or durable
registry storage. If an attacker can alter the verifier's trusted registry,
this protection does not hold.

No TEE, ZK, database persistence, multi-process coordination, or anti-rollback
mechanism is introduced in E1.1.
