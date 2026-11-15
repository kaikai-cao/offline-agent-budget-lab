# E4.8.2 — Durable Single-Writer Broker Model

**Status:** software-only stage package; local acceptance pending  
**Hardware:** none. This package does not call TBS, TPM APIs, or issue TPM commands.

## Objective

E4.8.1 showed that a process-local lock and in-memory replay table are insufficient as a deployable design. E4.8.2 adds two software properties for evaluation:

1. A host-local cross-process admission lock covering the complete `read -> durable intent -> increment -> read -> durable receipt` sequence.
2. A SQLite WAL journal that persists pending intents, committed receipts, and the last expected counter value.

The monotonic counter remains a file-backed simulator. This is not a test of TPM concurrency, actual NV durability, TEE isolation, or privileged-attacker resistance.

## Proposed protocol

For one lease and one counter:

1. Acquire the shared broker lock file. All cooperating broker processes must use the same lock path.
2. Load any pending intent and recover it before admitting a new operation.
3. Verify journal health and compare the observed counter with the journal's `expected_counter_value` anchor.
4. Check quota.
5. Commit a `PENDING` intent containing `lease_id`, `operation_id`, `request_digest`, and `pre_counter_value` to SQLite.
6. Issue one counter increment.
7. Read the counter independently and require exactly `pre_counter_value + 1`.
8. In one SQLite transaction, insert the receipt, mark the operation `COMMITTED`, and advance the expected counter anchor.
9. Release the broker lock.

No external tool is executed by this package. A receipt is a durable model record, not a signature.

## Recovery rules

Recovery is performed while holding the broker lock and only when there is exactly one pending intent:

| Observed counter minus intent pre-value | Recovery result | Behavior |
|---:|---|---|
| 0 | `NOT_APPLIED` | Mark intent not applied; do not automatically retry the same operation ID |
| 1 | `COMMITTED` | Reconstruct and persist the receipt; do not increment again |
| Other / multiple pending intents | `INDETERMINATE` | Mark broker unhealthy and fail closed |

Any mismatch between the hardware-counter emulator and the durable journal anchor also marks the broker `INDETERMINATE`. This detects a stale journal restore while the simulated monotonic counter remains ahead.

## Crash injection points

`consume(..., crash_at=...)` injects an exception after one of these durable boundaries:

- `after_intent`
- `after_increment`
- `after_read`
- `after_receipt_commit`

A new Broker object is then created over the same SQLite and counter files. This models process reconstruction at defined boundaries; it is not a physical power-cut test. The test harness doesn't terminate the process with `TerminateProcess` or simulate storage-controller write-cache failure.

Expected recovery:

- after intent: current counter equals pre-value; operation becomes `NOT_APPLIED`;
- after increment / after read: counter is pre-value + 1; receipt is reconstructed without another increment;
- after receipt commit: replay returns the stored receipt without increment.

## Threat model and limits

The model assumes:

- all cooperating broker instances on one host share the same lock file, journal, and counter state;
- the operating system correctly enforces the tested file-lock semantics;
- SQLite and the counter state file are not maliciously modified during normal operation;
- no caller bypasses the broker to increment the counter.

It does not defend against:

- local administrator or kernel compromise;
- code that directly accesses the TPM or bypasses the shared lock;
- different hosts with cloned software state and separate counters;
- malicious rollback of both the journal and counter emulator;
- power loss that violates filesystem / storage durability assumptions;
- TPM command transport ambiguity not represented by this emulator;
- external tool side effects, idempotency, or exactly-once execution;
- unsigned or replaceable receipt files.

The counter anchor catches a stale database restore when the monotonic counter remains ahead. It cannot authenticate the journal or stop an attacker who can replace all software trust state and the broker binary.

## Local acceptance

Run from this directory:

```powershell
python -m unittest discover -s tests -v
```

Expected: 13 tests pass. Tests cover broker reconstruction, idempotent replay, request rebinding, crash points, quota exhaustion, out-of-band increment detection and attribution limits, stale journal restoration, and independent-process sequence allocation.

No TPM command should be run for E4.8.2.
