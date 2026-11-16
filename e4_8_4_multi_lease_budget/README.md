# E4.8.4 — Multi-Lease Global Budget Broker (D8.1)

**Status:** D8.1 standalone Broker; D8.2 E4.8.3 Gateway integration and D8.3 adversarial validation are complete. D8.4 freezes the offline software-model baseline.
**Hardware:** none. This package does not call TBS/TPM APIs, access a TPM, or perform NV writes.

## Objective

E4.8.2 models one Lease against one durable counter. E4.8.4 introduces a single global budget epoch shared by multiple independently signed Leases.

The model reserves quota when a Lease is registered and uses one global counter sequence for all Lease operations. It enforces:

```text
A = SUM(lease.quota_limit)                and A <= G
0 <= U_i <= Q_i                          for every Lease i
S = SUM(lease.used_count)
S = observed_counter - baseline_counter   while the Broker is READY
0 <= S <= A <= G
```

Where `G` is the global quota, `Q_i` is one Lease's immutable reservation, `U_i` is its committed usage, `A` is total reserved quota, and `S` is total committed usage.

## Package layout

```text
e4_8_4_multi_lease_budget/
├── README.md
├── requirements.txt
├── run-tests.ps1
├── src/
│   ├── __init__.py
│   └── global_budget.py
├── tests/
│   ├── __init__.py
│   ├── process_worker.py
│   └── test_global_budget.py
├── examples/
│   └── multi_lease_demo.py
└── docs/
    ├── D8.0_MULTI_LEASE_GLOBAL_BUDGET_DESIGN.md
    ├── D8.2_EXECUTION_BINDING_INTEGRATION.md
    ├── D8.3_ADVERSARIAL_VALIDATION.md
    └── D8.4_OFFLINE_GLOBAL_BUDGET_FREEZE.md
```

## Run on Windows PowerShell

From the extracted repository directory:

```powershell
Set-Location -LiteralPath "D:\Research\offline-agent-budget-lab\e4_8_4_multi_lease_budget"
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Or run:

```powershell
.\run-tests.ps1
```

Run the small API demonstration:

```powershell
python .\examples\multi_lease_demo.py
```

Expected test result for this D8.1 package: **39 tests pass**. The process-concurrency test starts independent Python processes, rather than relying only on threads.

## Main API

### 1. Create the shared Broker

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.global_budget import GlobalBudgetBroker

issuer_private = Ed25519PrivateKey.generate()
broker = GlobalBudgetBroker(
    global_budget_id="budget-epoch-001",
    global_quota_limit=100,
    issuer_public_key=issuer_private.public_key(),
    journal_path="state/global-journal.sqlite3",
    counter_state_path="state/global-counter.json",
    broker_lock_path="state/global-broker.lock",
)
```

All cooperating Gateway/Broker processes in this single-host model must use the same epoch ID, quota, Issuer public key, Journal path, Counter state path, Counter lock path, and Broker lock path.

### 2. Issue and register signed Lease Grants

```python
from src.global_budget import ToolPermission, issue_lease_grant

grant = issue_lease_grant(
    issuer_private,
    issuer_id="issuer-01",
    grant_id="grant-agent-a-001",
    lease_id="lease-agent-a-001",
    global_budget_id="budget-epoch-001",
    nonce="nonce-agent-a-001",
    quota_limit=20,
    issued_at=1_800_000_000,
    expires_at=1_800_003_600,
    audience="gateway-a",
    subject_id="agent-a",
    context_digest="sha256:" + "1" * 64,
    allowed_tools=(ToolPermission("invoice_review", "sha256:" + "2" * 64),),
)
broker.register_lease(grant)
```

The Global Budget Broker independently verifies the Ed25519 signature and exact version-3 grant payload. Registration is idempotent only for the same Lease ID and exact signed grant digest. Lease ID, Grant ID, and nonce conflicts are rejected. A registration that would make total reserved quota exceed the global quota is rejected atomically.

### 3. Consume one unit from one Lease

```python
receipt = broker.consume(
    grant,
    operation_id="operation-0001",
    request_digest="sha256:" + "3" * 64,
)
print(receipt.global_sequence)
print(receipt.lease_used_count)
```

The global sequence is unique across all Leases. Exact operation replay returns the original receipt. An Operation ID cannot be reused across Leases or request digests.

### 4. Revoke a Lease

The Issuer signs a revocation record binding the epoch, revocation ID, Lease ID, original Grant digest and revocation timestamp. The Broker verifies and persists it. Replaying the exact revocation is idempotent; conflicting reuse is rejected. Revoked/expired quota is not refunded in D8.1.

## Recovery semantics

The single global lock permits at most one pending global counter increment:

| Counter delta from pending pre-value | Result | Usage accounting |
|---:|---|---|
| `0` | `NOT_APPLIED` | Lease usage unchanged; use a new Operation ID |
| `1` | Recover and commit original receipt | Original Lease usage increases exactly once |
| Other / multiple pending intents | Global `INDETERMINATE` | Stop all new Lease consumption |

Recovery runs before registration, revocation or new consumption. An already-persisted pending operation may be settled after its Lease expires or is revoked; this settlement is not a new authorization. It cannot be reassigned to another Lease.

A successful counter increment and the matching receipt, Lease usage and expected counter anchor are committed together in one SQLite transaction. Budget is consumed before any downstream tool execution; downstream tool failures do not refund quota.

## Configuration and restoration checks

The Broker pins the epoch, global limit, Issuer key digest, Journal/Counter/lock paths and baseline in SQLite metadata. A small configuration anchor alongside the Counter also records the baseline. This catches accidental reconfiguration, a missing Journal while the Counter is ahead, and restoring an older Journal while retaining a newer Counter.

This is still software state. It does not resist an attacker who can maliciously replace all Journal, Counter, configuration-anchor files and executable code together.

## D8.1 test coverage

The 39 tests cover:

- signed v3 Lease registration, exact replay, grant tampering, epoch mismatch and identifier conflicts;
- atomic global reservation bounds and concurrent registration races;
- globally unique sequences, per-Lease quota isolation, global cap and Operation ID binding;
- thread concurrency and independent OS process concurrency across Leases;
- crash after intent, increment, read and receipt commit;
- multiple/ambiguous pending intents, out-of-band increments and stale/deleted Journal restoration;
- Lease expiry, signed revocation, pending-operation settlement and non-refundable reservations;
- immutable epoch, Issuer key and storage configuration binding.

## Explicit limitations

- One host and cooperating processes sharing one SQLite Journal, one file-backed Counter and one global lock.
- The counter is a JSON-file emulator, not a TPM NV Counter. File locks model host-local serialization only.
- No multi-host consensus, distributed lock service, TEE isolation, TPM attestation, power-loss/storage-controller durability guarantee or malicious administrator resistance.
- The Issuer/Gateway private-key lifecycle and Online revocation delivery are not productionized.
- D8.1 provides the standalone Global Budget Broker; D8.2 adds the E4.8.3 adapter while retaining the legacy single-Lease path. D8.3 validates the integrated boundary. See the D8.4 freeze record for the accepted offline baseline.
- Passing tests validates only this software model and the enumerated crash/concurrency cases. It is not a formal proof or production security certification.
