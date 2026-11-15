# E2 State-Trust Mechanism Comparison v0.1

**Status:** comparative experiment package; not a production security implementation.

## Question

What additional trust assumption is required to prevent two isolated copies of
one offline lease from both consuming the same budget? Compare:

1. E0/E1 software-local state (negative baseline).
2. Shared online atomic spend/allocation authority (online positive control).
3. A local monotonic-state emulator representing a TEE/secure element API
   (offline hardware-assumption model).

## Fixed setup

- Root budget: 10 units.
- Example child lease: 4 units.
- Each test uses integer cost units.
- Executors and issuer replicas may have their ordinary software state copied.
- The E2 emulators are reference models only; no actual TEE, secure element,
  distributed database, consensus protocol, or remote attestation is implemented.

## Mechanism A — software-local ledger

Two independently reconstructed `LocalBudgetLedger` instances can each start
from the same signed lease and each accept spends up to the lease amount. This
is already demonstrated by E1-02/E1-03. Local locks serialize threads sharing
one object; they do not coordinate independent copies.

Expected property: local integrity, not global anti-double-spend under state
cloning/rollback.

## Mechanism B — shared online atomic authority

All executor replicas call one shared atomic authority for each spend. It
maintains one authoritative spent balance and operation-ID set per lease.
It rejects overspend and replay across replicas.

Trade-off: every spend needs connectivity to the same live authority. When the
authority is unavailable, the model fails closed. Therefore this mechanism is
a control for global uniqueness, but does not provide fully offline execution.

The in-memory implementation is a single-process serialization model, not a
claim that a distributed service is linearizable or Byzantine fault tolerant.

## Mechanism C — monotonic-state emulator

Multiple software executor instances for one device use one separately held
monotonic-state object. Reconstructing the untrusted software executor does not
reset the protected counter. The model binds a lease to a device identity and
rejects spending beyond the provisioned balance.

Trade-off: it assumes a real hardware facility provides non-exportable identity,
atomic monotonic state, persistence across software rollback/restart, and a
trusted API. The emulator demonstrates the state transition expected from such
an interface; it does not establish that actual hardware has these properties.
If the secure element itself can be cloned, rolled back, or compromised, the
model's guarantee no longer applies.

## Issuer-side allocation fork

E1-05 shows that two copies of in-memory Issuer state can allocate more than the
root budget while signing with the same key. E2 adds a shared allocation
registry as an online control: issuer replicas reserve every new lease against
one authoritative aggregate before activating it. This has the same online
availability trade-off as shared spend coordination.

## E2 test matrix

| Test | Mechanism | Expected result |
|---|---|---|
| E2-01 | Shared online spend authority | Second copied branch rejected at aggregate limit |
| E2-02 | Shared online spend authority | Duplicate operation ID rejected across replicas |
| E2-03 | Shared online spend authority | Offline authority causes fail-closed behavior |
| E2-04 | Shared online spend authority | Concurrent requests never exceed shared budget |
| E2-05 | Monotonic-state emulator | Copied software executor cannot exceed shared device quota |
| E2-06 | Monotonic-state emulator | Reconstructing software executor does not reset protected state |
| E2-07 | Monotonic-state emulator | Different device identity rejected |
| E2-08 | Monotonic-state emulator | Unavailable protected state fails closed |
| E2-09 | Shared root allocation registry | Issuer replicas cannot overallocate one root through shared registry |
| E2-10 | Shared root allocation registry | Offline registry prevents new allocation |

## Interpretation rules

- `PREVENTED` means the attempted extra spend/allocation is refused before the
  modeled operation is accepted.
- `DETECTED` means an already-created effect is only identified later during
  reconciliation.
- `OUT_OF_SCOPE` means the result relies on an assumption not modeled here.
- Do not report emulator results as real TEE measurements.
- Do not report the shared in-memory authority as a distributed consensus
  result.
- Do not claim software-only offline prevention against arbitrary state
  cloning based on these tests.

## Decision guidance

- If offline execution must continue during network partitions, a design based
  only on shared online atomic state cannot satisfy the availability
  requirement.
- If cloned software state must not double-spend offline, a non-clonable,
  rollback-resistant local trust anchor (or an equivalent assumption) is needed
  for prevention. Without it, a design can at best detect/attribute duplicate
  spends after reconnection, assuming both branches report evidence.
- Issuer-side global allocation also needs one authoritative allocator or an
  explicitly partitioned, non-overlapping allocation protocol. Local copied
  Issuer state plus the same signing key is not enough.
- ZK can add privacy to allocation/spend evidence, but does not itself provide
  non-clonable state, atomic global uniqueness, or rollback resistance.
