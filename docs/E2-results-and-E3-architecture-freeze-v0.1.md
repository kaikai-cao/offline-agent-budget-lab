# E2 Results and E3 Architecture Freeze v0.1

**Project:** `offline-agent-budget-lab`  
**Status:** E2 local acceptance complete; E3 design stage proposed  
**Scope:** Interpret the E2 comparison tests and freeze the next architecture assumptions. This document does not claim real TEE validation or research novelty.

## 1. E2 execution results

The Windows environment reported:

- E2-specific tests: **10/10 passed**.
- Full regression suite: **100/100 passed**.
- Runtime dependency: `cryptography==46.0.7`.

The successful tests establish that the implemented test doubles behave as specified. They do not establish the security of a real online authority, TPM, TEE, secure element, or hardware monotonic counter.

## 2. What the three mechanisms demonstrate

### A. Pure software-local ledger

E1 already demonstrated that two independently cloned software ledger states can each accept locally valid spends against the same lease. A later reconciliation can detect overrun only when both branches' evidence is presented. This is detection after effects, not prevention before effects.

### B. Shared online authority

The E2 tests show that a single shared authority can serialize concurrent spends, reject replay across replicas, and prevent two replicas from spending the same global balance. The tests also show fail-closed behavior when the authority is unavailable.

**Consequence:** this mechanism can protect allocation and consumption while connected, but cannot itself provide offline spending availability. It is suitable for the online allocation phase, or for online execution, not as the only mechanism during a network partition.

### C. Monotonic-state emulator

The E2 tests show that the emulator can preserve a spend state across executor reconstruction, reject a different device identity, reject cloned-executor overspend, and fail closed when unavailable.

**Boundary:** this is an emulator-level result. It does not test a real hardware root of trust, non-exportable key, anti-rollback storage, firmware, remote attestation, physical attacks, device reset behavior, or atomicity between a hardware state update and an external tool side effect. Executor reconstruction is not equivalent to a real device reboot or adversarial hardware cloning test.

## 3. Architecture decision supported by E2

For the selected hybrid requirement—partial offline execution, global budget conservation, and final reconciliation—the current evidence supports the following candidate architecture:

1. **Online allocation phase:** a single authoritative allocation domain reserves and signs disjoint child leases. It enforces the root invariant:

   `sum(child_lease.budget) <= root_budget`

2. **Freeze phase:** the issuer produces a signed allocation manifest covering the complete set of issued leases. New allocations require a new authorized epoch/manifest rather than silently extending the old set.

3. **Offline execution phase:** each lease is bound to a designated executor/device trust identity. A trusted local state provider must atomically enforce one-time operation IDs and monotonic budget consumption. If that provider is unavailable or its state cannot be trusted, execution fails closed.

4. **Evidence phase:** the executor signs receipts bound to the lease, tool, schema, request/context digests, result digest, cost, sequence, and previous receipt hash.

5. **Reconciliation phase:** the verifier checks the allocation manifest, trusted executor identities, receipt chain, independently trusted terminal checkpoints, per-lease accounting, and root budget conservation. Missing or indeterminate evidence is not treated as proof of non-execution and must not silently release budget.

This architecture is a design hypothesis and a composition of known mechanisms. It is not yet a novel protocol claim.

## 4. Explicit trust assumptions to carry forward

- The online allocation authority is a single logical atomic allocation domain during allocation.
- The root budget and lease manifest are authenticated and independently retained by the verifier.
- Each offline lease is associated with one trusted execution identity/device.
- The local trusted-state mechanism resists rollback and cloning under its stated hardware assumptions.
- A budget reservation is durably consumed before an irreversible tool effect is permitted, or the operation remains charged as `indeterminate` after an ambiguous failure.
- The tool's execution/effect boundary is controlled by the trusted executor; an untrusted planner cannot bypass it.
- Independent terminal checkpoints are retained outside the executor's rollback domain.

If any assumption is removed, the security claim must be weakened accordingly.

## 5. Important unresolved issue: state/effect atomicity

A monotonic counter alone does not automatically make a non-idempotent external tool operation atomic.

- Decrementing budget before the tool effect can conservatively consume budget even if the tool never completes.
- Performing the tool effect before durably consuming budget can permit a retry after a crash and cause duplicate effects.
- The system therefore needs a reserve-before-effect protocol, a durable operation identifier, explicit `indeterminate` handling, and a tool-side idempotency or deduplication contract where available.

This issue must be included in E3. Do not claim “exactly once execution” solely from a monotonic counter.

## 6. Role of zero-knowledge proofs

ZK is not the mechanism that prevents state rollback or double spending. Under the candidate architecture, its possible role is to hide selected lease amounts, branch identities, delegation relationships, or per-branch usage while proving allocation and aggregate-spend constraints.

A ZK proof still needs a sound uniqueness/state mechanism for one-time consumption. It must not be presented as a replacement for the online allocator or trusted offline state provider.

## 7. E3 design-stage deliverables

E3 should be a bounded architecture/specification stage, not another feature sprint. It should produce:

1. A precise state machine covering `allocated`, `reserved`, `committed`, `aborted`, `indeterminate`, and `reconciled` states.
2. A protocol sequence for online allocation, offline reservation/execution, receipt creation, reconnect, and final reconciliation.
3. A failure matrix for crash-before-effect, crash-after-effect-before-receipt, duplicate retry, device unavailable, state rollback attempt, lease expiry, and missing checkpoint.
4. A clear separation between guaranteed prevention, post-hoc detection, and out-of-scope cases.
5. An interface contract for a local trusted-state provider, with the current emulator explicitly labelled as a test double.
6. A short decision on whether a real hardware experiment is feasible on the available machine/platform. No hardware claims may be inferred from the emulator tests.

## 8. E3 acceptance criteria

E3 is complete only when:

- Every state transition has a defined precondition, durable update, and failure behavior.
- The budget invariant is stated for both allocated leases and consumed/indeterminate operations.
- The design specifies how a copied lease is rejected on a different device and what happens if the device identity itself is compromised.
- Crash ambiguity never causes automatic budget refund when an external effect may have occurred.
- Final reconciliation distinguishes `ACCEPTED`, `INCOMPLETE`, and `REJECTED` with explicit rules.
- The design clearly identifies which properties depend on hardware, online availability, executor honesty, and independent checkpoints.
- No unsupported claim of exactly-once execution, real TEE security, or novelty is made.

## 9. Current decision

**Proceed to E3 architecture freeze. Do not begin a real TEE implementation or ZK circuit yet.**

E2 supports choosing a hybrid architecture with online disjoint allocation and an offline trusted-state boundary as the candidate design. It does not establish that a particular commercial TEE/TPM/secure element can satisfy the required contract. That requires a separate platform feasibility check and, eventually, a real hardware experiment.
