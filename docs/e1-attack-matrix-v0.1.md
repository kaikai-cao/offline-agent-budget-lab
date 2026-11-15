# E1 Attack Experiments v0.1 (pre-E1.1 baseline)

> Historical baseline report. E1-04 was remediated in E1.1; see `e1.1-executor-trust-binding.md` for the current verifier behavior.

**Status:** executable attack tests added; outcomes are local simulation results, not a production security proof.

## Scope

E1 evaluates the E0.1–E0.4 software-only baseline. It does not add code to the production modules. Tests use a MockTool effect counter that is independent of the ledger's claimed operation count.

Fixed setup: root budget 10; leases A/B/C = 4/3/3; one query costs one unit; Ed25519 signatures; SHA-256 digests; in-memory issuer, ledger and receipt chain.

## Attack matrix

| ID | Attack | Test observation | Classification |
|---|---|---|---|
| E1-01 | Sequential operation replay in one ledger instance | Duplicate operation ID rejected before MockTool effect; one actual effect | PREVENTED (within one in-memory ledger instance) |
| E1-02 | Clone one lease + ledger state + executor key into two offline branches | Both branches independently spend 3 from the same 4-unit lease; both chains verify locally; submitting both bundles is rejected as duplicate lease bundle | Local double-spend reproduced; duplicate bundle DETECTED at reconciliation when both branches are submitted |
| E1-03 | Reconstruct ledger from same lease to simulate rollback/reset | Reconstructed ledger starts with full allocation; each instance spends 3; both bundles together rejected | Rollback/reset reproduced; duplicate branch DETECTED when both are submitted |
| E1-04 | Use a receipt-signing key unrelated to lease holder key | Reconciler accepts a valid bundle whose executor key differs from `lease.holder_public_key` | MISSED by current E0 verifier; key-binding gap |
| E1-05 | Fork issuer in-memory state while reusing same root signing key and root ID | Two Issuer instances each allocate 7 from a nominal 10 budget; both leases have valid issuer signatures; aggregate allocation is 14 | Issuer-state rollback/fork reproduced; no shared durable allocation registry |
| E1-06 | Submit a valid receipt-chain prefix | Prefix verifies internally, but reconciliation rejects it against the independent full-chain head and ledger | DETECTED with trusted head; prefix alone is insufficient |

## Important interpretation limits

1. E1-02 and E1-03 demonstrate independent local state instances can each accept spending against the same signed lease. The reconciler rejects duplicate lease bundles if both branches are submitted. It does not prove that an out-of-band checkpoint registry is implemented or that it can discover every fork.
2. `TrustedChainHead` is an input data object. The current library does not authenticate who supplied it. Its trustworthiness is an external assumption.
3. E1-04 is a concrete verifier gap: lease issuance records `holder_public_key`, but E0 receipt verification accepts the executor public key supplied by the evidence bundle and does not compare it with the lease holder key or another pre-registered executor key. A deployment may pin an executor key out-of-band, but that behavior is not implemented in this baseline.
4. E1-05 simulates restoring/forking an issuer with the same signing key and root identity but empty volatile allocation state. It assumes the attacker can obtain a second active issuer instance or restore a snapshot containing the signing key.
5. These tests establish behavior of this Python implementation under the described harness. They are not independent statistical attack repetitions, a formal proof, or evidence of actual TEE behavior.

## E1 decision gate

Before any ZK integration, resolve or explicitly scope:

- Trusted binding between lease holder identity and the key authorized to sign execution receipts.
- How one lease is guaranteed to have one authoritative consumption state / chain lineage across offline copies.
- Durable issuer allocation state or an explicit one-issuer/one-state trust assumption.
- How trusted chain-head checkpoints are produced, authenticated, and made rollback-resistant.

Do not describe a detected attack as prevented. Do not claim global offline double-spend prevention from local locks, signatures, hash chains, or ZK alone.
