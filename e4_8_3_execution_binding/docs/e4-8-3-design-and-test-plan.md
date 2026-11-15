# E4.8.3 — Lease Grant / Budget / Tool Execution / Receipt Binding

**Scope:** software-only protocol and recovery model. No real TPM, TBS, IEE repository, or external production tool is contacted.

## 1. Research question

E4.8.1 established that `NV_Increment` and `NV_Read` are separate commands and that a caller cannot safely treat the subsequent read value as an invocation-specific return value under unconstrained concurrency. E4.8.2 added a durable, host-local, cross-process single-writer Broker. E4.8.3 asks the next question:

> After the Broker assigns a budget sequence, how can an authorization decision and a specific Agent tool effect be bound to that exact sequence, request, tool schema, context, and durable execution receipt?

The model must also state what happens when the tool effect happens but receipt persistence does not.

## 2. Protocol objects and trust inputs

### 2.1 Signed Lease Grant

The Issuer signs a canonical JSON payload using Ed25519. The signed fields are:

- `issuer_id`, `grant_id`, `lease_id`;
- `subject_id`, `audience` (the intended Gateway);
- `context_digest`;
- `issued_at`, `expires_at`, `quota_limit`, `nonce`;
- permitted tool names and their exact `schema_hash` values.

The Gateway receives the Issuer public key from its trusted configuration. A grant cannot select its own verification key. Any modification to the signed payload invalidates the signature.

### 2.2 Tool Schema and request digest

The Gateway obtains `schema_hash` from the registered trusted Tool Adapter. It does not accept a caller-supplied hash. The grant must authorize the exact adapter hash currently loaded by the Gateway.

The request digest covers the canonical representation of:

```text
version
Gateway audience
Grant Digest (which covers quota, expiry, permission set, subject, context, etc.)
grant_id / lease_id / subject_id
context_digest
operation_id
tool_name
trusted adapter schema_hash
arguments
```

This prevents a caller from reusing an Operation ID while changing its arguments, context, tool name, schema version, or Grant. Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects NaN/Infinity.

### 2.3 Budget receipt and execution receipt

E4.8.2 `DurableCounterBroker.consume()` assigns a durable `counter_value` for the exact `(operation_id, request_digest, lease_id)` binding. The Gateway then produces a signed execution receipt that covers:

- issuer / grant / lease / subject / audience;
- context digest;
- operation ID, tool name, schema hash, request digest;
- allocated counter value;
- result digest and result payload;
- completion timestamp and Gateway identity.

The receipt is signed by the Gateway Ed25519 key. The verifier must obtain the Gateway public key through a trusted channel. The receipt is a Gateway attestation over the modeled flow; it is not a direct TPM quote or proof that a physical TPM executed a particular command.

## 3. End-to-end sequence

1. Gateway verifies the Issuer signature, grant validity interval, audience, subject, context, tool allowlist, actual adapter schema hash, and that the Grant's lease/quota match the configured single-lease Broker.
2. Gateway computes the canonical request digest.
3. Gateway acquires its cross-process lock. It refuses a new operation while a different operation remains unresolved.
4. Gateway durably stores `ALLOCATING` before calling the Broker.
5. Durable Broker consumes one sequence for `(operation_id, request_digest)`. Retrying the same tuple returns the original durable Broker receipt and does not increment again.
6. Gateway stores `BUDGET_CONSUMED`, then durably stores `DISPATCHING` before calling the tool.
7. Gateway calls the trusted adapter with the exact `operation_id` and request digest.
8. After success, Gateway signs the execution receipt and commits it to the execution journal.
9. Replays of the same operation return the exact stored receipt. Rebinding the operation ID to different content is rejected.

## 4. State machine and recovery

```text
ALLOCATING -> BUDGET_CONSUMED -> DISPATCHING -> COMMITTED
     |                |                |
     v                v                v
FAILED_NO_BUDGET   (resume)       COMMITTED or INDETERMINATE
```

### Crash windows

| Crash point | Durable state / external observation | Recovery rule |
|---|---|---|
| After Broker allocated, before Gateway journal update | Gateway row `ALLOCATING`; Broker already has receipt | Re-call Broker with same Operation ID + digest; it returns the existing sequence, not a second increment |
| After `BUDGET_CONSUMED`, before dispatch marker | No `DISPATCHING` record | Same operation may safely enter dispatch; budget is not allocated again |
| After `DISPATCHING`, before tool invocation | It is indistinguishable after restart from a crash after the tool started | Require durable adapter lookup or adapter-enforced Operation ID idempotency; otherwise mark `INDETERMINATE` |
| After tool effect, before Gateway receipt | Gateway row is `DISPATCHING` | Positive adapter lookup recovers result; idempotent adapter may safely retry same key; non-idempotent adapter fails closed as `INDETERMINATE` |
| After receipt commit | Gateway row `COMMITTED` | Return same signed receipt, without Broker increment or tool invocation |

### Why `operation_id` idempotency must live at the tool boundary

A Gateway database cannot roll back an external side effect. It also cannot infer whether a tool call happened merely because the Gateway process crashed after writing `DISPATCHING`. A real tool/service must atomically persist the idempotency key with its effect, or expose an authoritative status query. Otherwise exactly-once effects are not established. The only safe generic behavior is to stop and mark the operation `INDETERMINATE`.

## 5. Failure and denial semantics

- Invalid signature, expired/not-yet-valid grant, wrong audience, wrong subject, wrong context, disallowed tool, schema drift, or Lease/Quota mismatch: reject before consuming budget.
- Reused Operation ID with different content: `OperationBindingConflict`.
- Broker confirms quota exhausted or no increment applied: `FAILED_NO_BUDGET`; use a new Operation ID for a new attempt.
- Broker anchor mismatch or uncertain counter recovery: `INDETERMINATE`.
- Tool is non-idempotent and a prior `DISPATCHING` state has no positive durable lookup: `INDETERMINATE`; never invoke again automatically.
- A different operation is requested while one is unresolved: `GatewayBusy`.

Budget is consumed before tool execution. This avoids unbudgeted execution but can burn quota when the tool fails or a crash leaves an unresolved operation.

## 6. Threat model

### Modeled and tested

- Caller cannot self-select Issuer verification key.
- Grant field tampering / expired grants are rejected.
- Caller cannot substitute context, subject, tool, schema or arguments without changing the bound digest or failing grant checks.
- Duplicate operation requests do not allocate a second budget sequence or create a second test-tool effect.
- Cross-process duplicate requests share one durable execution receipt under the same lock/journal domain.
- Tool effect + Gateway crash is recoverable only when the tool provides a durable lookup or an enforced idempotency key.

### Not defended by this model

- Compromised Gateway process, Issuer, OS kernel or local administrator.
- Theft/replacement of Issuer/Gateway private keys.
- Rollback or malicious replacement of all SQLite files, counter emulator files, executable code and key state.
- Multiple hosts, cloned hosts, distributed lock service failure, or multi-lease quota sharding.
- A real TPM NV command's transport ambiguity, TPM authorization policy, physical hardware state, or direct TPM attestation.
- External tool systems that falsely claim idempotency or return stale/incorrect lookup results.
- Data confidentiality: the toy Tool service stores JSON result payloads in SQLite without encryption.
- Exactly-once external effects for a non-idempotent tool.

## 7. Claim boundaries

E4.8.3 can support a model-level claim that a signed grant and a durable budget allocation can be cryptographically bound to an exact tool request and a Gateway-signed execution receipt, under the stated trusted Gateway/Broker/adapter assumptions.

It does **not** prove that the real TPM is the exclusive counter writer, that the Gateway is isolated from untrusted local code, that an arbitrary tool is exactly-once, or that the model resists a privileged attacker. The counter used by this test package is the E4.8.2 JSON-file emulator.

## 8. Local acceptance checklist

- [ ] Install/verify `cryptography` in the Python interpreter used for testing.
- [ ] Run `python -m unittest discover -s tests -v` on Windows.
- [ ] Expect 20 tests to pass, including the independent-process duplicate operation test.
- [ ] Verify the package does not call TBS / TPM APIs and does not edit E4.7.3 or IEE.
- [ ] Review and preserve the exact Python version and test output for the stage log.

Passing this package's tests is local model validation, not a security proof or hardware validation.
