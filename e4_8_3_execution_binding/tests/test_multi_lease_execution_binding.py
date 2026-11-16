from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import base64
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_GLOBAL_BUDGET_SOURCE = _REPOSITORY_ROOT / "e4_8_4_multi_lease_budget" / "src"
if str(_GLOBAL_BUDGET_SOURCE) not in sys.path:
    sys.path.insert(0, str(_GLOBAL_BUDGET_SOURCE))

from global_budget import (  # noqa: E402
    GlobalBudgetBroker,
    ToolPermission as GlobalToolPermission,
    issue_lease_grant as issue_global_lease_grant,
    issue_lease_revocation,
)
from src.execution_binding import (  # noqa: E402
    BudgetAllocationFailed,
    ExecutionBindingGateway,
    ExecutionIndeterminate,
    GrantRejected,
    InjectedCrash,
    SQLiteIdempotentTool,
    ToolPermission as ExecutionToolPermission,
    ToolRequest,
    canonical_json_bytes,
    context_hash,
    issue_lease_grant as issue_execution_lease_grant,
    schema_hash,
    verify_execution_receipt,
)
from src.global_budget_adapter import GlobalBudgetExecutionAdapter  # noqa: E402


class MultiLeaseExecutionBindingIntegrationTests(unittest.TestCase):
    NOW = 1_800_000_000
    GLOBAL_BUDGET_ID = "budget-epoch-integration"
    GLOBAL_QUOTA = 6
    GATEWAY_ID = "gateway-multi-lease"
    TOOL_NAME = "invoice_review"
    TOOL_SCHEMA = {
        "type": "object",
        "required": ["invoice_id", "decision"],
        "properties": {
            "invoice_id": {"type": "string"},
            "decision": {"enum": ["approve", "reject"]},
        },
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="d82-multi-lease-integration-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.issuer_private = Ed25519PrivateKey.generate()
        self.gateway_private = Ed25519PrivateKey.generate()
        self.now = [self.NOW]
        self.tool = self.make_tool()
        self.global_broker = self.make_global_broker()
        self.adapter = GlobalBudgetExecutionAdapter(
            global_broker=self.global_broker,
            issuer_public_key=self.issuer_private.public_key(),
        )

    def make_tool(self):
        return SQLiteIdempotentTool(
            tool_name=self.TOOL_NAME,
            schema=self.TOOL_SCHEMA,
            database_path=self.root / "tool-service.sqlite3",
        )

    def make_global_broker(self):
        return GlobalBudgetBroker(
            global_budget_id=self.GLOBAL_BUDGET_ID,
            global_quota_limit=self.GLOBAL_QUOTA,
            issuer_public_key=self.issuer_private.public_key(),
            journal_path=self.root / "global-journal.sqlite3",
            counter_state_path=self.root / "global-counter.json",
            broker_lock_path=self.root / "global-broker.lock",
            clock=lambda: self.now[0],
        )

    def context(self):
        return {"tenant_id": "tenant-A", "session_id": "session-global", "purpose": "invoice-review"}

    def make_global_grant(self, *, lease_id: str, subject_id: str, quota: int = 2):
        return issue_global_lease_grant(
            self.issuer_private,
            issuer_id="issuer-lab",
            grant_id=f"grant-{lease_id}",
            lease_id=lease_id,
            global_budget_id=self.GLOBAL_BUDGET_ID,
            nonce=f"nonce-{lease_id}",
            quota_limit=quota,
            issued_at=self.NOW - 60,
            expires_at=self.NOW + 3600,
            audience=self.GATEWAY_ID,
            subject_id=subject_id,
            context_digest=context_hash(self.context()),
            allowed_tools=(GlobalToolPermission(self.TOOL_NAME, schema_hash(self.TOOL_SCHEMA)),),
        )

    def make_execution_grant(self, global_grant, operation_id: str, *, subject_id: str | None = None):
        subject = global_grant.subject_id if subject_id is None else subject_id
        grant = issue_execution_lease_grant(
            self.issuer_private,
            issuer_id=global_grant.issuer_id,
            grant_id=global_grant.grant_id,
            lease_id=global_grant.lease_id,
            subject_id=subject,
            audience=global_grant.audience,
            context_digest=global_grant.context_digest,
            issued_at=global_grant.issued_at,
            expires_at=global_grant.expires_at,
            quota_limit=global_grant.quota_limit,
            nonce=global_grant.nonce,
            allowed_tools=(
                ExecutionToolPermission(self.TOOL_NAME, schema_hash(self.TOOL_SCHEMA)),
            ),
            parent_authorization_digest=hashlib.sha256(
                f"parent:{operation_id}".encode("utf-8")
            ).hexdigest(),
            parent_authorization_nonce=f"parent-nonce-{operation_id}",
            operation_id=operation_id,
        )
        return grant

    def bind_operation(self, global_grant, operation_id: str, *, subject_id: str | None = None):
        execution_grant = self.make_execution_grant(
            global_grant, operation_id, subject_id=subject_id
        )
        self.adapter.bind_lease(execution_grant, global_grant)
        return execution_grant

    def make_gateway(self, *, journal_name="execution-journal.sqlite3", lock_name="gateway.lock", tool=None):
        return ExecutionBindingGateway(
            issuer_public_key=self.issuer_private.public_key(),
            gateway_private_key=self.gateway_private,
            gateway_id=self.GATEWAY_ID,
            broker=self.adapter,
            journal_path=self.root / journal_name,
            lock_path=self.root / lock_name,
            tools={self.TOOL_NAME: self.tool if tool is None else tool},
            clock=lambda: self.now[0],
        )

    def request(self, execution_grant, operation_id: str):
        return ToolRequest(
            operation_id=operation_id,
            subject_id=execution_grant.subject_id,
            tool_name=self.TOOL_NAME,
            arguments={"invoice_id": f"INV-{operation_id}", "decision": "approve"},
            context=self.context(),
        )

    def test_two_leases_share_one_gateway_journal_and_global_counter(self):
        lease_a = self.make_global_grant(lease_id="lease-A", subject_id="agent-A", quota=2)
        lease_b = self.make_global_grant(lease_id="lease-B", subject_id="agent-B", quota=2)
        grants = [
            self.bind_operation(lease_a, "op-A1"),
            self.bind_operation(lease_a, "op-A2"),
            self.bind_operation(lease_b, "op-B1"),
        ]
        gateway = self.make_gateway()

        outcomes = [
            gateway.execute(grant, self.request(grant, grant.operation_id))
            for grant in grants
        ]
        payloads = [outcome.receipt["payload"] for outcome in outcomes]

        self.assertEqual([item["global_sequence"] for item in payloads], [1, 2, 3])
        self.assertEqual([item["budget_counter_value"] for item in payloads], [1, 2, 3])
        self.assertEqual([item["lease_used_count"] for item in payloads], [1, 2, 1])
        self.assertTrue(all(item["global_budget_id"] == self.GLOBAL_BUDGET_ID for item in payloads))
        self.assertTrue(all(verify_execution_receipt(o.receipt, gateway.gateway_public_key) for o in outcomes))

        state = self.global_broker.assert_invariants()
        self.assertEqual(state["reserved"], 4)
        self.assertEqual(state["used"], 3)
        self.assertEqual(state["counter_value"] - state["baseline_counter_value"], 3)
        leases = {row["lease_id"]: row for row in self.global_broker.inspect()["leases"]}
        self.assertEqual(leases["lease-A"]["used_count"], 2)
        self.assertEqual(leases["lease-B"]["used_count"], 1)

    def test_execution_and_global_grants_must_match_before_registration(self):
        global_grant = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        mismatched_execution_grant = self.make_execution_grant(
            global_grant, "op-mismatch", subject_id="agent-other"
        )
        with self.assertRaises(GrantRejected):
            self.adapter.bind_lease(mismatched_execution_grant, global_grant)
        self.assertEqual(self.global_broker.inspect()["reserved_total"], 0)
        self.assertEqual(self.global_broker.counter.read(), 0)

    def test_crash_after_global_allocation_recovers_same_sequence_and_receipt_metadata(self):
        global_grant = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        execution_grant = self.bind_operation(global_grant, "op-crash")
        gateway = self.make_gateway()
        request = self.request(execution_grant, "op-crash")

        with self.assertRaises(InjectedCrash):
            gateway.execute(execution_grant, request, crash_at="after_budget_allocation")
        self.assertEqual(self.global_broker.inspect()["used_total"], 1)

        restarted_adapter = GlobalBudgetExecutionAdapter(
            global_broker=self.global_broker,
            issuer_public_key=self.issuer_private.public_key(),
        )
        restarted_adapter.bind_lease(execution_grant, global_grant)
        restarted_tool = self.make_tool()
        restarted = ExecutionBindingGateway(
            issuer_public_key=self.issuer_private.public_key(),
            gateway_private_key=self.gateway_private,
            gateway_id=self.GATEWAY_ID,
            broker=restarted_adapter,
            journal_path=self.root / "execution-journal.sqlite3",
            lock_path=self.root / "gateway.lock",
            tools={self.TOOL_NAME: restarted_tool},
            clock=lambda: self.now[0],
        )
        outcome = restarted.execute(execution_grant, request)
        payload = outcome.receipt["payload"]

        self.assertEqual(payload["global_sequence"], 1)
        self.assertEqual(payload["lease_used_count"], 1)
        self.assertEqual(payload["global_lease_grant_digest"], global_grant.grant_digest)
        self.assertEqual(self.global_broker.counter.read(), 1)
        self.assertEqual(restarted_tool.effect_count(), 1)
        self.assertEqual(self.global_broker.inspect()["used_total"], 1)
        self.assertTrue(verify_execution_receipt(outcome.receipt, restarted.gateway_public_key))

    def test_revoked_global_lease_is_rejected_before_execution_journal_or_budget(self):
        global_grant = self.make_global_grant(lease_id="lease-revoked", subject_id="agent-R")
        execution_grant = self.bind_operation(global_grant, "op-revoked")
        revocation = issue_lease_revocation(
            self.issuer_private,
            issuer_id=global_grant.issuer_id,
            global_budget_id=self.GLOBAL_BUDGET_ID,
            revocation_id="revoke-lease-revoked",
            lease_id=global_grant.lease_id,
            grant_digest=global_grant.grant_digest,
            revoked_at=self.NOW,
        )
        self.global_broker.revoke_lease(revocation)
        gateway = self.make_gateway()

        with self.assertRaises(GrantRejected):
            gateway.execute(execution_grant, self.request(execution_grant, "op-revoked"))
        self.assertEqual(self.global_broker.counter.read(), 0)
        self.assertEqual(self.global_broker.inspect()["used_total"], 0)
        self.assertIsNone(gateway.journal.get("op-revoked"))

    def test_unbound_execution_grant_is_rejected_before_budget(self):
        global_grant = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        registered_grant = self.bind_operation(global_grant, "op-bound")
        unbound_grant = self.make_execution_grant(global_grant, "op-unbound")
        gateway = self.make_gateway()

        with self.assertRaises(GrantRejected):
            gateway.execute(unbound_grant, self.request(unbound_grant, "op-unbound"))
        self.assertEqual(self.global_broker.counter.read(), 0)
        self.assertIsNone(gateway.journal.get("op-unbound"))
        self.assertIsNotNone(registered_grant)

    def test_distinct_gateways_for_different_leases_share_unique_global_sequences(self):
        lease_a = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        lease_b = self.make_global_grant(lease_id="lease-B", subject_id="agent-B")
        grant_a = self.bind_operation(lease_a, "op-concurrent-A")
        grant_b = self.bind_operation(lease_b, "op-concurrent-B")
        gateway_a = self.make_gateway(journal_name="execution-A.sqlite3", lock_name="gateway-A.lock")
        gateway_b = self.make_gateway(journal_name="execution-B.sqlite3", lock_name="gateway-B.lock")

        def run(gateway, grant, op):
            return gateway.execute(grant, self.request(grant, op))

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run, gateway_a, grant_a, "op-concurrent-A")
            second = pool.submit(run, gateway_b, grant_b, "op-concurrent-B")
            outcomes = [first.result(timeout=20), second.result(timeout=20)]

        sequences = sorted(item.receipt["payload"]["global_sequence"] for item in outcomes)
        self.assertEqual(sequences, [1, 2])
        self.assertEqual(self.global_broker.inspect()["used_total"], 2)
        self.assertEqual(self.global_broker.assert_invariants()["used"], 2)
        self.assertTrue(all(verify_execution_receipt(o.receipt, gateway_a.gateway_public_key) for o in outcomes))

    def test_gateway_and_global_broker_must_trust_the_same_issuer_key(self):
        global_grant = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        execution_grant = self.bind_operation(global_grant, "op-issuer-mismatch")
        other_issuer = Ed25519PrivateKey.generate()
        alternate_signature = base64.b64encode(
            other_issuer.sign(canonical_json_bytes(execution_grant.unsigned_dict()))
        ).decode("ascii")
        forged_same_payload = replace(execution_grant, signature_b64=alternate_signature)
        gateway = ExecutionBindingGateway(
            issuer_public_key=other_issuer.public_key(),
            gateway_private_key=self.gateway_private,
            gateway_id=self.GATEWAY_ID,
            broker=self.adapter,
            journal_path=self.root / "execution-journal-wrong-issuer.sqlite3",
            lock_path=self.root / "gateway-wrong-issuer.lock",
            tools={self.TOOL_NAME: self.tool},
            clock=lambda: self.now[0],
        )

        with self.assertRaises(GrantRejected):
            gateway.execute(
                forged_same_payload,
                self.request(forged_same_payload, "op-issuer-mismatch"),
            )
        self.assertEqual(self.global_broker.counter.read(), 0)
        self.assertIsNone(gateway.journal.get("op-issuer-mismatch"))

    def test_global_metadata_tampering_invalidates_gateway_signature(self):
        global_grant = self.make_global_grant(lease_id="lease-A", subject_id="agent-A")
        execution_grant = self.bind_operation(global_grant, "op-tamper")
        gateway = self.make_gateway()
        outcome = gateway.execute(execution_grant, self.request(execution_grant, "op-tamper"))
        tampered = {
            "payload": dict(outcome.receipt["payload"]),
            "signature_b64": outcome.receipt["signature_b64"],
        }
        tampered["payload"]["global_budget_id"] = "budget-epoch-substituted"
        self.assertFalse(verify_execution_receipt(tampered, gateway.gateway_public_key))


if __name__ == "__main__":
    unittest.main(verbosity=2)
