from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
    context_hash,
    issue_lease_grant as issue_execution_lease_grant,
    schema_hash,
    verify_execution_receipt,
)
from src.global_budget_adapter import GlobalBudgetExecutionAdapter  # noqa: E402


class MultiLeaseAdversarialTests(unittest.TestCase):
    """D8.3 attack-oriented checks at the Gateway / shared-Broker boundary."""

    NOW = 1_800_000_000
    GLOBAL_BUDGET_ID = "budget-epoch-d83"
    GLOBAL_QUOTA = 8
    GATEWAY_ID = "gateway-d83"
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
        self.tmp = tempfile.TemporaryDirectory(prefix="d83-multi-lease-adversarial-")
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
        return {
            "tenant_id": "tenant-d83",
            "session_id": "session-adversarial",
            "purpose": "invoice-review",
        }

    def make_global_grant(self, *, lease_id: str, subject_id: str, quota: int = 2):
        return issue_global_lease_grant(
            self.issuer_private,
            issuer_id="issuer-d83",
            grant_id=f"grant-{lease_id}",
            lease_id=lease_id,
            global_budget_id=self.GLOBAL_BUDGET_ID,
            nonce=f"nonce-{lease_id}",
            quota_limit=quota,
            issued_at=self.NOW - 60,
            expires_at=self.NOW + 300,
            audience=self.GATEWAY_ID,
            subject_id=subject_id,
            context_digest=context_hash(self.context()),
            allowed_tools=(
                GlobalToolPermission(self.TOOL_NAME, schema_hash(self.TOOL_SCHEMA)),
            ),
        )

    def make_execution_grant(self, global_grant, operation_id: str):
        return issue_execution_lease_grant(
            self.issuer_private,
            issuer_id=global_grant.issuer_id,
            grant_id=global_grant.grant_id,
            lease_id=global_grant.lease_id,
            subject_id=global_grant.subject_id,
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
                f"parent:{global_grant.lease_id}:{operation_id}".encode("utf-8")
            ).hexdigest(),
            parent_authorization_nonce=f"parent-nonce:{global_grant.lease_id}:{operation_id}",
            operation_id=operation_id,
        )

    def bind_operation(self, global_grant, operation_id: str):
        execution_grant = self.make_execution_grant(global_grant, operation_id)
        self.adapter.bind_lease(execution_grant, global_grant)
        return execution_grant

    def make_gateway(
        self,
        *,
        journal_name: str = "execution-journal.sqlite3",
        lock_name: str = "gateway.lock",
        adapter=None,
        tool=None,
        gateway_private_key=None,
    ):
        return ExecutionBindingGateway(
            issuer_public_key=self.issuer_private.public_key(),
            gateway_private_key=gateway_private_key or self.gateway_private,
            gateway_id=self.GATEWAY_ID,
            broker=adapter or self.adapter,
            journal_path=self.root / journal_name,
            lock_path=self.root / lock_name,
            tools={self.TOOL_NAME: tool or self.tool},
            clock=lambda: self.now[0],
        )

    def request(self, grant, *, invoice_id: str | None = None):
        return ToolRequest(
            operation_id=grant.operation_id,
            subject_id=grant.subject_id,
            tool_name=self.TOOL_NAME,
            arguments={
                "invoice_id": invoice_id or f"INV-{grant.lease_id}-{grant.operation_id}",
                "decision": "approve",
            },
            context=self.context(),
        )

    def test_normal_completion_persists_global_metadata_and_survives_gateway_restart(self):
        global_grant = self.make_global_grant(lease_id="lease-metadata", subject_id="agent-metadata")
        execution_grant = self.bind_operation(global_grant, "op-metadata")
        request = self.request(execution_grant)
        gateway = self.make_gateway()

        first = gateway.execute(execution_grant, request)
        row = gateway.journal.get("op-metadata")
        payload = first.receipt["payload"]
        self.assertEqual(row["status"], "COMMITTED")
        self.assertEqual(row["global_budget_id"], self.GLOBAL_BUDGET_ID)
        self.assertEqual(row["global_lease_grant_digest"], global_grant.grant_digest)
        self.assertEqual(row["global_sequence"], payload["global_sequence"])
        self.assertEqual(row["lease_used_count"], 1)

        restarted_adapter = GlobalBudgetExecutionAdapter(
            global_broker=self.global_broker,
            issuer_public_key=self.issuer_private.public_key(),
        )
        restarted_adapter.bind_lease(execution_grant, global_grant)
        restarted_gateway = self.make_gateway(
            adapter=restarted_adapter,
            tool=self.make_tool(),
        )
        replay = restarted_gateway.execute(execution_grant, request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, first.receipt)
        self.assertTrue(verify_execution_receipt(replay.receipt, restarted_gateway.gateway_public_key))
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(self.global_broker.counter.read(), 1)
        self.global_broker.assert_invariants()

    def test_same_operation_id_raced_across_two_leases_cannot_charge_twice(self):
        global_a = self.make_global_grant(lease_id="lease-race-A", subject_id="agent-A")
        global_b = self.make_global_grant(lease_id="lease-race-B", subject_id="agent-B")
        grant_a = self.bind_operation(global_a, "op-global-collision")
        grant_b = self.bind_operation(global_b, "op-global-collision")
        gateway_a = self.make_gateway(journal_name="exec-A.sqlite3", lock_name="gateway-A.lock")
        gateway_b = self.make_gateway(journal_name="exec-B.sqlite3", lock_name="gateway-B.lock")

        def run(gateway, grant):
            try:
                return gateway.execute(grant, self.request(grant))
            except Exception as exc:  # collect both race outcomes for deterministic assertions
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(run, gateway_a, grant_a),
                pool.submit(run, gateway_b, grant_b),
            ]
            outcomes = [future.result(timeout=30) for future in futures]

        successes = [item for item in outcomes if not isinstance(item, Exception)]
        failures = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(successes), 1, repr(outcomes))
        self.assertEqual(len(failures), 1, repr(outcomes))
        self.assertIsInstance(failures[0], ExecutionIndeterminate)
        self.assertEqual(self.global_broker.counter.read(), 1)
        self.assertEqual(self.global_broker.inspect()["used_total"], 1)
        self.assertEqual(self.tool.effect_count(), 1)
        self.global_broker.assert_invariants()

    def test_exhausted_lease_does_not_block_another_lease(self):
        global_a = self.make_global_grant(lease_id="lease-small-A", subject_id="agent-A", quota=1)
        global_b = self.make_global_grant(lease_id="lease-small-B", subject_id="agent-B", quota=1)
        grant_a1 = self.bind_operation(global_a, "op-A1")
        grant_a2 = self.bind_operation(global_a, "op-A2")
        grant_b = self.bind_operation(global_b, "op-B1")
        gateway = self.make_gateway()

        first_a = gateway.execute(grant_a1, self.request(grant_a1))
        with self.assertRaises(BudgetAllocationFailed):
            gateway.execute(grant_a2, self.request(grant_a2))
        first_b = gateway.execute(grant_b, self.request(grant_b))

        self.assertEqual(first_a.receipt["payload"]["global_sequence"], 1)
        self.assertEqual(first_b.receipt["payload"]["global_sequence"], 2)
        leases = {row["lease_id"]: row for row in self.global_broker.inspect()["leases"]}
        self.assertEqual(leases["lease-small-A"]["used_count"], 1)
        self.assertEqual(leases["lease-small-B"]["used_count"], 1)
        self.assertEqual(self.global_broker.inspect()["used_total"], 2)
        self.assertEqual(self.tool.effect_count(), 2)
        self.global_broker.assert_invariants()

    def test_recovery_of_committed_budget_operation_after_revocation_and_expiry(self):
        global_grant = self.make_global_grant(
            lease_id="lease-recovery", subject_id="agent-recovery", quota=2
        )
        execution_grant = self.bind_operation(global_grant, "op-recovery-revoked-expired")
        request = self.request(execution_grant)
        gateway = self.make_gateway(journal_name="execution-recovery.sqlite3", lock_name="gateway-recovery.lock")

        with self.assertRaises(InjectedCrash):
            gateway.execute(execution_grant, request, crash_at="after_budget_allocation")
        gateway_row = gateway.journal.get(execution_grant.operation_id)
        self.assertEqual(gateway_row["status"], "ALLOCATING")
        self.assertIsNone(gateway_row["global_sequence"])
        broker_operation = self.global_broker.journal.get_operation(execution_grant.operation_id)
        self.assertEqual(broker_operation["status"], "COMMITTED")

        revocation = issue_lease_revocation(
            self.issuer_private,
            issuer_id=global_grant.issuer_id,
            global_budget_id=self.GLOBAL_BUDGET_ID,
            revocation_id="revoke-lease-recovery",
            lease_id=global_grant.lease_id,
            grant_digest=global_grant.grant_digest,
            revoked_at=self.now[0],
        )
        self.global_broker.revoke_lease(revocation)
        self.now[0] = global_grant.expires_at + 1

        # Simulate process restart: reconstruct the broker/adapter over the same durable files.
        restarted_broker = self.make_global_broker()
        restarted_adapter = GlobalBudgetExecutionAdapter(
            global_broker=restarted_broker,
            issuer_public_key=self.issuer_private.public_key(),
        )
        restarted_adapter.bind_lease(execution_grant, global_grant)
        restarted_gateway = self.make_gateway(
            journal_name="execution-recovery.sqlite3",
            lock_name="gateway-recovery.lock",
            adapter=restarted_adapter,
            tool=self.make_tool(),
        )

        recovered = restarted_gateway.execute(execution_grant, request)
        payload = recovered.receipt["payload"]
        self.assertEqual(payload["global_sequence"], 1)
        self.assertEqual(payload["lease_used_count"], 1)
        self.assertEqual(payload["global_lease_grant_digest"], global_grant.grant_digest)
        self.assertTrue(verify_execution_receipt(recovered.receipt, restarted_gateway.gateway_public_key))
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(restarted_broker.counter.read(), 1)

        replay = restarted_gateway.execute(execution_grant, request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, recovered.receipt)
        self.assertEqual(self.tool.effect_count(), 1)
        restarted_broker.assert_invariants()


if __name__ == "__main__":
    unittest.main(verbosity=2)
