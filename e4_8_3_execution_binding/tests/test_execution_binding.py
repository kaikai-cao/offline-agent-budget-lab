from __future__ import annotations

from dataclasses import replace
import json
import os
import sqlite3
from contextlib import closing
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from src.durable_broker import DurableCounterBroker, OperationBindingConflict
from src.execution_binding import (
    BudgetAllocationFailed,
    ExecutionBindingGateway,
    ExecutionIndeterminate,
    ExecutionJournal,
    GatewayBusy,
    GrantRejected,
    LeaseGrant,
    InjectedCrash,
    ParentAuthorizationReplay,
    SQLiteIdempotentTool,
    ToolAdapter,
    ToolPermission,
    ToolRequest,
    context_hash,
    issue_lease_grant,
    schema_hash,
    verify_execution_receipt,
    verify_lease_grant,
)


class NonIdempotentTool(ToolAdapter):
    def __init__(self) -> None:
        self.tool_name = "send_message"
        self.schema_hash = schema_hash({"type": "object", "required": ["recipient", "body"]})
        self.idempotent_by_operation_id = False
        self.effects = 0

    def execute(self, *, operation_id, request_digest, arguments, context):
        self.effects += 1
        return {"sent": True, "effect_number": self.effects, "recipient": arguments["recipient"]}

    def lookup(self, *, operation_id, request_digest):
        # This adapter models a service with no durable status/idempotency API.
        return None




class D63ScriptedLookupTool(NonIdempotentTool):
    """Test adapter with a caller-controlled provider lookup response."""

    def __init__(
        self,
        *,
        status,
        authoritative=False,
        declares_authoritative=False,
        supports_idempotency_key=False,
        result=None,
    ):
        super().__init__()
        from src.execution_binding import (
            ToolCapabilities,
            ToolLookupResult,
        )

        self._status = status
        self._authoritative = authoritative
        self._declares_authoritative = declares_authoritative
        self._supports_idempotency_key = supports_idempotency_key
        self._lookup_result = result
        self._ToolCapabilities = ToolCapabilities
        self._ToolLookupResult = ToolLookupResult

    @property
    def capabilities(self):
        return self._ToolCapabilities(
            naturally_idempotent=False,
            supports_idempotency_key=self._supports_idempotency_key,
            supports_authoritative_lookup=self._declares_authoritative,
        )

    def lookup(self, *, operation_id, request_digest):
        return self._ToolLookupResult(
            status=self._status,
            operation_id=operation_id,
            request_digest=request_digest,
            result=self._lookup_result,
            authoritative=self._authoritative,
        )

class ExecutionBindingTests(unittest.TestCase):
    NOW = 1_800_000_000
    CONTEXT = {"tenant_id": "tenant-A", "session_id": "session-9", "purpose": "invoice-review"}
    TOOL_SCHEMA = {
        "type": "object",
        "required": ["invoice_id", "decision"],
        "properties": {
            "invoice_id": {"type": "string"},
            "decision": {"enum": ["approve", "reject"]},
        },
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.issuer_private = Ed25519PrivateKey.generate()
        self.gateway_private = Ed25519PrivateKey.generate()
        self.tool = SQLiteIdempotentTool(
            tool_name="invoice_review",
            schema=self.TOOL_SCHEMA,
            database_path=self.root / "tool-service.sqlite3",
        )
        self.grant = self.make_grant(quota=5)
        self.request = ToolRequest(
            operation_id="op-001",
            subject_id="agent-17",
            tool_name="invoice_review",
            arguments={"invoice_id": "INV-2048", "decision": "approve"},
            context=dict(self.CONTEXT),
        )
        self.gateway = self.make_gateway(self.tool, quota=5)

    def tearDown(self):
        self.tmp.cleanup()

    def make_grant(self, *, quota: int, allowed_tool_name: str = "invoice_review",
                   allowed_schema_hash: str | None = None):
        if allowed_schema_hash is None:
            if allowed_tool_name == "invoice_review":
                allowed_schema_hash = schema_hash(self.TOOL_SCHEMA)
            else:
                allowed_schema_hash = schema_hash({"type": "object", "properties": {}})
        return issue_lease_grant(
            self.issuer_private,
            issuer_id="issuer-lab",
            grant_id="grant-2026-001",
            lease_id="lease-offline-17",
            subject_id="agent-17",
            audience="gateway-lab-1",
            context_digest=context_hash(self.CONTEXT),
            issued_at=self.NOW - 60,
            expires_at=self.NOW + 3600,
            quota_limit=quota,
            nonce="nonce-unique-001",
            allowed_tools=(ToolPermission(allowed_tool_name, allowed_schema_hash),),
        )

    def make_gateway(self, tool, *, quota: int = 5):
        broker = DurableCounterBroker(
            journal_path=self.root / "budget-journal.sqlite3",
            counter_state_path=self.root / "counter.json",
            broker_lock_path=self.root / "broker.lock",
            lease_id="lease-offline-17",
            quota_limit=quota,
        )
        return ExecutionBindingGateway(
            issuer_public_key=self.issuer_private.public_key(),
            gateway_private_key=self.gateway_private,
            gateway_id="gateway-lab-1",
            broker=broker,
            journal_path=self.root / "execution-journal.sqlite3",
            lock_path=self.root / "gateway.lock",
            tools={tool.tool_name: tool},
            clock=lambda: self.NOW,
        )

    def counter_value(self):
        return self.gateway.broker.counter.read()

    def make_integrated_grant(self, operation_id: str, parent_nonce: str,
                              parent_digest: str = "a" * 64):
        return issue_lease_grant(
            self.issuer_private,
            issuer_id="issuer-lab",
            grant_id=f"grant-{operation_id}",
            lease_id="lease-offline-17",
            subject_id="agent-17",
            audience="gateway-lab-1",
            context_digest=context_hash(self.CONTEXT),
            issued_at=self.NOW - 60,
            expires_at=self.NOW + 3600,
            quota_limit=5,
            nonce=f"lease-{operation_id}",
            allowed_tools=(ToolPermission("invoice_review", schema_hash(self.TOOL_SCHEMA)),),
            parent_authorization_digest=parent_digest,
            parent_authorization_nonce=parent_nonce,
            operation_id=operation_id,
        )

    def test_integrated_grant_binds_operation_id_and_parent_authorization(self):
        grant = self.make_integrated_grant("op-001", "parent-nonce-A")
        outcome = self.gateway.execute(grant, self.request)
        payload = outcome.receipt["payload"]
        self.assertEqual(payload["parent_authorization_digest"], "a" * 64)
        self.assertEqual(payload["parent_authorization_nonce"], "parent-nonce-A")
        self.assertEqual(payload["operation_id"], "op-001")

    def test_integrated_grant_rejects_operation_id_substitution_before_budget(self):
        grant = self.make_integrated_grant("op-authorized", "parent-nonce-B")
        substituted = ToolRequest(
            operation_id="op-substituted",
            subject_id=self.request.subject_id,
            tool_name=self.request.tool_name,
            arguments=dict(self.request.arguments),
            context=dict(self.request.context),
        )
        with self.assertRaises(GrantRejected):
            self.gateway.execute(grant, substituted)
        self.assertEqual(self.tool.effect_count(), 0)
        self.assertEqual(self.gateway.broker.counter.read(), 0)

    def test_parent_authorization_digest_cannot_bind_second_operation(self):
        first_grant = self.make_integrated_grant("op-digest-1", "parent-nonce-D")
        first_request = ToolRequest(
            operation_id="op-digest-1",
            subject_id=self.request.subject_id,
            tool_name=self.request.tool_name,
            arguments=dict(self.request.arguments),
            context=dict(self.request.context),
        )
        self.gateway.execute(first_grant, first_request)

        # Re-sign with a different lease nonce but the same parent authorization digest.
        second_grant = issue_lease_grant(
            self.issuer_private,
            issuer_id="issuer-lab",
            grant_id="grant-op-digest-2",
            lease_id="lease-offline-17",
            subject_id="agent-17",
            audience="gateway-lab-1",
            context_digest=context_hash(self.CONTEXT),
            issued_at=self.NOW - 60,
            expires_at=self.NOW + 3600,
            quota_limit=5,
            nonce="lease-op-digest-2",
            allowed_tools=(ToolPermission("invoice_review", schema_hash(self.TOOL_SCHEMA)),),
            parent_authorization_digest="a" * 64,
            parent_authorization_nonce="different-parent-nonce",
            operation_id="op-digest-2",
        )
        second_request = ToolRequest(
            operation_id="op-digest-2",
            subject_id=self.request.subject_id,
            tool_name=self.request.tool_name,
            arguments=dict(self.request.arguments),
            context=dict(self.request.context),
        )
        with self.assertRaises(ParentAuthorizationReplay):
            self.gateway.execute(second_grant, second_request)
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(self.gateway.broker.counter.read(), 1)

    def test_parent_authorization_nonce_cannot_bind_second_operation(self):
        first_grant = self.make_integrated_grant("op-parent-1", "parent-nonce-C")
        first_request = ToolRequest(
            operation_id="op-parent-1",
            subject_id=self.request.subject_id,
            tool_name=self.request.tool_name,
            arguments=dict(self.request.arguments),
            context=dict(self.request.context),
        )
        self.gateway.execute(first_grant, first_request)

        second_grant = self.make_integrated_grant("op-parent-2", "parent-nonce-C")
        second_request = ToolRequest(
            operation_id="op-parent-2",
            subject_id=self.request.subject_id,
            tool_name=self.request.tool_name,
            arguments=dict(self.request.arguments),
            context=dict(self.request.context),
        )
        with self.assertRaises(ParentAuthorizationReplay):
            self.gateway.execute(second_grant, second_request)
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(self.gateway.broker.counter.read(), 1)

    def test_execution_journal_additive_migration_preserves_legacy_rows(self):
        legacy_path = self.root / "legacy-executions.sqlite3"
        with closing(sqlite3.connect(legacy_path)) as con, con:
            con.execute(
                "CREATE TABLE executions ("
                "operation_id TEXT PRIMARY KEY, grant_digest TEXT NOT NULL, "
                "grant_id TEXT NOT NULL, lease_id TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "tool_name TEXT NOT NULL, schema_hash TEXT NOT NULL, context_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL, budget_counter_value INTEGER, "
                "receipt_json TEXT, updated_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )
            con.execute(
                "INSERT INTO executions(operation_id,grant_digest,grant_id,lease_id,subject_id,"
                "tool_name,schema_hash,context_digest,request_digest,status) "
                "VALUES('legacy-op','gd','g','l','s','t','sh','cd','rd','COMMITTED')"
            )
        journal = ExecutionJournal(legacy_path)
        row = journal.get("legacy-op")
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "COMMITTED")
        self.assertEqual(row["parent_authorization_digest"], "")
        self.assertEqual(row["parent_authorization_nonce"], "")

    def test_lease_grant_v1_and_v2_round_trip(self):
        legacy = LeaseGrant.from_dict(self.grant.to_dict())
        verify_lease_grant(legacy, self.issuer_private.public_key())
        self.assertEqual(legacy.version, 1)
        self.assertEqual(legacy.parent_authorization_digest, "")

        integrated = self.make_integrated_grant("op-roundtrip", "parent-roundtrip")
        restored = LeaseGrant.from_dict(integrated.to_dict())
        verify_lease_grant(restored, self.issuer_private.public_key())
        self.assertEqual(restored.version, 2)
        self.assertEqual(restored.parent_authorization_digest, "a" * 64)
        self.assertEqual(restored.parent_authorization_nonce, "parent-roundtrip")
        self.assertEqual(restored.operation_id, "op-roundtrip")

    def test_valid_grant_executes_and_receipt_binds_all_required_fields(self):
        outcome = self.gateway.execute(self.grant, self.request)
        payload = outcome.receipt["payload"]
        self.assertEqual(payload["lease_id"], self.grant.lease_id)
        self.assertEqual(payload["grant_id"], self.grant.grant_id)
        self.assertEqual(payload["subject_id"], self.grant.subject_id)
        self.assertEqual(payload["operation_id"], self.request.operation_id)
        self.assertEqual(payload["tool_name"], self.request.tool_name)
        self.assertEqual(payload["schema_hash"], self.tool.schema_hash)
        self.assertTrue(payload["request_digest"].startswith("sha256:"))
        self.assertEqual(payload["budget_counter_value"], 1)
        self.assertTrue(verify_execution_receipt(outcome.receipt, self.gateway.gateway_public_key))
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(self.counter_value(), 1)

    def test_distinct_operations_receive_distinct_counter_sequences(self):
        first = self.gateway.execute(self.grant, self.request)
        second_request = replace(self.request, operation_id="op-002", arguments={
            "invoice_id": "INV-2049", "decision": "reject"
        })
        second = self.gateway.execute(self.grant, second_request)
        self.assertEqual(first.receipt["payload"]["budget_counter_value"], 1)
        self.assertEqual(second.receipt["payload"]["budget_counter_value"], 2)
        self.assertEqual(self.counter_value(), 2)
        self.assertEqual(self.tool.effect_count(), 2)

    def test_same_operation_replay_returns_same_signed_receipt_without_new_effect(self):
        first = self.gateway.execute(self.grant, self.request)
        restarted = self.make_gateway(
            SQLiteIdempotentTool(tool_name="invoice_review", schema=self.TOOL_SCHEMA,
                                 database_path=self.root / "tool-service.sqlite3")
        )
        second = restarted.execute(self.grant, self.request)
        self.assertTrue(second.replayed)
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(self.counter_value(), 1)
        self.assertEqual(self.tool.effect_count(), 1)

    def test_operation_id_cannot_be_rebound_to_different_arguments(self):
        self.gateway.execute(self.grant, self.request)
        altered = replace(self.request, arguments={"invoice_id": "INV-9999", "decision": "reject"})
        with self.assertRaises(OperationBindingConflict):
            self.gateway.execute(self.grant, altered)
        self.assertEqual(self.counter_value(), 1)
        self.assertEqual(self.tool.effect_count(), 1)

    def test_forged_grant_is_rejected_before_budget_allocation(self):
        forged = replace(self.grant, quota_limit=self.grant.quota_limit + 1)
        with self.assertRaises(GrantRejected):
            self.gateway.execute(forged, self.request)
        self.assertEqual(self.counter_value(), 0)
        self.assertEqual(self.tool.effect_count(), 0)

    def test_expired_grant_is_rejected_before_budget_allocation(self):
        # Re-issue a correctly signed but expired grant.
        expired = issue_lease_grant(
            self.issuer_private, issuer_id="issuer-lab", grant_id="grant-expired",
            lease_id="lease-offline-17", subject_id="agent-17", audience="gateway-lab-1",
            context_digest=context_hash(self.CONTEXT), issued_at=self.NOW - 120,
            expires_at=self.NOW, quota_limit=5, nonce="nonce-expired",
            allowed_tools=(ToolPermission("invoice_review", schema_hash(self.TOOL_SCHEMA)),),
        )
        with self.assertRaises(GrantRejected):
            self.gateway.execute(expired, self.request)
        self.assertEqual(self.counter_value(), 0)

    def test_subject_substitution_is_rejected_before_budget_allocation(self):
        altered = replace(self.request, subject_id="agent-other")
        with self.assertRaises(GrantRejected):
            self.gateway.execute(self.grant, altered)
        self.assertEqual(self.counter_value(), 0)

    def test_context_substitution_is_rejected_before_budget_allocation(self):
        altered = replace(self.request, context={**self.CONTEXT, "tenant_id": "tenant-B"})
        with self.assertRaises(GrantRejected):
            self.gateway.execute(self.grant, altered)
        self.assertEqual(self.counter_value(), 0)

    def test_tool_not_allowlisted_is_rejected(self):
        other = SQLiteIdempotentTool(
            tool_name="send_message",
            schema={"type": "object", "required": ["recipient", "body"]},
            database_path=self.root / "other-tool.sqlite3",
        )
        gateway = self.make_gateway(other)
        request = ToolRequest("op-other", "agent-17", "send_message",
                              {"recipient": "user-1", "body": "hello"}, dict(self.CONTEXT))
        with self.assertRaises(GrantRejected):
            gateway.execute(self.grant, request)
        self.assertEqual(gateway.broker.counter.read(), 0)

    def test_schema_drift_is_rejected_before_budget_allocation(self):
        self.tool.schema_hash = schema_hash({"type": "object", "required": ["different"]})
        with self.assertRaises(GrantRejected):
            self.gateway.execute(self.grant, self.request)
        self.assertEqual(self.counter_value(), 0)

    def test_grant_quota_must_match_broker_configuration(self):
        grant_quota_7 = self.make_grant(quota=7)
        with self.assertRaises(GrantRejected):
            self.gateway.execute(grant_quota_7, self.request)
        self.assertEqual(self.counter_value(), 0)

    def test_receipt_tampering_invalidates_gateway_signature(self):
        outcome = self.gateway.execute(self.grant, self.request)
        tampered = json.loads(json.dumps(outcome.receipt))
        tampered["payload"]["budget_counter_value"] = 99
        self.assertFalse(verify_execution_receipt(tampered, self.gateway.gateway_public_key))

    def test_crash_after_budget_allocation_recovers_existing_sequence(self):
        with self.assertRaises(InjectedCrash):
            self.gateway.execute(self.grant, self.request, crash_at="after_budget_allocation")
        self.assertEqual(self.counter_value(), 1)
        self.assertEqual(self.tool.effect_count(), 0)
        restarted_tool = SQLiteIdempotentTool(
            tool_name="invoice_review", schema=self.TOOL_SCHEMA,
            database_path=self.root / "tool-service.sqlite3",
        )
        restarted = self.make_gateway(restarted_tool)
        outcome = restarted.execute(self.grant, self.request)
        self.assertEqual(outcome.receipt["payload"]["budget_counter_value"], 1)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertEqual(restarted_tool.effect_count(), 1)

    def test_crash_after_dispatch_intent_retries_through_tool_idempotency(self):
        with self.assertRaises(InjectedCrash):
            self.gateway.execute(self.grant, self.request, crash_at="after_dispatch_intent")
        self.assertEqual(self.tool.effect_count(), 0)
        restarted_tool = SQLiteIdempotentTool(
            tool_name="invoice_review", schema=self.TOOL_SCHEMA,
            database_path=self.root / "tool-service.sqlite3",
        )
        restarted = self.make_gateway(restarted_tool)
        outcome = restarted.execute(self.grant, self.request)
        self.assertEqual(outcome.receipt["payload"]["budget_counter_value"], 1)
        self.assertEqual(restarted_tool.effect_count(), 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_crash_after_tool_effect_recovers_result_without_second_effect(self):
        with self.assertRaises(InjectedCrash):
            self.gateway.execute(self.grant, self.request, crash_at="after_tool_effect")
        self.assertEqual(self.tool.effect_count(), 1)
        restarted_tool = SQLiteIdempotentTool(
            tool_name="invoice_review", schema=self.TOOL_SCHEMA,
            database_path=self.root / "tool-service.sqlite3",
        )
        restarted = self.make_gateway(restarted_tool)
        outcome = restarted.execute(self.grant, self.request)
        self.assertEqual(outcome.receipt["payload"]["budget_counter_value"], 1)
        self.assertEqual(restarted_tool.effect_count(), 1)
        self.assertTrue(verify_execution_receipt(outcome.receipt, restarted.gateway_public_key))

    def test_crash_after_receipt_commit_replays_durable_receipt(self):
        with self.assertRaises(InjectedCrash):
            self.gateway.execute(self.grant, self.request, crash_at="after_receipt_commit")
        restarted = self.make_gateway(
            SQLiteIdempotentTool(tool_name="invoice_review", schema=self.TOOL_SCHEMA,
                                 database_path=self.root / "tool-service.sqlite3")
        )
        outcome = restarted.execute(self.grant, self.request)
        self.assertTrue(outcome.replayed)
        self.assertEqual(outcome.receipt["payload"]["budget_counter_value"], 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_non_idempotent_tool_crash_becomes_indeterminate_without_reexecution(self):
        non_idempotent = NonIdempotentTool()
        gateway = self.make_gateway(non_idempotent)
        request = ToolRequest(
            operation_id="op-non-idempotent", subject_id="agent-17", tool_name="send_message",
            arguments={"recipient": "user-1", "body": "hello"}, context=dict(self.CONTEXT),
        )
        grant = self.make_grant(
            quota=5, allowed_tool_name="send_message", allowed_schema_hash=non_idempotent.schema_hash
        )
        # The tool is registered and its schema is authorized by this grant.
        with self.assertRaises(InjectedCrash):
            gateway.execute(grant, request, crash_at="after_tool_effect")
        self.assertEqual(non_idempotent.effects, 1)
        restarted = self.make_gateway(non_idempotent)
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)
        self.assertEqual(non_idempotent.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)


    def _d63_make_send_message_case(
        self,
        *,
        status,
        authoritative=False,
        declares_authoritative=False,
        supports_idempotency_key=False,
        result=None,
    ):
        from src.execution_binding import ToolLookupStatus

        # Each scenario gets independent journal, broker and counter files.
        # This prevents one subTest's INDETERMINATE state from contaminating
        # the next subTest.
        case_tmp = tempfile.TemporaryDirectory(prefix="d63-case-")
        self.addCleanup(case_tmp.cleanup)

        previous_root = self.root
        self.root = Path(case_tmp.name)
        try:
            tool = D63ScriptedLookupTool(
                status=status,
                authoritative=authoritative,
                declares_authoritative=declares_authoritative,
                supports_idempotency_key=supports_idempotency_key,
                result=result,
            )
            request = ToolRequest(
                operation_id="op-d63",
                subject_id="agent-17",
                tool_name="send_message",
                arguments={"recipient": "user-1", "body": "hello"},
                context=dict(self.CONTEXT),
            )
            grant = self.make_grant(
                quota=5,
                allowed_tool_name="send_message",
                allowed_schema_hash=tool.schema_hash,
            )
            gateway = self.make_gateway(tool)
        finally:
            self.root = previous_root

        return tool, request, grant, gateway, ToolLookupStatus

    def _d63_crash_before_tool_call(self, gateway, grant, request):
        with self.assertRaises(InjectedCrash):
            gateway.execute(grant, request, crash_at="after_dispatch_intent")

    def test_d63_recovery_lookup_state_matrix(self):
        from src.execution_binding import ToolLookupStatus

        # Recovery must fail closed for ambiguous or non-authoritative states.
        rejected_cases = [
            (
                "in_progress",
                ToolLookupStatus.IN_PROGRESS,
                True,
                True,
                False,
            ),
            (
                "non_authoritative_not_found",
                ToolLookupStatus.NOT_FOUND,
                False,
                True,
                False,
            ),
            (
                "undeclared_authoritative_failed_no_effect",
                ToolLookupStatus.FAILED_NO_EFFECT,
                True,
                False,
                False,
            ),
            (
                "unknown_without_idempotency",
                ToolLookupStatus.UNKNOWN,
                False,
                False,
                False,
            ),
        ]

        for (
            label,
            status,
            authoritative,
            declares_authoritative,
            supports_idempotency_key,
        ) in rejected_cases:
            with self.subTest(case=label):
                tool, request, grant, gateway, _ = self._d63_make_send_message_case(
                    status=status,
                    authoritative=authoritative,
                    declares_authoritative=declares_authoritative,
                    supports_idempotency_key=supports_idempotency_key,
                )

                self._d63_crash_before_tool_call(gateway, grant, request)
                restarted = self.make_gateway(tool)

                with self.assertRaises(ExecutionIndeterminate):
                    restarted.execute(grant, request)

                self.assertEqual(tool.effects, 0)
                self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d63_authoritative_not_found_allows_one_recovery_dispatch(self):
        from src.execution_binding import ToolLookupStatus

        tool, request, grant, gateway, _ = self._d63_make_send_message_case(
            status=ToolLookupStatus.NOT_FOUND,
            authoritative=True,
            declares_authoritative=True,
        )
        self._d63_crash_before_tool_call(gateway, grant, request)

        restarted = self.make_gateway(tool)
        outcome = restarted.execute(grant, request)

        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertTrue(verify_execution_receipt(
            outcome.receipt, restarted.gateway_public_key
        ))

    def test_d63_authoritative_failed_no_effect_allows_one_recovery_dispatch(self):
        from src.execution_binding import ToolLookupStatus

        tool, request, grant, gateway, _ = self._d63_make_send_message_case(
            status=ToolLookupStatus.FAILED_NO_EFFECT,
            authoritative=True,
            declares_authoritative=True,
        )
        self._d63_crash_before_tool_call(gateway, grant, request)

        restarted = self.make_gateway(tool)
        outcome = restarted.execute(grant, request)

        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertTrue(verify_execution_receipt(
            outcome.receipt, restarted.gateway_public_key
        ))

    def test_d63_authoritative_succeeded_recovers_without_redispatch(self):
        from src.execution_binding import ToolLookupStatus

        recovered_result = {
            "sent": True,
            "effect_number": 1,
            "recipient": "user-1",
        }
        tool, request, grant, gateway, _ = self._d63_make_send_message_case(
            status=ToolLookupStatus.SUCCEEDED,
            authoritative=True,
            declares_authoritative=True,
            result=recovered_result,
        )
        self._d63_crash_before_tool_call(gateway, grant, request)

        restarted = self.make_gateway(tool)
        outcome = restarted.execute(grant, request)

        self.assertEqual(tool.effects, 0)
        self.assertEqual(outcome.receipt["payload"]["result"], recovered_result)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertTrue(verify_execution_receipt(
            outcome.receipt, restarted.gateway_public_key
        ))

    def test_d63_unknown_with_idempotency_key_allows_recovery_retry(self):
        from src.execution_binding import ToolLookupStatus

        tool, request, grant, gateway, _ = self._d63_make_send_message_case(
            status=ToolLookupStatus.UNKNOWN,
            supports_idempotency_key=True,
        )
        self._d63_crash_before_tool_call(gateway, grant, request)

        restarted = self.make_gateway(tool)
        restarted.execute(grant, request)

        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d63_first_dispatch_allows_non_authoritative_not_found(self):
        from src.execution_binding import ToolLookupStatus

        tool, request, grant, gateway, _ = self._d63_make_send_message_case(
            status=ToolLookupStatus.NOT_FOUND,
            authoritative=False,
            declares_authoritative=False,
        )

        # This is the first dispatch, not recovery after an uncertain call.
        gateway.execute(grant, request)

        self.assertEqual(tool.effects, 1)
        self.assertEqual(gateway.broker.counter.read(), 1)

    def test_d63_lookup_binding_mismatch_never_dispatches(self):
        from src.execution_binding import (
            ToolLookupResult,
            ToolLookupStatus,
        )

        for mismatch in ("operation_id", "request_digest"):
            with self.subTest(mismatch=mismatch):
                tool, request, grant, gateway, _ = self._d63_make_send_message_case(
                    status=ToolLookupStatus.NOT_FOUND,
                    authoritative=True,
                    declares_authoritative=True,
                )

                # First create a durable DISPATCHING record.
                self._d63_crash_before_tool_call(gateway, grant, request)

                original_lookup = tool.lookup

                def mismatched_lookup(*, operation_id, request_digest):
                    return ToolLookupResult(
                        status=ToolLookupStatus.NOT_FOUND,
                        operation_id=(
                            "different-operation"
                            if mismatch == "operation_id"
                            else operation_id
                        ),
                        request_digest=(
                            "different-digest"
                            if mismatch == "request_digest"
                            else request_digest
                        ),
                        authoritative=True,
                    )

                tool.lookup = mismatched_lookup
                restarted = self.make_gateway(tool)

                with self.assertRaises(ExecutionIndeterminate):
                    restarted.execute(grant, request)

                self.assertEqual(tool.effects, 0)
                self.assertEqual(restarted.broker.counter.read(), 1)
                tool.lookup = original_lookup

    def test_unresolved_operation_blocks_new_operation_until_recovery(self):
        with self.assertRaises(InjectedCrash):
            self.gateway.execute(self.grant, self.request, crash_at="after_dispatch_intent")
        second = replace(self.request, operation_id="op-002", arguments={
            "invoice_id": "INV-2049", "decision": "reject"
        })
        with self.assertRaises(GatewayBusy):
            self.gateway.execute(self.grant, second)
        self.assertEqual(self.counter_value(), 1)

    def test_two_processes_replaying_same_operation_share_one_signed_receipt(self):
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

        grant_file = self.root / "grant.json"
        issuer_pub_file = self.root / "issuer-public.bin"
        gateway_priv_file = self.root / "gateway-private.bin"
        request_file = self.root / "request.json"
        grant_file.write_text(json.dumps(self.grant.to_dict()), encoding="utf-8")
        issuer_pub_file.write_bytes(self.issuer_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        gateway_priv_file.write_bytes(self.gateway_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ))
        request_file.write_text(json.dumps({
            "operation_id": self.request.operation_id,
            "subject_id": self.request.subject_id,
            "tool_name": self.request.tool_name,
            "arguments": dict(self.request.arguments),
            "context": dict(self.request.context),
        }), encoding="utf-8")

        child = r'''import json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from src.durable_broker import DurableCounterBroker
from src.execution_binding import ExecutionBindingGateway, LeaseGrant, SQLiteIdempotentTool, ToolRequest
root = Path(sys.argv[1])
grant = LeaseGrant.from_dict(json.loads((root / "grant.json").read_text(encoding="utf-8")))
issuer = Ed25519PublicKey.from_public_bytes((root / "issuer-public.bin").read_bytes())
gateway_key = Ed25519PrivateKey.from_private_bytes((root / "gateway-private.bin").read_bytes())
request_obj = json.loads((root / "request.json").read_text(encoding="utf-8"))
schema = {"type":"object","required":["invoice_id","decision"],"properties":{"invoice_id":{"type":"string"},"decision":{"enum":["approve","reject"]}}}
tool = SQLiteIdempotentTool(tool_name="invoice_review", schema=schema, database_path=root / "tool-service.sqlite3")
broker = DurableCounterBroker(journal_path=root / "budget-journal.sqlite3", counter_state_path=root / "counter.json", broker_lock_path=root / "broker.lock", lease_id="lease-offline-17", quota_limit=5)
gateway = ExecutionBindingGateway(issuer_public_key=issuer, gateway_private_key=gateway_key, gateway_id="gateway-lab-1", broker=broker, journal_path=root / "execution-journal.sqlite3", lock_path=root / "gateway.lock", tools={tool.tool_name:tool}, clock=lambda: 1800000000)
request = ToolRequest(**request_obj)
outcome = gateway.execute(grant, request)
print(json.dumps(outcome.receipt, sort_keys=True))
'''
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", child, str(self.root)],
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        outputs = []
        for proc in processes:
            stdout, stderr = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, msg=f"child failed: {stderr}")
            outputs.append(json.loads(stdout.strip()))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(self.tool.effect_count(), 1)
        self.assertEqual(self.gateway.broker.counter.read(), 1)

    def test_d62_structured_lookup_states_and_binding_validation(self):
        from src.execution_binding import (
            ToolLookupStatus,
            ToolLookupResult,
            ToolCapabilities,
            coerce_tool_lookup_result,
        )

        unknown = coerce_tool_lookup_result(
            None, operation_id="op-x", request_digest="digest-x"
        )
        self.assertEqual(unknown.status, ToolLookupStatus.UNKNOWN)
        self.assertFalse(unknown.authoritative)

        legacy_positive = coerce_tool_lookup_result(
            {"ok": True}, operation_id="op-x", request_digest="digest-x"
        )
        self.assertEqual(legacy_positive.status, ToolLookupStatus.SUCCEEDED)
        self.assertFalse(legacy_positive.authoritative)

        not_found = ToolLookupResult(
            ToolLookupStatus.NOT_FOUND, "op-x", "digest-x", authoritative=True
        )
        self.assertEqual(
            coerce_tool_lookup_result(
                not_found, operation_id="op-x", request_digest="digest-x"
            ).status,
            ToolLookupStatus.NOT_FOUND,
        )

        with self.assertRaises(ExecutionIndeterminate):
            coerce_tool_lookup_result(
                ToolLookupResult(
                    ToolLookupStatus.NOT_FOUND, "other-op", "digest-x",
                    authoritative=True,
                ),
                operation_id="op-x",
                request_digest="digest-x",
            )

        with self.assertRaises(ExecutionIndeterminate):
            coerce_tool_lookup_result(
                ToolLookupResult(
                    ToolLookupStatus.NOT_FOUND, "op-x", "other-digest",
                    authoritative=True,
                ),
                operation_id="op-x",
                request_digest="digest-x",
            )

        with self.assertRaises(ValueError):
            ToolCapabilities(
                supports_idempotency_key=False,
                idempotency_retention_seconds=60,
            )

    def test_d62_sqlite_lookup_reports_authoritative_not_found_and_success(self):
        from src.execution_binding import ToolLookupStatus

        absent = self.tool.lookup(
            operation_id="not-yet-executed",
            request_digest="sha256:" + "a" * 64,
        )
        self.assertEqual(absent.status, ToolLookupStatus.NOT_FOUND)
        self.assertTrue(absent.authoritative)

        self.tool.execute(
            operation_id="lookup-existing",
            request_digest="sha256:" + "b" * 64,
            arguments={"invoice_id": "INV-LOOKUP", "decision": "approve"},
            context=dict(self.CONTEXT),
        )
        found = self.tool.lookup(
            operation_id="lookup-existing",
            request_digest="sha256:" + "b" * 64,
        )
        self.assertEqual(found.status, ToolLookupStatus.SUCCEEDED)
        self.assertTrue(found.authoritative)
        self.assertEqual(found.result["operation_id"], "lookup-existing")

    def test_quota_exhaustion_does_not_invoke_second_tool_or_increment(self):
        grant_one = self.make_grant(quota=1)
        # Broker and grant both use quota=1 in a fresh isolated test directory.
        with tempfile.TemporaryDirectory() as other_tmp:
            root = Path(other_tmp)
            tool = SQLiteIdempotentTool(
                tool_name="invoice_review", schema=self.TOOL_SCHEMA,
                database_path=root / "tool.sqlite3",
            )
            broker = DurableCounterBroker(
                journal_path=root / "budget.sqlite3", counter_state_path=root / "counter.json",
                broker_lock_path=root / "broker.lock", lease_id="lease-offline-17", quota_limit=1,
            )
            gateway = ExecutionBindingGateway(
                issuer_public_key=self.issuer_private.public_key(), gateway_private_key=self.gateway_private,
                gateway_id="gateway-lab-1", broker=broker, journal_path=root / "exec.sqlite3",
                lock_path=root / "gateway.lock", tools={tool.tool_name: tool}, clock=lambda: self.NOW,
            )
            first = gateway.execute(grant_one, self.request)
            second_request = replace(self.request, operation_id="op-002", arguments={
                "invoice_id": "INV-2049", "decision": "reject"
            })
            with self.assertRaises(BudgetAllocationFailed):
                gateway.execute(grant_one, second_request)
            self.assertEqual(broker.counter.read(), 1)
            self.assertEqual(tool.effect_count(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
