from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
import sqlite3
from contextlib import closing
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
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
        retention_seconds=None,
        naturally_idempotent=False,
        idempotency_scope=None,
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
        self._retention_seconds = retention_seconds
        self._naturally_idempotent = naturally_idempotent
        self._idempotency_scope = idempotency_scope
        self._lookup_result = result
        self.lookup_calls = 0
        self._ToolCapabilities = ToolCapabilities
        self._ToolLookupResult = ToolLookupResult

    @property
    def capabilities(self):
        return self._ToolCapabilities(
            naturally_idempotent=self._naturally_idempotent,
            supports_idempotency_key=self._supports_idempotency_key,
            supports_authoritative_lookup=self._declares_authoritative,
            idempotency_retention_seconds=self._retention_seconds,
            idempotency_scope=self._idempotency_scope,
        )

    def lookup(self, *, operation_id, request_digest):
        self.lookup_calls += 1
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
                   allowed_schema_hash: str | None = None,
                   audience: str = "gateway-lab-1"):
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
            audience=audience,
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


    def _d71_gateway_at(
        self, root, tool, clock, *, gateway_private_key=None,
        gateway_id="gateway-lab-1", lock_name="gateway.lock",
        broker_root=None, broker_lock_name="broker.lock"
    ):
        broker_root = root if broker_root is None else Path(broker_root)
        broker_root.mkdir(parents=True, exist_ok=True)
        broker = DurableCounterBroker(
            journal_path=broker_root / "budget-journal.sqlite3",
            counter_state_path=broker_root / "counter.json",
            broker_lock_path=broker_root / broker_lock_name,
            lease_id="lease-offline-17",
            quota_limit=5,
        )
        return ExecutionBindingGateway(
            issuer_public_key=self.issuer_private.public_key(),
            gateway_private_key=(
                self.gateway_private
                if gateway_private_key is None else gateway_private_key
            ),
            gateway_id=gateway_id,
            broker=broker,
            journal_path=root / "execution-journal.sqlite3",
            lock_path=root / lock_name,
            tools={tool.tool_name: tool},
            clock=clock,
        )

    def _d71_case(
        self, *, retention_seconds=10, naturally_idempotent=False,
        idempotency_scope="mock-send-message-tenant-A",
    ):
        from src.execution_binding import ToolLookupStatus

        tmp = tempfile.TemporaryDirectory(prefix="d71-case-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)

        tool = D63ScriptedLookupTool(
            status=ToolLookupStatus.UNKNOWN,
            supports_idempotency_key=True,
            retention_seconds=retention_seconds,
            naturally_idempotent=naturally_idempotent,
            idempotency_scope=idempotency_scope,
        )

        request = ToolRequest(
            operation_id="op-d71",
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

        now = [self.NOW]
        clock = lambda: now[0]
        gateway = self._d71_gateway_at(root, tool, clock)

        with self.assertRaises(InjectedCrash):
            gateway.execute(grant, request, crash_at="after_dispatch_intent")

        return root, tool, request, grant, gateway, now

    def test_d71_unknown_retry_inside_retention_window(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        now[0] += 9
        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        restarted.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_exact_retention_expiry_is_rejected(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        now[0] += 10
        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertEqual(
            restarted.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )

    def test_d71_expired_retention_is_rejected(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        now[0] += 11
        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_missing_dispatch_timestamp_is_rejected(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        con = sqlite3.connect(root / "execution-journal.sqlite3")
        try:
            con.execute(
                "UPDATE executions SET dispatch_started_at=NULL WHERE operation_id=?",
                (request.operation_id,),
            )
            con.commit()
        finally:
            con.close()
        restarted = self._d71_gateway_at(root, tool, lambda: now[0] + 1)
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_clock_rollback_is_rejected(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        restarted = self._d71_gateway_at(root, tool, lambda: now[0] - 1)
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_non_expiring_key_declaration_allows_recovery(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=None
        )
        # Remain inside the signed grant validity interval.
        now[0] += 3500
        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        restarted.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_natural_idempotence_ignores_key_expiry(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=1,
            naturally_idempotent=True,
        )
        now[0] += 100
        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        restarted.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d71_first_dispatch_is_not_blocked_by_retention_guard(self):
        from src.execution_binding import ToolLookupStatus

        tmp = tempfile.TemporaryDirectory(prefix="d71-first-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        tool = D63ScriptedLookupTool(
            status=ToolLookupStatus.UNKNOWN,
            supports_idempotency_key=True,
            retention_seconds=1,
        )
        request = ToolRequest(
            operation_id="op-d71-first",
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
        gateway = self._d71_gateway_at(root, tool, lambda: self.NOW)
        gateway.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(gateway.broker.counter.read(), 1)

    def test_d71_dispatch_timestamp_is_not_overwritten(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        original = gateway.journal.get(request.operation_id)["dispatch_started_at"]
        gateway.journal.set_dispatching(
            request.operation_id, self.NOW + 5, "sha256:" + "b" * 64
        )
        self.assertEqual(
            gateway.journal.get(request.operation_id)["dispatch_started_at"],
            original,
        )

    def test_d71_additive_migration_preserves_existing_rows(self):
        tmp = tempfile.TemporaryDirectory(prefix="d71-migration-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "legacy-journal.sqlite3"

        con = sqlite3.connect(db)
        try:
            con.execute(
                "CREATE TABLE executions ("
                "operation_id TEXT PRIMARY KEY, grant_digest TEXT NOT NULL, "
                "grant_id TEXT NOT NULL, lease_id TEXT NOT NULL, "
                "subject_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
                "schema_hash TEXT NOT NULL, context_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL, "
                "budget_counter_value INTEGER, receipt_json TEXT, "
                "parent_authorization_digest TEXT NOT NULL DEFAULT '', "
                "parent_authorization_nonce TEXT NOT NULL DEFAULT '', "
                "updated_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )
            con.execute(
                "INSERT INTO executions("
                "operation_id,grant_digest,grant_id,lease_id,subject_id,"
                "tool_name,schema_hash,context_digest,request_digest,status,"
                "budget_counter_value"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "legacy-op", "gd", "gid", "lid", "sid",
                    "tool", "sh", "cd", "rd", "DISPATCHING", 1,
                ),
            )
            con.commit()
        finally:
            con.close()

        journal = ExecutionJournal(db)
        row = journal.get("legacy-op")
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "DISPATCHING")
        self.assertEqual(row["budget_counter_value"], 1)
        self.assertIsNone(row["dispatch_started_at"])
        self.assertIsNone(row["tool_capabilities_digest"])
        self.assertIsNone(row["gateway_id"])
        self.assertIsNone(row["gateway_public_key_digest"])


    def test_d72_dispatch_persists_capability_contract_before_lookup(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        row = gateway.journal.get(request.operation_id)
        digest = row["tool_capabilities_digest"]
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(tool.lookup_calls, 0)

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        restarted.execute(grant, request)
        self.assertEqual(tool.lookup_calls, 1)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d72_retention_contract_drift_fails_closed_before_lookup(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        self.assertIsNotNone(
            gateway.journal.get(request.operation_id)["tool_capabilities_digest"]
        )
        tool._retention_seconds = 11

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertEqual(
            restarted.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )

    def test_d72_idempotency_scope_drift_fails_closed_before_lookup(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        tool._idempotency_scope = "mock-send-message-tenant-B"

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d72_missing_capability_snapshot_fails_closed(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        con = sqlite3.connect(root / "execution-journal.sqlite3")
        try:
            con.execute(
                "UPDATE executions SET tool_capabilities_digest=NULL WHERE operation_id=?",
                (request.operation_id,),
            )
            con.commit()
        finally:
            con.close()

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d72_migration_preserves_d71_dispatch_timestamp(self):
        tmp = tempfile.TemporaryDirectory(prefix="d72-migration-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "d71-journal.sqlite3"

        con = sqlite3.connect(db)
        try:
            con.execute(
                "CREATE TABLE executions ("
                "operation_id TEXT PRIMARY KEY, grant_digest TEXT NOT NULL, "
                "grant_id TEXT NOT NULL, lease_id TEXT NOT NULL, "
                "subject_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
                "schema_hash TEXT NOT NULL, context_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL, "
                "budget_counter_value INTEGER, receipt_json TEXT, "
                "parent_authorization_digest TEXT NOT NULL DEFAULT '', "
                "parent_authorization_nonce TEXT NOT NULL DEFAULT '', "
                "dispatch_started_at INTEGER, "
                "updated_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )
            con.execute(
                "INSERT INTO executions("
                "operation_id,grant_digest,grant_id,lease_id,subject_id,"
                "tool_name,schema_hash,context_digest,request_digest,status,"
                "budget_counter_value,dispatch_started_at"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "d71-existing", "gd", "gid", "lid", "sid",
                    "tool", "sh", "cd", "rd", "DISPATCHING", 1, self.NOW,
                ),
            )
            con.commit()
        finally:
            con.close()

        journal = ExecutionJournal(db)
        row = journal.get("d71-existing")
        self.assertEqual(row["status"], "DISPATCHING")
        self.assertEqual(row["dispatch_started_at"], self.NOW)
        self.assertIsNone(row["tool_capabilities_digest"])
        self.assertIsNone(row["gateway_id"])
        self.assertIsNone(row["gateway_public_key_digest"])


    def test_d73_gateway_identity_is_persisted_before_dispatch(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        row = gateway.journal.get(request.operation_id)
        self.assertEqual(row["gateway_id"], gateway.gateway_id)
        self.assertEqual(
            row["gateway_public_key_digest"],
            gateway.gateway_public_key_digest,
        )
        self.assertRegex(
            row["gateway_public_key_digest"], r"^sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(tool.lookup_calls, 0)

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        restarted.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d73_signing_key_rotation_fails_closed_before_lookup(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        rotated_key = Ed25519PrivateKey.generate()
        restarted = self._d71_gateway_at(
            root, tool, lambda: now[0], gateway_private_key=rotated_key
        )
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertEqual(
            restarted.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )

    def test_d73_missing_gateway_identity_snapshot_fails_closed(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        con = sqlite3.connect(root / "execution-journal.sqlite3")
        try:
            con.execute(
                "UPDATE executions SET gateway_id=NULL, "
                "gateway_public_key_digest=NULL WHERE operation_id=?",
                (request.operation_id,),
            )
            con.commit()
        finally:
            con.close()

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(restarted.broker.counter.read(), 1)
        self.assertEqual(
            restarted.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )

    def test_d73_changed_signing_key_cannot_replay_committed_receipt(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        gateway.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(tool.lookup_calls, 1)

        rotated_key = Ed25519PrivateKey.generate()
        restarted = self._d71_gateway_at(
            root, tool, lambda: now[0], gateway_private_key=rotated_key
        )
        with self.assertRaises(ExecutionIndeterminate):
            restarted.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 1)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)


    def test_d74_same_identity_can_reuse_journal_for_new_operations(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        gateway.execute(grant, request)
        second_request = replace(request, operation_id="op-d74-second")
        second = gateway.execute(grant, second_request)

        self.assertFalse(second.replayed)
        self.assertEqual(tool.effects, 2)
        self.assertEqual(gateway.broker.counter.read(), 2)
        with closing(sqlite3.connect(root / "execution-journal.sqlite3")) as con:
            row = con.execute(
                "SELECT gateway_id,gateway_public_key_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
        self.assertEqual(row, (gateway.gateway_id, gateway.gateway_public_key_digest))

    def test_d74_different_signing_key_rejected_across_new_operation(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        gateway.execute(grant, request)
        new_request = replace(request, operation_id="op-d74-key-rotation")
        other = self._d71_gateway_at(
            root, tool, lambda: now[0],
            gateway_private_key=Ed25519PrivateKey.generate(),
            lock_name="gateway-other.lock",
        )

        with self.assertRaises(ExecutionIndeterminate):
            other.execute(grant, new_request)

        self.assertEqual(tool.lookup_calls, 1)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(other.broker.counter.read(), 1)
        self.assertIsNone(other.journal.get(new_request.operation_id))

    def test_d74_different_gateway_id_rejected_across_new_operation(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        gateway.execute(grant, request)
        new_request = replace(request, operation_id="op-d74-gateway-id")
        other = self._d71_gateway_at(
            root, tool, lambda: now[0],
            gateway_id="gateway-lab-2",
            lock_name="gateway-other.lock",
        )

        other_grant = self.make_grant(
            quota=5,
            allowed_tool_name="send_message",
            allowed_schema_hash=tool.schema_hash,
            audience="gateway-lab-2",
        )
        with self.assertRaises(ExecutionIndeterminate):
            other.execute(other_grant, new_request)

        self.assertEqual(tool.lookup_calls, 1)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(other.broker.counter.read(), 1)
        self.assertIsNone(other.journal.get(new_request.operation_id))

    def test_d74_competing_first_identity_bindings_are_serialized(self):
        tmp = tempfile.TemporaryDirectory(prefix="d74-race-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "execution-journal.sqlite3"
        first = ExecutionJournal(db)
        second = ExecutionJournal(db)
        barrier = threading.Barrier(2)

        identities = [
            ("gateway-race-A", "sha256:" + "a" * 64, "sha256:" + "1" * 64),
            ("gateway-race-B", "sha256:" + "b" * 64, "sha256:" + "2" * 64),
        ]

        def attempt(journal, identity):
            barrier.wait(timeout=10)
            try:
                journal.bind_gateway_identity(*identity)
                return (identity, "bound")
            except ExecutionIndeterminate:
                return (identity, "rejected")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda item: attempt(item[0], item[1]),
                [(first, identities[0]), (second, identities[1])],
            ))

        self.assertEqual(sorted(result for _, result in results), ["bound", "rejected"])
        with closing(sqlite3.connect(db)) as con:
            stored = con.execute(
                "SELECT gateway_id,gateway_public_key_digest,broker_identity_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
        self.assertIn(tuple(stored), identities)

    def test_d74_d73_rows_bootstrap_global_identity_registry(self):
        tmp = tempfile.TemporaryDirectory(prefix="d74-bootstrap-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "d73-journal.sqlite3"
        identity = (
            "gateway-lab-1", "sha256:" + "c" * 64, "sha256:" + "d" * 64
        )

        con = sqlite3.connect(db)
        try:
            con.execute(
                "CREATE TABLE executions ("
                "operation_id TEXT PRIMARY KEY, grant_digest TEXT NOT NULL, "
                "grant_id TEXT NOT NULL, lease_id TEXT NOT NULL, "
                "subject_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
                "schema_hash TEXT NOT NULL, context_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL, "
                "budget_counter_value INTEGER, receipt_json TEXT, "
                "parent_authorization_digest TEXT NOT NULL DEFAULT '', "
                "parent_authorization_nonce TEXT NOT NULL DEFAULT '', "
                "dispatch_started_at INTEGER, tool_capabilities_digest TEXT, "
                "gateway_id TEXT, gateway_public_key_digest TEXT, "
                "updated_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
                ")"
            )
            con.execute(
                "INSERT INTO executions(operation_id,grant_digest,grant_id,lease_id,"
                "subject_id,tool_name,schema_hash,context_digest,request_digest,status,"
                "gateway_id,gateway_public_key_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "legacy-d73", "gd", "gid", "lid", "sid", "tool", "sh",
                    "cd", "rd", "COMMITTED", identity[0], identity[1],
                ),
            )
            con.commit()
        finally:
            con.close()

        journal = ExecutionJournal(db)
        journal.bind_gateway_identity(*identity)
        with closing(sqlite3.connect(db)) as con:
            stored = con.execute(
                "SELECT gateway_id,gateway_public_key_digest,broker_identity_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
        self.assertEqual(stored, identity)


    def test_d75_broker_configuration_is_persisted_and_stable(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        with closing(sqlite3.connect(root / "execution-journal.sqlite3")) as con:
            row = con.execute(
                "SELECT gateway_id,gateway_public_key_digest,broker_identity_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()

        self.assertEqual(
            row,
            (
                gateway.gateway_id,
                gateway.gateway_public_key_digest,
                gateway.broker_identity_digest,
            ),
        )
        self.assertRegex(row[2], r"^sha256:[0-9a-f]{64}$")

        restarted = self._d71_gateway_at(root, tool, lambda: now[0])
        self.assertEqual(
            restarted.broker_identity_digest,
            gateway.broker_identity_digest,
        )
        restarted.execute(grant, request)
        self.assertEqual(tool.effects, 1)
        self.assertEqual(restarted.broker.counter.read(), 1)

    def test_d75_different_broker_storage_fails_closed_before_tool_lookup(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        alternate_broker_root = root / "alternate-broker"
        other = self._d71_gateway_at(
            root,
            tool,
            lambda: now[0],
            broker_root=alternate_broker_root,
            broker_lock_name="alternate-broker.lock",
            lock_name="alternate-gateway.lock",
        )

        with self.assertRaises(ExecutionIndeterminate):
            other.execute(grant, request)

        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(gateway.broker.counter.read(), 1)
        self.assertEqual(other.broker.counter.read(), 0)
        self.assertEqual(
            other.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )

    def test_d75_d74_registry_migration_pins_first_broker_configuration(self):
        tmp = tempfile.TemporaryDirectory(prefix="d75-d74-migration-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "execution-journal.sqlite3"
        gateway_id = "gateway-lab-1"
        key_digest = "sha256:" + "e" * 64
        broker_digest = "sha256:" + "f" * 64
        alternate_digest = "sha256:" + "1" * 64

        con = sqlite3.connect(db)
        try:
            con.execute(
                "CREATE TABLE gateway_identity ("
                "singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1), "
                "gateway_id TEXT NOT NULL, "
                "gateway_public_key_digest TEXT NOT NULL, "
                "created_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')) )"
            )
            con.execute(
                "INSERT INTO gateway_identity(singleton_id,gateway_id,gateway_public_key_digest) "
                "VALUES(1,?,?)",
                (gateway_id, key_digest),
            )
            con.commit()
        finally:
            con.close()

        journal = ExecutionJournal(db)
        journal.bind_gateway_identity(gateway_id, key_digest, broker_digest)
        with closing(sqlite3.connect(db)) as con:
            stored = con.execute(
                "SELECT gateway_id,gateway_public_key_digest,broker_identity_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
        self.assertEqual(stored, (gateway_id, key_digest, broker_digest))

        with self.assertRaises(ExecutionIndeterminate):
            journal.bind_gateway_identity(gateway_id, key_digest, alternate_digest)

    def test_d75_competing_broker_bindings_are_serialized(self):
        tmp = tempfile.TemporaryDirectory(prefix="d75-race-")
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "execution-journal.sqlite3"
        first = ExecutionJournal(db)
        second = ExecutionJournal(db)
        barrier = threading.Barrier(2)
        identity = ("gateway-race", "sha256:" + "a" * 64)
        broker_digests = ["sha256:" + "b" * 64, "sha256:" + "c" * 64]

        def attempt(journal, broker_digest):
            barrier.wait(timeout=10)
            try:
                journal.bind_gateway_identity(*identity, broker_digest)
                return "bound"
            except ExecutionIndeterminate:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda item: attempt(item[0], item[1]),
                [(first, broker_digests[0]), (second, broker_digests[1])],
            ))

        self.assertEqual(sorted(results), ["bound", "rejected"])
        with closing(sqlite3.connect(db)) as con:
            stored = con.execute(
                "SELECT gateway_id,gateway_public_key_digest,broker_identity_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
        self.assertIn(tuple(stored), [
            (identity[0], identity[1], broker_digests[0]),
            (identity[0], identity[1], broker_digests[1]),
        ])


    def test_d75_broker_path_change_after_gateway_construction_fails_closed(self):
        root, tool, request, grant, gateway, now = self._d71_case(
            retention_seconds=10
        )
        self.assertEqual(gateway.broker.counter.read(), 1)
        original_digest = gateway.broker_identity_digest

        # Mutate the already-constructed Broker object. A constructor-cached
        # digest would miss this and incorrectly allow recovery to continue.
        gateway.broker.lock_path = root / "replacement-broker.lock"

        with self.assertRaises(ExecutionIndeterminate):
            gateway.execute(grant, request)

        self.assertNotEqual(gateway.broker_identity_digest, original_digest)
        self.assertEqual(tool.lookup_calls, 0)
        self.assertEqual(tool.effects, 0)
        self.assertEqual(gateway.broker.counter.read(), 1)
        self.assertEqual(
            gateway.journal.get(request.operation_id)["status"],
            "INDETERMINATE",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
