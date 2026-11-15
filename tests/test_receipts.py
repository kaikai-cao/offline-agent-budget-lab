from __future__ import annotations

import unittest
from dataclasses import replace

from budget_lab import (
    BudgetIssuer,
    LeaseRequest,
    LocalBudgetLedger,
    OperationStatus,
    ReceiptChain,
    generate_ed25519_keypair,
    verify_receipt_chain,
)
from budget_lab.crypto import encode_public_key

NOW = 1_800_000_000
EXPIRES = NOW + 3600
SCHEMA_HASH = "a" * 64
REQUEST_HASH = "b" * 64
CONTEXT_HASH = "c" * 64
RESULT_HASH = "d" * 64


class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer_private, self.issuer_public = generate_ed25519_keypair()
        self.issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=self.issuer_private,
            root_grant_id="root-e03-test",
        )
        self.holder_private, holder_public = generate_ed25519_keypair()
        self.lease = self.issuer.issue_leases(
            (LeaseRequest("lease-A", "agent-A", encode_public_key(holder_public), 4),),
            issued_at=NOW,
            expires_at=EXPIRES,
        )[0]
        self.ledger = LocalBudgetLedger(
            self.lease, self.issuer_public, clock=lambda: NOW + 1
        )
        self.executor_private, self.executor_public = generate_ed25519_keypair()
        self.clock_value = NOW + 2
        self.chain = ReceiptChain(
            self.lease,
            self.issuer_public,
            self.executor_private,
            chain_id="chain-test-01",
            clock=lambda: self.clock_value,
        )

    def _commit_and_append(self, operation_id: str, result_hash: str = RESULT_HASH):
        self.ledger.reserve(operation_id)
        self.ledger.commit(operation_id)
        return self.chain.append(
            self.ledger,
            operation_id,
            request_hash=REQUEST_HASH,
            context_hash=CONTEXT_HASH,
            result_hash=result_hash,
        )

    def test_committed_operation_creates_bound_signed_receipt(self) -> None:
        receipt = self._commit_and_append("op-001")
        self.assertEqual(receipt.tool_id, "data.query")
        self.assertEqual(receipt.schema_hash, SCHEMA_HASH)
        self.assertEqual(receipt.operation_status, OperationStatus.COMMITTED.value)
        self.assertEqual(receipt.cost, 1)
        self.assertTrue(
            verify_receipt_chain(
                self.chain.receipts,
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
                ledger=self.ledger,
            )
        )

    def test_receipt_json_round_trip(self) -> None:
        receipt = self._commit_and_append("op-json")
        restored = type(receipt).from_dict(receipt.to_dict())
        self.assertEqual(restored, receipt)
        self.assertEqual(restored.receipt_hash, receipt.receipt_hash)

    def test_receipt_parser_rejects_unknown_fields(self) -> None:
        receipt = self._commit_and_append("op-unknown-field")
        data = receipt.to_dict()
        data["unrecognized"] = "value"
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            type(receipt).from_dict(data)

    def test_uncommitted_operation_cannot_be_receipted(self) -> None:
        self.ledger.reserve("op-reserved")
        with self.assertRaisesRegex(ValueError, "terminal ledger operation"):
            self.chain.append(
                self.ledger,
                "op-reserved",
                request_hash=REQUEST_HASH,
                context_hash=CONTEXT_HASH,
            )

    def test_committed_operation_requires_result_hash(self) -> None:
        self.ledger.reserve("op-no-result")
        self.ledger.commit("op-no-result")
        with self.assertRaisesRegex(ValueError, "requires result_hash"):
            self.chain.append(
                self.ledger,
                "op-no-result",
                request_hash=REQUEST_HASH,
                context_hash=CONTEXT_HASH,
            )

    def test_aborted_operation_can_be_recorded_without_result(self) -> None:
        self.ledger.reserve("op-aborted")
        self.ledger.abort("op-aborted")
        receipt = self.chain.append(
            self.ledger,
            "op-aborted",
            request_hash=REQUEST_HASH,
            context_hash=CONTEXT_HASH,
        )
        self.assertEqual(receipt.operation_status, OperationStatus.ABORTED.value)
        self.assertIsNone(receipt.result_hash)
        self.assertTrue(
            verify_receipt_chain(
                self.chain.receipts,
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
                ledger=self.ledger,
            )
        )

    def test_indeterminate_operation_can_be_recorded_without_result(self) -> None:
        self.ledger.reserve("op-unknown", cost=2)
        self.ledger.mark_indeterminate("op-unknown")
        receipt = self.chain.append(
            self.ledger,
            "op-unknown",
            request_hash=REQUEST_HASH,
            context_hash=CONTEXT_HASH,
        )
        self.assertEqual(receipt.operation_status, OperationStatus.INDETERMINATE.value)
        self.assertIsNone(receipt.result_hash)
        self.assertEqual(self.ledger.snapshot.indeterminate_budget, 2)

    def test_non_committed_operation_rejects_result_hash(self) -> None:
        self.ledger.reserve("op-abort-result")
        self.ledger.abort("op-abort-result")
        with self.assertRaisesRegex(ValueError, "must not include result_hash"):
            self.chain.append(
                self.ledger,
                "op-abort-result",
                request_hash=REQUEST_HASH,
                context_hash=CONTEXT_HASH,
                result_hash=RESULT_HASH,
            )

    def test_duplicate_receipt_for_same_operation_is_rejected(self) -> None:
        self._commit_and_append("op-duplicate-receipt")
        with self.assertRaisesRegex(ValueError, "already has a receipt"):
            self.chain.append(
                self.ledger,
                "op-duplicate-receipt",
                request_hash=REQUEST_HASH,
                context_hash=CONTEXT_HASH,
                result_hash=RESULT_HASH,
            )

    def test_malformed_digest_is_rejected(self) -> None:
        self.ledger.reserve("op-bad-digest")
        self.ledger.commit("op-bad-digest")
        with self.assertRaisesRegex(ValueError, "request_hash"):
            self.chain.append(
                self.ledger,
                "op-bad-digest",
                request_hash="not-a-digest",
                context_hash=CONTEXT_HASH,
                result_hash=RESULT_HASH,
            )

    def test_receipt_field_tampering_invalidates_signature(self) -> None:
        receipt = self._commit_and_append("op-tamper")
        tampered = replace(receipt, request_hash="e" * 64)
        self.assertFalse(
            verify_receipt_chain(
                (tampered,),
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
            )
        )

    def test_wrong_executor_key_is_rejected(self) -> None:
        self._commit_and_append("op-wrong-executor")
        _, wrong_public = generate_ed25519_keypair()
        self.assertFalse(
            verify_receipt_chain(
                self.chain.receipts,
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=wrong_public,
            )
        )

    def test_wrong_issuer_key_is_rejected(self) -> None:
        self._commit_and_append("op-wrong-issuer")
        _, wrong_public = generate_ed25519_keypair()
        self.assertFalse(
            verify_receipt_chain(
                self.chain.receipts,
                lease=self.lease,
                issuer_public_key_bytes=wrong_public,
                executor_public_key_bytes=self.executor_public,
            )
        )

    def test_previous_hash_tampering_is_rejected(self) -> None:
        first = self._commit_and_append("op-link-1")
        self.ledger.reserve("op-link-2")
        self.ledger.commit("op-link-2")
        second = self.chain.append(
            self.ledger,
            "op-link-2",
            request_hash=REQUEST_HASH,
            context_hash=CONTEXT_HASH,
            result_hash=RESULT_HASH,
        )
        tampered_second = replace(second, previous_receipt_hash="f" * 64)
        self.assertFalse(
            verify_receipt_chain(
                (first, tampered_second),
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
            )
        )

    def test_reordering_receipts_is_rejected(self) -> None:
        self._commit_and_append("op-order-1")
        self._commit_and_append("op-order-2")
        self.assertFalse(
            verify_receipt_chain(
                tuple(reversed(self.chain.receipts)),
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
            )
        )

    def test_ledger_completeness_check_rejects_missing_receipt(self) -> None:
        self._commit_and_append("op-complete-1")
        self._commit_and_append("op-complete-2")
        prefix = self.chain.receipts[:1]
        # A hash chain alone cannot prove its tail was not truncated.
        self.assertTrue(
            verify_receipt_chain(
                prefix,
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
            )
        )
        # Completeness is detectable only when compared with a trusted ledger view.
        self.assertFalse(
            verify_receipt_chain(
                prefix,
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
                ledger=self.ledger,
            )
        )

    def test_ledger_for_different_lease_is_rejected(self) -> None:
        self._commit_and_append("op-mismatch")
        receipt = self.chain.receipts[0]
        # A different ledger cannot be substituted for the receipt's lease.
        other_issuer_private, other_issuer_public = generate_ed25519_keypair()
        other_issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=other_issuer_private,
            root_grant_id="root-other",
        )
        _, holder_public = generate_ed25519_keypair()
        other_lease = other_issuer.issue_leases(
            (LeaseRequest("lease-other", "agent-other", encode_public_key(holder_public), 4),),
            issued_at=NOW,
            expires_at=EXPIRES,
        )[0]
        other_ledger = LocalBudgetLedger(
            other_lease, other_issuer_public, clock=lambda: NOW + 1
        )
        self.assertFalse(
            verify_receipt_chain(
                (receipt,),
                lease=self.lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=self.executor_public,
                ledger=other_ledger,
            )
        )

    def test_append_rejects_ledger_for_different_lease(self) -> None:
        other_issuer_private, other_issuer_public = generate_ed25519_keypair()
        other_issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=other_issuer_private,
            root_grant_id="root-other-append",
        )
        _, holder_public = generate_ed25519_keypair()
        other_lease = other_issuer.issue_leases(
            (LeaseRequest("lease-other-append", "agent-other", encode_public_key(holder_public), 4),),
            issued_at=NOW,
            expires_at=EXPIRES,
        )[0]
        other_ledger = LocalBudgetLedger(
            other_lease, other_issuer_public, clock=lambda: NOW + 1
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.chain.append(
                other_ledger,
                "missing",
                request_hash=REQUEST_HASH,
                context_hash=CONTEXT_HASH,
            )

    def test_receipt_chain_head_hash_tracks_last_receipt(self) -> None:
        self.assertEqual(self.chain.head_hash, "0" * 64)
        receipt = self._commit_and_append("op-head")
        self.assertEqual(self.chain.head_hash, receipt.receipt_hash)

    def test_receipt_chain_rejects_invalid_lease_signature_at_creation(self) -> None:
        _, wrong_issuer_public = generate_ed25519_keypair()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            ReceiptChain(
                self.lease,
                wrong_issuer_public,
                self.executor_private,
                clock=lambda: NOW + 2,
            )


if __name__ == "__main__":
    unittest.main()
