from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from budget_lab import (
    BudgetIssuer,
    DuplicateOperationError,
    InsufficientBudgetError,
    InvalidOperationTransition,
    LeaseRequest,
    LocalBudgetLedger,
    OperationStatus,
    generate_ed25519_keypair,
)
from budget_lab.crypto import encode_public_key


NOW = 1_800_000_000
EXPIRES = NOW + 3_600
SCHEMA_HASH = "a" * 64


class LocalBudgetLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer_private_key, self.issuer_public_key = generate_ed25519_keypair()
        self.issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=self.issuer_private_key,
            root_grant_id="root-e02-test",
        )
        _, holder_public_key = generate_ed25519_keypair()
        request = LeaseRequest(
            lease_id="lease-A",
            agent_id="agent-A",
            holder_public_key=encode_public_key(holder_public_key),
            allocated_budget=4,
        )
        self.lease = self.issuer.issue_leases(
            (request,), issued_at=NOW, expires_at=EXPIRES
        )[0]
        self.clock_value = NOW + 1
        self.ledger = LocalBudgetLedger(
            self.lease,
            self.issuer_public_key,
            clock=lambda: self.clock_value,
        )

    def test_initial_snapshot_matches_signed_lease(self) -> None:
        snapshot = self.ledger.snapshot
        self.assertEqual(snapshot.lease_id, "lease-A")
        self.assertEqual(snapshot.allocated_budget, 4)
        self.assertEqual(snapshot.available_budget, 4)
        self.assertEqual(snapshot.committed_budget, 0)
        self.assertEqual(snapshot.reserved_budget, 0)
        self.assertEqual(snapshot.indeterminate_budget, 0)
        self.assertEqual(snapshot.next_sequence, 1)

    def test_invalid_issuer_signature_is_rejected(self) -> None:
        _, wrong_public_key = generate_ed25519_keypair()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            LocalBudgetLedger(
                self.lease, wrong_public_key, clock=lambda: NOW + 1
            )

    def test_lease_not_yet_valid_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not valid yet"):
            LocalBudgetLedger(
                self.lease, self.issuer_public_key, clock=lambda: NOW - 1
            )

    def test_expired_lease_is_rejected_at_initialization(self) -> None:
        with self.assertRaisesRegex(ValueError, "expired"):
            LocalBudgetLedger(
                self.lease, self.issuer_public_key, clock=lambda: EXPIRES
            )

    def test_reservation_reduces_available_budget(self) -> None:
        operation = self.ledger.reserve("op-001")
        self.assertEqual(operation.sequence, 1)
        self.assertEqual(operation.cost, 1)
        self.assertIs(operation.status, OperationStatus.RESERVED)
        self.assertEqual(self.ledger.snapshot.available_budget, 3)
        self.assertEqual(self.ledger.snapshot.reserved_budget, 1)

    def test_reservation_rejects_cost_above_available_budget(self) -> None:
        before = self.ledger.snapshot
        with self.assertRaises(InsufficientBudgetError):
            self.ledger.reserve("op-too-large", cost=5)
        self.assertEqual(self.ledger.snapshot, before)
        self.assertIsNone(self.ledger.get_operation("op-too-large"))

    def test_reservation_rejects_bool_and_non_positive_cost(self) -> None:
        for invalid_cost in (True, False, 0, -1):
            with self.subTest(cost=invalid_cost):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    self.ledger.reserve(f"op-invalid-{invalid_cost}", cost=invalid_cost)

    def test_duplicate_operation_id_is_rejected(self) -> None:
        self.ledger.reserve("op-duplicate")
        before = self.ledger.snapshot
        with self.assertRaises(DuplicateOperationError):
            self.ledger.reserve("op-duplicate")
        self.assertEqual(self.ledger.snapshot, before)

    def test_operation_id_cannot_be_reused_after_abort(self) -> None:
        self.ledger.reserve("op-aborted")
        self.ledger.abort("op-aborted")
        with self.assertRaises(DuplicateOperationError):
            self.ledger.reserve("op-aborted")
        self.assertEqual(self.ledger.snapshot.available_budget, 4)

    def test_commit_keeps_budget_consumed(self) -> None:
        self.ledger.reserve("op-commit", cost=2)
        committed = self.ledger.commit("op-commit")
        self.assertIs(committed.status, OperationStatus.COMMITTED)
        snapshot = self.ledger.snapshot
        self.assertEqual(snapshot.committed_budget, 2)
        self.assertEqual(snapshot.reserved_budget, 0)
        self.assertEqual(snapshot.available_budget, 2)

    def test_repeated_commit_is_idempotent(self) -> None:
        self.ledger.reserve("op-commit-retry")
        first = self.ledger.commit("op-commit-retry")
        second = self.ledger.commit("op-commit-retry")
        self.assertEqual(first, second)
        self.assertEqual(self.ledger.snapshot.committed_budget, 1)

    def test_abort_releases_reserved_budget(self) -> None:
        self.ledger.reserve("op-abort", cost=3)
        aborted = self.ledger.abort("op-abort")
        self.assertIs(aborted.status, OperationStatus.ABORTED)
        snapshot = self.ledger.snapshot
        self.assertEqual(snapshot.reserved_budget, 0)
        self.assertEqual(snapshot.available_budget, 4)
        self.assertEqual(snapshot.aborted_count, 1)

    def test_repeated_abort_is_idempotent(self) -> None:
        self.ledger.reserve("op-abort-retry")
        first = self.ledger.abort("op-abort-retry")
        second = self.ledger.abort("op-abort-retry")
        self.assertEqual(first, second)

    def test_indeterminate_keeps_budget_occupied(self) -> None:
        self.ledger.reserve("op-unknown", cost=2)
        operation = self.ledger.mark_indeterminate("op-unknown")
        self.assertIs(operation.status, OperationStatus.INDETERMINATE)
        snapshot = self.ledger.snapshot
        self.assertEqual(snapshot.indeterminate_budget, 2)
        self.assertEqual(snapshot.reserved_budget, 0)
        self.assertEqual(snapshot.available_budget, 2)

    def test_repeated_indeterminate_transition_is_idempotent(self) -> None:
        self.ledger.reserve("op-unknown-retry")
        first = self.ledger.mark_indeterminate("op-unknown-retry")
        second = self.ledger.mark_indeterminate("op-unknown-retry")
        self.assertEqual(first, second)

    def test_incompatible_terminal_transition_is_rejected(self) -> None:
        self.ledger.reserve("op-terminal")
        self.ledger.abort("op-terminal")
        with self.assertRaises(InvalidOperationTransition):
            self.ledger.commit("op-terminal")
        with self.assertRaises(InvalidOperationTransition):
            self.ledger.mark_indeterminate("op-terminal")

    def test_unknown_operation_transition_is_rejected(self) -> None:
        with self.assertRaises(KeyError):
            self.ledger.commit("missing-op")

    def test_sequence_increments_for_each_accepted_reservation(self) -> None:
        first = self.ledger.reserve("op-seq-1")
        self.ledger.abort("op-seq-1")
        second = self.ledger.reserve("op-seq-2")
        self.assertEqual((first.sequence, second.sequence), (1, 2))
        self.assertEqual(self.ledger.snapshot.next_sequence, 3)

    def test_expiry_is_rechecked_when_reserving(self) -> None:
        self.clock_value = EXPIRES
        with self.assertRaisesRegex(ValueError, "expired"):
            self.ledger.reserve("op-after-expiry")
        self.assertEqual(self.ledger.snapshot.available_budget, 4)


    def test_non_finite_clock_value_is_rejected(self) -> None:
        for invalid_now in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(now=invalid_now):
                with self.assertRaisesRegex(ValueError, "finite numeric Unix timestamp"):
                    LocalBudgetLedger(
                        self.lease,
                        self.issuer_public_key,
                        clock=lambda value=invalid_now: value,
                    )

    def test_mixed_operation_states_preserve_budget_invariant(self) -> None:
        self.ledger.reserve("op-mixed-commit", cost=2)
        self.ledger.commit("op-mixed-commit")
        self.ledger.reserve("op-mixed-unknown", cost=1)
        self.ledger.mark_indeterminate("op-mixed-unknown")
        self.ledger.reserve("op-mixed-abort", cost=1)
        self.ledger.abort("op-mixed-abort")

        snapshot = self.ledger.snapshot
        self.assertEqual(snapshot.committed_budget, 2)
        self.assertEqual(snapshot.indeterminate_budget, 1)
        self.assertEqual(snapshot.reserved_budget, 0)
        self.assertEqual(snapshot.available_budget, 1)
        self.assertEqual(snapshot.aborted_count, 1)
        self.assertEqual(
            snapshot.committed_budget
            + snapshot.reserved_budget
            + snapshot.indeterminate_budget
            + snapshot.available_budget,
            snapshot.allocated_budget,
        )

    def test_reserved_operation_can_be_committed_after_lease_expiry(self) -> None:
        self.ledger.reserve("op-before-expiry")
        self.clock_value = EXPIRES
        operation = self.ledger.commit("op-before-expiry")
        self.assertIs(operation.status, OperationStatus.COMMITTED)
        self.assertEqual(self.ledger.snapshot.committed_budget, 1)

    def test_concurrent_distinct_operations_cannot_overreserve(self) -> None:
        # One budget unit remains after three sequential reservations.
        self.ledger.reserve("seed-1")
        self.ledger.reserve("seed-2")
        self.ledger.reserve("seed-3")
        barrier = threading.Barrier(8)

        def try_reserve(index: int) -> str:
            barrier.wait()
            try:
                self.ledger.reserve(f"parallel-{index}")
                return "reserved"
            except InsufficientBudgetError:
                return "denied"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(try_reserve, range(8)))

        self.assertEqual(outcomes.count("reserved"), 1)
        self.assertEqual(outcomes.count("denied"), 7)
        self.assertEqual(self.ledger.snapshot.available_budget, 0)
        self.assertEqual(self.ledger.snapshot.reserved_budget, 4)

    def test_concurrent_same_operation_id_is_accepted_once(self) -> None:
        barrier = threading.Barrier(8)

        def try_reserve(_: int) -> str:
            barrier.wait()
            try:
                self.ledger.reserve("same-op-id")
                return "reserved"
            except DuplicateOperationError:
                return "duplicate"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(try_reserve, range(8)))

        self.assertEqual(outcomes.count("reserved"), 1)
        self.assertEqual(outcomes.count("duplicate"), 7)
        self.assertEqual(len(self.ledger.operations()), 1)
        self.assertEqual(self.ledger.snapshot.reserved_budget, 1)

    def test_operations_are_returned_in_sequence_order(self) -> None:
        self.ledger.reserve("op-order-1")
        self.ledger.reserve("op-order-2")
        self.ledger.reserve("op-order-3")
        self.assertEqual(
            [operation.operation_id for operation in self.ledger.operations()],
            ["op-order-1", "op-order-2", "op-order-3"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
