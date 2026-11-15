from __future__ import annotations

import unittest
from dataclasses import replace

from budget_lab import (
    BudgetIssuer,
    BudgetLease,
    LeaseLedgerState,
    LeaseRequest,
    generate_ed25519_keypair,
    verify_lease_signature,
)
from budget_lab.crypto import encode_public_key


NOW = 1_800_000_000
EXPIRES = NOW + 3_600
SCHEMA_HASH = "a" * 64


class BudgetIssuerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer_private_key, self.issuer_public_key = generate_ed25519_keypair()
        self.issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=self.issuer_private_key,
            root_grant_id="root-test-001",
        )

    def make_request(self, lease_id: str, agent_id: str, budget: int) -> LeaseRequest:
        _, holder_public_key = generate_ed25519_keypair()
        return LeaseRequest(
            lease_id=lease_id,
            agent_id=agent_id,
            holder_public_key=encode_public_key(holder_public_key),
            allocated_budget=budget,
        )

    def issue_standard_batch(self) -> tuple[BudgetLease, ...]:
        requests = (
            self.make_request("lease-A", "agent-A", 4),
            self.make_request("lease-B", "agent-B", 3),
            self.make_request("lease-C", "agent-C", 3),
        )
        return self.issuer.issue_leases(requests, issued_at=NOW, expires_at=EXPIRES)

    def test_issue_three_leases_and_verify_signatures(self) -> None:
        leases = self.issue_standard_batch()

        self.assertEqual([lease.allocated_budget for lease in leases], [4, 3, 3])
        self.assertEqual(sum(lease.allocated_budget for lease in leases), 10)
        self.assertEqual(self.issuer.snapshot.allocated_budget, 10)
        self.assertEqual(self.issuer.snapshot.unallocated_budget, 0)

        for lease in leases:
            self.assertTrue(verify_lease_signature(lease, self.issuer_public_key))
            self.assertEqual(lease.root_grant_id, "root-test-001")
            self.assertEqual(lease.parent_grant_id, "root-test-001")
            self.assertEqual(lease.root_budget, 10)
            self.assertEqual(lease.allowed_tool, "data.query")
            self.assertEqual(lease.schema_hash, SCHEMA_HASH)

    def test_oversubscription_is_rejected_without_state_change(self) -> None:
        self.issuer.issue_leases(
            (self.make_request("lease-A", "agent-A", 7),),
            issued_at=NOW,
            expires_at=EXPIRES,
        )
        before = self.issuer.snapshot

        with self.assertRaisesRegex(ValueError, "root budget exceeded"):
            self.issuer.issue_leases(
                (self.make_request("lease-B", "agent-B", 4),),
                issued_at=NOW,
                expires_at=EXPIRES,
            )

        after = self.issuer.snapshot
        self.assertEqual(after, before)
        self.assertIsNone(self.issuer.get_lease("lease-B"))

    def test_duplicate_lease_id_within_batch_is_rejected_atomically(self) -> None:
        request_1 = self.make_request("same-id", "agent-A", 2)
        request_2 = self.make_request("same-id", "agent-B", 2)

        with self.assertRaisesRegex(ValueError, "unique within a batch"):
            self.issuer.issue_leases(
                (request_1, request_2), issued_at=NOW, expires_at=EXPIRES
            )

        self.assertEqual(self.issuer.snapshot.allocated_budget, 0)
        self.assertEqual(self.issuer.snapshot.lease_count, 0)

    def test_previously_issued_lease_id_cannot_be_reused(self) -> None:
        first = self.make_request("lease-A", "agent-A", 2)
        self.issuer.issue_leases((first,), issued_at=NOW, expires_at=EXPIRES)

        replacement = self.make_request("lease-A", "agent-B", 1)
        with self.assertRaisesRegex(ValueError, "already issued"):
            self.issuer.issue_leases(
                (replacement,), issued_at=NOW, expires_at=EXPIRES
            )

        self.assertEqual(self.issuer.snapshot.allocated_budget, 2)
        self.assertEqual(self.issuer.snapshot.lease_count, 1)

    def test_signature_fails_after_credential_field_tampering(self) -> None:
        lease = self.issue_standard_batch()[0]
        tampered = replace(lease, allocated_budget=lease.allocated_budget - 1)

        self.assertFalse(verify_lease_signature(tampered, self.issuer_public_key))

    def test_signature_fails_with_wrong_issuer_key(self) -> None:
        lease = self.issue_standard_batch()[0]
        _, wrong_public_key = generate_ed25519_keypair()

        self.assertFalse(verify_lease_signature(lease, wrong_public_key))

    def test_credential_json_round_trip(self) -> None:
        lease = self.issue_standard_batch()[0]
        restored = BudgetLease.from_dict(lease.to_dict())

        self.assertEqual(restored, lease)
        self.assertTrue(verify_lease_signature(restored, self.issuer_public_key))

    def test_credential_parser_rejects_unknown_fields(self) -> None:
        lease = self.issue_standard_batch()[0]
        data = lease.to_dict()
        data["untrusted_extra"] = "unexpected"

        with self.assertRaisesRegex(ValueError, "unknown fields"):
            BudgetLease.from_dict(data)

    def test_invalid_request_budget_bool_is_rejected(self) -> None:
        _, holder_public_key = generate_ed25519_keypair()
        with self.assertRaisesRegex(ValueError, "positive integer"):
            LeaseRequest(
                lease_id="lease-bool",
                agent_id="agent-A",
                holder_public_key=encode_public_key(holder_public_key),
                allocated_budget=True,  # type: ignore[arg-type]
            )

    def test_invalid_expiry_is_rejected_without_state_change(self) -> None:
        request = self.make_request("lease-A", "agent-A", 2)
        with self.assertRaisesRegex(ValueError, "later than issued_at"):
            self.issuer.issue_leases((request,), issued_at=NOW, expires_at=NOW)

        self.assertEqual(self.issuer.snapshot.allocated_budget, 0)

    def test_initial_ledger_state_is_derived_from_lease(self) -> None:
        lease = self.issue_standard_batch()[0]
        state = LeaseLedgerState.initial_from_lease(lease)

        self.assertEqual(state.lease_id, lease.lease_id)
        self.assertEqual(state.allocated_budget, 4)
        self.assertEqual(state.spent_budget, 0)
        self.assertEqual(state.remaining_budget, 4)
        self.assertEqual(state.next_sequence, 1)
        self.assertEqual(state.seen_operation_ids, ())
        self.assertIsNone(state.last_receipt_hash)

    def test_ledger_state_rejects_spend_above_allocation(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            LeaseLedgerState(
                lease_id="lease-A",
                allocated_budget=4,
                spent_budget=5,
            )

    def test_request_rejects_non_ed25519_public_key_length(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
            LeaseRequest(
                lease_id="lease-short-key",
                agent_id="agent-A",
                holder_public_key=encode_public_key(b"x" * 31),
                allocated_budget=1,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
