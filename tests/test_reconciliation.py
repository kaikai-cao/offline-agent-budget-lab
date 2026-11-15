from __future__ import annotations

import base64
import unittest
from dataclasses import replace

from budget_lab import (
    BudgetIssuer, BudgetReconciler, LeaseEvidenceBundle, LeaseRequest,
    LocalBudgetLedger, OperationStatus, ReceiptChain, ReconciliationStatus,
    TrustedChainHead, encode_public_key, generate_ed25519_keypair,
    verify_allocation_manifest,
)

NOW = 1_800_000_000
EXPIRES = NOW + 3600
SCHEMA_HASH = "a" * 64
REQUEST_HASH = "b" * 64
CONTEXT_HASH = "c" * 64
RESULT_HASH = "d" * 64


class BudgetReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer_private, self.issuer_public = generate_ed25519_keypair()
        self.issuer = BudgetIssuer(
            root_budget=10, cost_unit="query_unit", allowed_tool="data.query",
            schema_hash=SCHEMA_HASH, private_key=self.issuer_private,
            root_grant_id="root-e04-test",
        )
        requests = []
        for lease_id, agent_id, budget in (("lease-A", "agent-A", 4), ("lease-B", "agent-B", 3), ("lease-C", "agent-C", 3)):
            _, holder_public = generate_ed25519_keypair()
            requests.append(LeaseRequest(lease_id, agent_id, encode_public_key(holder_public), budget))
        self.leases = self.issuer.issue_leases(tuple(requests), issued_at=NOW, expires_at=EXPIRES)
        self.manifest = self.issuer.create_allocation_manifest(generated_at=NOW + 1, manifest_id="manifest-e04-test")
        self.reconciler = BudgetReconciler()
        self.trusted_executor_keys = {}

    def make_bundle(self, lease, *, committed=0, aborted=0, indeterminate=0, reserved=0, include_anchor=True):
        ledger = LocalBudgetLedger(lease, self.issuer_public, clock=lambda: NOW + 2)
        executor_private, executor_public = generate_ed25519_keypair()
        # This represents a separately administered trust configuration, not
        # a value learned from the evidence bundle at reconciliation time.
        self.trusted_executor_keys[lease.lease_id] = executor_public
        chain_id = f"chain-{lease.lease_id}"
        chain = ReceiptChain(lease, self.issuer_public, executor_private, chain_id=chain_id, clock=lambda: NOW + 3)
        sequence = 0

        def add_operation(status):
            nonlocal sequence
            sequence += 1
            operation_id = f"{lease.lease_id}-op-{sequence}"
            ledger.reserve(operation_id)
            result_hash = None
            if status is OperationStatus.COMMITTED:
                ledger.commit(operation_id)
                result_hash = RESULT_HASH
            elif status is OperationStatus.ABORTED:
                ledger.abort(operation_id)
            elif status is OperationStatus.INDETERMINATE:
                ledger.mark_indeterminate(operation_id)
            if status is not OperationStatus.RESERVED:
                chain.append(ledger, operation_id, request_hash=REQUEST_HASH,
                             context_hash=CONTEXT_HASH, result_hash=result_hash)

        for _ in range(committed): add_operation(OperationStatus.COMMITTED)
        for _ in range(aborted): add_operation(OperationStatus.ABORTED)
        for _ in range(indeterminate): add_operation(OperationStatus.INDETERMINATE)
        for _ in range(reserved): add_operation(OperationStatus.RESERVED)
        receipts = chain.receipts
        anchor = TrustedChainHead(lease.lease_id, chain_id, len(receipts), chain.head_hash) if include_anchor else None
        return LeaseEvidenceBundle(lease, ledger, receipts, executor_public, chain_id, anchor)

    def complete_bundles(self):
        return (
            self.make_bundle(self.leases[0], committed=2),
            self.make_bundle(self.leases[1], committed=1, aborted=1),
            self.make_bundle(self.leases[2], committed=2),
        )

    def run_reconcile(self, bundles=None):
        return self.reconciler.reconcile(
            self.manifest, self.complete_bundles() if bundles is None else bundles,
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )

    def test_manifest_covers_all_issued_leases_and_verifies(self):
        self.assertTrue(verify_allocation_manifest(self.manifest, self.issuer_public))
        self.assertEqual(self.manifest.allocated_budget, 10)
        self.assertEqual([entry.lease_id for entry in self.manifest.entries], ["lease-A", "lease-B", "lease-C"])

    def test_manifest_round_trip(self):
        restored = type(self.manifest).from_dict(self.manifest.to_dict())
        self.assertEqual(restored, self.manifest)
        self.assertTrue(verify_allocation_manifest(restored, self.issuer_public))
        self.assertEqual(restored.manifest_hash, self.manifest.manifest_hash)

    def test_manifest_signature_tampering_rejected(self):
        tampered = replace(self.manifest, issuer_signature=base64.b64encode(b"x" * 64).decode("ascii"))
        self.assertFalse(verify_allocation_manifest(tampered, self.issuer_public))

    def test_manifest_parser_rejects_unknown_fields(self):
        data = self.manifest.to_dict(); data["unknown"] = 1
        with self.assertRaisesRegex(ValueError, "invalid manifest fields"):
            type(self.manifest).from_dict(data)

    def test_valid_three_agent_reconciliation_accepted(self):
        bundles = self.complete_bundles()
        # The trusted Executor/Proxy may be distinct from the Agent holding
        # the lease; acceptance depends on the external pinned key, not equality
        # with the holder key in the lease.
        for bundle in bundles:
            holder_public = base64.b64decode(bundle.lease.holder_public_key)
            self.assertNotEqual(bundle.executor_public_key_bytes, holder_public)
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.ACCEPTED)
        self.assertEqual((report.root_budget, report.allocated_budget), (10, 10))
        self.assertEqual((report.committed_budget, report.reserved_budget, report.indeterminate_budget), (5, 0, 0))
        self.assertEqual(report.occupied_budget, 5)
        self.assertEqual(report.unallocated_budget, 0)
        self.assertTrue(all(row.checkpoint_verified for row in report.leases))

    def test_aborted_operations_do_not_count_as_spent(self):
        bundles = (self.make_bundle(self.leases[0], committed=1, aborted=2), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2]))
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.ACCEPTED)
        self.assertEqual(report.committed_budget, 1)
        self.assertEqual(report.leases[0].aborted_count, 2)

    def test_missing_manifest_lease_bundle_is_incomplete(self):
        report = self.run_reconcile(self.complete_bundles()[:2])
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)
        self.assertTrue(any("missing manifest lease bundles" in x for x in report.findings))

    def test_duplicate_bundle_is_rejected(self):
        a = self.make_bundle(self.leases[0])
        report = self.run_reconcile((a, a, self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_unmanifested_extra_lease_bundle_is_rejected(self):
        other_private, other_public = generate_ed25519_keypair()
        other_issuer = BudgetIssuer(
            root_budget=1, cost_unit="query_unit", allowed_tool="data.query",
            schema_hash=SCHEMA_HASH, private_key=other_private, root_grant_id="other-root",
        )
        _, holder_public = generate_ed25519_keypair()
        extra_lease = other_issuer.issue_leases(
            (LeaseRequest("lease-extra", "agent-extra", encode_public_key(holder_public), 1),),
            issued_at=NOW, expires_at=EXPIRES,
        )[0]
        extra_bundle = LocalBudgetLedger(extra_lease, other_public, clock=lambda: NOW + 2)
        _, executor_public = generate_ed25519_keypair()
        bundle = LeaseEvidenceBundle(
            extra_lease, extra_bundle, (), executor_public, "chain-extra",
            TrustedChainHead("lease-extra", "chain-extra", 0, "0" * 64),
        )
        report = self.run_reconcile(self.complete_bundles() + (bundle,))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_wrong_issuer_key_rejected(self):
        _, wrong_public = generate_ed25519_keypair()
        report = self.reconciler.reconcile(
            self.manifest, self.complete_bundles(),
            issuer_public_key_bytes=wrong_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_lease_credential_must_match_manifest(self):
        bundle = self.make_bundle(self.leases[0], committed=1)
        altered = replace(bundle.lease, allocated_budget=3)
        report = self.run_reconcile((replace(bundle, lease=altered), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_missing_terminal_receipt_rejected(self):
        bundle = self.make_bundle(self.leases[0], committed=2)
        report = self.run_reconcile((replace(bundle, receipts=bundle.receipts[:1]), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_tampered_receipt_signature_rejected(self):
        bundle = self.make_bundle(self.leases[0], committed=1)
        tampered = replace(bundle.receipts[0], request_hash="e" * 64)
        report = self.run_reconcile((replace(bundle, receipts=(tampered,)), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_missing_trusted_head_is_incomplete(self):
        bundles = (self.make_bundle(self.leases[0], committed=1, include_anchor=False), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2]))
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)
        self.assertFalse(report.leases[0].checkpoint_verified)

    def test_wrong_trusted_head_is_rejected(self):
        bundle = self.make_bundle(self.leases[0], committed=1)
        wrong = replace(bundle.trusted_head, head_hash="f" * 64)
        report = self.run_reconcile((replace(bundle, trusted_head=wrong), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_wrong_chain_id_is_rejected(self):
        bundle = self.make_bundle(self.leases[0], committed=1)
        report = self.run_reconcile((replace(bundle, chain_id="other-chain"), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_reserved_operation_makes_report_incomplete_and_occupies_budget(self):
        bundles = (self.make_bundle(self.leases[0], committed=1, reserved=1), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2]))
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)
        self.assertEqual(report.reserved_budget, 1)
        self.assertEqual(report.occupied_budget, 2)

    def test_indeterminate_operation_makes_report_incomplete_and_occupies_budget(self):
        bundles = (self.make_bundle(self.leases[0], committed=1, indeterminate=1), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2]))
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)
        self.assertEqual(report.indeterminate_budget, 1)
        self.assertEqual(report.occupied_budget, 2)

    def test_missing_anchor_does_not_accept_rolled_back_prefix(self):
        prefix = self.make_bundle(self.leases[0], committed=1, include_anchor=False)
        report = self.run_reconcile((prefix, self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)

    def test_independent_anchor_detects_prefix_rollback(self):
        # The trusted head describes a two-receipt chain, while the submitted
        # (rolled-back) local ledger and receipt package contain only one.
        full = self.make_bundle(self.leases[0], committed=2)
        prefix = self.make_bundle(self.leases[0], committed=1, include_anchor=False)
        report = self.run_reconcile((replace(prefix, trusted_head=full.trusted_head), self.make_bundle(self.leases[1]), self.make_bundle(self.leases[2])))
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)

    def test_empty_chains_can_be_reconciled_with_trusted_empty_heads(self):
        report = self.run_reconcile(tuple(self.make_bundle(lease) for lease in self.leases))
        self.assertEqual(report.status, ReconciliationStatus.ACCEPTED)
        self.assertEqual(report.committed_budget, 0)

    def test_missing_trusted_executor_key_is_incomplete_and_fails_closed(self):
        bundles = self.complete_bundles()
        report = self.reconciler.reconcile(
            self.manifest, bundles,
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys={},
        )
        self.assertEqual(report.status, ReconciliationStatus.INCOMPLETE)
        self.assertTrue(any("no independently trusted executor key" in item for item in report.findings))

    def test_evidence_bundle_cannot_replace_pinned_executor_key(self):
        from dataclasses import replace
        bundle = self.make_bundle(self.leases[0], committed=1)
        _, attacker_public = generate_ed25519_keypair()
        self.assertNotEqual(bundle.executor_public_key_bytes, attacker_public)
        tampered_bundle = replace(bundle, executor_public_key_bytes=attacker_public)
        bundles = (
            tampered_bundle,
            self.make_bundle(self.leases[1]),
            self.make_bundle(self.leases[2]),
        )
        report = self.run_reconcile(bundles)
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)
        self.assertTrue(any("does not match the independently trusted key" in item for item in report.findings))

    def test_empty_issuer_cannot_create_manifest(self):
        empty = BudgetIssuer(root_budget=10, cost_unit="query_unit", allowed_tool="data.query", schema_hash=SCHEMA_HASH, private_key=self.issuer_private, root_grant_id="empty")
        with self.assertRaisesRegex(ValueError, "without issued leases"):
            empty.create_allocation_manifest(generated_at=NOW + 1)

    def test_manifest_timestamp_rejects_bool(self):
        with self.assertRaisesRegex(ValueError, "positive Unix timestamp"):
            self.issuer.create_allocation_manifest(generated_at=True)

    def test_manifest_creation_freezes_future_lease_issuance(self):
        _, holder_public = generate_ed25519_keypair()
        before = self.issuer.snapshot
        with self.assertRaisesRegex(RuntimeError, "issuance is frozen"):
            self.issuer.issue_leases(
                (LeaseRequest("lease-late", "agent-late", encode_public_key(holder_public), 1),),
                issued_at=NOW,
                expires_at=EXPIRES,
            )
        self.assertEqual(self.issuer.snapshot, before)
        self.assertIsNone(self.issuer.get_lease("lease-late"))


if __name__ == "__main__":
    unittest.main()
