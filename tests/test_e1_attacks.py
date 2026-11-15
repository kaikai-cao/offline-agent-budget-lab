from __future__ import annotations

import unittest

from budget_lab import (
    BudgetIssuer,
    BudgetReconciler,
    LeaseEvidenceBundle,
    LeaseRequest,
    LocalBudgetLedger,
    ReceiptChain,
    ReconciliationStatus,
    TrustedChainHead,
    generate_ed25519_keypair,
    verify_lease_signature,
    verify_receipt_chain,
)
from budget_lab.crypto import encode_public_key

NOW = 1_800_000_000
EXPIRES = NOW + 3600
SCHEMA_HASH = "a" * 64
REQUEST_HASH_1 = "b" * 64
REQUEST_HASH_2 = "e" * 64
CONTEXT_HASH = "c" * 64
RESULT_HASH_1 = "d" * 64
RESULT_HASH_2 = "f" * 64
ZERO_HASH = "0" * 64


class E1AttackExperiments(unittest.TestCase):
    """Adversarial experiments against the E0 software-only baseline.

    These tests intentionally document both controls that work and attack
    surfaces that remain. A test passing can mean an attack was reproduced and
    classified, not that the attack was prevented.
    """

    def setUp(self) -> None:
        self.issuer_private, self.issuer_public = generate_ed25519_keypair()
        self.issuer = BudgetIssuer(
            root_budget=10,
            cost_unit="query_unit",
            allowed_tool="data.query",
            schema_hash=SCHEMA_HASH,
            private_key=self.issuer_private,
            root_grant_id="root-e1-test",
        )
        self.holder_keys = {}
        requests = []
        for lease_id, agent_id, amount in (
            ("lease-A", "agent-A", 4),
            ("lease-B", "agent-B", 3),
            ("lease-C", "agent-C", 3),
        ):
            holder_private, holder_public = generate_ed25519_keypair()
            self.holder_keys[lease_id] = (holder_private, holder_public)
            requests.append(
                LeaseRequest(
                    lease_id=lease_id,
                    agent_id=agent_id,
                    holder_public_key=encode_public_key(holder_public),
                    allocated_budget=amount,
                )
            )
        self.leases = self.issuer.issue_leases(
            requests, issued_at=NOW, expires_at=EXPIRES
        )
        self.lease_by_id = {lease.lease_id: lease for lease in self.leases}
        self.manifest = self.issuer.create_allocation_manifest(generated_at=NOW + 1)
        self.reconciler = BudgetReconciler()
        self.trusted_executor_private = {}
        self.trusted_executor_keys = {}
        for lease in self.leases:
            private_key, public_key = generate_ed25519_keypair()
            self.trusted_executor_private[lease.lease_id] = private_key
            self.trusted_executor_keys[lease.lease_id] = public_key
        self.actual_tool_effects: list[str] = []

    def make_branch(
        self,
        lease,
        *,
        operation_count: int,
        chain_id: str,
        executor_private=None,
        request_hash: str = REQUEST_HASH_1,
        result_hash: str = RESULT_HASH_1,
        operation_prefix: str | None = None,
    ):
        if executor_private is None:
            executor_private = self.trusted_executor_private[lease.lease_id]
        executor_public = executor_private.public_key().public_bytes_raw()
        ledger = LocalBudgetLedger(
            lease, self.issuer_public, clock=lambda: NOW + 2
        )
        chain = ReceiptChain(
            lease,
            self.issuer_public,
            executor_private,
            chain_id=chain_id,
            clock=lambda: NOW + 3,
        )
        prefix = operation_prefix or lease.lease_id
        for index in range(1, operation_count + 1):
            operation_id = f"{prefix}-op-{index}"
            ledger.reserve(operation_id, cost=1)
            # MockTool effect: count the effect independently of Agent claims.
            self.actual_tool_effects.append(operation_id)
            ledger.commit(operation_id)
            chain.append(
                ledger,
                operation_id,
                request_hash=request_hash,
                context_hash=CONTEXT_HASH,
                result_hash=result_hash,
            )
        head = TrustedChainHead(
            lease_id=lease.lease_id,
            chain_id=chain_id,
            chain_length=len(chain.receipts),
            head_hash=chain.head_hash,
        )
        bundle = LeaseEvidenceBundle(
            lease=lease,
            ledger=ledger,
            receipts=chain.receipts,
            executor_public_key_bytes=executor_public,
            chain_id=chain_id,
            trusted_head=head,
        )
        return ledger, chain, bundle, executor_public

    def empty_bundle(self, lease, *, chain_id: str):
        executor_private = self.trusted_executor_private[lease.lease_id]
        executor_public = executor_private.public_key().public_bytes_raw()
        ledger = LocalBudgetLedger(
            lease, self.issuer_public, clock=lambda: NOW + 2
        )
        chain = ReceiptChain(
            lease,
            self.issuer_public,
            executor_private,
            chain_id=chain_id,
            clock=lambda: NOW + 3,
        )
        head = TrustedChainHead(lease.lease_id, chain_id, 0, ZERO_HASH)
        return LeaseEvidenceBundle(
            lease, ledger, (), executor_public, chain_id, head
        )

    def test_e1_01_same_instance_replay_is_blocked_before_tool_effect(self):
        lease = self.lease_by_id["lease-A"]
        executor_private, executor_public = generate_ed25519_keypair()
        ledger = LocalBudgetLedger(lease, self.issuer_public, clock=lambda: NOW + 2)
        chain = ReceiptChain(
            lease, self.issuer_public, executor_private,
            chain_id="chain-replay", clock=lambda: NOW + 3,
        )

        ledger.reserve("same-operation")
        self.actual_tool_effects.append("same-operation")
        ledger.commit("same-operation")
        chain.append(
            ledger, "same-operation", request_hash=REQUEST_HASH_1,
            context_hash=CONTEXT_HASH, result_hash=RESULT_HASH_1,
        )

        from budget_lab import DuplicateOperationError
        with self.assertRaises(DuplicateOperationError):
            ledger.reserve("same-operation")
            self.actual_tool_effects.append("same-operation")

        self.assertEqual(self.actual_tool_effects.count("same-operation"), 1)
        self.assertEqual(ledger.snapshot.committed_budget, 1)
        self.assertTrue(
            verify_receipt_chain(
                chain.receipts, lease=lease,
                issuer_public_key_bytes=self.issuer_public,
                executor_public_key_bytes=executor_public,
                ledger=ledger,
            )
        )

    def test_e1_02_cloned_ledger_state_allows_two_locally_valid_forks(self):
        lease_a = self.lease_by_id["lease-A"]
        # Simulate copying both the lease and the executor signing key/state.
        cloned_executor_private = self.trusted_executor_private[lease_a.lease_id]
        a1, chain1, bundle1, _ = self.make_branch(
            lease_a, operation_count=3, chain_id="chain-A-cloned",
            executor_private=cloned_executor_private,
            request_hash=REQUEST_HASH_1, result_hash=RESULT_HASH_1,
            operation_prefix="same-cloned-state",
        )
        a2, chain2, bundle2, _ = self.make_branch(
            lease_a, operation_count=3, chain_id="chain-A-cloned",
            executor_private=cloned_executor_private,
            request_hash=REQUEST_HASH_2, result_hash=RESULT_HASH_2,
            operation_prefix="same-cloned-state",
        )
        self.assertEqual(a1.snapshot.committed_budget, 3)
        self.assertEqual(a2.snapshot.committed_budget, 3)
        self.assertEqual(len(self.actual_tool_effects), 6)
        self.assertGreater(
            a1.snapshot.committed_budget + a2.snapshot.committed_budget,
            lease_a.allocated_budget,
        )
        # Both branches are independently well-formed and locally verifiable.
        self.assertTrue(verify_receipt_chain(
            chain1.receipts, lease=lease_a,
            issuer_public_key_bytes=self.issuer_public,
            executor_public_key_bytes=bundle1.executor_public_key_bytes,
            ledger=a1,
        ))
        self.assertTrue(verify_receipt_chain(
            chain2.receipts, lease=lease_a,
            issuer_public_key_bytes=self.issuer_public,
            executor_public_key_bytes=bundle2.executor_public_key_bytes,
            ledger=a2,
        ))

        # Reconciler's current one-bundle-per-lease model detects both submitted forks.
        b_bundle = self.make_branch(
            self.lease_by_id["lease-B"], operation_count=3, chain_id="chain-B"
        )[2]
        c_bundle = self.make_branch(
            self.lease_by_id["lease-C"], operation_count=3, chain_id="chain-C"
        )[2]
        self.assertEqual(len(self.actual_tool_effects), 12)
        report = self.reconciler.reconcile(
            self.manifest, (bundle1, bundle2, b_bundle, c_bundle),
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)
        self.assertTrue(any("duplicate evidence bundle" in item for item in report.findings))

    def test_e1_03_reconstructed_ledger_resets_local_spend_state(self):
        lease = self.lease_by_id["lease-A"]
        first, _, first_bundle, _ = self.make_branch(
            lease, operation_count=3, chain_id="chain-before-rollback",
            operation_prefix="rollback-op",
        )
        # Reconstructing a new in-memory ledger from the same valid lease resets spend to zero.
        restored, _, restored_bundle, _ = self.make_branch(
            lease, operation_count=3, chain_id="chain-after-rollback",
            operation_prefix="rollback-op-restored",
        )
        self.assertEqual(first.snapshot.committed_budget, 3)
        self.assertEqual(restored.snapshot.committed_budget, 3)
        self.assertEqual(len(self.actual_tool_effects), 6)
        self.assertGreater(
            first.snapshot.committed_budget + restored.snapshot.committed_budget,
            lease.allocated_budget,
        )
        report = self.reconciler.reconcile(
            self.manifest,
            (first_bundle, restored_bundle,
             self.empty_bundle(self.lease_by_id["lease-B"], chain_id="chain-B-empty"),
             self.empty_bundle(self.lease_by_id["lease-C"], chain_id="chain-C-empty")),
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)
        self.assertTrue(any("duplicate evidence bundle" in item for item in report.findings))

    def test_e1_04_evidence_cannot_self_select_executor_trust_key(self):
        lease = self.lease_by_id["lease-A"]
        pinned_executor_public = self.trusted_executor_keys["lease-A"]
        attacker_private, attacker_public = generate_ed25519_keypair()
        self.assertNotEqual(pinned_executor_public, attacker_public)
        attacker_bundle = self.make_branch(
            lease, operation_count=1, chain_id="chain-unauthorized-signer",
            executor_private=attacker_private,
        )[2]
        bundles = (
            attacker_bundle,
            self.empty_bundle(self.lease_by_id["lease-B"], chain_id="chain-B-empty"),
            self.empty_bundle(self.lease_by_id["lease-C"], chain_id="chain-C-empty"),
        )
        report = self.reconciler.reconcile(
            self.manifest, bundles,
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )
        # The verifier must not trust the public key supplied inside the evidence.
        # The attacker key is not present in the independently pinned registry.
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)
        self.assertTrue(any(
            "does not match the independently trusted key" in item
            for item in report.findings
        ))
        self.assertEqual(attacker_bundle.executor_public_key_bytes, attacker_public)

    def test_e1_05_issuer_state_fork_can_overallocate_under_same_root_key(self):
        # Two restored Issuer instances share root identity and signing key but
        # each has fresh in-memory allocated_budget=0 state.
        issuer1 = BudgetIssuer(
            root_budget=10, cost_unit="query_unit", allowed_tool="data.query",
            schema_hash=SCHEMA_HASH, private_key=self.issuer_private,
            root_grant_id="forked-root",
        )
        issuer2 = BudgetIssuer(
            root_budget=10, cost_unit="query_unit", allowed_tool="data.query",
            schema_hash=SCHEMA_HASH, private_key=self.issuer_private,
            root_grant_id="forked-root",
        )
        _, holder_a = generate_ed25519_keypair()
        _, holder_b = generate_ed25519_keypair()
        lease1 = issuer1.issue_leases(
            (LeaseRequest("fork-lease-A", "agent-A", encode_public_key(holder_a), 7),),
            issued_at=NOW, expires_at=EXPIRES,
        )[0]
        lease2 = issuer2.issue_leases(
            (LeaseRequest("fork-lease-B", "agent-B", encode_public_key(holder_b), 7),),
            issued_at=NOW, expires_at=EXPIRES,
        )[0]
        self.assertTrue(verify_lease_signature(lease1, self.issuer_public))
        self.assertTrue(verify_lease_signature(lease2, self.issuer_public))
        self.assertEqual(issuer1.snapshot.allocated_budget, 7)
        self.assertEqual(issuer2.snapshot.allocated_budget, 7)
        self.assertGreater(lease1.allocated_budget + lease2.allocated_budget, 10)

    def test_e1_06_truncated_receipt_prefix_needs_independent_checkpoint(self):
        lease = self.lease_by_id["lease-A"]
        ledger, chain, full_bundle, executor_public = self.make_branch(
            lease, operation_count=2, chain_id="chain-truncation",
            operation_prefix="truncation-op",
        )
        prefix = chain.receipts[:1]
        # The prefix is internally valid when no complete ledger/checkpoint is supplied.
        self.assertTrue(verify_receipt_chain(
            prefix, lease=lease,
            issuer_public_key_bytes=self.issuer_public,
            executor_public_key_bytes=executor_public,
        ))
        # But the independently expected full head rejects the submitted prefix.
        truncated_bundle = LeaseEvidenceBundle(
            lease, ledger, prefix, executor_public, chain.chain_id, full_bundle.trusted_head
        )
        report = self.reconciler.reconcile(
            self.manifest,
            (truncated_bundle,
             self.empty_bundle(self.lease_by_id["lease-B"], chain_id="chain-B-empty"),
             self.empty_bundle(self.lease_by_id["lease-C"], chain_id="chain-C-empty")),
            issuer_public_key_bytes=self.issuer_public,
            trusted_executor_keys=self.trusted_executor_keys,
        )
        self.assertEqual(report.status, ReconciliationStatus.REJECTED)


if __name__ == "__main__":
    unittest.main()
