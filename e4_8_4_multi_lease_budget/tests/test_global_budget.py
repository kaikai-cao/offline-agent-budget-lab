from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import base64
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.global_budget import (
    BrokerConfigurationMismatch,
    BrokerIndeterminate,
    GlobalBudgetBroker,
    GlobalBudgetExceeded,
    GlobalBudgetMismatch,
    GrantRejected,
    InjectedCrash,
    LeaseGrant,
    LeaseInactive,
    LeaseNotRegistered,
    LeaseQuotaExceeded,
    LeaseRegistrationConflict,
    LeaseRevocation,
    OperationBindingConflict,
    OperationNotApplied,
    RevocationRejected,
    ToolPermission,
    issue_lease_grant,
    issue_lease_revocation,
)


class GlobalBudgetBrokerTests(unittest.TestCase):
    NOW = 2_000_000_000
    GLOBAL_ID = "budget-epoch-2026-01"
    GLOBAL_QUOTA = 10
    TOOL_PERMISSIONS = (ToolPermission("invoice_review", "sha256:" + "a" * 64),)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="d81-global-budget-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.issuer_private = Ed25519PrivateKey.generate()
        self.now = [self.NOW]
        self.broker = self.make_broker()
        self.grant_index = 0

    def make_broker(self, **overrides):
        args = {
            "global_budget_id": self.GLOBAL_ID,
            "global_quota_limit": self.GLOBAL_QUOTA,
            "issuer_public_key": self.issuer_private.public_key(),
            "journal_path": self.root / "global-journal.sqlite3",
            "counter_state_path": self.root / "global-counter.json",
            "broker_lock_path": self.root / "global-broker.lock",
            "clock": lambda: self.now[0],
        }
        args.update(overrides)
        return GlobalBudgetBroker(**args)

    def make_grant(self, *, lease_id=None, quota=3, grant_id=None, nonce=None,
                   issued_at=None, expires_at=None, global_budget_id=None):
        self.grant_index += 1
        index = self.grant_index
        return issue_lease_grant(
            self.issuer_private,
            issuer_id="issuer-test",
            grant_id=grant_id or f"grant-{index}",
            lease_id=lease_id or f"lease-{index}",
            global_budget_id=global_budget_id or self.GLOBAL_ID,
            nonce=nonce or f"nonce-{index}",
            quota_limit=quota,
            issued_at=self.NOW if issued_at is None else issued_at,
            expires_at=self.NOW + 3600 if expires_at is None else expires_at,
            audience="gateway-test",
            subject_id=f"agent-{index}",
            context_digest="sha256:" + "b" * 64,
            allowed_tools=self.TOOL_PERMISSIONS,
        )

    @staticmethod
    def digest(index: int) -> str:
        return "sha256:" + f"{index:064x}"

    def register(self, *, quota=3, lease_id=None, **kwargs):
        grant = self.make_grant(quota=quota, lease_id=lease_id, **kwargs)
        self.broker.register_lease(grant)
        return grant

    def invariant(self):
        state = self.broker.assert_invariants()
        inspect = self.broker.inspect()
        self.assertEqual(state["reserved"], inspect["reserved_total"])
        self.assertEqual(state["used"], inspect["used_total"])
        self.assertLessEqual(state["reserved"], state["global_quota_limit"])
        self.assertEqual(
            state["used"],
            state["counter_value"] - state["baseline_counter_value"],
        )
        for lease in inspect["leases"]:
            self.assertGreaterEqual(lease["used_count"], 0)
            self.assertLessEqual(lease["used_count"], lease["quota_limit"])
        return state

    def test_signed_v3_lease_registration_and_reconstruction(self):
        grant = self.make_grant(quota=4)
        record = self.broker.register_lease(grant)
        self.assertEqual(record["lease_id"], grant.lease_id)
        self.assertEqual(record["grant_digest"], grant.grant_digest)
        self.assertEqual(record["used_count"], 0)
        restarted = self.make_broker()
        self.assertEqual(restarted.inspect()["reserved_total"], 4)
        self.assertEqual(restarted.inspect()["health"], "READY")

    def test_exact_registration_replay_is_idempotent_even_after_expiry(self):
        grant = self.make_grant(quota=4, expires_at=self.NOW + 5)
        first = self.broker.register_lease(grant)
        self.now[0] += 10
        replay = self.broker.register_lease(grant)
        self.assertEqual(first["grant_digest"], replay["grant_digest"])
        self.assertEqual(self.broker.inspect()["reserved_total"], 4)

    def test_same_lease_id_with_changed_signed_content_is_rejected(self):
        original = self.make_grant(lease_id="lease-fixed", quota=2)
        self.broker.register_lease(original)
        changed = self.make_grant(lease_id="lease-fixed", quota=3)
        with self.assertRaises(LeaseRegistrationConflict):
            self.broker.register_lease(changed)
        self.assertEqual(self.broker.inspect()["reserved_total"], 2)

    def test_duplicate_grant_id_or_nonce_is_rejected_across_leases(self):
        first = self.make_grant(lease_id="lease-A", grant_id="grant-shared", nonce="nonce-A")
        self.broker.register_lease(first)
        second_grant_id = self.make_grant(lease_id="lease-B", grant_id="grant-shared", nonce="nonce-B")
        second_nonce = self.make_grant(lease_id="lease-C", grant_id="grant-C", nonce="nonce-A")
        for grant in (second_grant_id, second_nonce):
            with self.subTest(lease=grant.lease_id):
                with self.assertRaises(LeaseRegistrationConflict):
                    self.broker.register_lease(grant)
        self.assertEqual(self.broker.inspect()["reserved_total"], first.quota_limit)

    def test_invalid_signature_wrong_epoch_and_expired_registration_are_rejected(self):
        valid = self.make_grant(quota=2)
        tampered = replace(valid, quota_limit=3)
        with self.assertRaises(GrantRejected):
            self.broker.register_lease(tampered)
        wrong_epoch = self.make_grant(global_budget_id="another-epoch", quota=2)
        with self.assertRaises(GlobalBudgetMismatch):
            self.broker.register_lease(wrong_epoch)
        expired = self.make_grant(lease_id="lease-expired", quota=2,
                                  issued_at=self.NOW - 100, expires_at=self.NOW - 1)
        with self.assertRaises(GrantRejected):
            self.broker.register_lease(expired)
        self.assertEqual(self.broker.inspect()["reserved_total"], 0)

    def test_version_two_grant_is_not_accepted_by_global_broker(self):
        grant = self.make_grant(quota=2)
        legacy = replace(grant, version=2)
        with self.assertRaises(GrantRejected):
            self.broker.register_lease(legacy)

    def test_reservation_that_exceeds_global_budget_is_atomic(self):
        a = self.make_grant(lease_id="lease-A", quota=6)
        b = self.make_grant(lease_id="lease-B", quota=5)
        self.broker.register_lease(a)
        with self.assertRaises(GlobalBudgetExceeded):
            self.broker.register_lease(b)
        info = self.broker.inspect()
        self.assertEqual(info["reserved_total"], 6)
        self.assertIsNone(self.broker.journal.get_lease("lease-B"))

    def test_concurrent_registrations_never_overreserve_global_budget(self):
        grants = [self.make_grant(lease_id=f"lease-race-{i}", quota=1) for i in range(16)]
        def attempt(grant):
            try:
                self.broker.register_lease(grant)
                return "accepted"
            except GlobalBudgetExceeded:
                return "full"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, grants))
        self.assertEqual(results.count("accepted"), self.GLOBAL_QUOTA)
        self.assertEqual(results.count("full"), len(grants) - self.GLOBAL_QUOTA)
        self.assertEqual(self.broker.inspect()["reserved_total"], self.GLOBAL_QUOTA)
        self.invariant()

    def test_multiple_leases_share_one_unique_global_sequence(self):
        a = self.register(quota=3)
        b = self.register(quota=3)
        r1 = self.broker.consume(a, operation_id="op-A-1", request_digest=self.digest(1))
        r2 = self.broker.consume(b, operation_id="op-B-1", request_digest=self.digest(2))
        r3 = self.broker.consume(a, operation_id="op-A-2", request_digest=self.digest(3))
        self.assertEqual([r1.global_sequence, r2.global_sequence, r3.global_sequence], [1, 2, 3])
        self.assertEqual([r1.lease_used_count, r2.lease_used_count, r3.lease_used_count], [1, 1, 2])
        self.invariant()

    def test_each_lease_has_an_independent_quota(self):
        a = self.register(quota=1)
        b = self.register(quota=2)
        self.broker.consume(a, operation_id="op-A", request_digest=self.digest(1))
        with self.assertRaises(LeaseQuotaExceeded):
            self.broker.consume(a, operation_id="op-A2", request_digest=self.digest(2))
        receipt = self.broker.consume(b, operation_id="op-B", request_digest=self.digest(3))
        self.assertEqual(receipt.global_sequence, 2)
        self.assertEqual(self.broker.inspect()["used_total"], 2)
        self.invariant()

    def test_total_consumption_reaches_global_ceiling_without_exceeding_it(self):
        self.GLOBAL_QUOTA = 2
        self.root = self.root / "global-quota-two"
        self.root.mkdir()
        self.broker = self.make_broker()
        a = self.register(quota=1)
        b = self.register(quota=1)
        self.broker.consume(a, operation_id="op-1", request_digest=self.digest(1))
        self.broker.consume(b, operation_id="op-2", request_digest=self.digest(2))
        self.assertEqual(self.broker.inspect()["used_total"], 2)
        with self.assertRaises(LeaseQuotaExceeded):
            # Each Lease is exhausted exactly when the global ceiling is reached.
            self.broker.consume(a, operation_id="op-3", request_digest=self.digest(3))
        self.invariant()

    def test_exact_operation_replay_returns_same_receipt_without_more_usage(self):
        grant = self.register(quota=3)
        first = self.broker.consume(grant, operation_id="same-op", request_digest=self.digest(1))
        replay = self.broker.consume(grant, operation_id="same-op", request_digest=self.digest(1))
        self.assertEqual(first, replay)
        self.assertEqual(self.broker.counter.read(), 1)
        self.assertEqual(self.broker.journal.get_lease(grant.lease_id)["used_count"], 1)


    def test_committed_replay_detects_receipt_binding_tampering(self):
        grant = self.register(quota=2)
        self.broker.consume(grant, operation_id="receipt-tamper", request_digest=self.digest(1))
        with self.broker.journal._db() as con:
            con.execute(
                "UPDATE receipts SET global_sequence=99 WHERE operation_id=?",
                ("receipt-tamper",),
            )
            con.commit()
        with self.assertRaises(BrokerIndeterminate):
            self.broker.consume(grant, operation_id="receipt-tamper", request_digest=self.digest(1))
        self.assertEqual(self.broker.inspect()["health"], "INDETERMINATE")

    def test_operation_id_is_global_across_leases(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        self.broker.consume(a, operation_id="global-op", request_digest=self.digest(1))
        with self.assertRaises(OperationBindingConflict):
            self.broker.consume(b, operation_id="global-op", request_digest=self.digest(1))
        self.assertEqual(self.broker.counter.read(), 1)

    def test_operation_id_cannot_be_rebound_to_another_request_digest(self):
        grant = self.register(quota=2)
        self.broker.consume(grant, operation_id="bound-op", request_digest=self.digest(1))
        with self.assertRaises(OperationBindingConflict):
            self.broker.consume(grant, operation_id="bound-op", request_digest=self.digest(2))
        self.assertEqual(self.broker.counter.read(), 1)

    def test_global_counter_and_per_lease_usage_commit_atomically(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        self.broker.consume(a, operation_id="op-a", request_digest=self.digest(1))
        self.broker.consume(b, operation_id="op-b", request_digest=self.digest(2))
        info = self.broker.inspect()
        self.assertEqual(info["expected_counter_value"], 2)
        self.assertEqual(info["used_total"], 2)
        self.assertEqual(sum(row["used_count"] for row in info["leases"]), 2)
        self.invariant()

    def test_concurrent_threads_across_leases_get_distinct_sequences(self):
        grants = [self.register(quota=3) for _ in range(3)]
        work = [(grants[i % 3], i) for i in range(9)]
        def consume(item):
            grant, index = item
            return self.broker.consume(
                grant, operation_id=f"thread-op-{index}", request_digest=self.digest(index + 1)
            )
        with ThreadPoolExecutor(max_workers=9) as pool:
            receipts = list(pool.map(consume, work))
        sequences = sorted(receipt.global_sequence for receipt in receipts)
        self.assertEqual(sequences, list(range(1, 10)))
        self.assertEqual(len(set(sequences)), len(sequences))
        self.invariant()

    def test_independent_processes_across_leases_share_one_sequence_domain(self):
        grants = [self.register(quota=3) for _ in range(2)]
        public_raw = self.issuer_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        worker = Path(__file__).with_name("process_worker.py")
        configs = []
        for index, grant in enumerate(grants):
            config_path = self.root / f"worker-{index}.json"
            config = {
                "global_budget_id": self.GLOBAL_ID,
                "global_quota_limit": self.GLOBAL_QUOTA,
                "issuer_public_key_b64": base64.b64encode(public_raw).decode("ascii"),
                "journal_path": str(self.root / "global-journal.sqlite3"),
                "counter_state_path": str(self.root / "global-counter.json"),
                "broker_lock_path": str(self.root / "global-broker.lock"),
                "now": self.now[0],
                "grant": grant.as_dict(),
                "operations": [
                    {"operation_id": f"proc-{index}-{n}", "request_digest": self.digest(index * 10 + n + 1)}
                    for n in range(3)
                ],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            configs.append(config_path)
        processes = [
            subprocess.Popen(
                [sys.executable, str(worker), str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for path in configs
        ]
        all_receipts = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, msg=stderr)
            all_receipts.extend(json.loads(stdout))
        sequences = sorted(item["global_sequence"] for item in all_receipts)
        self.assertEqual(sequences, list(range(1, 7)))
        self.invariant()

    def test_crash_after_intent_does_not_charge_and_new_lease_can_proceed(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        with self.assertRaises(InjectedCrash):
            self.broker.consume(a, operation_id="crash-before-increment", request_digest=self.digest(1), crash_at="after_intent")
        self.assertEqual(self.broker.counter.read(), 0)
        receipt = self.broker.consume(b, operation_id="other-lease-op", request_digest=self.digest(2))
        self.assertEqual(receipt.global_sequence, 1)
        self.assertEqual(self.broker.journal.get_lease(a.lease_id)["used_count"], 0)
        self.assertEqual(self.broker.journal.get_lease(b.lease_id)["used_count"], 1)
        with self.assertRaises(OperationNotApplied):
            self.broker.consume(a, operation_id="crash-before-increment", request_digest=self.digest(1))
        self.invariant()

    def test_crash_after_increment_or_read_recovers_and_charges_original_lease_once(self):
        for crash_point in ("after_increment", "after_read"):
            with self.subTest(crash_point=crash_point):
                tmp = tempfile.TemporaryDirectory(prefix="d81-crash-")
                root_before = self.root
                broker_before = self.broker
                self.root = Path(tmp.name)
                self.addCleanup(tmp.cleanup)
                self.broker = self.make_broker()
                self.grant_index = 0
                a = self.register(quota=2)
                b = self.register(quota=2)
                with self.assertRaises(InjectedCrash):
                    self.broker.consume(a, operation_id=f"crash-{crash_point}", request_digest=self.digest(1), crash_at=crash_point)
                receipt = self.broker.consume(b, operation_id="follow-up", request_digest=self.digest(2))
                self.assertEqual(receipt.global_sequence, 2)
                self.assertEqual(self.broker.journal.get_lease(a.lease_id)["used_count"], 1)
                self.assertEqual(self.broker.journal.get_lease(b.lease_id)["used_count"], 1)
                self.invariant()
                self.root = root_before
                self.broker = broker_before

    def test_crash_after_receipt_commit_replays_same_receipt(self):
        grant = self.register(quota=2)
        with self.assertRaises(InjectedCrash):
            self.broker.consume(grant, operation_id="crash-after-commit", request_digest=self.digest(1), crash_at="after_receipt_commit")
        receipt = self.broker.consume(grant, operation_id="crash-after-commit", request_digest=self.digest(1))
        self.assertEqual(receipt.global_sequence, 1)
        self.assertEqual(receipt.lease_used_count, 1)
        self.assertEqual(self.broker.counter.read(), 1)
        self.invariant()

    def test_multiple_pending_intents_mark_global_broker_indeterminate(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        with self.broker.journal._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO operations(operation_id,lease_id,grant_digest,request_digest,pre_counter_value,status) "
                "VALUES(?,?,?,?,0,'PENDING')",
                ("pending-a", a.lease_id, a.grant_digest, self.digest(1)),
            )
            con.execute(
                "INSERT INTO operations(operation_id,lease_id,grant_digest,request_digest,pre_counter_value,status) "
                "VALUES(?,?,?,?,0,'PENDING')",
                ("pending-b", b.lease_id, b.grant_digest, self.digest(2)),
            )
            con.commit()
        with self.assertRaises(BrokerIndeterminate):
            self.broker.recover_pending()
        self.assertEqual(self.broker.inspect()["health"], "INDETERMINATE")
        with self.assertRaises(BrokerIndeterminate):
            self.broker.consume(a, operation_id="later", request_digest=self.digest(3))

    def test_out_of_band_counter_increment_breaks_global_anchor(self):
        grant = self.register(quota=2)
        self.broker.counter.increment()
        with self.assertRaises(BrokerIndeterminate):
            self.broker.consume(grant, operation_id="after-bypass", request_digest=self.digest(1))
        self.assertEqual(self.broker.inspect()["health"], "INDETERMINATE")

    def test_expired_lease_blocks_new_work_but_pending_intent_is_settled(self):
        old = self.register(quota=2, issued_at=self.NOW, expires_at=self.NOW + 5)
        other = self.register(quota=2, expires_at=self.NOW + 100)
        with self.assertRaises(InjectedCrash):
            self.broker.consume(old, operation_id="pending-before-expiry", request_digest=self.digest(1), crash_at="after_increment")
        self.now[0] += 10
        new_receipt = self.broker.consume(other, operation_id="new-after-expiry", request_digest=self.digest(2))
        self.assertEqual(new_receipt.global_sequence, 2)
        self.assertEqual(self.broker.journal.get_lease(old.lease_id)["used_count"], 1)
        with self.assertRaises(LeaseInactive):
            self.broker.consume(old, operation_id="new-expired-op", request_digest=self.digest(3))
        self.assertEqual(self.broker.journal.get_lease(old.lease_id)["state"], "EXPIRED")
        self.invariant()

    def test_signed_revocation_blocks_new_operations_and_exact_replay_is_idempotent(self):
        grant = self.register(quota=3)
        record = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="revoke-1", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW,
        )
        first = self.broker.revoke_lease(record)
        replay = self.broker.revoke_lease(record)
        self.assertEqual(first["state"], "REVOKED")
        self.assertEqual(replay["state"], "REVOKED")
        self.assertEqual(self.broker.inspect()["reserved_total"], 3)
        with self.assertRaises(LeaseInactive):
            self.broker.consume(grant, operation_id="after-revoke", request_digest=self.digest(1))
        self.invariant()

    def test_revocation_signature_epoch_lease_binding_and_timestamp_are_checked(self):
        grant = self.register(quota=2)
        wrong_key = Ed25519PrivateKey.generate()
        invalid_signature = issue_lease_revocation(
            wrong_key, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="bad-signer", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW,
        )
        with self.assertRaises(RevocationRejected):
            self.broker.revoke_lease(invalid_signature)
        wrong_epoch = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id="other-epoch",
            revocation_id="wrong-epoch", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW,
        )
        with self.assertRaises(GlobalBudgetMismatch):
            self.broker.revoke_lease(wrong_epoch)
        wrong_grant = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="wrong-grant", lease_id=grant.lease_id,
            grant_digest=self.digest(99), revoked_at=self.NOW,
        )
        with self.assertRaises(RevocationRejected):
            self.broker.revoke_lease(wrong_grant)
        future = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="future", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW + 10,
        )
        with self.assertRaises(RevocationRejected):
            self.broker.revoke_lease(future)


    def test_revocation_issuer_label_must_match_registered_grant(self):
        grant = self.register(quota=2)
        record = issue_lease_revocation(
            self.issuer_private, issuer_id="different-issuer-label",
            global_budget_id=self.GLOBAL_ID, revocation_id="wrong-issuer-label",
            lease_id=grant.lease_id, grant_digest=grant.grant_digest,
            revoked_at=self.NOW,
        )
        with self.assertRaises(RevocationRejected):
            self.broker.revoke_lease(record)
        self.assertEqual(self.broker.journal.get_lease(grant.lease_id)["state"], "ACTIVE")

    def test_revocation_id_cannot_be_reused_for_different_content(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        first = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="same-revocation", lease_id=a.lease_id,
            grant_digest=a.grant_digest, revoked_at=self.NOW,
        )
        changed = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="same-revocation", lease_id=b.lease_id,
            grant_digest=b.grant_digest, revoked_at=self.NOW,
        )
        self.broker.revoke_lease(first)
        with self.assertRaises(RevocationRejected):
            self.broker.revoke_lease(changed)

    def test_revocation_or_expiry_does_not_refund_reserved_quota(self):
        grant = self.register(quota=5)
        record = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="no-refund", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW,
        )
        self.broker.revoke_lease(record)
        new_grant = self.make_grant(quota=6)
        with self.assertRaises(GlobalBudgetExceeded):
            self.broker.register_lease(new_grant)
        self.assertEqual(self.broker.inspect()["reserved_total"], 5)

    def test_pending_intent_is_settled_even_if_lease_is_revoked_after_crash(self):
        grant = self.register(quota=2)
        with self.assertRaises(InjectedCrash):
            self.broker.consume(grant, operation_id="pending-to-revoke", request_digest=self.digest(1), crash_at="after_increment")
        record = issue_lease_revocation(
            self.issuer_private, issuer_id="issuer-test", global_budget_id=self.GLOBAL_ID,
            revocation_id="revoke-after-crash", lease_id=grant.lease_id,
            grant_digest=grant.grant_digest, revoked_at=self.NOW,
        )
        revoked = self.broker.revoke_lease(record)
        self.assertEqual(revoked["state"], "REVOKED")
        self.assertEqual(revoked["used_count"], 1)
        self.assertEqual(self.broker.inspect()["used_total"], 1)

    def test_changed_epoch_limit_key_or_storage_configuration_fails_closed(self):
        self.register(quota=2)
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker(global_quota_limit=self.GLOBAL_QUOTA + 1)
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker(global_budget_id="different-epoch")
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker(issuer_public_key=Ed25519PrivateKey.generate().public_key())
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker(journal_path=self.root / "alternate.sqlite3")


    def test_pending_increment_delta_greater_than_one_fails_closed_globally(self):
        grant = self.register(quota=3)
        with self.assertRaises(InjectedCrash):
            self.broker.consume(grant, operation_id="ambiguous-pending", request_digest=self.digest(1), crash_at="after_intent")
        self.broker.counter.increment()
        self.broker.counter.increment()
        with self.assertRaises(BrokerIndeterminate):
            self.broker.recover_pending()
        info = self.broker.inspect()
        self.assertEqual(info["health"], "INDETERMINATE")
        self.assertEqual(info["used_total"], 0)
        self.assertEqual(self.broker.journal.get_operation("ambiguous-pending")["status"], "INDETERMINATE")

    def test_stale_journal_restore_while_counter_is_ahead_is_detected(self):
        grant = self.register(quota=3)
        backup = self.root / "journal-before-consume.sqlite3"
        with self.broker.journal._db() as source:
            target = sqlite3.connect(backup)
            try:
                source.backup(target)
            finally:
                target.close()
        self.broker.consume(grant, operation_id="before-restore", request_digest=self.digest(1))
        journal_path = self.root / "global-journal.sqlite3"
        # All SQLite connections are closed at this point. Restore only the
        # journal while intentionally leaving the counter and config anchor ahead.
        for suffix in ("-wal", "-shm"):
            Path(str(journal_path) + suffix).unlink(missing_ok=True)
        shutil.copy2(backup, journal_path)
        restarted = self.make_broker()
        with self.assertRaises(BrokerIndeterminate):
            restarted.assert_invariants()
        self.assertEqual(restarted.inspect()["health"], "INDETERMINATE")
        self.assertEqual(restarted.counter.read(), 1)


    def test_deleted_journal_is_not_reinitialized_from_an_advanced_counter(self):
        grant = self.register(quota=3)
        self.broker.consume(grant, operation_id="before-journal-delete", request_digest=self.digest(1))
        journal_path = self.root / "global-journal.sqlite3"
        for suffix in ("-wal", "-shm"):
            Path(str(journal_path) + suffix).unlink(missing_ok=True)
        journal_path.unlink()
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker()
        self.assertEqual(self.broker.counter.read(), 1)

    def test_changed_counter_lock_path_is_detected_by_pinned_configuration(self):
        self.register(quota=2)
        with self.assertRaises(BrokerConfigurationMismatch):
            self.make_broker(counter_lock_path=self.root / "alternate-counter.lock")

    def test_runtime_lock_configuration_drift_is_rejected(self):
        grant = self.register(quota=2)
        self.broker.lock_path = self.root / "replacement.lock"
        with self.assertRaises(BrokerConfigurationMismatch):
            self.broker.consume(grant, operation_id="drift", request_digest=self.digest(1))
        self.assertEqual(self.broker.counter.read(), 0)

    def test_committed_receipt_can_be_replayed_after_lease_expiry(self):
        grant = self.register(quota=2, expires_at=self.NOW + 5)
        first = self.broker.consume(grant, operation_id="before-expiry", request_digest=self.digest(1))
        self.now[0] += 10
        replay = self.broker.consume(grant, operation_id="before-expiry", request_digest=self.digest(1))
        self.assertEqual(first, replay)
        self.assertEqual(self.broker.counter.read(), 1)


    def test_per_lease_usage_tampering_is_detected_even_when_global_sum_matches(self):
        a = self.register(quota=2)
        b = self.register(quota=2)
        self.broker.consume(a, operation_id="attribution-op", request_digest=self.digest(1))
        with self.broker.journal._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE leases SET used_count=0 WHERE lease_id=?", (a.lease_id,))
            con.execute("UPDATE leases SET used_count=1 WHERE lease_id=?", (b.lease_id,))
            con.commit()
        with self.assertRaises(BrokerIndeterminate):
            self.broker.assert_invariants()
        self.assertEqual(self.broker.inspect()["health"], "INDETERMINATE")

    def test_mixed_lease_operations_preserve_all_invariants(self):
        grants = [self.register(quota=3) for _ in range(3)]
        for index in range(7):
            grant = grants[index % len(grants)]
            self.broker.consume(grant, operation_id=f"mixed-{index}", request_digest=self.digest(index + 1))
            self.invariant()
        info = self.broker.inspect()
        self.assertEqual(info["reserved_total"], 9)
        self.assertEqual(info["used_total"], 7)
        self.assertEqual(info["expected_counter_value"] - info["baseline_counter_value"], 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
