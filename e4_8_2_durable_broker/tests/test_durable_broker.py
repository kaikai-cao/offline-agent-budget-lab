from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from src.durable_broker import (
    BrokerIndeterminate,
    BudgetExceeded,
    DurableCounterBroker,
    InjectedCrash,
    OperationBindingConflict,
    OperationNotApplied,
)


def backup_sqlite_database(source: Path, destination: Path) -> None:
    """Copy a SQLite database and close both handles on Windows as well."""
    source_conn = sqlite3.connect(source)
    destination_conn = sqlite3.connect(destination)
    try:
        source_conn.backup(destination_conn)
    finally:
        destination_conn.close()
        source_conn.close()


class DurableBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "journal.sqlite3"
        self.counter = self.root / "counter.json"
        self.lock = self.root / "broker.lock"

    def tearDown(self):
        self.tmp.cleanup()

    def broker(self, quota=20):
        return DurableCounterBroker(
            journal_path=self.db,
            counter_state_path=self.counter,
            broker_lock_path=self.lock,
            lease_id="lease-test",
            quota_limit=quota,
        )

    def test_receipt_and_idempotency_survive_broker_reconstruction(self):
        first = self.broker().consume(operation_id="op-1", request_digest="sha256:a")
        second = self.broker().consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(first, second)
        self.assertEqual(self.broker().counter.read(), 1)
        self.assertEqual(self.broker().inspect()["health"], "READY")

    def test_request_rebinding_is_rejected_after_reconstruction(self):
        self.broker().consume(operation_id="op-1", request_digest="sha256:a")
        with self.assertRaises(OperationBindingConflict):
            self.broker().consume(operation_id="op-1", request_digest="sha256:b")
        self.assertEqual(self.broker().counter.read(), 1)

    def test_crash_after_intent_is_recovered_as_not_applied(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_intent")
        restarted = self.broker()
        with self.assertRaises(OperationNotApplied):
            restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(restarted.counter.read(), 0)
        next_receipt = restarted.consume(operation_id="op-2", request_digest="sha256:b")
        self.assertEqual(next_receipt.counter_value, 1)

    def test_crash_after_increment_recovers_receipt_without_second_increment(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_increment")
        restarted = self.broker()
        receipt = restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(receipt.counter_value, 1)
        self.assertEqual(restarted.counter.read(), 1)

    def test_crash_after_read_recovers_receipt_without_second_increment(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_read")
        restarted = self.broker()
        receipt = restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(receipt.counter_value, 1)
        self.assertEqual(restarted.counter.read(), 1)

    def test_crash_after_receipt_commit_replays_durable_receipt(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_receipt_commit")
        restarted = self.broker()
        receipt = restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(receipt.counter_value, 1)
        self.assertEqual(restarted.counter.read(), 1)

    def test_quota_exhaustion_does_not_increment(self):
        b = self.broker(quota=1)
        b.consume(operation_id="op-1", request_digest="sha256:a")
        with self.assertRaises(BudgetExceeded):
            b.consume(operation_id="op-2", request_digest="sha256:b")
        self.assertEqual(b.counter.read(), 1)

    def test_out_of_band_increment_breaks_counter_anchor_and_fails_closed(self):
        b = self.broker()
        b.counter.increment()  # deliberately bypass broker gate to model an unauthorized writer
        with self.assertRaises(BrokerIndeterminate):
            b.consume(operation_id="op-1", request_digest="sha256:a")
        state = b.inspect()
        self.assertEqual(state["health"], "INDETERMINATE")
        self.assertEqual(state["observed_counter_value"], 1)

    def test_one_bypass_increment_during_pending_is_indistinguishable_from_broker_increment(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_intent")
        restarted = self.broker()
        # A single direct increment creates the same observable delta (+1) as
        # the intended increment. The broker cannot identify who caused it.
        restarted.counter.increment()
        recovered = restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(recovered.counter_value, 1)
        self.assertEqual(restarted.inspect()["health"], "READY")

    def test_out_of_band_increment_during_pending_intent_is_ambiguous(self):
        with self.assertRaises(InjectedCrash):
            self.broker().consume(operation_id="op-1", request_digest="sha256:a", crash_at="after_intent")
        restarted = self.broker()
        # A second unauthorized increment makes the delta exceed the one
        # increment attributable to the pending intent.
        restarted.counter.increment()
        restarted.counter.increment()
        with self.assertRaises(BrokerIndeterminate):
            restarted.consume(operation_id="op-1", request_digest="sha256:a")
        self.assertEqual(restarted.inspect()["health"], "INDETERMINATE")

    def test_restoring_old_journal_while_counter_is_ahead_is_detected(self):
        b = self.broker()
        backup = self.root / "journal-before-operation.sqlite3"
        backup_sqlite_database(self.db, backup)
        b.consume(operation_id="op-1", request_digest="sha256:a")
        # Simulate a stale software-journal restore while keeping the monotonic counter.
        # Use SQLite's backup API to restore a coherent stale database image
        # without manually manipulating live WAL sidecar files.
        backup_sqlite_database(backup, self.db)
        restored = self.broker()
        with self.assertRaises(BrokerIndeterminate):
            restored.consume(operation_id="op-2", request_digest="sha256:b")
        self.assertEqual(restored.inspect()["observed_counter_value"], 1)

    def test_independent_processes_receive_distinct_sequence_values(self):
        count = 10
        code = (
            "from src.durable_broker import DurableCounterBroker; import sys; "
            "db,counter,lock,op=sys.argv[1:5]; "
            "b=DurableCounterBroker(journal_path=db,counter_state_path=counter,"
            "broker_lock_path=lock,lease_id='lease-test',quota_limit=50); "
            "r=b.consume(operation_id=op,request_digest='sha256:'+op); "
            "print(r.counter_value)"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", code, str(self.db), str(self.counter), str(self.lock), f"op-{i}"],
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for i in range(count)
        ]
        results = []
        for proc in processes:
            stdout, stderr = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, msg=f"child failed: {stderr}")
            results.append(int(stdout.strip()))
        self.assertEqual(sorted(results), list(range(1, count + 1)))
        self.assertEqual(self.broker(quota=50).counter.read(), count)

    def test_two_processes_replaying_same_operation_share_one_receipt(self):
        code = (
            "from src.durable_broker import DurableCounterBroker; import sys; "
            "db,counter,lock=sys.argv[1:4]; "
            "b=DurableCounterBroker(journal_path=db,counter_state_path=counter,"
            "broker_lock_path=lock,lease_id='lease-test',quota_limit=50); "
            "r=b.consume(operation_id='same-op',request_digest='sha256:same'); "
            "print(r.counter_value)"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", code, str(self.db), str(self.counter), str(self.lock)],
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(2)
        ]
        values = []
        for proc in processes:
            stdout, stderr = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, 0, msg=f"child failed: {stderr}")
            values.append(int(stdout.strip()))
        self.assertEqual(values, [1, 1])
        self.assertEqual(self.broker(quota=50).counter.read(), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
