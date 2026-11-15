from concurrent.futures import ThreadPoolExecutor
import unittest

from src.counter_binding_model import (
    BudgetExceeded,
    OperationBindingConflict,
    SerializedCounterBroker,
    SimulatedNvCounter,
    recover_single_pending_intent,
)


class CounterCommandBoundaryTests(unittest.TestCase):
    def test_increment_response_does_not_contain_counter_value(self):
        counter = SimulatedNvCounter()
        response = counter.nv_increment()
        self.assertEqual(response.response_code, 0)
        self.assertFalse(hasattr(response, "value"))
        self.assertEqual(counter.nv_read(), 1)

    def test_each_successful_increment_advances_once(self):
        counter = SimulatedNvCounter(initial_value=7)
        counter.nv_increment()
        counter.nv_increment()
        self.assertEqual(counter.nv_read(), 9)


class InterleavingAndQuotaTests(unittest.TestCase):
    def test_two_clients_can_observe_same_post_increment_read_value(self):
        counter = SimulatedNvCounter()

        # Legal command-level interleaving: A.Increment, B.Increment, A.Read, B.Read.
        response_a = counter.nv_increment()
        response_b = counter.nv_increment()
        observed_a = counter.nv_read()
        observed_b = counter.nv_read()

        self.assertEqual(response_a.response_code, 0)
        self.assertEqual(response_b.response_code, 0)
        self.assertEqual(counter.nv_read(), 2)
        self.assertEqual(observed_a, 2)
        self.assertEqual(observed_b, 2)
        self.assertEqual(observed_a, observed_b)

    def test_pre_increment_quota_check_can_overrun_under_interleaving(self):
        counter = SimulatedNvCounter()
        quota = 1

        # Both clients check before either increments.
        pre_a = counter.nv_read()
        pre_b = counter.nv_read()
        allow_a = pre_a < quota
        allow_b = pre_b < quota
        self.assertTrue(allow_a)
        self.assertTrue(allow_b)

        if allow_a:
            counter.nv_increment()
        if allow_b:
            counter.nv_increment()

        self.assertEqual(counter.nv_read(), 2)
        self.assertGreater(counter.nv_read(), quota)

    def test_post_increment_quota_check_fails_closed_but_can_burn_counter(self):
        counter = SimulatedNvCounter()
        quota = 1

        pre_a = counter.nv_read()
        pre_b = counter.nv_read()
        self.assertLess(pre_a, quota)
        self.assertLess(pre_b, quota)

        counter.nv_increment()
        counter.nv_increment()
        post_a = counter.nv_read()
        post_b = counter.nv_read()

        # Neither client may execute after observing a value above quota.
        execute_a = post_a <= quota
        execute_b = post_b <= quota
        self.assertFalse(execute_a)
        self.assertFalse(execute_b)
        self.assertEqual(counter.nv_read(), 2)  # quota slot(s) were conservatively burned


class SerializedBrokerTests(unittest.TestCase):
    def test_broker_serializes_sequence_assignment_under_threads(self):
        counter = SimulatedNvCounter()
        broker = SerializedCounterBroker(counter)

        def consume(i: int):
            return broker.consume(
                lease_id="lease-A",
                operation_id=f"op-{i}",
                request_digest=f"sha256:{i:064x}",
                quota=64,
            )

        with ThreadPoolExecutor(max_workers=12) as pool:
            receipts = list(pool.map(consume, range(1, 33)))

        sequences = sorted(receipt.counter_value for receipt in receipts)
        self.assertEqual(sequences, list(range(1, 33)))
        self.assertEqual(counter.nv_read(), 32)
        self.assertEqual(len(broker.receipts), 32)

    def test_same_operation_replay_returns_existing_receipt(self):
        counter = SimulatedNvCounter()
        broker = SerializedCounterBroker(counter)
        first = broker.consume(
            lease_id="lease-A", operation_id="op-1", request_digest="sha256:abc", quota=5
        )
        replay = broker.consume(
            lease_id="lease-A", operation_id="op-1", request_digest="sha256:abc", quota=5
        )
        self.assertEqual(first, replay)
        self.assertEqual(counter.nv_read(), 1)
        self.assertEqual(len(broker.receipts), 1)

    def test_operation_id_cannot_be_rebound_to_other_request(self):
        counter = SimulatedNvCounter()
        broker = SerializedCounterBroker(counter)
        broker.consume(
            lease_id="lease-A", operation_id="op-1", request_digest="sha256:abc", quota=5
        )
        with self.assertRaises(OperationBindingConflict):
            broker.consume(
                lease_id="lease-A", operation_id="op-1", request_digest="sha256:other", quota=5
            )
        self.assertEqual(counter.nv_read(), 1)

    def test_broker_rejects_quota_exhaustion_before_increment(self):
        counter = SimulatedNvCounter(initial_value=2)
        broker = SerializedCounterBroker(counter)
        with self.assertRaises(BudgetExceeded):
            broker.consume(
                lease_id="lease-A", operation_id="op-3", request_digest="sha256:3", quota=2
            )
        self.assertEqual(counter.nv_read(), 2)


class CrashRecoveryTests(unittest.TestCase):
    def test_pending_intent_no_increment(self):
        result = recover_single_pending_intent(
            pre_increment_value=10, observed_value=10, exclusive_recovery=True
        )
        self.assertEqual(result.status, "NOT_APPLIED")

    def test_pending_intent_exactly_one_increment(self):
        result = recover_single_pending_intent(
            pre_increment_value=10, observed_value=11, exclusive_recovery=True
        )
        self.assertEqual(result.status, "APPLIED_RECOVERABLE")
        self.assertEqual(result.recovered_sequence, 11)

    def test_pending_intent_multiple_increments_is_ambiguous(self):
        result = recover_single_pending_intent(
            pre_increment_value=10, observed_value=12, exclusive_recovery=True
        )
        self.assertEqual(result.status, "AMBIGUOUS")

    def test_recovery_without_exclusive_admission_is_ambiguous(self):
        result = recover_single_pending_intent(
            pre_increment_value=10, observed_value=11, exclusive_recovery=False
        )
        self.assertEqual(result.status, "AMBIGUOUS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
