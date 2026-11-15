from __future__ import annotations

import threading
import unittest

from budget_lab import (
    AuthorityUnavailable,
    BudgetExceeded,
    DeviceBindingError,
    DuplicateSpend,
    MonotonicStateEmulator,
    SharedAtomicSpendAuthority,
    SharedRootAllocationRegistry,
    StateTrustError,
)


class E2StateTrustComparisonTests(unittest.TestCase):
    """Compare online shared state and a local monotonic-state abstraction."""

    def test_shared_online_authority_prevents_two_replicas_from_overspending(self):
        authority = SharedAtomicSpendAuthority()
        authority.register_lease("lease-A", 4)

        # Two cloned executor processes share one online authority.
        first = authority.consume("lease-A", "replica-1-op", 3)
        self.assertEqual(first.cumulative_spent, 3)
        with self.assertRaises(BudgetExceeded):
            authority.consume("lease-A", "replica-2-op", 3)

        self.assertEqual(authority.snapshot("lease-A"), (4, 3, 1))

    def test_shared_online_authority_rejects_replay_across_replicas(self):
        authority = SharedAtomicSpendAuthority()
        authority.register_lease("lease-A", 4)
        authority.consume("lease-A", "same-op", 1)
        with self.assertRaises(DuplicateSpend):
            authority.consume("lease-A", "same-op", 1)
        self.assertEqual(authority.snapshot("lease-A"), (4, 1, 1))

    def test_shared_online_authority_fails_closed_when_offline(self):
        authority = SharedAtomicSpendAuthority()
        authority.register_lease("lease-A", 4)
        authority.set_available(False)
        with self.assertRaises(AuthorityUnavailable):
            authority.consume("lease-A", "offline-op", 1)
        authority.set_available(True)
        self.assertEqual(authority.snapshot("lease-A"), (4, 0, 0))

    def test_shared_authority_concurrent_spends_preserve_global_budget(self):
        authority = SharedAtomicSpendAuthority()
        authority.register_lease("lease-A", 4)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker(index: int) -> None:
            try:
                authority.consume("lease-A", f"op-{index}", 1)
                result = "accepted"
            except BudgetExceeded:
                result = "rejected"
            with lock:
                outcomes.append(result)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        budget, spent, sequence = authority.snapshot("lease-A")
        self.assertEqual((budget, spent, sequence), (4, 4, 4))
        self.assertEqual(outcomes.count("accepted"), 4)
        self.assertEqual(outcomes.count("rejected"), 8)

    def test_monotonic_state_emulator_prevents_cloned_executor_overrun(self):
        secure_state = MonotonicStateEmulator("device-A")
        secure_state.provision("lease-A", 4, device_id="device-A")

        # Two software replicas can be reconstructed, but both must use the
        # same simulated protected state associated with one physical device.
        secure_state.consume("lease-A", "replica-1-op", 3, device_id="device-A")
        with self.assertRaises(BudgetExceeded):
            secure_state.consume("lease-A", "replica-2-op", 3, device_id="device-A")

        self.assertEqual(secure_state.snapshot("lease-A", device_id="device-A"), (4, 3, 1))

    def test_monotonic_state_survives_executor_reconstruction(self):
        secure_state = MonotonicStateEmulator("device-A")
        secure_state.provision("lease-A", 4, device_id="device-A")
        secure_state.consume("lease-A", "before-restart", 2, device_id="device-A")

        # Reconstructing the untrusted software executor does not reset the
        # separately-held monotonic state model.
        recreated_executor_state = {"local_cache": "reset"}
        self.assertEqual(recreated_executor_state, {"local_cache": "reset"})
        self.assertEqual(secure_state.snapshot("lease-A", device_id="device-A"), (4, 2, 1))
        secure_state.consume("lease-A", "after-restart", 2, device_id="device-A")
        with self.assertRaises(BudgetExceeded):
            secure_state.consume("lease-A", "over-budget", 1, device_id="device-A")

    def test_monotonic_state_rejects_use_from_another_device(self):
        secure_state = MonotonicStateEmulator("device-A")
        secure_state.provision("lease-A", 4, device_id="device-A")
        with self.assertRaises(DeviceBindingError):
            secure_state.consume("lease-A", "foreign-device-op", 1, device_id="device-B")
        self.assertEqual(secure_state.snapshot("lease-A", device_id="device-A"), (4, 0, 0))

    def test_monotonic_state_fails_closed_when_unavailable(self):
        secure_state = MonotonicStateEmulator("device-A")
        secure_state.provision("lease-A", 4, device_id="device-A")
        secure_state.set_available(False)
        with self.assertRaises(StateTrustError):
            secure_state.consume("lease-A", "offline-op", 1, device_id="device-A")
        secure_state.set_available(True)
        self.assertEqual(secure_state.snapshot("lease-A", device_id="device-A"), (4, 0, 0))

    def test_shared_root_registry_prevents_issuer_fork_overallocation(self):
        registry = SharedRootAllocationRegistry()
        registry.register_root("root-A", 10)

        # Two Issuer replicas with cloned local state must reserve against the
        # same authoritative registry before signing/activating a lease.
        registry.allocate("root-A", "lease-from-issuer-1", 6)
        with self.assertRaises(BudgetExceeded):
            registry.allocate("root-A", "lease-from-issuer-2", 6)
        self.assertEqual(registry.snapshot("root-A"), (10, 6, 1))

    def test_shared_root_registry_fails_closed_when_offline(self):
        registry = SharedRootAllocationRegistry()
        registry.register_root("root-A", 10)
        registry.set_available(False)
        with self.assertRaises(AuthorityUnavailable):
            registry.allocate("root-A", "offline-lease", 3)
        registry.set_available(True)
        self.assertEqual(registry.snapshot("root-A"), (10, 0, 0))


if __name__ == "__main__":
    unittest.main()
