"""E2 comparative state-trust mechanisms.

These are executable reference models, not production distributed services or
real secure hardware. They make the trust and connectivity assumptions explicit.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


class StateTrustError(RuntimeError):
    """Base class for state-trust mechanism failures."""


class AuthorityUnavailable(StateTrustError):
    """The shared online authority is unavailable; fail-closed behavior applies."""


class DuplicateSpend(StateTrustError):
    """An operation ID has already been consumed for the relevant lease."""


class BudgetExceeded(StateTrustError):
    """The requested operation would exceed the authoritative budget."""


class DeviceBindingError(StateTrustError):
    """A lease is being used outside its provisioned device identity."""


class AllocationConflict(StateTrustError):
    """A lease ID was already allocated or the root budget would be exceeded."""


@dataclass(frozen=True)
class SpendRecord:
    mechanism: str
    lease_id: str
    operation_id: str
    cost: int
    cumulative_spent: int
    sequence: int


def _validate_nonempty(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _validate_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


class SharedAtomicSpendAuthority:
    """Online, shared, atomic spend authority.

    Every spend must reach the same live authority instance. It is a single-
    process reference model for an online atomic service, not a distributed
    consensus implementation and not an offline mechanism.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._available = True
        self._leases: dict[str, dict[str, object]] = {}

    def set_available(self, available: bool) -> None:
        if not isinstance(available, bool):
            raise TypeError("available must be bool")
        with self._lock:
            self._available = available

    def register_lease(self, lease_id: str, budget: int) -> None:
        _validate_nonempty("lease_id", lease_id)
        _validate_positive_int("budget", budget)
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("shared spend authority is unavailable")
            current = self._leases.get(lease_id)
            if current is not None:
                if current["budget"] == budget:
                    return
                raise AllocationConflict("lease already registered with a different budget")
            self._leases[lease_id] = {
                "budget": budget,
                "spent": 0,
                "operation_ids": set(),
                "sequence": 0,
            }

    def consume(self, lease_id: str, operation_id: str, cost: int = 1) -> SpendRecord:
        _validate_nonempty("lease_id", lease_id)
        _validate_nonempty("operation_id", operation_id)
        _validate_positive_int("cost", cost)
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("shared spend authority is unavailable")
            state = self._leases.get(lease_id)
            if state is None:
                raise KeyError(f"unknown lease_id: {lease_id}")
            operation_ids = state["operation_ids"]
            assert isinstance(operation_ids, set)
            if operation_id in operation_ids:
                raise DuplicateSpend(f"operation_id already consumed: {operation_id}")
            spent = int(state["spent"])
            budget = int(state["budget"])
            if spent + cost > budget:
                raise BudgetExceeded(
                    f"budget exceeded: spent={spent}, cost={cost}, budget={budget}"
                )
            operation_ids.add(operation_id)
            spent += cost
            sequence = int(state["sequence"]) + 1
            state["spent"] = spent
            state["sequence"] = sequence
            return SpendRecord(
                mechanism="shared-online-atomic-authority",
                lease_id=lease_id,
                operation_id=operation_id,
                cost=cost,
                cumulative_spent=spent,
                sequence=sequence,
            )

    def snapshot(self, lease_id: str) -> tuple[int, int, int]:
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("shared spend authority is unavailable")
            state = self._leases.get(lease_id)
            if state is None:
                raise KeyError(f"unknown lease_id: {lease_id}")
            return int(state["budget"]), int(state["spent"]), int(state["sequence"])


class MonotonicStateEmulator:
    """Offline local monotonic-state abstraction for comparative experiments.

    Multiple software executor instances representing one physical device use
    this same state object. Executor state may be reconstructed, but this
    emulator's protected state is deliberately not included in the executor
    snapshot. This is only a model of the desired TEE/secure-element API; it
    does not provide real hardware isolation, anti-rollback, attestation, or
    protection against cloning/compromising the emulator itself.
    """

    def __init__(self, device_id: str) -> None:
        _validate_nonempty("device_id", device_id)
        self._device_id = device_id
        self._lock = threading.Lock()
        self._leases: dict[str, dict[str, object]] = {}
        self._available = True

    @property
    def device_id(self) -> str:
        return self._device_id

    def set_available(self, available: bool) -> None:
        if not isinstance(available, bool):
            raise TypeError("available must be bool")
        with self._lock:
            self._available = available

    def provision(self, lease_id: str, budget: int, *, device_id: str) -> None:
        _validate_nonempty("lease_id", lease_id)
        _validate_positive_int("budget", budget)
        _validate_nonempty("device_id", device_id)
        with self._lock:
            if not self._available:
                raise StateTrustError("monotonic state is unavailable")
            if device_id != self._device_id:
                raise DeviceBindingError("device identity does not match this state store")
            current = self._leases.get(lease_id)
            if current is not None:
                if current["budget"] == budget:
                    return
                raise AllocationConflict("lease already provisioned with a different budget")
            self._leases[lease_id] = {
                "budget": budget,
                "spent": 0,
                "operation_ids": set(),
                "sequence": 0,
            }

    def consume(
        self,
        lease_id: str,
        operation_id: str,
        cost: int = 1,
        *,
        device_id: str,
    ) -> SpendRecord:
        _validate_nonempty("lease_id", lease_id)
        _validate_nonempty("operation_id", operation_id)
        _validate_positive_int("cost", cost)
        _validate_nonempty("device_id", device_id)
        with self._lock:
            if not self._available:
                raise StateTrustError("monotonic state is unavailable")
            if device_id != self._device_id:
                raise DeviceBindingError("device identity does not match this state store")
            state = self._leases.get(lease_id)
            if state is None:
                raise KeyError(f"unknown lease_id: {lease_id}")
            operation_ids = state["operation_ids"]
            assert isinstance(operation_ids, set)
            if operation_id in operation_ids:
                raise DuplicateSpend(f"operation_id already consumed: {operation_id}")
            spent = int(state["spent"])
            budget = int(state["budget"])
            if spent + cost > budget:
                raise BudgetExceeded(
                    f"budget exceeded: spent={spent}, cost={cost}, budget={budget}"
                )
            operation_ids.add(operation_id)
            spent += cost
            sequence = int(state["sequence"]) + 1
            state["spent"] = spent
            state["sequence"] = sequence
            return SpendRecord(
                mechanism="monotonic-state-emulator",
                lease_id=lease_id,
                operation_id=operation_id,
                cost=cost,
                cumulative_spent=spent,
                sequence=sequence,
            )

    def snapshot(self, lease_id: str, *, device_id: str) -> tuple[int, int, int]:
        with self._lock:
            if not self._available:
                raise StateTrustError("monotonic state is unavailable")
            if device_id != self._device_id:
                raise DeviceBindingError("device identity does not match this state store")
            state = self._leases.get(lease_id)
            if state is None:
                raise KeyError(f"unknown lease_id: {lease_id}")
            return int(state["budget"]), int(state["spent"]), int(state["sequence"])


class SharedRootAllocationRegistry:
    """Online atomic registry to compare against a forkable local Issuer state.

    Multiple issuer replicas must consult this same registry before activating
    a new lease. This models a shared authoritative allocation service; it does
    not implement distributed consensus or allow offline global allocation.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._available = True
        self._roots: dict[str, dict[str, object]] = {}

    def set_available(self, available: bool) -> None:
        if not isinstance(available, bool):
            raise TypeError("available must be bool")
        with self._lock:
            self._available = available

    def register_root(self, root_grant_id: str, root_budget: int) -> None:
        _validate_nonempty("root_grant_id", root_grant_id)
        _validate_positive_int("root_budget", root_budget)
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("root allocation registry is unavailable")
            current = self._roots.get(root_grant_id)
            if current is not None:
                if current["root_budget"] == root_budget:
                    return
                raise AllocationConflict("root already registered with a different budget")
            self._roots[root_grant_id] = {"root_budget": root_budget, "allocations": {}}

    def allocate(self, root_grant_id: str, lease_id: str, amount: int) -> int:
        _validate_nonempty("root_grant_id", root_grant_id)
        _validate_nonempty("lease_id", lease_id)
        _validate_positive_int("amount", amount)
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("root allocation registry is unavailable")
            root = self._roots.get(root_grant_id)
            if root is None:
                raise KeyError(f"unknown root_grant_id: {root_grant_id}")
            allocations = root["allocations"]
            assert isinstance(allocations, dict)
            if lease_id in allocations:
                raise AllocationConflict(f"lease_id already allocated: {lease_id}")
            allocated = sum(int(value) for value in allocations.values())
            budget = int(root["root_budget"])
            if allocated + amount > budget:
                raise BudgetExceeded(
                    f"root budget exceeded: allocated={allocated}, amount={amount}, budget={budget}"
                )
            allocations[lease_id] = amount
            return allocated + amount

    def snapshot(self, root_grant_id: str) -> tuple[int, int, int]:
        with self._lock:
            if not self._available:
                raise AuthorityUnavailable("root allocation registry is unavailable")
            root = self._roots.get(root_grant_id)
            if root is None:
                raise KeyError(f"unknown root_grant_id: {root_grant_id}")
            allocations = root["allocations"]
            assert isinstance(allocations, dict)
            allocated = sum(int(value) for value in allocations.values())
            return int(root["root_budget"]), allocated, len(allocations)
