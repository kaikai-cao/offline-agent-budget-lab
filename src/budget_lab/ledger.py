"""Single-process in-memory local budget ledger (E0.2).

This module provides atomic in-process reservation and operation-state
transitions. It deliberately does not implement durable storage, cross-process
coordination, execution receipts, or anti-rollback protection.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable

from .crypto import verify_lease_signature
from .models import BudgetLease


class OperationStatus(str, Enum):
    RESERVED = "reserved"
    COMMITTED = "committed"
    ABORTED = "aborted"
    INDETERMINATE = "indeterminate"


class DuplicateOperationError(ValueError):
    """Raised when an operation ID has already been reserved in this ledger."""


class InsufficientBudgetError(ValueError):
    """Raised when the requested reservation exceeds the available lease budget."""


class InvalidOperationTransition(RuntimeError):
    """Raised when an operation is moved between incompatible terminal states."""


@dataclass(frozen=True)
class LedgerOperation:
    operation_id: str
    sequence: int
    cost: int
    status: OperationStatus


@dataclass(frozen=True)
class LedgerSnapshot:
    lease_id: str
    allocated_budget: int
    committed_budget: int
    reserved_budget: int
    indeterminate_budget: int
    available_budget: int
    committed_count: int
    reserved_count: int
    aborted_count: int
    indeterminate_count: int
    next_sequence: int


class LocalBudgetLedger:
    """A signed-lease-backed, process-local budget ledger.

    Every public state-changing method is guarded by one process-local lock.
    The lock prevents two threads sharing this object from reserving the same
    remaining budget. It does not coordinate multiple processes or copied
    ledger instances.

    ``reserved`` consumes available capacity immediately. ``commit`` keeps the
    capacity consumed. ``abort`` releases it and is only safe when the caller
    knows the external operation did not take effect. ``indeterminate`` keeps
    the capacity occupied conservatively when the external outcome is unknown.
    """

    def __init__(
        self,
        lease: BudgetLease,
        issuer_public_key_bytes: bytes,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not verify_lease_signature(lease, issuer_public_key_bytes):
            raise ValueError("lease issuer signature verification failed")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")

        self._lease = lease
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._operations: dict[str, LedgerOperation] = {}
        self._next_sequence = 1

        # Refuse to initialize a local ledger from a lease that is not currently
        # valid. Subsequent reservations repeat this check.
        self._check_lease_time()

    @property
    def lease(self) -> BudgetLease:
        return self._lease

    def _check_lease_time(self) -> None:
        now_value = self._clock()
        if (
            isinstance(now_value, bool)
            or not isinstance(now_value, (int, float))
            or not math.isfinite(now_value)
        ):
            raise ValueError("clock must return a finite numeric Unix timestamp")
        if now_value < self._lease.issued_at:
            raise ValueError("lease is not valid yet")
        if now_value >= self._lease.expires_at:
            raise ValueError("lease has expired")

    @staticmethod
    def _validate_operation_id(operation_id: str) -> None:
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise ValueError("operation_id must be a non-empty string")

    @staticmethod
    def _validate_cost(cost: int) -> None:
        if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
            raise ValueError("cost must be a positive integer")

    def reserve(self, operation_id: str, *, cost: int = 1) -> LedgerOperation:
        """Atomically reserve budget for one unique operation ID.

        Duplicate IDs are rejected even when the previous operation was
        aborted. IDs are never reusable within this ledger instance.
        """
        self._validate_operation_id(operation_id)
        self._validate_cost(cost)

        with self._lock:
            self._check_lease_time()
            if operation_id in self._operations:
                raise DuplicateOperationError(
                    f"operation_id has already been used: {operation_id}"
                )

            snapshot = self._snapshot_unlocked()
            if cost > snapshot.available_budget:
                raise InsufficientBudgetError(
                    "insufficient budget: "
                    f"requested={cost}, available={snapshot.available_budget}, "
                    f"allocated={snapshot.allocated_budget}"
                )

            operation = LedgerOperation(
                operation_id=operation_id,
                sequence=self._next_sequence,
                cost=cost,
                status=OperationStatus.RESERVED,
            )
            self._operations[operation_id] = operation
            self._next_sequence += 1
            return operation

    def commit(self, operation_id: str) -> LedgerOperation:
        """Mark a reserved operation as committed; repeated commit is idempotent."""
        return self._transition(
            operation_id,
            expected=OperationStatus.RESERVED,
            target=OperationStatus.COMMITTED,
        )

    def abort(self, operation_id: str) -> LedgerOperation:
        """Release a reservation when it is known no external effect occurred."""
        return self._transition(
            operation_id,
            expected=OperationStatus.RESERVED,
            target=OperationStatus.ABORTED,
        )

    def mark_indeterminate(self, operation_id: str) -> LedgerOperation:
        """Keep a reservation occupied when external execution outcome is unknown."""
        return self._transition(
            operation_id,
            expected=OperationStatus.RESERVED,
            target=OperationStatus.INDETERMINATE,
        )

    def _transition(
        self,
        operation_id: str,
        *,
        expected: OperationStatus,
        target: OperationStatus,
    ) -> LedgerOperation:
        self._validate_operation_id(operation_id)
        with self._lock:
            current = self._operations.get(operation_id)
            if current is None:
                raise KeyError(f"unknown operation_id: {operation_id}")
            if current.status is target:
                # Safe retry of the same state transition.
                return current
            if current.status is not expected:
                raise InvalidOperationTransition(
                    f"cannot transition operation from {current.status.value} "
                    f"to {target.value}"
                )
            updated = replace(current, status=target)
            self._operations[operation_id] = updated
            return updated

    def get_operation(self, operation_id: str) -> LedgerOperation | None:
        self._validate_operation_id(operation_id)
        with self._lock:
            return self._operations.get(operation_id)

    def operations(self) -> tuple[LedgerOperation, ...]:
        with self._lock:
            return tuple(sorted(self._operations.values(), key=lambda item: item.sequence))

    @property
    def snapshot(self) -> LedgerSnapshot:
        with self._lock:
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> LedgerSnapshot:
        by_status = {
            status: [op for op in self._operations.values() if op.status is status]
            for status in OperationStatus
        }
        committed = sum(op.cost for op in by_status[OperationStatus.COMMITTED])
        reserved = sum(op.cost for op in by_status[OperationStatus.RESERVED])
        indeterminate = sum(op.cost for op in by_status[OperationStatus.INDETERMINATE])
        available = self._lease.allocated_budget - committed - reserved - indeterminate
        # This is an internal invariant. No public operation can make it negative.
        if available < 0:
            raise RuntimeError("ledger invariant violated: available budget is negative")
        return LedgerSnapshot(
            lease_id=self._lease.lease_id,
            allocated_budget=self._lease.allocated_budget,
            committed_budget=committed,
            reserved_budget=reserved,
            indeterminate_budget=indeterminate,
            available_budget=available,
            committed_count=len(by_status[OperationStatus.COMMITTED]),
            reserved_count=len(by_status[OperationStatus.RESERVED]),
            aborted_count=len(by_status[OperationStatus.ABORTED]),
            indeterminate_count=len(by_status[OperationStatus.INDETERMINATE]),
            next_sequence=self._next_sequence,
        )
