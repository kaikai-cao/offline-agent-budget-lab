"""Software-only model of TPM NV Counter integration boundaries.

This module intentionally contains no TPM/TBS access and must never be treated
as a hardware test. It models the command-level shape documented by TCG:
NV_Increment returns a response code, while NV_Read is a separate command.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Dict, List


class BudgetExceeded(RuntimeError):
    """Raised when the monotonic counter has exhausted the configured quota."""


class OperationBindingConflict(RuntimeError):
    """Raised when an operation ID is reused with different bound content."""


class CounterStateError(RuntimeError):
    """Raised when the observed counter transition is not the expected one."""


@dataclass(frozen=True)
class NvIncrementResponse:
    """The modeled NV_Increment response: status only, no counter value."""

    response_code: int = 0


class SimulatedNvCounter:
    """A thread-safe in-memory counter; each command is individually atomic."""

    def __init__(self, initial_value: int = 0) -> None:
        if not isinstance(initial_value, int) or initial_value < 0:
            raise ValueError("initial_value must be a non-negative integer")
        self._value = initial_value
        self._lock = Lock()

    def nv_increment(self) -> NvIncrementResponse:
        """Increment by one and return status only, mirroring command shape."""
        with self._lock:
            self._value += 1
        return NvIncrementResponse(response_code=0)

    def nv_read(self) -> int:
        """Read the current counter value as a separate command."""
        with self._lock:
            return self._value


@dataclass(frozen=True)
class Receipt:
    """Unsigned model receipt; real deployments still need trusted signing."""

    lease_id: str
    operation_id: str
    request_digest: str
    counter_value: int


class SerializedCounterBroker:
    """Single-broker model that serializes increment + read + receipt creation.

    The lock is only a process-local software lock. It demonstrates the
    sequencing property under a singleton broker assumption; it is NOT a
    clone-resistant or hardware-enforced lock.
    """

    def __init__(self, counter: SimulatedNvCounter) -> None:
        self._counter = counter
        self._critical_section = Lock()
        self._receipts_by_operation: Dict[str, Receipt] = {}
        self.receipts: List[Receipt] = []

    def consume(
        self,
        *,
        lease_id: str,
        operation_id: str,
        request_digest: str,
        quota: int,
    ) -> Receipt:
        for name, value in (
            ("lease_id", lease_id),
            ("operation_id", operation_id),
            ("request_digest", request_digest),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(quota, int) or quota < 0:
            raise ValueError("quota must be a non-negative integer")

        with self._critical_section:
            prior = self._receipts_by_operation.get(operation_id)
            if prior is not None:
                if (prior.lease_id, prior.request_digest) != (lease_id, request_digest):
                    raise OperationBindingConflict(
                        "operation_id was already used with a different lease or request digest"
                    )
                return prior

            before = self._counter.nv_read()
            if before >= quota:
                raise BudgetExceeded(f"quota exhausted: counter={before}, quota={quota}")

            increment = self._counter.nv_increment()
            if increment.response_code != 0:
                raise CounterStateError(
                    f"NV_Increment failed with response code 0x{increment.response_code:08X}"
                )

            after = self._counter.nv_read()
            if after != before + 1:
                raise CounterStateError(
                    f"counter transition was not exactly +1: before={before}, after={after}"
                )

            receipt = Receipt(
                lease_id=lease_id,
                operation_id=operation_id,
                request_digest=request_digest,
                counter_value=after,
            )
            self._receipts_by_operation[operation_id] = receipt
            self.receipts.append(receipt)
            return receipt


@dataclass(frozen=True)
class RecoveryResult:
    status: str
    observed_value: int
    recovered_sequence: int | None = None
    explanation: str = ""


def recover_single_pending_intent(
    *,
    pre_increment_value: int,
    observed_value: int,
    exclusive_recovery: bool,
) -> RecoveryResult:
    """Classify one pending intent using a pre-value and a later NV_Read.

    Recovery is only classifiable when admission is stopped and exactly one
    increment may have occurred since the durable intent was written. If that
    exclusivity condition is not known to hold, the result is ambiguous.
    """

    if pre_increment_value < 0 or observed_value < 0:
        raise ValueError("counter values must be non-negative")
    if not exclusive_recovery:
        return RecoveryResult(
            status="AMBIGUOUS",
            observed_value=observed_value,
            explanation="Recovery was not exclusive; another operation may have incremented the counter.",
        )

    delta = observed_value - pre_increment_value
    if delta == 0:
        return RecoveryResult(
            status="NOT_APPLIED",
            observed_value=observed_value,
            explanation="No increment is visible relative to the durable pre-value.",
        )
    if delta == 1:
        return RecoveryResult(
            status="APPLIED_RECOVERABLE",
            observed_value=observed_value,
            recovered_sequence=observed_value,
            explanation="Exactly one increment is visible under the exclusive single-intent assumption.",
        )
    return RecoveryResult(
        status="AMBIGUOUS",
        observed_value=observed_value,
        explanation=f"Observed delta {delta}; cannot attribute it to one pending intent.",
    )
