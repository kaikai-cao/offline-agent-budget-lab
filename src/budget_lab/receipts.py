"""Signed execution receipts and an in-memory hash chain (E0.3).

A receipt is an executor-signed assertion about a terminal local-ledger
operation. It binds the operation to the lease's tool/schema plus request,
context and (when committed) result digests. It is not a hardware attestation
or independent proof that an external tool really performed the operation.
"""

from __future__ import annotations

import base64
import hashlib
import math
import threading
import time
import uuid
from dataclasses import asdict, dataclass, fields
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto import canonical_json_bytes, verify_lease_signature
from .ledger import LocalBudgetLedger, OperationStatus
from .models import BudgetLease

_SHA256_ZERO = "0" * 64
_SHA256_LEN = 64
_RECEIPT_SIGNATURE_DOMAIN = b"offline-agent-budget-lab:execution-receipt:v1\x00"
_RECEIPT_HASH_DOMAIN = b"offline-agent-budget-lab:execution-receipt-hash:v1\x00"
_TERMINAL_STATUSES = {
    OperationStatus.COMMITTED.value,
    OperationStatus.ABORTED.value,
    OperationStatus.INDETERMINATE.value,
}


def _require_non_empty_string(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_sha256_hex(name: str, value: object, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LEN
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _executor_key_id(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()[:24]


def _decode_signature(signature_b64: str) -> bytes:
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("executor_signature must be valid standard Base64") from exc
    if len(signature) != 64:
        raise ValueError("executor_signature must encode exactly 64 bytes")
    return signature


@dataclass(frozen=True)
class ExecutionReceipt:
    """Immutable signed record for one terminal budget-ledger operation."""

    receipt_version: int
    chain_id: str
    chain_index: int
    root_grant_id: str
    grant_id: str
    lease_id: str
    operation_id: str
    operation_sequence: int
    tool_id: str
    schema_hash: str
    request_hash: str
    context_hash: str
    result_hash: str | None
    cost: int
    operation_status: str
    created_at: int
    executor_key_id: str
    previous_receipt_hash: str
    executor_signature: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.receipt_version, bool)
            or not isinstance(self.receipt_version, int)
            or self.receipt_version != 1
        ):
            raise ValueError("receipt_version must be integer 1")
        for name in (
            "chain_id",
            "root_grant_id",
            "grant_id",
            "lease_id",
            "operation_id",
            "tool_id",
            "executor_key_id",
            "executor_signature",
        ):
            _require_non_empty_string(name, getattr(self, name))
        for name in ("chain_index", "operation_sequence", "cost", "created_at"):
            _require_positive_int(name, getattr(self, name))
        _require_sha256_hex("schema_hash", self.schema_hash)
        _require_sha256_hex("request_hash", self.request_hash)
        _require_sha256_hex("context_hash", self.context_hash)
        _require_sha256_hex("result_hash", self.result_hash, optional=True)
        _require_sha256_hex("previous_receipt_hash", self.previous_receipt_hash)
        if self.operation_status not in _TERMINAL_STATUSES:
            raise ValueError("operation_status must be committed, aborted, or indeterminate")
        if self.operation_status == OperationStatus.COMMITTED.value and self.result_hash is None:
            raise ValueError("committed receipt requires result_hash")
        if self.operation_status != OperationStatus.COMMITTED.value and self.result_hash is not None:
            raise ValueError("aborted/indeterminate receipt must not contain result_hash")
        _decode_signature(self.executor_signature)

    def unsigned_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("executor_signature")
        return payload

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionReceipt":
        if not isinstance(data, dict):
            raise ValueError("receipt must be a JSON object")
        expected = {field.name for field in fields(cls)}
        actual = set(data)
        missing = expected - actual
        unknown = actual - expected
        if missing or unknown:
            details = []
            if missing:
                details.append(f"missing fields: {sorted(missing)}")
            if unknown:
                details.append(f"unknown fields: {sorted(unknown)}")
            raise ValueError("invalid receipt fields (" + "; ".join(details) + ")")
        return cls(**data)

    @property
    def receipt_hash(self) -> str:
        """Hash of the complete signed envelope (excluding no signed fields)."""
        return hashlib.sha256(
            _RECEIPT_HASH_DOMAIN + canonical_json_bytes(self.to_dict())
        ).hexdigest()


class ReceiptChain:
    """In-memory, single-process append-only chain for one signed lease.

    This object prevents accidental duplicate append and links records in the
    current process. It does not make local storage immutable or durable, and
    cannot by itself detect deletion of a suffix without a trusted checkpoint.
    """

    def __init__(
        self,
        lease: BudgetLease,
        issuer_public_key_bytes: bytes,
        executor_private_key: Ed25519PrivateKey,
        *,
        chain_id: str | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not verify_lease_signature(lease, issuer_public_key_bytes):
            raise ValueError("lease issuer signature verification failed")
        if not isinstance(executor_private_key, Ed25519PrivateKey):
            raise TypeError("executor_private_key must be an Ed25519PrivateKey")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if chain_id is None:
            chain_id = str(uuid.uuid4())
        _require_non_empty_string("chain_id", chain_id)

        self._lease = lease
        self._private_key = executor_private_key
        self._public_key_bytes = executor_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._executor_key_id = _executor_key_id(self._public_key_bytes)
        self._chain_id = chain_id
        self._clock = clock or time.time
        self._receipts: list[ExecutionReceipt] = []
        self._operation_ids: set[str] = set()
        self._lock = threading.Lock()

    @property
    def executor_public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def chain_id(self) -> str:
        return self._chain_id

    @property
    def receipts(self) -> tuple[ExecutionReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    @property
    def head_hash(self) -> str:
        with self._lock:
            return self._receipts[-1].receipt_hash if self._receipts else _SHA256_ZERO

    def append(
        self,
        ledger: LocalBudgetLedger,
        operation_id: str,
        *,
        request_hash: str,
        context_hash: str,
        result_hash: str | None = None,
    ) -> ExecutionReceipt:
        """Append one receipt after its ledger operation reaches a terminal state.

        ``committed`` requires a result digest. ``aborted`` means the caller
        asserts no external effect occurred. ``indeterminate`` means the
        external outcome is unknown; its reserved budget remains occupied.
        """
        if not isinstance(ledger, LocalBudgetLedger):
            raise TypeError("ledger must be a LocalBudgetLedger")
        if ledger.lease.to_dict() != self._lease.to_dict():
            raise ValueError("ledger lease does not match receipt-chain lease")
        _require_non_empty_string("operation_id", operation_id)
        _require_sha256_hex("request_hash", request_hash)
        _require_sha256_hex("context_hash", context_hash)
        _require_sha256_hex("result_hash", result_hash, optional=True)

        operation = ledger.get_operation(operation_id)
        if operation is None:
            raise KeyError(f"unknown operation_id: {operation_id}")
        if operation.status.value not in _TERMINAL_STATUSES:
            raise ValueError("receipt can only be appended for a terminal ledger operation")
        if operation.status is OperationStatus.COMMITTED and result_hash is None:
            raise ValueError("committed operation requires result_hash")
        if operation.status is not OperationStatus.COMMITTED and result_hash is not None:
            raise ValueError("aborted/indeterminate operation must not include result_hash")

        with self._lock:
            if operation_id in self._operation_ids:
                raise ValueError(f"operation already has a receipt: {operation_id}")
            now_value = self._clock()
            if (
                isinstance(now_value, bool)
                or not isinstance(now_value, (int, float))
                or not math.isfinite(now_value)
                or now_value <= 0
            ):
                raise ValueError("clock must return a finite positive Unix timestamp")

            unsigned = {
                "receipt_version": 1,
                "chain_id": self._chain_id,
                "chain_index": len(self._receipts) + 1,
                "root_grant_id": self._lease.root_grant_id,
                "grant_id": self._lease.grant_id,
                "lease_id": self._lease.lease_id,
                "operation_id": operation.operation_id,
                "operation_sequence": operation.sequence,
                "tool_id": self._lease.allowed_tool,
                "schema_hash": self._lease.schema_hash,
                "request_hash": request_hash,
                "context_hash": context_hash,
                "result_hash": result_hash,
                "cost": operation.cost,
                "operation_status": operation.status.value,
                "created_at": int(now_value),
                "executor_key_id": self._executor_key_id,
                "previous_receipt_hash": self._receipts[-1].receipt_hash if self._receipts else _SHA256_ZERO,
            }
            signature = self._private_key.sign(
                _RECEIPT_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned)
            )
            receipt = ExecutionReceipt(
                **unsigned,
                executor_signature=base64.b64encode(signature).decode("ascii"),
            )
            self._receipts.append(receipt)
            self._operation_ids.add(operation_id)
            return receipt


def verify_receipt_chain(
    receipts: Iterable[ExecutionReceipt],
    *,
    lease: BudgetLease,
    issuer_public_key_bytes: bytes,
    executor_public_key_bytes: bytes,
    ledger: LocalBudgetLedger | None = None,
) -> bool:
    """Verify lease binding, signatures, chain links and optional ledger coverage.

    The caller-supplied ``executor_public_key_bytes`` is used only to verify
    signatures; this function does not establish that the key is trusted. A
    higher-level verifier must compare it with an independently pinned key.

    Supplying ``ledger`` additionally checks every terminal ledger operation is
    represented exactly once and that receipt cost/status/sequence match it.
    This completeness guarantee only applies if the verifier trusts that ledger
    snapshot; an attacker able to delete both ledger and receipts can erase the
    evidence. Without a trusted checkpoint/ledger, a valid prefix also verifies.
    """
    try:
        if not verify_lease_signature(lease, issuer_public_key_bytes):
            return False
        if not isinstance(executor_public_key_bytes, bytes) or len(executor_public_key_bytes) != 32:
            return False
        if ledger is not None:
            if not isinstance(ledger, LocalBudgetLedger):
                return False
            if ledger.lease.to_dict() != lease.to_dict():
                return False

        items = tuple(receipts)
        public_key = Ed25519PublicKey.from_public_bytes(executor_public_key_bytes)
        expected_key_id = _executor_key_id(executor_public_key_bytes)
        previous_hash = _SHA256_ZERO
        chain_id: str | None = None
        seen_ids: set[str] = set()

        for index, receipt in enumerate(items, start=1):
            if not isinstance(receipt, ExecutionReceipt):
                return False
            # Re-run validation in case a caller constructed an unusual object
            # through low-level mechanisms rather than the dataclass constructor.
            ExecutionReceipt.from_dict(receipt.to_dict())
            if receipt.chain_index != index:
                return False
            if chain_id is None:
                chain_id = receipt.chain_id
            elif receipt.chain_id != chain_id:
                return False
            if receipt.root_grant_id != lease.root_grant_id:
                return False
            if receipt.grant_id != lease.grant_id or receipt.lease_id != lease.lease_id:
                return False
            if receipt.tool_id != lease.allowed_tool or receipt.schema_hash != lease.schema_hash:
                return False
            if receipt.executor_key_id != expected_key_id:
                return False
            if receipt.previous_receipt_hash != previous_hash:
                return False
            if receipt.operation_id in seen_ids:
                return False

            signature = _decode_signature(receipt.executor_signature)
            public_key.verify(
                signature,
                _RECEIPT_SIGNATURE_DOMAIN + canonical_json_bytes(receipt.unsigned_payload()),
            )
            previous_hash = receipt.receipt_hash
            seen_ids.add(receipt.operation_id)

        if ledger is not None:
            operations = {op.operation_id: op for op in ledger.operations()}
            terminal = {
                operation_id: operation
                for operation_id, operation in operations.items()
                if operation.status is not OperationStatus.RESERVED
            }
            if seen_ids != set(terminal):
                return False
            by_receipt = {receipt.operation_id: receipt for receipt in items}
            for operation_id, operation in terminal.items():
                receipt = by_receipt[operation_id]
                if (
                    receipt.operation_sequence != operation.sequence
                    or receipt.cost != operation.cost
                    or receipt.operation_status != operation.status.value
                ):
                    return False
        return True
    except (InvalidSignature, TypeError, ValueError, KeyError, AttributeError):
        return False
