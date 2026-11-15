"""Typed data models for root-budget leases and initial local ledger state.

This module intentionally contains no execution or spend-transition logic.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import asdict, dataclass, fields
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_non_empty_string(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_positive_int(name: str, value: object) -> None:
    # bool is a subclass of int in Python; explicitly reject it.
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_non_negative_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def validate_public_key_b64(value: str) -> bytes:
    """Decode and validate a raw Ed25519 public key encoded as standard Base64."""
    _require_non_empty_string("holder_public_key", value)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("holder_public_key must be valid standard Base64") from exc
    if len(raw) != 32:
        raise ValueError("holder_public_key must encode exactly 32 bytes")
    return raw


@dataclass(frozen=True)
class LeaseRequest:
    """Issuer input for one child lease.

    The caller supplies the Agent's raw Ed25519 public key encoded as Base64.
    The corresponding private key is never accepted by the Issuer.
    """

    lease_id: str
    agent_id: str
    holder_public_key: str
    allocated_budget: int

    def __post_init__(self) -> None:
        _require_non_empty_string("lease_id", self.lease_id)
        _require_non_empty_string("agent_id", self.agent_id)
        validate_public_key_b64(self.holder_public_key)
        _require_positive_int("allocated_budget", self.allocated_budget)


@dataclass(frozen=True)
class BudgetLease:
    """Issuer-signed, immutable credential for one independently allocated lease."""

    credential_version: int
    root_grant_id: str
    parent_grant_id: str
    grant_id: str
    lease_id: str
    agent_id: str
    holder_public_key: str
    allocated_budget: int
    root_budget: int
    cost_unit: str
    allowed_tool: str
    schema_hash: str
    issued_at: int
    expires_at: int
    issuer_key_id: str
    issuer_signature: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.credential_version, bool)
            or not isinstance(self.credential_version, int)
            or self.credential_version != 1
        ):
            raise ValueError("credential_version must be integer 1")
        for name in (
            "root_grant_id",
            "parent_grant_id",
            "grant_id",
            "lease_id",
            "agent_id",
            "cost_unit",
            "allowed_tool",
            "issuer_key_id",
            "issuer_signature",
        ):
            _require_non_empty_string(name, getattr(self, name))
        validate_public_key_b64(self.holder_public_key)
        _require_positive_int("allocated_budget", self.allocated_budget)
        _require_positive_int("root_budget", self.root_budget)
        if self.allocated_budget > self.root_budget:
            raise ValueError("allocated_budget cannot exceed root_budget")
        if not isinstance(self.schema_hash, str) or not _SHA256_RE.fullmatch(self.schema_hash):
            raise ValueError("schema_hash must be a lowercase 64-character SHA-256 hex digest")
        _require_positive_int("issued_at", self.issued_at)
        _require_positive_int("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")

    def unsigned_payload(self) -> dict[str, Any]:
        """Return exactly the fields covered by the issuer's digital signature."""
        payload = asdict(self)
        payload.pop("issuer_signature")
        return payload

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation, including the signature."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BudgetLease":
        """Reconstruct a credential while rejecting missing or unknown fields."""
        if not isinstance(data, dict):
            raise ValueError("credential must be a JSON object")
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
            raise ValueError("invalid credential fields (" + "; ".join(details) + ")")
        return cls(**data)


@dataclass(frozen=True)
class LeaseLedgerState:
    """Initial/serializable local lease ledger state.

    E0 only constructs and validates the initial state. Spend transitions,
    durable storage, and anti-rollback behavior are deliberately out of scope.
    """

    lease_id: str
    allocated_budget: int
    spent_budget: int = 0
    next_sequence: int = 1
    seen_operation_ids: tuple[str, ...] = ()
    last_receipt_hash: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty_string("lease_id", self.lease_id)
        _require_positive_int("allocated_budget", self.allocated_budget)
        _require_non_negative_int("spent_budget", self.spent_budget)
        _require_positive_int("next_sequence", self.next_sequence)
        if self.spent_budget > self.allocated_budget:
            raise ValueError("spent_budget cannot exceed allocated_budget")
        if not isinstance(self.seen_operation_ids, tuple):
            raise ValueError("seen_operation_ids must be a tuple")
        for operation_id in self.seen_operation_ids:
            _require_non_empty_string("operation_id", operation_id)
        if len(set(self.seen_operation_ids)) != len(self.seen_operation_ids):
            raise ValueError("seen_operation_ids must not contain duplicates")
        if self.last_receipt_hash is not None:
            if not isinstance(self.last_receipt_hash, str) or not _SHA256_RE.fullmatch(
                self.last_receipt_hash
            ):
                raise ValueError("last_receipt_hash must be None or a lowercase SHA-256 hex digest")

    @property
    def remaining_budget(self) -> int:
        return self.allocated_budget - self.spent_budget

    @classmethod
    def initial_from_lease(cls, lease: BudgetLease) -> "LeaseLedgerState":
        return cls(
            lease_id=lease.lease_id,
            allocated_budget=lease.allocated_budget,
            spent_budget=0,
            next_sequence=1,
            seen_operation_ids=(),
            last_receipt_hash=None,
        )
