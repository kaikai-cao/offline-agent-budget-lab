"""In-memory, single-process root-budget allocator and lease issuer."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import encode_public_key, issuer_key_id, sign_lease_payload
from .models import BudgetLease, LeaseRequest


@dataclass(frozen=True)
class IssuerSnapshot:
    root_grant_id: str
    root_budget: int
    allocated_budget: int
    lease_count: int

    @property
    def unallocated_budget(self) -> int:
        return self.root_budget - self.allocated_budget


class BudgetIssuer:
    """Issue signed, disjoint child leases from one in-memory root budget.

    Concurrency guarantee: calls to ``issue_leases`` are serialized by a
    process-local lock. This does NOT provide crash durability, cross-process
    coordination, or protection against copying/restoring the Issuer's state.
    Those are explicitly outside this first E0 module.
    """

    def __init__(
        self,
        *,
        root_budget: int,
        cost_unit: str,
        allowed_tool: str,
        schema_hash: str,
        private_key: Ed25519PrivateKey,
        root_grant_id: str | None = None,
    ) -> None:
        if isinstance(root_budget, bool) or not isinstance(root_budget, int) or root_budget <= 0:
            raise ValueError("root_budget must be a positive integer")
        if not isinstance(cost_unit, str) or not cost_unit.strip():
            raise ValueError("cost_unit must be a non-empty string")
        if not isinstance(allowed_tool, str) or not allowed_tool.strip():
            raise ValueError("allowed_tool must be a non-empty string")
        if (
            not isinstance(schema_hash, str)
            or len(schema_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in schema_hash)
        ):
            raise ValueError("schema_hash must be a lowercase 64-character SHA-256 hex digest")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        if root_grant_id is None:
            root_grant_id = str(uuid.uuid4())
        if not isinstance(root_grant_id, str) or not root_grant_id.strip():
            raise ValueError("root_grant_id must be a non-empty string")

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        self._root_budget = root_budget
        self._root_grant_id = root_grant_id
        self._cost_unit = cost_unit
        self._allowed_tool = allowed_tool
        self._schema_hash = schema_hash
        self._private_key = private_key
        self._issuer_public_key_bytes = public_key_bytes
        self._issuer_key_id = issuer_key_id(public_key_bytes)
        self._allocated_budget = 0
        self._leases: dict[str, BudgetLease] = {}
        self._allocation_frozen = False
        self._lock = threading.Lock()

    @property
    def issuer_public_key_bytes(self) -> bytes:
        """Raw 32-byte public key. The private key is never exposed."""
        return self._issuer_public_key_bytes

    @property
    def issuer_public_key_b64(self) -> str:
        return encode_public_key(self._issuer_public_key_bytes)

    @property
    def snapshot(self) -> IssuerSnapshot:
        with self._lock:
            return IssuerSnapshot(
                root_grant_id=self._root_grant_id,
                root_budget=self._root_budget,
                allocated_budget=self._allocated_budget,
                lease_count=len(self._leases),
            )

    def issue_leases(
        self,
        requests: Iterable[LeaseRequest],
        *,
        issued_at: int,
        expires_at: int,
    ) -> tuple[BudgetLease, ...]:
        """Atomically allocate and sign a batch of child leases.

        Validation and signing complete before the issuer's in-memory
        allocation state is changed. All requests in one batch either become
        registered together or none do.
        """
        if isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at <= 0:
            raise ValueError("issued_at must be a positive Unix timestamp")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= issued_at:
            raise ValueError("expires_at must be later than issued_at")

        request_list = tuple(requests)
        if not request_list:
            raise ValueError("at least one lease request is required")
        if any(not isinstance(request, LeaseRequest) for request in request_list):
            raise TypeError("all requests must be LeaseRequest instances")

        lease_ids = [request.lease_id for request in request_list]
        if len(set(lease_ids)) != len(lease_ids):
            raise ValueError("lease_id values must be unique within a batch")

        requested_total = sum(request.allocated_budget for request in request_list)

        with self._lock:
            if self._allocation_frozen:
                raise RuntimeError("lease issuance is frozen after allocation manifest creation")
            reused_ids = set(lease_ids).intersection(self._leases)
            if reused_ids:
                raise ValueError(f"lease_id already issued: {sorted(reused_ids)}")
            if self._allocated_budget + requested_total > self._root_budget:
                raise ValueError(
                    "root budget exceeded: "
                    f"allocated={self._allocated_budget}, requested={requested_total}, "
                    f"root_budget={self._root_budget}"
                )

            # Build and sign the full batch before mutating issuer state.
            new_leases: list[BudgetLease] = []
            for request in request_list:
                payload = {
                    "credential_version": 1,
                    "root_grant_id": self._root_grant_id,
                    "parent_grant_id": self._root_grant_id,
                    "grant_id": str(uuid.uuid4()),
                    "lease_id": request.lease_id,
                    "agent_id": request.agent_id,
                    "holder_public_key": request.holder_public_key,
                    "allocated_budget": request.allocated_budget,
                    "root_budget": self._root_budget,
                    "cost_unit": self._cost_unit,
                    "allowed_tool": self._allowed_tool,
                    "schema_hash": self._schema_hash,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "issuer_key_id": self._issuer_key_id,
                }
                signature = sign_lease_payload(self._private_key, payload)
                new_leases.append(BudgetLease(**payload, issuer_signature=signature))

            # Commit in-memory allocation state only after the full batch succeeds.
            for lease in new_leases:
                self._leases[lease.lease_id] = lease
            self._allocated_budget += requested_total
            return tuple(new_leases)

    @property
    def leases(self) -> tuple[BudgetLease, ...]:
        """Return all issued leases in deterministic lease-ID order."""
        with self._lock:
            return tuple(self._leases[key] for key in sorted(self._leases))

    def create_allocation_manifest(self, *, generated_at: int, manifest_id: str | None = None):
        """Create an issuer-signed snapshot of the complete current lease set.

        The manifest is a point-in-time allocation inventory. It does not make
        the issuer's in-memory state durable or protect it against rollback.
        """
        if isinstance(generated_at, bool) or not isinstance(generated_at, int) or generated_at <= 0:
            raise ValueError("generated_at must be a positive Unix timestamp")
        import uuid
        from .reconciliation import sign_allocation_manifest

        if manifest_id is None:
            manifest_id = str(uuid.uuid4())
        if not isinstance(manifest_id, str) or not manifest_id.strip():
            raise ValueError("manifest_id must be a non-empty string")
        with self._lock:
            if not self._leases:
                raise ValueError("cannot create an allocation manifest without issued leases")
            manifest = sign_allocation_manifest(
                leases=tuple(self._leases.values()),
                root_budget=self._root_budget,
                root_grant_id=self._root_grant_id,
                cost_unit=self._cost_unit,
                allowed_tool=self._allowed_tool,
                schema_hash=self._schema_hash,
                issuer_private_key=self._private_key,
                generated_at=generated_at,
                manifest_id=manifest_id,
            )
            # The manifest is the final allocation inventory for this E0 run.
            # Prevent later issuance from escaping the signed manifest.
            self._allocation_frozen = True
            return manifest

    def get_lease(self, lease_id: str) -> BudgetLease | None:
        with self._lock:
            return self._leases.get(lease_id)
