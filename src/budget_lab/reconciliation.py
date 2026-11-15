"""Root-level allocation manifest and final budget reconciliation (E0.4).

This is an in-memory, single-issuer/single-process research baseline. It checks
that the submitted lease set matches an issuer-signed allocation manifest,
that every submitted ledger is internally within its lease, and that signed
receipts cover every terminal ledger operation. Completeness against omitted
receipt-chain suffixes requires an independently trusted chain-head anchor.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from enum import Enum
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto import canonical_json_bytes, issuer_key_id, verify_lease_signature
from .ledger import LocalBudgetLedger, OperationStatus
from .models import BudgetLease
from .receipts import ExecutionReceipt, verify_receipt_chain

_MANIFEST_DOMAIN = b"offline-agent-budget-lab:allocation-manifest:v1\x00"
_ZERO_HASH = "0" * 64
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class ReconciliationStatus(str, Enum):
    ACCEPTED = "accepted"
    INCOMPLETE = "incomplete"
    REJECTED = "rejected"


def _require_non_empty(name: str, value: object) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_digest(name: str, value: object) -> None:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def lease_credential_digest(lease: BudgetLease) -> str:
    """Hash the complete signed lease envelope for manifest membership checks."""
    return hashlib.sha256(
        b"offline-agent-budget-lab:lease-envelope:v1\x00"
        + canonical_json_bytes(lease.to_dict())
    ).hexdigest()


@dataclass(frozen=True)
class LeaseManifestEntry:
    lease_id: str
    grant_id: str
    allocated_budget: int
    credential_hash: str

    def __post_init__(self) -> None:
        _require_non_empty("lease_id", self.lease_id)
        _require_non_empty("grant_id", self.grant_id)
        _require_positive_int("allocated_budget", self.allocated_budget)
        _require_digest("credential_hash", self.credential_hash)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "LeaseManifestEntry":
        if not isinstance(data, dict):
            raise ValueError("manifest entry must be a JSON object")
        expected = {item.name for item in fields(cls)}
        if set(data) != expected:
            raise ValueError("manifest entry fields do not match schema")
        return cls(**data)  # type: ignore[arg-type]


@dataclass(frozen=True)
class AllocationManifest:
    """Issuer-signed snapshot of every lease allocated under one root grant."""

    manifest_version: int
    manifest_id: str
    root_grant_id: str
    root_budget: int
    allocated_budget: int
    cost_unit: str
    allowed_tool: str
    schema_hash: str
    issuer_key_id: str
    generated_at: int
    entries: tuple[LeaseManifestEntry, ...]
    issuer_signature: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.manifest_version, bool)
            or not isinstance(self.manifest_version, int)
            or self.manifest_version != 1
        ):
            raise ValueError("manifest_version must be integer 1")
        for name in (
            "manifest_id", "root_grant_id", "cost_unit", "allowed_tool",
            "issuer_key_id", "issuer_signature",
        ):
            _require_non_empty(name, getattr(self, name))
        _require_positive_int("root_budget", self.root_budget)
        _require_positive_int("allocated_budget", self.allocated_budget)
        _require_positive_int("generated_at", self.generated_at)
        _require_digest("schema_hash", self.schema_hash)
        if self.allocated_budget > self.root_budget:
            raise ValueError("allocated_budget cannot exceed root_budget")
        if not isinstance(self.entries, tuple) or not self.entries:
            raise ValueError("entries must be a non-empty tuple")
        if any(not isinstance(entry, LeaseManifestEntry) for entry in self.entries):
            raise ValueError("entries must contain LeaseManifestEntry values")
        lease_ids = [entry.lease_id for entry in self.entries]
        grant_ids = [entry.grant_id for entry in self.entries]
        if len(set(lease_ids)) != len(lease_ids):
            raise ValueError("manifest lease_id values must be unique")
        if len(set(grant_ids)) != len(grant_ids):
            raise ValueError("manifest grant_id values must be unique")
        if sum(entry.allocated_budget for entry in self.entries) != self.allocated_budget:
            raise ValueError("manifest allocated_budget does not match entry total")
        try:
            signature = base64.b64decode(self.issuer_signature.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("issuer_signature must be valid standard Base64") from exc
        if len(signature) != 64:
            raise ValueError("issuer_signature must encode exactly 64 bytes")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "manifest_version": self.manifest_version,
            "manifest_id": self.manifest_id,
            "root_grant_id": self.root_grant_id,
            "root_budget": self.root_budget,
            "allocated_budget": self.allocated_budget,
            "cost_unit": self.cost_unit,
            "allowed_tool": self.allowed_tool,
            "schema_hash": self.schema_hash,
            "issuer_key_id": self.issuer_key_id,
            "generated_at": self.generated_at,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    def to_dict(self) -> dict[str, object]:
        result = self.unsigned_payload()
        result["issuer_signature"] = self.issuer_signature
        return result

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AllocationManifest":
        if not isinstance(data, dict):
            raise ValueError("manifest must be a JSON object")
        expected = {item.name for item in fields(cls)}
        missing, unknown = expected - set(data), set(data) - expected
        if missing or unknown:
            raise ValueError(
                f"invalid manifest fields (missing={sorted(missing)}, unknown={sorted(unknown)})"
            )
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError("manifest entries must be a JSON array")
        values = dict(data)
        values["entries"] = tuple(LeaseManifestEntry.from_dict(item) for item in raw_entries)  # type: ignore[arg-type]
        return cls(**values)  # type: ignore[arg-type]

    @property
    def manifest_hash(self) -> str:
        return hashlib.sha256(
            b"offline-agent-budget-lab:allocation-manifest-hash:v1\x00"
            + canonical_json_bytes(self.to_dict())
        ).hexdigest()


def sign_allocation_manifest(
    *,
    leases: Iterable[BudgetLease],
    root_budget: int,
    root_grant_id: str,
    cost_unit: str,
    allowed_tool: str,
    schema_hash: str,
    issuer_private_key: Ed25519PrivateKey,
    generated_at: int,
    manifest_id: str,
) -> AllocationManifest:
    """Create a manifest; intended to be called by BudgetIssuer under its lock."""
    lease_list = tuple(leases)
    if not lease_list:
        raise ValueError("cannot create an allocation manifest without leases")
    public_bytes = issuer_private_key.public_key().public_bytes_raw()
    entries = tuple(
        sorted(
            (
                LeaseManifestEntry(
                    lease_id=lease.lease_id,
                    grant_id=lease.grant_id,
                    allocated_budget=lease.allocated_budget,
                    credential_hash=lease_credential_digest(lease),
                )
                for lease in lease_list
            ),
            key=lambda entry: entry.lease_id,
        )
    )
    unsigned = {
        "manifest_version": 1,
        "manifest_id": manifest_id,
        "root_grant_id": root_grant_id,
        "root_budget": root_budget,
        "allocated_budget": sum(entry.allocated_budget for entry in entries),
        "cost_unit": cost_unit,
        "allowed_tool": allowed_tool,
        "schema_hash": schema_hash,
        "issuer_key_id": issuer_key_id(public_bytes),
        "generated_at": generated_at,
        "entries": [entry.to_dict() for entry in entries],
    }
    signature = issuer_private_key.sign(_MANIFEST_DOMAIN + canonical_json_bytes(unsigned))
    return AllocationManifest(
        **{key: value for key, value in unsigned.items() if key != "entries"},
        entries=entries,
        issuer_signature=base64.b64encode(signature).decode("ascii"),
    )


def verify_allocation_manifest(
    manifest: AllocationManifest,
    issuer_public_key_bytes: bytes,
) -> bool:
    try:
        if not isinstance(manifest, AllocationManifest):
            return False
        if not isinstance(issuer_public_key_bytes, bytes) or len(issuer_public_key_bytes) != 32:
            return False
        if issuer_key_id(issuer_public_key_bytes) != manifest.issuer_key_id:
            return False
        signature = base64.b64decode(manifest.issuer_signature.encode("ascii"), validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(issuer_public_key_bytes)
        public_key.verify(signature, _MANIFEST_DOMAIN + canonical_json_bytes(manifest.unsigned_payload()))
        return True
    except (InvalidSignature, TypeError, ValueError, AttributeError):
        return False


@dataclass(frozen=True)
class TrustedChainHead:
    """Out-of-band expected chain head supplied by an independent trust source.

    The object is data, not a cryptographic proof of trust. The caller must
    obtain it from a trusted checkpoint registry or other independent anchor,
    not merely copy it from the same untrusted receipt package being checked.
    """

    lease_id: str
    chain_id: str
    chain_length: int
    head_hash: str

    def __post_init__(self) -> None:
        _require_non_empty("lease_id", self.lease_id)
        _require_non_empty("chain_id", self.chain_id)
        if isinstance(self.chain_length, bool) or not isinstance(self.chain_length, int) or self.chain_length < 0:
            raise ValueError("chain_length must be a non-negative integer")
        _require_digest("head_hash", self.head_hash)


@dataclass(frozen=True)
class LeaseEvidenceBundle:
    lease: BudgetLease
    ledger: LocalBudgetLedger
    receipts: tuple[ExecutionReceipt, ...]
    executor_public_key_bytes: bytes
    chain_id: str
    trusted_head: TrustedChainHead | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.lease, BudgetLease):
            raise TypeError("lease must be a BudgetLease")
        if not isinstance(self.ledger, LocalBudgetLedger):
            raise TypeError("ledger must be a LocalBudgetLedger")
        if not isinstance(self.receipts, tuple):
            raise TypeError("receipts must be a tuple")
        if any(not isinstance(item, ExecutionReceipt) for item in self.receipts):
            raise TypeError("receipts must contain ExecutionReceipt values")
        if not isinstance(self.executor_public_key_bytes, bytes) or len(self.executor_public_key_bytes) != 32:
            raise ValueError("executor_public_key_bytes must be exactly 32 bytes")
        _require_non_empty("chain_id", self.chain_id)
        if self.trusted_head is not None and not isinstance(self.trusted_head, TrustedChainHead):
            raise TypeError("trusted_head must be TrustedChainHead or None")


@dataclass(frozen=True)
class LeaseReconciliation:
    lease_id: str
    allocated_budget: int
    committed_budget: int
    reserved_budget: int
    indeterminate_budget: int
    aborted_count: int
    occupied_budget: int
    receipt_count: int
    checkpoint_verified: bool
    findings: tuple[str, ...]


@dataclass(frozen=True)
class ReconciliationReport:
    status: ReconciliationStatus
    root_grant_id: str
    root_budget: int
    allocated_budget: int
    committed_budget: int
    reserved_budget: int
    indeterminate_budget: int
    occupied_budget: int
    unallocated_budget: int
    leases: tuple[LeaseReconciliation, ...]
    findings: tuple[str, ...]


class BudgetReconciler:
    """Verify issuer allocation manifest and reconcile all lease evidence."""

    def reconcile(
        self,
        manifest: AllocationManifest,
        bundles: Iterable[LeaseEvidenceBundle],
        *,
        issuer_public_key_bytes: bytes,
        trusted_executor_keys: Mapping[str, bytes] | None = None,
    ) -> ReconciliationReport:
        """Reconcile bundles using executor keys pinned outside the evidence.

        ``LeaseEvidenceBundle.executor_public_key_bytes`` is an untrusted claim
        carried with the evidence. It is never used as a trust anchor. The
        caller must supply a separately trusted mapping from lease ID to the
        expected executor public key (for example, from deployment config or
        an independently administered registry).
        """
        findings: list[str] = []
        lease_reports: list[LeaseReconciliation] = []
        status = ReconciliationStatus.ACCEPTED

        if trusted_executor_keys is None:
            trusted_executor_keys = {}
        elif not isinstance(trusted_executor_keys, Mapping):
            return ReconciliationReport(
                ReconciliationStatus.REJECTED, getattr(manifest, "root_grant_id", ""),
                getattr(manifest, "root_budget", 0), getattr(manifest, "allocated_budget", 0),
                0, 0, 0, 0, 0, (), ("trusted_executor_keys must be an external mapping",)
            )

        if not verify_allocation_manifest(manifest, issuer_public_key_bytes):
            return ReconciliationReport(
                ReconciliationStatus.REJECTED, getattr(manifest, "root_grant_id", ""),
                getattr(manifest, "root_budget", 0), getattr(manifest, "allocated_budget", 0),
                0, 0, 0, 0, 0, (), ("issuer allocation manifest signature or structure is invalid",)
            )

        try:
            bundle_list = tuple(bundles)
        except TypeError:
            bundle_list = ()
            findings.append("evidence bundles are not iterable")
            status = ReconciliationStatus.REJECTED

        by_lease: dict[str, LeaseEvidenceBundle] = {}
        for bundle in bundle_list:
            if not isinstance(bundle, LeaseEvidenceBundle):
                findings.append("evidence bundle has invalid type")
                status = ReconciliationStatus.REJECTED
                continue
            lease_id = bundle.lease.lease_id
            if lease_id in by_lease:
                findings.append(f"duplicate evidence bundle for lease: {lease_id}")
                status = ReconciliationStatus.REJECTED
            else:
                by_lease[lease_id] = bundle

        expected_entries = {entry.lease_id: entry for entry in manifest.entries}
        extra_ids = set(by_lease) - set(expected_entries)
        missing_ids = set(expected_entries) - set(by_lease)
        if extra_ids:
            findings.append(f"unmanifested lease bundles supplied: {sorted(extra_ids)}")
            status = ReconciliationStatus.REJECTED
        if missing_ids:
            findings.append(f"missing manifest lease bundles: {sorted(missing_ids)}")
            if status is not ReconciliationStatus.REJECTED:
                status = ReconciliationStatus.INCOMPLETE

        totals = {"committed": 0, "reserved": 0, "indeterminate": 0, "occupied": 0}
        for lease_id in sorted(set(expected_entries) & set(by_lease)):
            entry = expected_entries[lease_id]
            bundle = by_lease[lease_id]
            local_findings: list[str] = []
            checkpoint_verified = False
            lease = bundle.lease
            ledger = bundle.ledger

            if not verify_lease_signature(lease, issuer_public_key_bytes):
                local_findings.append("lease issuer signature is invalid")
            if (
                lease.grant_id != entry.grant_id
                or lease.allocated_budget != entry.allocated_budget
                or lease_credential_digest(lease) != entry.credential_hash
            ):
                local_findings.append("lease credential does not match issuer allocation manifest")
            if (
                lease.root_grant_id != manifest.root_grant_id
                or lease.root_budget != manifest.root_budget
                or lease.cost_unit != manifest.cost_unit
                or lease.allowed_tool != manifest.allowed_tool
                or lease.schema_hash != manifest.schema_hash
                or lease.issuer_key_id != manifest.issuer_key_id
            ):
                local_findings.append("lease root or policy fields differ from allocation manifest")
            if ledger.lease.to_dict() != lease.to_dict():
                local_findings.append("ledger is not bound to the supplied lease")

            snapshot = ledger.snapshot
            if snapshot.lease_id != lease.lease_id or snapshot.allocated_budget != lease.allocated_budget:
                local_findings.append("ledger snapshot does not match lease allocation")

            trusted_executor_key = trusted_executor_keys.get(lease_id)
            if trusted_executor_key is None:
                local_findings.append("no independently trusted executor key is configured for this lease")
            elif not isinstance(trusted_executor_key, bytes) or len(trusted_executor_key) != 32:
                local_findings.append("configured trusted executor key is not a 32-byte Ed25519 public key")
            elif bundle.executor_public_key_bytes != trusted_executor_key:
                local_findings.append("evidence bundle executor key does not match the independently trusted key")
            else:
                chain_ok = verify_receipt_chain(
                    bundle.receipts,
                    lease=lease,
                    issuer_public_key_bytes=issuer_public_key_bytes,
                    executor_public_key_bytes=trusted_executor_key,
                    ledger=ledger,
                )
                if not chain_ok:
                    local_findings.append("receipt chain does not verify against lease and terminal ledger operations")

            observed_length = len(bundle.receipts)
            observed_head = bundle.receipts[-1].receipt_hash if bundle.receipts else _ZERO_HASH
            if any(receipt.chain_id != bundle.chain_id for receipt in bundle.receipts):
                local_findings.append("receipt chain_id differs from evidence bundle")
            if bundle.trusted_head is None:
                local_findings.append("no independent trusted chain-head anchor; suffix completeness is unproven")
            else:
                anchor = bundle.trusted_head
                if anchor.lease_id != lease_id:
                    local_findings.append("trusted chain-head anchor is for a different lease")
                elif (
                    anchor.chain_id != bundle.chain_id
                    or anchor.chain_length != observed_length
                    or anchor.head_hash != observed_head
                ):
                    local_findings.append("submitted receipt chain does not match trusted chain-head anchor")
                else:
                    checkpoint_verified = True

            committed = snapshot.committed_budget
            reserved = snapshot.reserved_budget
            indeterminate = snapshot.indeterminate_budget
            occupied = committed + reserved + indeterminate
            if occupied > lease.allocated_budget:
                local_findings.append("occupied budget exceeds lease allocation")
            if reserved > 0:
                local_findings.append("one or more operations remain reserved")
            if indeterminate > 0:
                local_findings.append("one or more operations have indeterminate execution outcomes")

            totals["committed"] += committed
            totals["reserved"] += reserved
            totals["indeterminate"] += indeterminate
            totals["occupied"] += occupied
            lease_reports.append(
                LeaseReconciliation(
                    lease_id=lease_id,
                    allocated_budget=lease.allocated_budget,
                    committed_budget=committed,
                    reserved_budget=reserved,
                    indeterminate_budget=indeterminate,
                    aborted_count=snapshot.aborted_count,
                    occupied_budget=occupied,
                    receipt_count=observed_length,
                    checkpoint_verified=checkpoint_verified,
                    findings=tuple(local_findings),
                )
            )
            if local_findings:
                findings.extend(f"{lease_id}: {item}" for item in local_findings)
                hard_failure = any(
                    item not in {
                        "no independent trusted chain-head anchor; suffix completeness is unproven",
                        "no independently trusted executor key is configured for this lease",
                        "one or more operations remain reserved",
                        "one or more operations have indeterminate execution outcomes",
                    }
                    for item in local_findings
                )
                if hard_failure:
                    status = ReconciliationStatus.REJECTED
                elif status is ReconciliationStatus.ACCEPTED:
                    status = ReconciliationStatus.INCOMPLETE

        allocated = manifest.allocated_budget
        if allocated > manifest.root_budget:
            findings.append("manifest allocated budget exceeds root budget")
            status = ReconciliationStatus.REJECTED
        if totals["occupied"] > manifest.root_budget:
            findings.append("aggregate occupied budget exceeds root budget")
            status = ReconciliationStatus.REJECTED

        return ReconciliationReport(
            status=status,
            root_grant_id=manifest.root_grant_id,
            root_budget=manifest.root_budget,
            allocated_budget=allocated,
            committed_budget=totals["committed"],
            reserved_budget=totals["reserved"],
            indeterminate_budget=totals["indeterminate"],
            occupied_budget=totals["occupied"],
            unallocated_budget=manifest.root_budget - allocated,
            leases=tuple(lease_reports),
            findings=tuple(findings),
        )
