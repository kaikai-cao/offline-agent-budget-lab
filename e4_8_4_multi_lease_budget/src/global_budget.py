"""Software-only multi-Lease global budget broker.

One immutable budget epoch owns one shared counter, one SQLite journal and one
cross-process admission lock. Issuer-signed Lease Grants reserve quota in that
epoch. This module is an experimental model, not a TPM/TEE or production
multi-host implementation.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterable, Mapping
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GlobalBudgetError(RuntimeError):
    """Base class for deterministic broker denials and integrity failures."""


class GrantRejected(GlobalBudgetError):
    pass


class GlobalBudgetMismatch(GrantRejected):
    pass


class LeaseRegistrationConflict(GlobalBudgetError):
    pass


class LeaseNotRegistered(GlobalBudgetError):
    pass


class LeaseInactive(GlobalBudgetError):
    pass


class GlobalBudgetExceeded(GlobalBudgetError):
    pass


class LeaseQuotaExceeded(GlobalBudgetError):
    pass


class OperationBindingConflict(GlobalBudgetError):
    pass


class OperationNotApplied(GlobalBudgetError):
    pass


class BrokerIndeterminate(GlobalBudgetError):
    pass


class BrokerConfigurationMismatch(GlobalBudgetError):
    pass


class RevocationRejected(GlobalBudgetError):
    pass


class InjectedCrash(GlobalBudgetError):
    """A deterministic interruption after a durable protocol boundary."""


# ---------------------------------------------------------------------------
# Canonical data and signed protocol objects
# ---------------------------------------------------------------------------

def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not canonical-JSON serializable: {exc}") from exc


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(ch in "0123456789abcdef" for ch in value[7:])
    )


@dataclass(frozen=True)
class ToolPermission:
    tool_name: str
    schema_hash: str

    def as_dict(self) -> dict[str, str]:
        return {"tool_name": self.tool_name, "schema_hash": self.schema_hash}


@dataclass(frozen=True)
class LeaseGrant:
    """Issuer-signed version-3 Lease authorization for one budget epoch."""

    version: int
    issuer_id: str
    grant_id: str
    lease_id: str
    global_budget_id: str
    nonce: str
    quota_limit: int
    issued_at: int
    expires_at: int
    audience: str
    subject_id: str
    context_digest: str
    allowed_tools: tuple[ToolPermission, ...]
    signature_b64: str

    def unsigned_dict(self) -> dict[str, Any]:
        permissions = sorted(
            (p.as_dict() for p in self.allowed_tools),
            key=lambda item: item["tool_name"],
        )
        return {
            "version": self.version,
            "issuer_id": self.issuer_id,
            "grant_id": self.grant_id,
            "lease_id": self.lease_id,
            "global_budget_id": self.global_budget_id,
            "nonce": self.nonce,
            "quota_limit": self.quota_limit,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "audience": self.audience,
            "subject_id": self.subject_id,
            "context_digest": self.context_digest,
            "allowed_tools": permissions,
        }

    @property
    def grant_digest(self) -> str:
        return "sha256:" + sha256_hex(self.unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LeaseGrant":
        if not isinstance(value, Mapping):
            raise ValueError("LeaseGrant payload must be an object")
        expected = {
            "version", "issuer_id", "grant_id", "lease_id", "global_budget_id",
            "nonce", "quota_limit", "issued_at", "expires_at", "audience",
            "subject_id", "context_digest", "allowed_tools", "signature_b64",
        }
        if set(value) != expected:
            raise ValueError("LeaseGrant fields do not match the version-3 schema")
        tools = value["allowed_tools"]
        if not isinstance(tools, list):
            raise ValueError("allowed_tools must be a list")
        permissions_list = []
        for item in tools:
            if not isinstance(item, Mapping) or set(item) != {"tool_name", "schema_hash"}:
                raise ValueError("each allowed_tools item must contain tool_name and schema_hash")
            permissions_list.append(
                ToolPermission(tool_name=item["tool_name"], schema_hash=item["schema_hash"])
            )
        permissions = tuple(permissions_list)
        return cls(
            version=value["version"], issuer_id=value["issuer_id"],
            grant_id=value["grant_id"], lease_id=value["lease_id"],
            global_budget_id=value["global_budget_id"], nonce=value["nonce"],
            quota_limit=value["quota_limit"], issued_at=value["issued_at"],
            expires_at=value["expires_at"], audience=value["audience"],
            subject_id=value["subject_id"], context_digest=value["context_digest"],
            allowed_tools=permissions, signature_b64=value["signature_b64"],
        )


def _validate_grant_shape(grant: LeaseGrant) -> None:
    if not isinstance(grant, LeaseGrant):
        raise GrantRejected("grant must be a LeaseGrant")
    if grant.version != 3:
        raise GrantRejected("Global Budget Broker accepts only LeaseGrant version 3")
    for field_name in (
        "issuer_id", "grant_id", "lease_id", "global_budget_id", "nonce",
        "audience", "subject_id", "context_digest",
    ):
        try:
            _nonempty(getattr(grant, field_name), field_name)
        except ValueError as exc:
            raise GrantRejected(str(exc)) from exc
    for field_name in ("quota_limit", "issued_at", "expires_at"):
        value = getattr(grant, field_name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise GrantRejected(f"{field_name} must be an integer")
    if grant.quota_limit <= 0:
        raise GrantRejected("quota_limit must be positive")
    if grant.issued_at >= grant.expires_at:
        raise GrantRejected("grant validity interval is empty")
    if not isinstance(grant.allowed_tools, tuple) or not grant.allowed_tools:
        raise GrantRejected("grant must authorize at least one tool")
    names: set[str] = set()
    for permission in grant.allowed_tools:
        if not isinstance(permission, ToolPermission):
            raise GrantRejected("allowed_tools contains an invalid permission")
        try:
            tool_name = _nonempty(permission.tool_name, "tool_name")
        except ValueError as exc:
            raise GrantRejected(str(exc)) from exc
        if tool_name in names:
            raise GrantRejected("allowed_tools contains duplicate tool names")
        names.add(tool_name)
        if not _is_sha256(permission.schema_hash):
            raise GrantRejected("tool schema_hash must be a sha256 digest")
    if not isinstance(grant.signature_b64, str) or not grant.signature_b64:
        raise GrantRejected("grant signature is missing")


def issue_lease_grant(
    private_key: Ed25519PrivateKey,
    *,
    issuer_id: str,
    grant_id: str,
    lease_id: str,
    global_budget_id: str,
    nonce: str,
    quota_limit: int,
    issued_at: int,
    expires_at: int,
    audience: str,
    subject_id: str,
    context_digest: str,
    allowed_tools: Iterable[ToolPermission],
) -> LeaseGrant:
    permissions = tuple(allowed_tools)
    unsigned = LeaseGrant(
        version=3,
        issuer_id=issuer_id,
        grant_id=grant_id,
        lease_id=lease_id,
        global_budget_id=global_budget_id,
        nonce=nonce,
        quota_limit=quota_limit,
        issued_at=issued_at,
        expires_at=expires_at,
        audience=audience,
        subject_id=subject_id,
        context_digest=context_digest,
        allowed_tools=permissions,
        signature_b64="pending",
    )
    _validate_grant_shape(unsigned)
    signature = private_key.sign(canonical_json_bytes(unsigned.unsigned_dict()))
    return LeaseGrant(
        **{**unsigned.__dict__, "signature_b64": base64.b64encode(signature).decode("ascii")}
    )


def verify_lease_grant(
    grant: LeaseGrant,
    trusted_issuer_public_key: Ed25519PublicKey,
) -> None:
    _validate_grant_shape(grant)
    try:
        signature = base64.b64decode(grant.signature_b64, validate=True)
        trusted_issuer_public_key.verify(signature, canonical_json_bytes(grant.unsigned_dict()))
    except (ValueError, InvalidSignature) as exc:
        raise GrantRejected("LeaseGrant signature is invalid") from exc


@dataclass(frozen=True)
class LeaseRevocation:
    version: int
    issuer_id: str
    global_budget_id: str
    revocation_id: str
    lease_id: str
    grant_digest: str
    revoked_at: int
    signature_b64: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "issuer_id": self.issuer_id,
            "global_budget_id": self.global_budget_id,
            "revocation_id": self.revocation_id,
            "lease_id": self.lease_id,
            "grant_digest": self.grant_digest,
            "revoked_at": self.revoked_at,
        }

    @property
    def revocation_digest(self) -> str:
        return "sha256:" + sha256_hex(self.unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LeaseRevocation":
        expected = {
            "version", "issuer_id", "global_budget_id", "revocation_id",
            "lease_id", "grant_digest", "revoked_at", "signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("revocation fields do not match the schema")
        return cls(**dict(value))


def issue_lease_revocation(
    private_key: Ed25519PrivateKey,
    *,
    issuer_id: str,
    global_budget_id: str,
    revocation_id: str,
    lease_id: str,
    grant_digest: str,
    revoked_at: int,
) -> LeaseRevocation:
    record = LeaseRevocation(
        version=1, issuer_id=issuer_id, global_budget_id=global_budget_id,
        revocation_id=revocation_id, lease_id=lease_id,
        grant_digest=grant_digest, revoked_at=revoked_at, signature_b64="pending",
    )
    signature = private_key.sign(canonical_json_bytes(record.unsigned_dict()))
    return LeaseRevocation(
        **{**record.__dict__, "signature_b64": base64.b64encode(signature).decode("ascii")}
    )


def _verify_revocation(
    record: LeaseRevocation,
    trusted_issuer_public_key: Ed25519PublicKey,
) -> None:
    if not isinstance(record, LeaseRevocation) or record.version != 1:
        raise RevocationRejected("unsupported revocation record")
    for name in ("issuer_id", "global_budget_id", "revocation_id", "lease_id"):
        value = getattr(record, name)
        if not isinstance(value, str) or not value.strip():
            raise RevocationRejected(f"{name} must be a non-empty string")
    if not _is_sha256(record.grant_digest):
        raise RevocationRejected("grant_digest must be a sha256 digest")
    if not isinstance(record.revoked_at, int) or isinstance(record.revoked_at, bool):
        raise RevocationRejected("revoked_at must be an integer")
    if not isinstance(record.signature_b64, str) or not record.signature_b64:
        raise RevocationRejected("revocation signature is missing")
    try:
        signature = base64.b64decode(record.signature_b64, validate=True)
        trusted_issuer_public_key.verify(signature, canonical_json_bytes(record.unsigned_dict()))
    except (ValueError, InvalidSignature) as exc:
        raise RevocationRejected("revocation signature is invalid") from exc


# ---------------------------------------------------------------------------
# Cross-process lock and file-backed counter emulator
# ---------------------------------------------------------------------------

class CrossProcessFileLock:
    """Advisory host-local lock: msvcrt on Windows, flock on POSIX."""

    def __init__(self, path: str | Path, timeout_seconds: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self._fh = None

    def __enter__(self) -> "CrossProcessFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+b", buffering=0)
        if os.fstat(self._fh.fileno()).st_size == 0:
            self._fh.write(b"\0")
            self._fh.flush()
        deadline = time.monotonic() + self.timeout_seconds
        if os.name == "nt":
            import msvcrt
            while True:
                self._fh.seek(0)
                try:
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    if time.monotonic() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(f"timed out acquiring lock: {self.path}")
                    time.sleep(0.05)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(f"timed out acquiring lock: {self.path}")
                    time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is None:
            return
        try:
            self._fh.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None


class FileBackedCounter:
    """JSON-file counter test double; not secure storage or a TPM substitute."""

    def __init__(self, state_path: str | Path, initial_value: int = 0,
                 lock_path: str | Path | None = None) -> None:
        if not isinstance(initial_value, int) or isinstance(initial_value, bool) or initial_value < 0:
            raise ValueError("initial_value must be a non-negative integer")
        self.path = Path(state_path)
        self.lock_path = Path(lock_path) if lock_path is not None else self.path.with_suffix(self.path.suffix + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with CrossProcessFileLock(self.lock_path):
            if not self.path.exists():
                self._write_value_unlocked(initial_value)
            else:
                self._read_value_unlocked()

    def _read_value_unlocked(self) -> int:
        try:
            obj = json.loads(self.path.read_text(encoding="utf-8"))
            value = obj["counter_value"]
        except Exception as exc:
            raise BrokerIndeterminate(f"counter state is unreadable: {exc}") from exc
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BrokerIndeterminate("counter state is not a non-negative integer")
        return value

    def _write_value_unlocked(self, value: int) -> None:
        payload = json.dumps({"counter_value": value}, sort_keys=True) + "\n"
        temporary = self.path.with_name(f"{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def read(self) -> int:
        with CrossProcessFileLock(self.lock_path):
            return self._read_value_unlocked()

    def increment(self) -> int:
        with CrossProcessFileLock(self.lock_path):
            value = self._read_value_unlocked()
            self._write_value_unlocked(value + 1)
        # Like TPM NV_Increment, the modeled write response carries no value.
        return 0


# ---------------------------------------------------------------------------
# Durable SQLite journal
# ---------------------------------------------------------------------------

class SQLiteJournal:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS budget_meta (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                    global_budget_id TEXT NOT NULL,
                    global_quota_limit INTEGER NOT NULL,
                    baseline_counter_value INTEGER NOT NULL,
                    expected_counter_value INTEGER NOT NULL,
                    issuer_public_key_digest TEXT NOT NULL,
                    config_digest TEXT NOT NULL,
                    health TEXT NOT NULL,
                    health_reason TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY,
                    issuer_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL UNIQUE,
                    nonce TEXT NOT NULL UNIQUE,
                    grant_digest TEXT NOT NULL,
                    quota_limit INTEGER NOT NULL CHECK(quota_limit > 0),
                    used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count >= 0),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    audience TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    allowed_tools_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE','EXPIRED','REVOKED'))
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    grant_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    pre_counter_value INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('PENDING','NOT_APPLIED','COMMITTED','INDETERMINATE')),
                    counter_value INTEGER,
                    lease_used_count INTEGER,
                    FOREIGN KEY(lease_id) REFERENCES leases(lease_id)
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    operation_id TEXT PRIMARY KEY,
                    global_budget_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    global_sequence INTEGER NOT NULL UNIQUE,
                    lease_used_count INTEGER NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id),
                    FOREIGN KEY(lease_id) REFERENCES leases(lease_id)
                );
                CREATE TABLE IF NOT EXISTS revocations (
                    revocation_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    grant_digest TEXT NOT NULL,
                    revocation_digest TEXT NOT NULL,
                    revoked_at INTEGER NOT NULL,
                    FOREIGN KEY(lease_id) REFERENCES leases(lease_id)
                );
                CREATE INDEX IF NOT EXISTS ix_operations_status ON operations(status);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    @contextmanager
    def _db(self):
        con = self._connect()
        try:
            yield con
        finally:
            con.close()

    def initialize(self, *, global_budget_id: str, global_quota_limit: int,
                   baseline_counter_value: int, issuer_digest: str,
                   config_digest: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT * FROM budget_meta WHERE singleton_id=1").fetchone()
                expected = (
                    global_budget_id, global_quota_limit, issuer_digest, config_digest
                )
                if row is None:
                    con.execute(
                        "INSERT INTO budget_meta(singleton_id,global_budget_id,global_quota_limit,"
                        "baseline_counter_value,expected_counter_value,issuer_public_key_digest,"
                        "config_digest,health,health_reason) VALUES(1,?,?,?,?,?,?,'READY','')",
                        (global_budget_id, global_quota_limit, baseline_counter_value,
                         baseline_counter_value, issuer_digest, config_digest),
                    )
                else:
                    stored = (row[1], row[2], row[5], row[6])
                    if stored != expected:
                        raise BrokerConfigurationMismatch(
                            "global budget epoch, limit, Issuer key or durable storage configuration changed"
                        )
                con.commit()
            except Exception:
                con.rollback()
                raise

    def has_meta_record(self) -> bool:
        with self._db() as con:
            row = con.execute(
                "SELECT 1 FROM budget_meta WHERE singleton_id=1"
            ).fetchone()
        return row is not None

    def meta(self) -> dict[str, Any]:
        with self._db() as con:
            row = con.execute(
                "SELECT global_budget_id,global_quota_limit,baseline_counter_value,"
                "expected_counter_value,issuer_public_key_digest,config_digest,health,health_reason "
                "FROM budget_meta WHERE singleton_id=1"
            ).fetchone()
        if row is None:
            raise BrokerIndeterminate("budget metadata is missing")
        keys = ("global_budget_id", "global_quota_limit", "baseline_counter_value",
                "expected_counter_value", "issuer_public_key_digest", "config_digest",
                "health", "health_reason")
        return dict(zip(keys, row))

    def get_lease(self, lease_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute(
                "SELECT lease_id,issuer_id,grant_id,nonce,grant_digest,quota_limit,used_count,issued_at,"
                "expires_at,audience,subject_id,context_digest,allowed_tools_json,state "
                "FROM leases WHERE lease_id=?", (lease_id,)
            ).fetchone()
        if row is None:
            return None
        keys = ("lease_id", "issuer_id", "grant_id", "nonce", "grant_digest", "quota_limit", "used_count",
                "issued_at", "expires_at", "audience", "subject_id", "context_digest",
                "allowed_tools_json", "state")
        return dict(zip(keys, row))

    def all_leases(self) -> list[dict[str, Any]]:
        with self._db() as con:
            ids = [row[0] for row in con.execute("SELECT lease_id FROM leases ORDER BY lease_id")]
        return [self.get_lease(lease_id) for lease_id in ids]

    def get_operation(self, operation_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute(
                "SELECT operation_id,lease_id,grant_digest,request_digest,pre_counter_value,"
                "status,counter_value,lease_used_count FROM operations WHERE operation_id=?",
                (operation_id,)
            ).fetchone()
        if row is None:
            return None
        keys = ("operation_id", "lease_id", "grant_digest", "request_digest", "pre_counter_value",
                "status", "counter_value", "lease_used_count")
        return dict(zip(keys, row))

    def pending_operations(self) -> list[dict[str, Any]]:
        with self._db() as con:
            ids = [row[0] for row in con.execute(
                "SELECT operation_id FROM operations WHERE status='PENDING' ORDER BY operation_id"
            )]
        return [self.get_operation(operation_id) for operation_id in ids]

    def get_receipt(self, operation_id: str) -> "GlobalBudgetReceipt | None":
        with self._db() as con:
            row = con.execute(
                "SELECT global_budget_id,lease_id,operation_id,request_digest,global_sequence,"
                "lease_used_count FROM receipts WHERE operation_id=?", (operation_id,)
            ).fetchone()
        return GlobalBudgetReceipt(*row) if row else None

    def _mark_not_applied(self, operation_id: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE operations SET status='NOT_APPLIED' WHERE operation_id=? AND status='PENDING'", (operation_id,))
            con.commit()

    def _mark_indeterminate(self, operation_ids: Iterable[str], reason: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.executemany(
                "UPDATE operations SET status='INDETERMINATE' WHERE operation_id=? AND status='PENDING'",
                [(operation_id,) for operation_id in operation_ids],
            )
            con.execute(
                "UPDATE budget_meta SET health='INDETERMINATE',health_reason=? WHERE singleton_id=1",
                (reason,),
            )
            con.commit()

    def commit_pending(self, row: Mapping[str, Any], counter_value: int) -> "GlobalBudgetReceipt":
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                current = con.execute(
                    "SELECT status,lease_id,grant_digest,request_digest,pre_counter_value "
                    "FROM operations WHERE operation_id=?", (row["operation_id"],)
                ).fetchone()
                meta = con.execute(
                    "SELECT global_budget_id,expected_counter_value FROM budget_meta WHERE singleton_id=1"
                ).fetchone()
                lease = con.execute(
                    "SELECT grant_digest,quota_limit,used_count FROM leases WHERE lease_id=?",
                    (row["lease_id"],)
                ).fetchone()
                if current is None or current[0] != "PENDING":
                    raise BrokerIndeterminate("pending operation changed before receipt commit")
                if (current[1], current[2], current[3], current[4]) != (
                    row["lease_id"], row["grant_digest"], row["request_digest"], row["pre_counter_value"]
                ):
                    raise BrokerIndeterminate("pending operation binding changed")
                if meta is None or counter_value != int(meta[1]) + 1 or counter_value != int(row["pre_counter_value"]) + 1:
                    raise BrokerIndeterminate("counter sequence does not match pending intent")
                if lease is None or lease[0] != row["grant_digest"]:
                    raise BrokerIndeterminate("pending operation Lease binding is missing or changed")
                if int(lease[2]) >= int(lease[1]):
                    raise BrokerIndeterminate("pending operation would exceed its Lease quota")
                next_used = int(lease[2]) + 1
                con.execute(
                    "UPDATE leases SET used_count=? WHERE lease_id=? AND used_count=?",
                    (next_used, row["lease_id"], int(lease[2]))
                )
                con.execute(
                    "INSERT INTO receipts(operation_id,global_budget_id,lease_id,request_digest,"
                    "global_sequence,lease_used_count) VALUES(?,?,?,?,?,?)",
                    (row["operation_id"], meta[0], row["lease_id"], row["request_digest"],
                     counter_value, next_used)
                )
                con.execute(
                    "UPDATE operations SET status='COMMITTED',counter_value=?,lease_used_count=? "
                    "WHERE operation_id=? AND status='PENDING'",
                    (counter_value, next_used, row["operation_id"])
                )
                con.execute(
                    "UPDATE budget_meta SET expected_counter_value=? WHERE singleton_id=1",
                    (counter_value,)
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
        return GlobalBudgetReceipt(
            global_budget_id=meta[0], lease_id=row["lease_id"],
            operation_id=row["operation_id"], request_digest=row["request_digest"],
            global_sequence=counter_value, lease_used_count=next_used,
        )

    def _set_lease_state(self, lease_id: str, state: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE leases SET state=? WHERE lease_id=?", (state, lease_id))
            con.commit()

    def _insert_lease(self, grant: LeaseGrant) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                reserved = int(con.execute("SELECT COALESCE(SUM(quota_limit),0) FROM leases").fetchone()[0])
                meta = con.execute("SELECT global_quota_limit FROM budget_meta WHERE singleton_id=1").fetchone()
                if meta is None:
                    raise BrokerIndeterminate("global budget metadata is missing")
                if reserved + grant.quota_limit > int(meta[0]):
                    raise GlobalBudgetExceeded(
                        f"Lease reservation would exceed global budget: reserved={reserved}, "
                        f"requested={grant.quota_limit}, limit={meta[0]}"
                    )
                con.execute(
                    "INSERT INTO leases(lease_id,issuer_id,grant_id,nonce,grant_digest,quota_limit,used_count,"
                    "issued_at,expires_at,audience,subject_id,context_digest,allowed_tools_json,state) "
                    "VALUES(?,?,?,?,?,?,0,?,?,?,?,?,?,'ACTIVE')",
                    (grant.lease_id, grant.issuer_id, grant.grant_id, grant.nonce, grant.grant_digest,
                     grant.quota_limit, grant.issued_at, grant.expires_at, grant.audience,
                     grant.subject_id, grant.context_digest,
                     canonical_json_bytes([p.as_dict() for p in grant.allowed_tools]).decode("utf-8"))
                )
                con.commit()
            except Exception:
                con.rollback()
                raise

    def _insert_revocation(self, record: LeaseRevocation) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO revocations(revocation_id,lease_id,grant_digest,revocation_digest,revoked_at) "
                "VALUES(?,?,?,?,?)",
                (record.revocation_id, record.lease_id, record.grant_digest,
                 record.revocation_digest, record.revoked_at)
            )
            con.execute("UPDATE leases SET state='REVOKED' WHERE lease_id=?", (record.lease_id,))
            con.commit()

    def totals(self) -> dict[str, int]:
        with self._db() as con:
            reserved, used = con.execute(
                "SELECT COALESCE(SUM(quota_limit),0),COALESCE(SUM(used_count),0) FROM leases"
            ).fetchone()
        return {"reserved": int(reserved), "used": int(used)}

    def accounting_integrity(self, *, baseline: int, expected: int,
                             global_budget_id: str) -> dict[str, int | bool]:
        with self._db() as con:
            committed_count = int(con.execute(
                "SELECT COUNT(*) FROM operations WHERE status='COMMITTED'"
            ).fetchone()[0])
            receipt_count = int(con.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
            mismatched_receipts = int(con.execute(
                "SELECT COUNT(*) FROM operations o LEFT JOIN receipts r "
                "ON r.operation_id=o.operation_id "
                "WHERE (o.status='COMMITTED' AND (r.operation_id IS NULL OR "
                "r.global_budget_id<>? OR r.lease_id<>o.lease_id OR "
                "r.request_digest<>o.request_digest OR "
                "r.global_sequence<>o.counter_value OR "
                "r.lease_used_count<>o.lease_used_count)) "
                "OR (o.status<>'COMMITTED' AND r.operation_id IS NOT NULL)",
                (global_budget_id,),
            ).fetchone()[0])
            mismatched_lease_usage = len(con.execute(
                "SELECT l.lease_id FROM leases l LEFT JOIN operations o "
                "ON o.lease_id=l.lease_id AND o.status='COMMITTED' "
                "GROUP BY l.lease_id HAVING l.used_count<>COUNT(o.operation_id)"
            ).fetchall())
            sequence = con.execute(
                "SELECT COUNT(*),MIN(global_sequence),MAX(global_sequence) FROM receipts"
            ).fetchone()
        sequence_count = int(sequence[0])
        sequence_ok = (
            (sequence_count == 0 and expected == baseline)
            or (
                sequence_count == expected - baseline
                and int(sequence[1]) == baseline + 1
                and int(sequence[2]) == expected
            )
        )
        return {
            "committed_count": committed_count,
            "receipt_count": receipt_count,
            "mismatched_receipts": mismatched_receipts,
            "mismatched_lease_usage": mismatched_lease_usage,
            "sequence_ok": sequence_ok,
        }

    def revocation(self, revocation_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute(
                "SELECT revocation_id,lease_id,grant_digest,revocation_digest,revoked_at "
                "FROM revocations WHERE revocation_id=?", (revocation_id,)
            ).fetchone()
        if row is None:
            return None
        keys = ("revocation_id", "lease_id", "grant_digest", "revocation_digest", "revoked_at")
        return dict(zip(keys, row))

    def create_intent(self, *, operation_id: str, lease_id: str,
                      grant_digest: str, request_digest: str, pre_counter_value: int) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO operations(operation_id,lease_id,grant_digest,request_digest,"
                    "pre_counter_value,status) VALUES(?,?,?,?,?,'PENDING')",
                    (operation_id, lease_id, grant_digest, request_digest, pre_counter_value)
                )
                con.commit()
            except Exception:
                con.rollback()
                raise

    def set_health_indeterminate(self, reason: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE budget_meta SET health='INDETERMINATE',health_reason=? WHERE singleton_id=1",
                (reason,)
            )
            con.commit()


@dataclass(frozen=True)
class GlobalBudgetReceipt:
    global_budget_id: str
    lease_id: str
    operation_id: str
    request_digest: str
    global_sequence: int
    lease_used_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "global_budget_id": self.global_budget_id,
            "lease_id": self.lease_id,
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "global_sequence": self.global_sequence,
            "lease_used_count": self.lease_used_count,
        }


# ---------------------------------------------------------------------------
# Global Broker
# ---------------------------------------------------------------------------

class GlobalBudgetBroker:
    """One shared broker for multiple Lease reservations and one global counter."""

    VALID_CRASH_POINTS = {
        None, "after_intent", "after_increment", "after_read", "after_receipt_commit"
    }

    def __init__(
        self,
        *,
        global_budget_id: str,
        global_quota_limit: int,
        issuer_public_key: Ed25519PublicKey,
        journal_path: str | Path,
        counter_state_path: str | Path,
        broker_lock_path: str | Path,
        counter_lock_path: str | Path | None = None,
        initial_counter_value: int = 0,
        clock=None,
    ) -> None:
        self.global_budget_id = _nonempty(global_budget_id, "global_budget_id")
        if not isinstance(global_quota_limit, int) or isinstance(global_quota_limit, bool) or global_quota_limit <= 0:
            raise ValueError("global_quota_limit must be a positive integer")
        self.global_quota_limit = global_quota_limit
        if not isinstance(issuer_public_key, Ed25519PublicKey):
            raise ValueError("issuer_public_key must be an Ed25519PublicKey")
        self.issuer_public_key = issuer_public_key
        self.journal = SQLiteJournal(journal_path)
        self.counter = FileBackedCounter(
            counter_state_path, initial_counter_value, lock_path=counter_lock_path
        )
        self.lock_path = Path(broker_lock_path)
        self.clock = clock or (lambda: int(time.time()))
        self.issuer_public_key_digest = self._issuer_key_digest()
        self.config_digest = self._configuration_digest()
        with CrossProcessFileLock(self.lock_path):
            anchor = self._verify_config_anchor_if_present()
            observed_at_open = self.counter.read()
            if anchor is not None and not self.journal.has_meta_record():
                # A missing Journal must not silently rebase the budget to a
                # counter value that has already advanced within this epoch.
                if observed_at_open != int(anchor["baseline_counter_value"]):
                    raise BrokerConfigurationMismatch(
                        "global journal is missing while the counter is ahead of its pinned baseline"
                    )
                baseline = int(anchor["baseline_counter_value"])
            else:
                baseline = observed_at_open
            self.journal.initialize(
                global_budget_id=self.global_budget_id,
                global_quota_limit=self.global_quota_limit,
                baseline_counter_value=baseline,
                issuer_digest=self.issuer_public_key_digest,
                config_digest=self.config_digest,
            )
            meta = self.journal.meta()
            if anchor is not None and int(meta["baseline_counter_value"]) != int(anchor["baseline_counter_value"]):
                raise BrokerConfigurationMismatch(
                    "global journal baseline differs from the counter-domain configuration anchor"
                )
            self._create_config_anchor_if_missing(int(meta["baseline_counter_value"]))

    def _issuer_key_digest(self) -> str:
        raw = self.issuer_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _canonical_path(value: str | Path) -> str:
        return os.path.normcase(str(Path(value).expanduser().resolve(strict=False)))

    def _configuration_digest(self) -> str:
        try:
            material = {
                "version": 1,
                "global_budget_id": self.global_budget_id,
                "global_quota_limit": self.global_quota_limit,
                "issuer_public_key_digest": self._issuer_key_digest(),
                "journal_path": self._canonical_path(self.journal.path),
                "counter_state_path": self._canonical_path(self.counter.path),
                "counter_lock_path": self._canonical_path(self.counter.lock_path),
                "broker_lock_path": self._canonical_path(self.lock_path),
            }
        except AttributeError as exc:
            raise BrokerConfigurationMismatch("Broker durable configuration is incomplete") from exc
        return "sha256:" + sha256_hex(material)

    def _config_anchor_path(self) -> Path:
        return self.counter.path.with_suffix(self.counter.path.suffix + ".config.json")

    def _config_anchor_payload(self, baseline_counter_value: int) -> dict[str, str | int]:
        return {
            "version": 1,
            "global_budget_id": self.global_budget_id,
            "config_digest": self.config_digest,
            "baseline_counter_value": baseline_counter_value,
        }

    def _verify_config_anchor_if_present(self) -> dict[str, Any] | None:
        anchor = self._config_anchor_path()
        if not anchor.exists():
            return None
        try:
            stored = json.loads(anchor.read_text(encoding="utf-8"))
        except Exception as exc:
            raise BrokerConfigurationMismatch(f"configuration anchor is unreadable: {exc}") from exc
        if (
            not isinstance(stored, dict)
            or stored.get("version") != 1
            or stored.get("global_budget_id") != self.global_budget_id
            or stored.get("config_digest") != self.config_digest
            or not isinstance(stored.get("baseline_counter_value"), int)
            or isinstance(stored.get("baseline_counter_value"), bool)
            or stored.get("baseline_counter_value", -1) < 0
        ):
            raise BrokerConfigurationMismatch(
                "global budget configuration differs from the counter-domain configuration anchor"
            )
        return stored

    def _create_config_anchor_if_missing(self, baseline_counter_value: int) -> None:
        anchor = self._config_anchor_path()
        anchor.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_json_bytes(
            self._config_anchor_payload(baseline_counter_value)
        ).decode("utf-8") + "\n"
        try:
            with open(anchor, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            stored = self._verify_config_anchor_if_present()
            if stored is None or int(stored["baseline_counter_value"]) != baseline_counter_value:
                raise BrokerConfigurationMismatch("counter-domain configuration anchor conflicts")

    def _assert_configuration(self) -> None:
        current = self._configuration_digest()
        if current != self.config_digest:
            raise BrokerConfigurationMismatch("Global Budget Broker configuration changed after initialization")
        meta = self.journal.meta()
        if meta["config_digest"] != current:
            raise BrokerConfigurationMismatch("Global Budget Broker configuration differs from the pinned journal")
        anchor = self._verify_config_anchor_if_present()
        if anchor is not None and int(anchor["baseline_counter_value"]) != int(meta["baseline_counter_value"]):
            raise BrokerConfigurationMismatch("journal baseline differs from the counter-domain configuration anchor")

    def _mark_indeterminate(self, reason: str, operation_ids: Iterable[str] = ()) -> None:
        self.journal._mark_indeterminate(operation_ids, reason)

    def _assert_invariants_locked(self) -> dict[str, int]:
        meta = self.journal.meta()
        totals = self.journal.totals()
        observed = self.counter.read()
        baseline = int(meta["baseline_counter_value"])
        expected = int(meta["expected_counter_value"])
        global_limit = int(meta["global_quota_limit"])
        leases = self.journal.all_leases()
        accounting = self.journal.accounting_integrity(
            baseline=baseline,
            expected=expected,
            global_budget_id=meta["global_budget_id"],
        )
        violations: list[str] = []
        if totals["reserved"] > global_limit:
            violations.append("sum of Lease reservations exceeds global quota")
        if any(int(lease["used_count"]) < 0 or int(lease["used_count"]) > int(lease["quota_limit"]) for lease in leases):
            violations.append("a Lease used_count is outside its quota")
        if totals["used"] != expected - baseline:
            violations.append("sum of Lease usage differs from global counter journal anchor")
        if observed != expected:
            violations.append(f"counter anchor mismatch: journal={expected}, observed={observed}")
        if expected - baseline < 0 or expected - baseline > global_limit:
            violations.append("global counter usage is outside the global quota")
        if totals["used"] > totals["reserved"]:
            violations.append("global usage exceeds total Lease reservations")
        if accounting["committed_count"] != totals["used"] or accounting["receipt_count"] != totals["used"]:
            violations.append("committed operations, durable receipts and Lease usage totals differ")
        if accounting["mismatched_receipts"]:
            violations.append("one or more committed operations do not match their durable receipts")
        if accounting["mismatched_lease_usage"]:
            violations.append("one or more Lease usage counters differ from committed operation attribution")
        if not accounting["sequence_ok"]:
            violations.append("durable receipt sequences are not contiguous with the global counter anchor")
        if violations:
            reason = "; ".join(violations)
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)
        if meta["health"] != "READY":
            raise BrokerIndeterminate(meta["health_reason"] or "Global Budget Broker is indeterminate")
        return {
            "reserved": totals["reserved"],
            "used": totals["used"],
            "counter_value": observed,
            "baseline_counter_value": baseline,
            "global_quota_limit": global_limit,
        }

    def _recover_pending_locked(self) -> GlobalBudgetReceipt | None:
        pending = self.journal.pending_operations()
        if not pending:
            return None
        if len(pending) != 1:
            ids = [row["operation_id"] for row in pending]
            reason = f"expected at most one pending global increment; found {len(pending)}"
            self._mark_indeterminate(reason, ids)
            raise BrokerIndeterminate(reason)
        row = pending[0]
        meta = self.journal.meta()
        if meta["health"] != "READY":
            raise BrokerIndeterminate(meta["health_reason"] or "global journal is indeterminate")
        if int(row["pre_counter_value"]) != int(meta["expected_counter_value"]):
            reason = "pending intent pre-counter value differs from global journal anchor"
            self._mark_indeterminate(reason, [row["operation_id"]])
            raise BrokerIndeterminate(reason)
        observed = self.counter.read()
        delta = observed - int(row["pre_counter_value"])
        if delta == 0:
            self.journal._mark_not_applied(row["operation_id"])
            return None
        if delta == 1:
            try:
                return self.journal.commit_pending(row, observed)
            except Exception as exc:
                reason = f"could not atomically settle pending global operation: {exc}"
                self._mark_indeterminate(reason, [row["operation_id"]])
                raise BrokerIndeterminate(reason) from exc
        reason = (
            "pending global increment is ambiguous: "
            f"pre={row['pre_counter_value']}, observed={observed}, delta={delta}"
        )
        self._mark_indeterminate(reason, [row["operation_id"]])
        raise BrokerIndeterminate(reason)

    def recover_pending(self) -> GlobalBudgetReceipt | None:
        """Recover the sole durable pending intent; never create a new operation."""
        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            receipt = self._recover_pending_locked()
            self._assert_invariants_locked()
            return receipt

    def register_lease(self, grant: LeaseGrant) -> dict[str, Any]:
        verify_lease_grant(grant, self.issuer_public_key)
        if grant.global_budget_id != self.global_budget_id:
            raise GlobalBudgetMismatch("LeaseGrant belongs to a different global budget epoch")
        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            self._recover_pending_locked()
            self._assert_invariants_locked()
            existing = self.journal.get_lease(grant.lease_id)
            if existing is not None:
                if existing["grant_digest"] == grant.grant_digest:
                    if existing["state"] == "ACTIVE" and int(self.clock()) >= int(existing["expires_at"]):
                        self.journal._set_lease_state(grant.lease_id, "EXPIRED")
                        existing = self.journal.get_lease(grant.lease_id)
                    return existing
                raise LeaseRegistrationConflict("lease_id is already bound to another signed grant")
            now = int(self.clock())
            if now < grant.issued_at:
                raise GrantRejected("LeaseGrant is not yet valid")
            if now >= grant.expires_at:
                raise GrantRejected("LeaseGrant has expired")
            try:
                self.journal._insert_lease(grant)
            except sqlite3.IntegrityError as exc:
                raise LeaseRegistrationConflict("grant_id or nonce is already bound to another Lease") from exc
            self._assert_invariants_locked()
            return self.journal.get_lease(grant.lease_id)

    def revoke_lease(self, record: LeaseRevocation) -> dict[str, Any]:
        _verify_revocation(record, self.issuer_public_key)
        if record.global_budget_id != self.global_budget_id:
            raise GlobalBudgetMismatch("revocation belongs to a different global budget epoch")
        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            self._recover_pending_locked()
            self._assert_invariants_locked()
            existing_revocation = self.journal.revocation(record.revocation_id)
            if existing_revocation is not None:
                if existing_revocation["revocation_digest"] == record.revocation_digest:
                    return self.journal.get_lease(record.lease_id)
                raise RevocationRejected("revocation_id is already bound to different content")
            lease = self.journal.get_lease(record.lease_id)
            if lease is None:
                raise LeaseNotRegistered("cannot revoke an unregistered Lease")
            if lease["grant_digest"] != record.grant_digest or lease["issuer_id"] != record.issuer_id:
                raise RevocationRejected("revocation does not bind the registered Lease grant and Issuer")
            if record.revoked_at < int(lease["issued_at"]) or record.revoked_at > int(self.clock()):
                raise RevocationRejected("revoked_at is outside the accepted time interval")
            try:
                self.journal._insert_revocation(record)
            except sqlite3.IntegrityError as exc:
                raise RevocationRejected("revocation_id conflicts with a stored record") from exc
            self._assert_invariants_locked()
            return self.journal.get_lease(record.lease_id)

    def _committed_receipt_or_fail(self, operation: Mapping[str, Any]) -> GlobalBudgetReceipt:
        receipt = self.journal.get_receipt(operation["operation_id"])
        if receipt is None:
            reason = "committed operation is missing its durable receipt"
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)
        expected = (
            self.global_budget_id,
            operation["lease_id"],
            operation["operation_id"],
            operation["request_digest"],
            operation["counter_value"],
            operation["lease_used_count"],
        )
        actual = (
            receipt.global_budget_id,
            receipt.lease_id,
            receipt.operation_id,
            receipt.request_digest,
            receipt.global_sequence,
            receipt.lease_used_count,
        )
        if actual != expected:
            reason = "committed operation differs from its durable receipt"
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)
        return receipt

    def _validate_new_operation_lease(self, grant: LeaseGrant) -> dict[str, Any]:
        lease = self.journal.get_lease(grant.lease_id)
        if lease is None:
            raise LeaseNotRegistered("Lease must be registered before consumption")
        if lease["grant_digest"] != grant.grant_digest:
            raise LeaseRegistrationConflict("supplied grant differs from the registered Lease")
        if lease["state"] == "REVOKED":
            raise LeaseInactive("Lease has been revoked")
        if lease["state"] == "EXPIRED":
            raise LeaseInactive("Lease has expired")
        now = int(self.clock())
        if now < int(lease["issued_at"]):
            raise GrantRejected("LeaseGrant is not yet valid")
        if now >= int(lease["expires_at"]):
            self.journal._set_lease_state(grant.lease_id, "EXPIRED")
            raise LeaseInactive("Lease has expired")
        return lease

    def consume(
        self,
        grant: LeaseGrant,
        *,
        operation_id: str,
        request_digest: str,
        crash_at: str | None = None,
    ) -> GlobalBudgetReceipt:
        if crash_at not in self.VALID_CRASH_POINTS:
            raise ValueError(f"unsupported crash point: {crash_at}")
        verify_lease_grant(grant, self.issuer_public_key)
        if grant.global_budget_id != self.global_budget_id:
            raise GlobalBudgetMismatch("LeaseGrant belongs to a different global budget epoch")
        try:
            operation_id = _nonempty(operation_id, "operation_id")
            if not _is_sha256(request_digest):
                raise ValueError("request_digest must be a sha256 digest")
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            existing = self.journal.get_operation(operation_id)
            if existing is not None:
                expected_binding = (grant.lease_id, grant.grant_digest, request_digest)
                actual_binding = (existing["lease_id"], existing["grant_digest"], existing["request_digest"])
                if actual_binding != expected_binding:
                    raise OperationBindingConflict("operation_id is already bound to another Lease or request")
                if existing["status"] == "COMMITTED":
                    return self._committed_receipt_or_fail(existing)
                if existing["status"] == "NOT_APPLIED":
                    raise OperationNotApplied("operation was not applied; use a new operation_id")
                if existing["status"] == "INDETERMINATE":
                    raise BrokerIndeterminate("operation is marked INDETERMINATE")

            self._recover_pending_locked()
            existing = self.journal.get_operation(operation_id)
            if existing is not None:
                if existing["status"] == "COMMITTED":
                    return self._committed_receipt_or_fail(existing)
                if existing["status"] == "NOT_APPLIED":
                    raise OperationNotApplied("operation was not applied; use a new operation_id")
                if existing["status"] == "INDETERMINATE":
                    raise BrokerIndeterminate("operation is marked INDETERMINATE")

            invariant_state = self._assert_invariants_locked()
            lease = self._validate_new_operation_lease(grant)
            if int(lease["used_count"]) >= int(lease["quota_limit"]):
                raise LeaseQuotaExceeded("Lease quota is exhausted")
            global_used = invariant_state["counter_value"] - invariant_state["baseline_counter_value"]
            if global_used >= invariant_state["global_quota_limit"]:
                raise GlobalBudgetExceeded("global budget is exhausted")

            self.journal.create_intent(
                operation_id=operation_id,
                lease_id=grant.lease_id,
                grant_digest=grant.grant_digest,
                request_digest=request_digest,
                pre_counter_value=invariant_state["counter_value"],
            )
            if crash_at == "after_intent":
                raise InjectedCrash("crash after global intent commit")
            try:
                response_code = self.counter.increment()
            except Exception as exc:
                # Keep the durable PENDING intent. A later recovery compares
                # the counter to its pre-value and settles only an exact delta.
                raise BrokerIndeterminate(
                    "global counter increment outcome is unknown; pending intent retained for recovery"
                ) from exc
            if response_code != 0:
                reason = f"global counter increment returned response code {response_code}"
                self._mark_indeterminate(reason, [operation_id])
                raise BrokerIndeterminate(reason)
            if crash_at == "after_increment":
                raise InjectedCrash("crash after global counter increment")
            observed = self.counter.read()
            if crash_at == "after_read":
                raise InjectedCrash("crash after global counter read")
            if observed != invariant_state["counter_value"] + 1:
                reason = (
                    "global counter transition was not exactly +1: "
                    f"before={invariant_state['counter_value']}, observed={observed}"
                )
                self._mark_indeterminate(reason, [operation_id])
                raise BrokerIndeterminate(reason)
            pending = self.journal.get_operation(operation_id)
            try:
                receipt = self.journal.commit_pending(pending, observed)
            except Exception as exc:
                reason = f"global receipt commit failed after counter increment: {exc}"
                self._mark_indeterminate(reason, [operation_id])
                raise BrokerIndeterminate(reason) from exc
            if crash_at == "after_receipt_commit":
                raise InjectedCrash("crash after global receipt commit")
            self._assert_invariants_locked()
            return receipt

    def assert_invariants(self) -> dict[str, int]:
        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            self._recover_pending_locked()
            return self._assert_invariants_locked()

    def inspect(self) -> dict[str, Any]:
        with CrossProcessFileLock(self.lock_path):
            self._assert_configuration()
            meta = self.journal.meta()
            totals = self.journal.totals()
            observed = self.counter.read()
            return {
                "global_budget_id": meta["global_budget_id"],
                "global_quota_limit": int(meta["global_quota_limit"]),
                "baseline_counter_value": int(meta["baseline_counter_value"]),
                "expected_counter_value": int(meta["expected_counter_value"]),
                "observed_counter_value": observed,
                "reserved_total": totals["reserved"],
                "used_total": totals["used"],
                "health": meta["health"],
                "health_reason": meta["health_reason"],
                "leases": self.journal.all_leases(),
                "pending_operation_ids": [row["operation_id"] for row in self.journal.pending_operations()],
            }
