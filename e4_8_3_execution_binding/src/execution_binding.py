"""E4.8.3: signed lease grants and tool-execution receipt binding.

SOFTWARE-ONLY MODEL. Uses the E4.8.2 file-backed counter emulator and durable
broker. It does not access TPM/TBS APIs or provide hardware-backed trust.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable, Mapping
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.durable_broker import (
    BrokerIndeterminate,
    BudgetExceeded,
    DurableCounterBroker,
    OperationBindingConflict,
    OperationNotApplied,
    CrossProcessFileLock,
)


class ExecutionBindingError(RuntimeError):
    """Base class for gateway protocol errors."""


class GrantRejected(ExecutionBindingError):
    """The signed lease grant or request context is not authorized."""


class ParentAuthorizationReplay(ExecutionBindingError):
    """A parent MVP authorization nonce was already bound to another operation."""


class GatewayBusy(ExecutionBindingError):
    """An earlier operation must be recovered before admitting another."""


class ExecutionIndeterminate(ExecutionBindingError):
    """External tool effect cannot safely be attributed or replayed."""


class BudgetAllocationFailed(ExecutionBindingError):
    """The counter broker did not allocate this operation."""


class ToolOperationConflict(ExecutionBindingError):
    """A tool's idempotency key was reused with a different request."""


class InjectedCrash(ExecutionBindingError):
    """Deterministic crash injected after a durable protocol boundary."""


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON used for all digest and signature inputs."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not canonical-JSON serializable: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def schema_hash(schema: Mapping[str, Any]) -> str:
    """Hash the trusted adapter's canonical schema descriptor."""
    return "sha256:" + sha256_hex(dict(schema))


def context_hash(context: Mapping[str, Any]) -> str:
    return "sha256:" + sha256_hex(dict(context))


@dataclass(frozen=True)
class ToolPermission:
    tool_name: str
    schema_hash: str

    def to_dict(self) -> dict[str, str]:
        return {"tool_name": self.tool_name, "schema_hash": self.schema_hash}


@dataclass(frozen=True)
class LeaseGrant:
    version: int
    issuer_id: str
    grant_id: str
    lease_id: str
    subject_id: str
    audience: str
    context_digest: str
    issued_at: int
    expires_at: int
    quota_limit: int
    nonce: str
    allowed_tools: tuple[ToolPermission, ...]
    signature_b64: str
    parent_authorization_digest: str = ""
    parent_authorization_nonce: str = ""
    operation_id: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        result = {
            "version": self.version,
            "issuer_id": self.issuer_id,
            "grant_id": self.grant_id,
            "lease_id": self.lease_id,
            "subject_id": self.subject_id,
            "audience": self.audience,
            "context_digest": self.context_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "quota_limit": self.quota_limit,
            "nonce": self.nonce,
            "allowed_tools": [p.to_dict() for p in sorted(self.allowed_tools, key=lambda x: x.tool_name)],
        }
        if self.version >= 2:
            result.update({
                "parent_authorization_digest": self.parent_authorization_digest,
                "parent_authorization_nonce": self.parent_authorization_nonce,
                "operation_id": self.operation_id,
            })
        return result

    def to_dict(self) -> dict[str, Any]:
        result = self.unsigned_dict()
        result["signature_b64"] = self.signature_b64
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LeaseGrant":
        try:
            tools = tuple(
                ToolPermission(str(item["tool_name"]), str(item["schema_hash"]))
                for item in value["allowed_tools"]
            )
            return cls(
                version=int(value["version"]),
                issuer_id=str(value["issuer_id"]),
                grant_id=str(value["grant_id"]),
                lease_id=str(value["lease_id"]),
                subject_id=str(value["subject_id"]),
                audience=str(value["audience"]),
                context_digest=str(value["context_digest"]),
                issued_at=int(value["issued_at"]),
                expires_at=int(value["expires_at"]),
                quota_limit=int(value["quota_limit"]),
                nonce=str(value["nonce"]),
                allowed_tools=tools,
                signature_b64=str(value["signature_b64"]),
                parent_authorization_digest=str(value.get("parent_authorization_digest", "")),
                parent_authorization_nonce=str(value.get("parent_authorization_nonce", "")),
                operation_id=str(value.get("operation_id", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GrantRejected(f"malformed serialized lease grant: {exc}") from exc

    @property
    def grant_digest(self) -> str:
        return "sha256:" + sha256_hex(self.unsigned_dict())


def issue_lease_grant(
    private_key: Ed25519PrivateKey,
    *,
    issuer_id: str,
    grant_id: str,
    lease_id: str,
    subject_id: str,
    audience: str,
    context_digest: str,
    issued_at: int,
    expires_at: int,
    quota_limit: int,
    nonce: str,
    allowed_tools: tuple[ToolPermission, ...] | list[ToolPermission],
    parent_authorization_digest: str = "",
    parent_authorization_nonce: str = "",
    operation_id: str = "",
) -> LeaseGrant:
    tools = tuple(allowed_tools)
    if not tools:
        raise ValueError("at least one tool permission is required")
    if len({p.tool_name for p in tools}) != len(tools):
        raise ValueError("allowed_tools contains duplicate tool names")
    if quota_limit < 1:
        raise ValueError("quota_limit must be positive")
    if issued_at >= expires_at:
        raise ValueError("expires_at must be later than issued_at")
    integrated = bool(parent_authorization_digest or parent_authorization_nonce or operation_id)
    unsigned = LeaseGrant(
        version=2 if integrated else 1,
        issuer_id=issuer_id,
        grant_id=grant_id,
        lease_id=lease_id,
        subject_id=subject_id,
        audience=audience,
        context_digest=context_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        quota_limit=quota_limit,
        nonce=nonce,
        allowed_tools=tools,
        signature_b64="",
        parent_authorization_digest=parent_authorization_digest,
        parent_authorization_nonce=parent_authorization_nonce,
        operation_id=operation_id,
    )
    _validate_grant_shape(unsigned)
    signature = private_key.sign(canonical_json_bytes(unsigned.unsigned_dict()))
    return LeaseGrant(**{**unsigned.__dict__, "signature_b64": base64.b64encode(signature).decode("ascii")})


def _validate_grant_shape(grant: LeaseGrant) -> None:
    for field_name in (
        "issuer_id", "grant_id", "lease_id", "subject_id", "audience",
        "context_digest", "nonce",
    ):
        value = getattr(grant, field_name)
        if not isinstance(value, str) or not value.strip():
            raise GrantRejected(f"grant field {field_name} must be a non-empty string")
    if grant.version not in (1, 2):
        raise GrantRejected("unsupported grant version")
    if not isinstance(grant.issued_at, int) or not isinstance(grant.expires_at, int):
        raise GrantRejected("grant timestamps must be integer Unix seconds")
    if grant.issued_at >= grant.expires_at:
        raise GrantRejected("grant validity interval is empty")
    if not isinstance(grant.quota_limit, int) or grant.quota_limit < 1:
        raise GrantRejected("grant quota_limit must be a positive integer")
    if not grant.allowed_tools:
        raise GrantRejected("grant contains no allowed tools")
    names = [p.tool_name for p in grant.allowed_tools]
    if len(names) != len(set(names)):
        raise GrantRejected("grant contains duplicate tool permissions")
    for permission in grant.allowed_tools:
        if not permission.tool_name.strip() or not permission.schema_hash.startswith("sha256:"):
            raise GrantRejected("malformed tool permission")
    integration_fields = (
        grant.parent_authorization_digest,
        grant.parent_authorization_nonce,
        grant.operation_id,
    )
    if grant.version == 1 and any(integration_fields):
        raise GrantRejected("version 1 grant cannot contain parent authorization bindings")
    if grant.version == 2 and not all(
        isinstance(value, str) and value.strip() for value in integration_fields
    ):
        raise GrantRejected("version 2 grant must bind parent authorization digest, nonce, and operation_id")
    if grant.version == 2 and (
        len(grant.parent_authorization_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in grant.parent_authorization_digest)
    ):
        raise GrantRejected("parent authorization digest must be a 64-character lowercase SHA-256 hex digest")


def verify_lease_grant(grant: LeaseGrant, trusted_issuer_public_key: Ed25519PublicKey) -> None:
    _validate_grant_shape(grant)
    try:
        signature = base64.b64decode(grant.signature_b64, validate=True)
        trusted_issuer_public_key.verify(signature, canonical_json_bytes(grant.unsigned_dict()))
    except (ValueError, InvalidSignature) as exc:
        raise GrantRejected("lease grant signature is invalid") from exc


@dataclass(frozen=True)
class ToolRequest:
    operation_id: str
    subject_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    context: Mapping[str, Any]


class ToolLookupStatus(str, Enum):
    NOT_FOUND = "NOT_FOUND"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED_NO_EFFECT = "FAILED_NO_EFFECT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ToolCapabilities:
    """Declared provider capabilities; declarations are adapter claims, not proofs.

    A positive idempotency_retention_seconds value is measured from the first
    durable dispatch intent. None explicitly declares that the idempotency key
    does not expire. It must not be used when a real provider's retention is
    unknown.
    """

    naturally_idempotent: bool = False
    supports_idempotency_key: bool = False
    supports_authoritative_lookup: bool = False
    idempotency_scope: str | None = None
    idempotency_retention_seconds: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "naturally_idempotent",
            "supports_idempotency_key",
            "supports_authoritative_lookup",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be bool")

        if self.idempotency_scope is not None:
            if not isinstance(self.idempotency_scope, str) or not self.idempotency_scope.strip():
                raise ValueError("idempotency_scope must be a non-empty string")

        if self.idempotency_retention_seconds is not None:
            if (not isinstance(self.idempotency_retention_seconds, int)
                    or isinstance(self.idempotency_retention_seconds, bool)
                    or self.idempotency_retention_seconds <= 0):
                raise ValueError("idempotency_retention_seconds must be a positive integer")

        if self.idempotency_retention_seconds is not None and not self.supports_idempotency_key:
            raise ValueError("retention requires supports_idempotency_key=True")


@dataclass(frozen=True)
class ToolLookupResult:
    """Provider lookup result bound to one exact operation and request."""

    status: ToolLookupStatus
    operation_id: str
    request_digest: str
    result: Mapping[str, Any] | None = None
    authoritative: bool = False


def coerce_tool_lookup_result(
    raw: Any, *, operation_id: str, request_digest: str
) -> ToolLookupResult:
    """Normalize lookup responses without guessing that absence means no effect."""
    if isinstance(raw, ToolLookupResult):
        normalized = raw
    elif raw is None:
        normalized = ToolLookupResult(
            ToolLookupStatus.UNKNOWN,
            operation_id,
            request_digest,
            authoritative=False,
        )
    elif isinstance(raw, Mapping):
        # Legacy positive results are useful for compatibility, but are not
        # authoritative unless the adapter explicitly declares that capability.
        normalized = ToolLookupResult(
            ToolLookupStatus.SUCCEEDED,
            operation_id,
            request_digest,
            result=dict(raw),
            authoritative=False,
        )
    else:
        raise ExecutionIndeterminate("tool lookup returned an unsupported response type")

    if normalized.operation_id != operation_id:
        raise ExecutionIndeterminate("tool lookup operation_id does not match the request")
    if normalized.request_digest != request_digest:
        raise ExecutionIndeterminate("tool lookup request_digest does not match the request")
    if not isinstance(normalized.status, ToolLookupStatus):
        raise ExecutionIndeterminate("tool lookup returned an invalid status")
    if normalized.status == ToolLookupStatus.SUCCEEDED:
        if not isinstance(normalized.result, Mapping):
            raise ExecutionIndeterminate("SUCCEEDED lookup omitted a mapping result")
    elif normalized.result is not None:
        raise ExecutionIndeterminate("non-SUCCEEDED lookup unexpectedly included a result")
    if not isinstance(normalized.authoritative, bool):
        raise ExecutionIndeterminate("tool lookup authoritative flag must be bool")

    return normalized


class ToolAdapter:
    """Adapter contract; concrete tools must expose trusted schema and idempotency.

    `idempotent_by_operation_id=True` is a strong adapter promise: repeated
    execute calls with the same operation_id and request_digest cause at most
    one external effect and return the original result. This must be enforced
    by the external tool/service, not merely by this gateway.
    """

    tool_name: str
    schema_hash: str
    idempotent_by_operation_id: bool

    @property
    def capabilities(self) -> ToolCapabilities:
        return ToolCapabilities(
            supports_idempotency_key=bool(
                getattr(self, "idempotent_by_operation_id", False)
            )
        )

    def execute(
        self,
        *,
        operation_id: str,
        request_digest: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        raise NotImplementedError

    def lookup(self, *, operation_id: str, request_digest: str) -> Mapping[str, Any] | None:
        raise NotImplementedError


def _tool_recovery_contract(
    tool: ToolAdapter,
) -> tuple[ToolCapabilities, bool, str]:
    """Return the current declared recovery capabilities and their stable digest."""
    capabilities = tool.capabilities
    if not isinstance(capabilities, ToolCapabilities):
        raise ExecutionIndeterminate("tool capabilities contract is invalid")

    legacy_idempotent = bool(
        getattr(tool, "idempotent_by_operation_id", False)
    )

    payload = {
        "version": 1,
        "tool_name": tool.tool_name,
        "schema_hash": tool.schema_hash,
        "naturally_idempotent": capabilities.naturally_idempotent,
        "supports_idempotency_key": capabilities.supports_idempotency_key,
        "supports_authoritative_lookup": capabilities.supports_authoritative_lookup,
        "idempotency_scope": capabilities.idempotency_scope,
        "idempotency_retention_seconds": capabilities.idempotency_retention_seconds,
        "legacy_idempotent_by_operation_id": legacy_idempotent,
    }
    digest = "sha256:" + sha256_hex(payload)
    return capabilities, legacy_idempotent, digest


class SQLiteIdempotentTool(ToolAdapter):
    """Test adapter whose idempotency/effect record survives reconstruction.

    The SQLite table stands in for an external tool service's own durable
    idempotency key. It is not a generic guarantee supplied by the gateway.
    """

    idempotent_by_operation_id = True

    @property
    def capabilities(self) -> ToolCapabilities:
        return ToolCapabilities(
            supports_idempotency_key=True,
            supports_authoritative_lookup=True,
            idempotency_scope="tool-service-database",
        )

    def __init__(self, *, tool_name: str, schema: Mapping[str, Any], database_path: str | Path) -> None:
        self.tool_name = tool_name
        self.schema_hash = schema_hash(schema)
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS tool_effects ("
                "operation_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, "
                "result_json TEXT NOT NULL)"
            )

    def _db(self):
        return _ClosingConnection(self.path)

    def execute(self, *, operation_id: str, request_digest: str,
                arguments: Mapping[str, Any], context: Mapping[str, Any]) -> Mapping[str, Any]:
        result = {
            "ok": True,
            "tool_name": self.tool_name,
            "operation_id": operation_id,
            "arguments": dict(arguments),
        }
        encoded = canonical_json_bytes(result).decode("utf-8")
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT request_digest,result_json FROM tool_effects WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row:
                if row[0] != request_digest:
                    con.rollback()
                    raise ToolOperationConflict("tool operation_id is bound to another request")
                con.commit()
                return json.loads(row[1])
            con.execute(
                "INSERT INTO tool_effects(operation_id,request_digest,result_json) VALUES(?,?,?)",
                (operation_id, request_digest, encoded),
            )
            con.commit()
        return result

    def lookup(self, *, operation_id: str, request_digest: str) -> ToolLookupResult:
        with self._db() as con:
            row = con.execute(
                "SELECT request_digest,result_json FROM tool_effects WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return ToolLookupResult(
                ToolLookupStatus.NOT_FOUND,
                operation_id,
                request_digest,
                authoritative=True,
            )
        if row[0] != request_digest:
            raise ToolOperationConflict("tool operation_id is bound to another request")
        return ToolLookupResult(
            ToolLookupStatus.SUCCEEDED,
            operation_id,
            request_digest,
            result=json.loads(row[1]),
            authoritative=True,
        )

    def effect_count(self) -> int:
        with self._db() as con:
            return int(con.execute("SELECT COUNT(*) FROM tool_effects").fetchone()[0])


class _ClosingConnection:
    """Small context wrapper that always closes SQLite connections on Windows."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        self.connection = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout=30000")
        self.connection.execute("PRAGMA synchronous=FULL")
        return self.connection

    def __exit__(self, exc_type, exc, tb) -> None:
        assert self.connection is not None
        try:
            if exc_type is not None and self.connection.in_transaction:
                self.connection.rollback()
        finally:
            self.connection.close()
            self.connection = None


class ExecutionJournal:
    """Durable gateway state. The separate Broker owns counter allocation."""

    TERMINAL = {"COMMITTED", "FAILED_NO_BUDGET", "INDETERMINATE"}
    UNRESOLVED = {"ALLOCATING", "BUDGET_CONSUMED", "DISPATCHING"}

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _ClosingConnection(self.path) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS executions ("
                "operation_id TEXT PRIMARY KEY, grant_digest TEXT NOT NULL, "
                "grant_id TEXT NOT NULL, lease_id TEXT NOT NULL, subject_id TEXT NOT NULL, "
                "tool_name TEXT NOT NULL, schema_hash TEXT NOT NULL, context_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL, budget_counter_value INTEGER, "
                "receipt_json TEXT, parent_authorization_digest TEXT NOT NULL DEFAULT '', "
                "parent_authorization_nonce TEXT NOT NULL DEFAULT '', "
                "dispatch_started_at INTEGER, "
                "tool_capabilities_digest TEXT, "
                "gateway_id TEXT, "
                "gateway_public_key_digest TEXT, "
                "updated_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )
            # Additive migration preserves existing E4.8.3 journal rows.
            columns = {
                row[1] for row in con.execute("PRAGMA table_info(executions)").fetchall()
            }
            if "parent_authorization_digest" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN "
                    "parent_authorization_digest TEXT NOT NULL DEFAULT ''"
                )
            if "parent_authorization_nonce" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN "
                    "parent_authorization_nonce TEXT NOT NULL DEFAULT ''"
                )
            if "dispatch_started_at" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN dispatch_started_at INTEGER"
                )
            if "tool_capabilities_digest" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN tool_capabilities_digest TEXT"
                )
            if "gateway_id" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN gateway_id TEXT"
                )
            if "gateway_public_key_digest" not in columns:
                con.execute(
                    "ALTER TABLE executions ADD COLUMN gateway_public_key_digest TEXT"
                )
            con.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_executions_parent_nonce "
                "ON executions(parent_authorization_nonce) "
                "WHERE parent_authorization_nonce <> ''"
            )
            con.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_executions_parent_digest "
                "ON executions(parent_authorization_digest) "
                "WHERE parent_authorization_digest <> ''"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS gateway_identity ("
                "singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1), "
                "gateway_id TEXT NOT NULL, "
                "gateway_public_key_digest TEXT NOT NULL, "
                "created_utc TEXT NOT NULL DEFAULT "
                "(strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
            )

    def bind_gateway_identity(
        self, gateway_id: str, gateway_public_key_digest: str
    ) -> None:
        """Pin this execution journal to exactly one Gateway identity.

        BEGIN IMMEDIATE serializes competing first-writer attempts even when
        Gateway instances were configured with different lock-file paths.
        Existing D7.3 rows can bootstrap the registry if their identity is
        complete and consistent. Legacy rows with no identity are not adopted.
        """
        if not isinstance(gateway_id, str) or not gateway_id.strip():
            raise ValueError("gateway_id must be a non-empty string")
        if (
            not isinstance(gateway_public_key_digest, str)
            or len(gateway_public_key_digest) != 71
            or not gateway_public_key_digest.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in gateway_public_key_digest[7:])
        ):
            raise ValueError("gateway_public_key_digest must be a sha256 digest")

        identity = (gateway_id, gateway_public_key_digest)
        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            stored = con.execute(
                "SELECT gateway_id,gateway_public_key_digest "
                "FROM gateway_identity WHERE singleton_id=1"
            ).fetchone()
            if stored is not None:
                if tuple(stored) != identity:
                    raise ExecutionIndeterminate(
                        "execution journal is already bound to a different Gateway identity"
                    )
                con.commit()
                return

            # Bootstrap an upgraded D7.3 database from its existing per-row
            # identity snapshots. Incomplete or conflicting snapshots fail closed.
            legacy = con.execute(
                "SELECT DISTINCT gateway_id,gateway_public_key_digest "
                "FROM executions "
                "WHERE gateway_id IS NOT NULL OR gateway_public_key_digest IS NOT NULL"
            ).fetchall()
            if legacy:
                if len(legacy) != 1 or legacy[0][0] is None or legacy[0][1] is None:
                    raise ExecutionIndeterminate(
                        "legacy execution journal contains incomplete or conflicting Gateway identities"
                    )
                if tuple(legacy[0]) != identity:
                    raise ExecutionIndeterminate(
                        "requested Gateway identity differs from the legacy journal identity"
                    )

            con.execute(
                "INSERT INTO gateway_identity("
                "singleton_id,gateway_id,gateway_public_key_digest"
                ") VALUES(1,?,?)",
                identity,
            )
            con.commit()

    def get(self, operation_id: str) -> dict[str, Any] | None:
        with _ClosingConnection(self.path) as con:
            row = con.execute(
                "SELECT operation_id,grant_digest,grant_id,lease_id,subject_id,tool_name,"
                "schema_hash,context_digest,request_digest,status,budget_counter_value,receipt_json,"
                "parent_authorization_digest,parent_authorization_nonce,dispatch_started_at,"
                "tool_capabilities_digest,gateway_id,gateway_public_key_digest "
                "FROM executions WHERE operation_id=?", (operation_id,)
            ).fetchone()
        if row is None:
            return None
        keys = ("operation_id", "grant_digest", "grant_id", "lease_id", "subject_id",
                "tool_name", "schema_hash", "context_digest", "request_digest", "status",
                "budget_counter_value", "receipt_json", "parent_authorization_digest",
                "parent_authorization_nonce", "dispatch_started_at", "tool_capabilities_digest",
                "gateway_id", "gateway_public_key_digest")
        return dict(zip(keys, row))

    def unresolved_other_than(self, operation_id: str) -> list[str]:
        with _ClosingConnection(self.path) as con:
            rows = con.execute(
                "SELECT operation_id FROM executions WHERE status IN "
                "('ALLOCATING','BUDGET_CONSUMED','DISPATCHING') AND operation_id<>?",
                (operation_id,),
            ).fetchall()
        return [r[0] for r in rows]

    def create_allocating(self, record: Mapping[str, Any]) -> None:
        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO executions(operation_id,grant_digest,grant_id,lease_id,subject_id,"
                    "tool_name,schema_hash,context_digest,request_digest,status,"
                    "parent_authorization_digest,parent_authorization_nonce,gateway_id,"
                    "gateway_public_key_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?,'ALLOCATING',?,?,?,?)",
                    (record["operation_id"], record["grant_digest"], record["grant_id"],
                     record["lease_id"], record["subject_id"], record["tool_name"],
                     record["schema_hash"], record["context_digest"], record["request_digest"],
                     record.get("parent_authorization_digest", ""),
                     record.get("parent_authorization_nonce", ""),
                     record.get("gateway_id"),
                     record.get("gateway_public_key_digest")),
                )
            except sqlite3.IntegrityError as exc:
                parent_nonce = record.get("parent_authorization_nonce", "")
                parent_digest = record.get("parent_authorization_digest", "")
                existing = None
                if parent_nonce:
                    existing = con.execute(
                        "SELECT operation_id FROM executions WHERE parent_authorization_nonce=?",
                        (parent_nonce,),
                    ).fetchone()
                if existing is None and parent_digest:
                    existing = con.execute(
                        "SELECT operation_id FROM executions WHERE parent_authorization_digest=?",
                        (parent_digest,),
                    ).fetchone()
                if existing is not None and existing[0] != record["operation_id"]:
                    raise ParentAuthorizationReplay(
                        "parent authorization digest or nonce is already bound to another operation"
                    ) from exc
                raise
            con.commit()

    def set_budget_consumed(self, operation_id: str, counter_value: int) -> None:
        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE executions SET status='BUDGET_CONSUMED',budget_counter_value=?, "
                "updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE operation_id=?",
                (counter_value, operation_id),
            )
            con.commit()

    def set_dispatching(
        self,
        operation_id: str,
        dispatch_started_at: int,
        capabilities_digest: str,
    ) -> None:
        if not isinstance(dispatch_started_at, int) or isinstance(dispatch_started_at, bool):
            raise ValueError("dispatch_started_at must be an integer Unix timestamp")
        if (
            not isinstance(capabilities_digest, str)
            or len(capabilities_digest) != 71
            or not capabilities_digest.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in capabilities_digest[7:])
        ):
            raise ValueError("capabilities_digest must be a sha256 digest")

        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE executions SET status='DISPATCHING', "
                "dispatch_started_at=COALESCE(dispatch_started_at, ?), "
                "tool_capabilities_digest=COALESCE(tool_capabilities_digest, ?), "
                "updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE operation_id=? AND status='BUDGET_CONSUMED'",
                (dispatch_started_at, capabilities_digest, operation_id),
            )
            con.commit()

    def set_status(self, operation_id: str, status: str) -> None:
        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE executions SET status=?,updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE operation_id=?", (status, operation_id)
            )
            con.commit()

    def commit_receipt(self, operation_id: str, receipt: Mapping[str, Any]) -> None:
        encoded = canonical_json_bytes(dict(receipt)).decode("utf-8")
        with _ClosingConnection(self.path) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE executions SET status='COMMITTED',receipt_json=?, "
                "updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE operation_id=?",
                (encoded, operation_id),
            )
            con.commit()


@dataclass(frozen=True)
class ExecutionOutcome:
    receipt: Mapping[str, Any]
    replayed: bool


class ExecutionBindingGateway:
    """Verifies a signed grant, allocates one budget sequence, and runs a tool.

    A per-gateway cross-process lock covers the full local protocol. The
    counter broker has its own lock/journal. This coordinates cooperating
    processes on one host; it is not a hardware or privilege boundary.
    """

    VALID_CRASH_POINTS = {
        None, "after_budget_allocation", "after_dispatch_intent",
        "after_tool_effect", "after_receipt_commit",
    }

    def __init__(
        self,
        *,
        issuer_public_key: Ed25519PublicKey,
        gateway_private_key: Ed25519PrivateKey,
        gateway_id: str,
        broker: DurableCounterBroker,
        journal_path: str | Path,
        lock_path: str | Path,
        tools: Mapping[str, ToolAdapter],
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not gateway_id.strip():
            raise ValueError("gateway_id must be non-empty")
        self.issuer_public_key = issuer_public_key
        self.gateway_private_key = gateway_private_key
        self.gateway_public_key = gateway_private_key.public_key()
        self.gateway_public_key_digest = (
            "sha256:" + hashlib.sha256(
                self.gateway_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).hexdigest()
        )
        self.gateway_id = gateway_id
        self.broker = broker
        self.journal = ExecutionJournal(journal_path)
        self.lock_path = Path(lock_path)
        self.tools = dict(tools)
        self.clock = clock or (lambda: int(time.time()))

    def _validate(self, grant: LeaseGrant, request: ToolRequest) -> tuple[ToolAdapter, str, str]:
        verify_lease_grant(grant, self.issuer_public_key)
        now = int(self.clock())
        if now < grant.issued_at:
            raise GrantRejected("grant is not yet valid")
        if now >= grant.expires_at:
            raise GrantRejected("grant has expired")
        if grant.audience != self.gateway_id:
            raise GrantRejected("grant audience does not match this gateway")
        if request.subject_id != grant.subject_id:
            raise GrantRejected("request subject differs from grant subject")
        if grant.version >= 2 and request.operation_id != grant.operation_id:
            raise GrantRejected("request operation_id differs from signed lease grant")
        if context_hash(request.context) != grant.context_digest:
            raise GrantRejected("request context differs from grant context digest")
        if self.broker.lease_id != grant.lease_id:
            raise GrantRejected("grant lease_id differs from configured counter broker")
        if self.broker.quota_limit != grant.quota_limit:
            raise GrantRejected("grant quota_limit differs from configured counter broker")
        tool = self.tools.get(request.tool_name)
        if tool is None:
            raise GrantRejected("tool is not registered in the trusted gateway")
        permission = next((p for p in grant.allowed_tools if p.tool_name == request.tool_name), None)
        if permission is None:
            raise GrantRejected("tool is not allowed by this grant")
        # The schema hash comes from the trusted adapter, never from caller input.
        if permission.schema_hash != tool.schema_hash:
            raise GrantRejected("trusted tool schema has drifted from the signed grant")
        if not isinstance(request.operation_id, str) or not request.operation_id.strip():
            raise GrantRejected("operation_id must be non-empty")
        if not isinstance(request.arguments, Mapping) or not isinstance(request.context, Mapping):
            raise GrantRejected("arguments and context must be JSON objects")
        # Validate serializability before reserving budget.
        canonical_json_bytes(dict(request.arguments))
        canonical_json_bytes(dict(request.context))
        context_digest = grant.context_digest
        digest_material = {
            "version": 1,
            "gateway_id": self.gateway_id,
            "grant_digest": grant.grant_digest,
            "grant_id": grant.grant_id,
            "lease_id": grant.lease_id,
            "subject_id": grant.subject_id,
            "context_digest": context_digest,
            "operation_id": request.operation_id,
            "tool_name": request.tool_name,
            "schema_hash": tool.schema_hash,
            "arguments": dict(request.arguments),
        }
        request_digest = "sha256:" + sha256_hex(digest_material)
        return tool, context_digest, request_digest

    def execute(
        self,
        grant: LeaseGrant,
        request: ToolRequest,
        *,
        crash_at: str | None = None,
    ) -> ExecutionOutcome:
        if crash_at not in self.VALID_CRASH_POINTS:
            raise ValueError(f"unsupported crash point: {crash_at}")
        tool, context_digest_value, request_digest = self._validate(grant, request)
        record = {
            "operation_id": request.operation_id,
            "grant_digest": grant.grant_digest,
            "grant_id": grant.grant_id,
            "lease_id": grant.lease_id,
            "subject_id": grant.subject_id,
            "tool_name": request.tool_name,
            "schema_hash": tool.schema_hash,
            "context_digest": context_digest_value,
            "request_digest": request_digest,
            "parent_authorization_digest": grant.parent_authorization_digest,
            "parent_authorization_nonce": grant.parent_authorization_nonce,
            "gateway_id": self.gateway_id,
            "gateway_public_key_digest": self.gateway_public_key_digest,
        }

        with CrossProcessFileLock(self.lock_path):
            existing = self.journal.get(request.operation_id)
            if existing is not None:
                identity_fields = ("gateway_id", "gateway_public_key_digest")
                missing_identity = [
                    field for field in identity_fields if not existing.get(field)
                ]
                if missing_identity:
                    if existing["status"] in ExecutionJournal.UNRESOLVED:
                        self.journal.set_status(
                            request.operation_id, "INDETERMINATE"
                        )
                    raise ExecutionIndeterminate(
                        "execution record has no persisted Gateway identity"
                    )

                for field in record:
                    if existing[field] != record[field]:
                        if field in identity_fields:
                            if existing["status"] in ExecutionJournal.UNRESOLVED:
                                self.journal.set_status(
                                    request.operation_id, "INDETERMINATE"
                                )
                            raise ExecutionIndeterminate(
                                "Gateway identity or signing key differs from "
                                "the identity bound to this execution"
                            )
                        raise OperationBindingConflict(
                            f"operation_id is already bound to a different {field}"
                        )
                if existing["status"] == "COMMITTED":
                    receipt = json.loads(existing["receipt_json"])
                    if not verify_execution_receipt(receipt, self.gateway_public_key):
                        raise ExecutionIndeterminate("stored execution receipt failed signature verification")
                    return ExecutionOutcome(receipt=receipt, replayed=True)
                if existing["status"] == "FAILED_NO_BUDGET":
                    raise BudgetAllocationFailed("operation was recorded as not budget-allocated; use a new operation_id")
                if existing["status"] == "INDETERMINATE":
                    raise ExecutionIndeterminate("operation is marked INDETERMINATE; do not replay automatically")

            # First validate the operation's own persisted identity above.
            # Then enforce the journal-wide identity before admitting new work.
            self.journal.bind_gateway_identity(
                self.gateway_id, self.gateway_public_key_digest
            )
            blockers = self.journal.unresolved_other_than(request.operation_id)
            if blockers:
                raise GatewayBusy(
                    "another operation requires recovery first: " + ",".join(blockers)
                )

            capabilities, legacy_idempotent, capabilities_digest = (
                _tool_recovery_contract(tool)
            )

            if existing is not None and existing["status"] == "DISPATCHING":
                persisted_digest = existing.get("tool_capabilities_digest")
                if not persisted_digest:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "DISPATCHING record has no persisted tool capability contract"
                    )
                if persisted_digest != capabilities_digest:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "tool recovery capability contract changed after dispatch"
                    )

            if existing is None:
                self.journal.create_allocating(record)
                existing = self.journal.get(request.operation_id)

            if existing["status"] == "ALLOCATING":
                try:
                    budget_receipt = self.broker.consume(
                        operation_id=request.operation_id,
                        request_digest=request_digest,
                    )
                except OperationNotApplied as exc:
                    self.journal.set_status(request.operation_id, "FAILED_NO_BUDGET")
                    raise BudgetAllocationFailed(
                        "broker confirmed no increment was applied; use a new operation_id"
                    ) from exc
                except OperationBindingConflict as exc:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "broker operation binding conflicts with the Gateway journal"
                    ) from exc
                except BudgetExceeded as exc:
                    self.journal.set_status(request.operation_id, "FAILED_NO_BUDGET")
                    raise BudgetAllocationFailed(f"budget quota exhausted: {exc}") from exc
                except BrokerIndeterminate as exc:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(f"budget broker could not safely allocate: {exc}") from exc
                if (budget_receipt.lease_id != grant.lease_id
                        or budget_receipt.operation_id != request.operation_id
                        or budget_receipt.request_digest != request_digest
                        or not isinstance(budget_receipt.counter_value, int)
                        or budget_receipt.counter_value < 1):
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate("Broker returned a receipt with mismatched bindings")
                if crash_at == "after_budget_allocation":
                    raise InjectedCrash("crash after durable broker allocation and before gateway journal update")
                self.journal.set_budget_consumed(request.operation_id, budget_receipt.counter_value)
                existing = self.journal.get(request.operation_id)

            dispatch_started_now = False
            if existing["status"] == "BUDGET_CONSUMED":
                self.journal.set_dispatching(
                    request.operation_id,
                    int(self.clock()),
                    capabilities_digest,
                )
                existing = self.journal.get(request.operation_id)
                dispatch_started_now = True
                if crash_at == "after_dispatch_intent":
                    raise InjectedCrash("crash after durable dispatch intent and before tool invocation")

            if existing["status"] != "DISPATCHING":
                raise ExecutionIndeterminate(f"unexpected gateway state: {existing['status']}")

            # Recovery decisions use explicit provider states.
            raw_lookup = tool.lookup(
                operation_id=request.operation_id,
                request_digest=request_digest,
            )
            lookup = coerce_tool_lookup_result(
                raw_lookup,
                operation_id=request.operation_id,
                request_digest=request_digest,
            )

            authoritative_lookup = (
                lookup.authoritative
                and capabilities.supports_authoritative_lookup
            )

            if lookup.status == ToolLookupStatus.SUCCEEDED:
                if not authoritative_lookup:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "SUCCEEDED lookup lacks a declared authoritative lookup capability"
                    )
                result = dict(lookup.result)

            elif lookup.status == ToolLookupStatus.IN_PROGRESS:
                # Keep DISPATCHING unresolved; do not launch a concurrent duplicate.
                raise ExecutionIndeterminate(
                    "tool operation is still in progress; recovery must wait"
                )

            elif lookup.status == ToolLookupStatus.NOT_FOUND:
                if not authoritative_lookup and not dispatch_started_now:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "non-authoritative NOT_FOUND cannot justify recovery dispatch"
                    )
                result = tool.execute(
                    operation_id=request.operation_id,
                    request_digest=request_digest,
                    arguments=request.arguments,
                    context=request.context,
                )
                if crash_at == "after_tool_effect":
                    raise InjectedCrash("crash after tool returned its effect but before receipt commit")

            elif lookup.status == ToolLookupStatus.FAILED_NO_EFFECT:
                if not authoritative_lookup:
                    self.journal.set_status(request.operation_id, "INDETERMINATE")
                    raise ExecutionIndeterminate(
                        "FAILED_NO_EFFECT requires declared authoritative evidence"
                    )
                result = tool.execute(
                    operation_id=request.operation_id,
                    request_digest=request_digest,
                    arguments=request.arguments,
                    context=request.context,
                )
                if crash_at == "after_tool_effect":
                    raise InjectedCrash("crash after tool returned its effect but before receipt commit")

            elif lookup.status == ToolLookupStatus.UNKNOWN:
                if not dispatch_started_now:
                    # Natural idempotence is independent of key retention.
                    retry_safe = (
                        capabilities.naturally_idempotent or legacy_idempotent
                    )

                    if capabilities.supports_idempotency_key:
                        retention = capabilities.idempotency_retention_seconds
                        if retention is None:
                            # None is an explicit non-expiring-key declaration.
                            retry_safe = True
                        else:
                            started_at = existing.get("dispatch_started_at")
                            now = int(self.clock())
                            key_retry_safe = (
                                started_at is not None
                                and now >= started_at
                                and now - started_at < retention
                            )
                            # Natural idempotence is independently sufficient.
                            retry_safe = retry_safe or key_retry_safe

                    if not retry_safe:
                        self.journal.set_status(request.operation_id, "INDETERMINATE")
                        raise ExecutionIndeterminate(
                            "tool state is UNKNOWN and the idempotency retry contract "
                            "is absent, expired, or cannot be safely established"
                        )

                result = tool.execute(
                    operation_id=request.operation_id,
                    request_digest=request_digest,
                    arguments=request.arguments,
                    context=request.context,
                )
                if crash_at == "after_tool_effect":
                    raise InjectedCrash("crash after tool returned its effect but before receipt commit")

            else:
                self.journal.set_status(request.operation_id, "INDETERMINATE")
                raise ExecutionIndeterminate("unsupported tool lookup state")

            receipt = self._make_receipt(grant, request, tool, context_digest_value,
                                         request_digest, int(existing["budget_counter_value"]), result)
            self.journal.commit_receipt(request.operation_id, receipt)
            if crash_at == "after_receipt_commit":
                raise InjectedCrash("crash after durable execution receipt commit")
            return ExecutionOutcome(receipt=receipt, replayed=False)

    def _make_receipt(
        self,
        grant: LeaseGrant,
        request: ToolRequest,
        tool: ToolAdapter,
        context_digest_value: str,
        request_digest: str,
        counter_value: int,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        result_obj = dict(result)
        result_digest = "sha256:" + sha256_hex(result_obj)
        payload = {
            "version": 1,
            "status": "SUCCEEDED",
            "gateway_id": self.gateway_id,
            "issuer_id": grant.issuer_id,
            "grant_id": grant.grant_id,
            "grant_digest": grant.grant_digest,
            "parent_authorization_digest": grant.parent_authorization_digest,
            "parent_authorization_nonce": grant.parent_authorization_nonce,
            "lease_id": grant.lease_id,
            "subject_id": grant.subject_id,
            "audience": grant.audience,
            "context_digest": context_digest_value,
            "operation_id": request.operation_id,
            "tool_name": request.tool_name,
            "schema_hash": tool.schema_hash,
            "request_digest": request_digest,
            "budget_counter_value": counter_value,
            "result_digest": result_digest,
            "result": result_obj,
            "completed_at": int(self.clock()),
        }
        signature = self.gateway_private_key.sign(canonical_json_bytes(payload))
        return {
            "payload": payload,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }


def verify_execution_receipt(
    receipt: Mapping[str, Any], trusted_gateway_public_key: Ed25519PublicKey
) -> bool:
    try:
        payload = receipt["payload"]
        signature = base64.b64decode(receipt["signature_b64"], validate=True)
        if payload["result_digest"] != "sha256:" + sha256_hex(payload["result"]):
            return False
        trusted_gateway_public_key.verify(signature, canonical_json_bytes(payload))
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False
