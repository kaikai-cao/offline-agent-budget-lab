"""Bridge E4.8.3 Execution Binding to the shared D8.1 Global Budget Broker.

This adapter binds many E4.8.3 Lease Grants to their matching signed D8.1
Global Lease Grants. All bindings share one GlobalBudgetBroker, one journal,
one counter and one cross-process lock.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys
import threading
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.execution_binding import (
    BrokerIndeterminate as ExecutionBrokerIndeterminate,
    BudgetExceeded as ExecutionBudgetExceeded,
    GrantRejected as ExecutionGrantRejected,
    OperationBindingConflict as ExecutionOperationBindingConflict,
    OperationNotApplied as ExecutionOperationNotApplied,
    verify_lease_grant as verify_execution_lease_grant,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_GLOBAL_BUDGET_SOURCE = _REPOSITORY_ROOT / "e4_8_4_multi_lease_budget" / "src"
if not _GLOBAL_BUDGET_SOURCE.is_dir():
    raise ImportError(f"D8.1 Global Budget source directory not found: {_GLOBAL_BUDGET_SOURCE}")
if str(_GLOBAL_BUDGET_SOURCE) not in sys.path:
    sys.path.insert(0, str(_GLOBAL_BUDGET_SOURCE))

from global_budget import (  # noqa: E402
    BrokerConfigurationMismatch,
    BrokerIndeterminate as GlobalBrokerIndeterminate,
    GlobalBudgetBroker,
    GlobalBudgetExceeded,
    GlobalBudgetMismatch,
    GrantRejected as GlobalGrantRejected,
    LeaseGrant as GlobalLeaseGrant,
    LeaseInactive,
    LeaseNotRegistered,
    LeaseQuotaExceeded,
    LeaseRegistrationConflict,
    OperationBindingConflict as GlobalOperationBindingConflict,
    OperationNotApplied as GlobalOperationNotApplied,
    RevocationRejected,
    verify_lease_grant as verify_global_lease_grant,
)


@dataclass(frozen=True)
class GlobalBudgetExecutionReceipt:
    lease_id: str
    operation_id: str
    request_digest: str
    counter_value: int
    global_budget_id: str
    global_sequence: int
    lease_used_count: int
    global_lease_grant_digest: str


class GlobalBudgetExecutionAdapter:
    """Per-Gateway adapter for one shared GlobalBudgetBroker and many Leases.

    `bind_lease()` is a trusted control-plane operation. It validates the
    matching pair of signed grants and registers the Global Lease before the
    Gateway may execute it. Request-time selection is by the exact
    E4.8.3 execution-grant digest, never by caller-provided Lease identifiers.
    """

    is_global_budget_adapter = True

    def __init__(
        self,
        *,
        global_broker: GlobalBudgetBroker,
        issuer_public_key: Ed25519PublicKey,
    ) -> None:
        if not isinstance(global_broker, GlobalBudgetBroker):
            raise ValueError("global_broker must be a GlobalBudgetBroker")
        if not isinstance(issuer_public_key, Ed25519PublicKey):
            raise ValueError("issuer_public_key must be an Ed25519PublicKey")
        raw = issuer_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest != global_broker.issuer_public_key_digest:
            raise ValueError("Execution Gateway and Global Budget Broker must trust the same Issuer key")
        self.global_broker = global_broker
        self.issuer_public_key = issuer_public_key
        self._bindings: dict[str, tuple[Any, GlobalLeaseGrant]] = {}
        self._lock = threading.RLock()

    @property
    def journal(self):
        return self.global_broker.journal

    @property
    def counter(self):
        return self.global_broker.counter

    @property
    def lock_path(self):
        return self.global_broker.lock_path

    @property
    def global_budget_id(self) -> str:
        return self.global_broker.global_budget_id

    @property
    def global_quota_limit(self) -> int:
        return self.global_broker.global_quota_limit

    @property
    def issuer_public_key_digest(self) -> str:
        return self.global_broker.issuer_public_key_digest

    @property
    def config_digest(self) -> str:
        return self.global_broker.config_digest

    @staticmethod
    def _shared_grant_fields(grant: Any) -> dict[str, Any]:
        return {
            "issuer_id": grant.issuer_id,
            "grant_id": grant.grant_id,
            "lease_id": grant.lease_id,
            "nonce": grant.nonce,
            "quota_limit": grant.quota_limit,
            "issued_at": grant.issued_at,
            "expires_at": grant.expires_at,
            "audience": grant.audience,
            "subject_id": grant.subject_id,
            "context_digest": grant.context_digest,
            "allowed_tools": tuple(sorted(
                (item.tool_name, item.schema_hash) for item in grant.allowed_tools
            )),
        }

    def bind_lease(self, execution_grant: Any, global_lease_grant: GlobalLeaseGrant) -> dict[str, str]:
        """Register and pin one signed Global Lease to an E4.8.3 execution Grant."""
        verify_execution_lease_grant(execution_grant, self.issuer_public_key)
        verify_global_lease_grant(global_lease_grant, self.global_broker.issuer_public_key)
        if execution_grant.version not in (1, 2):
            raise ExecutionGrantRejected("unsupported E4.8.3 execution Grant version")
        if self._shared_grant_fields(execution_grant) != self._shared_grant_fields(global_lease_grant):
            raise ExecutionGrantRejected(
                "execution Grant and Global Lease Grant do not authorize the same subject, context, quota and tools"
            )
        if global_lease_grant.global_budget_id != self.global_budget_id:
            raise ExecutionGrantRejected("Global Lease Grant belongs to another budget epoch")

        # Registration is idempotent for the exact signed Grant. It is performed
        # here as an explicit control-plane step, never during tool execution.
        lease = self.global_broker.register_lease(global_lease_grant)
        if lease["grant_digest"] != global_lease_grant.grant_digest:
            raise ExecutionGrantRejected("Global Lease is not bound to the supplied signed Grant")
        if lease["state"] not in {"ACTIVE", "EXPIRED", "REVOKED"}:
            raise ExecutionGrantRejected("Global Lease has an unsupported ledger state")

        execution_digest = execution_grant.grant_digest
        with self._lock:
            existing = self._bindings.get(execution_digest)
            if existing is not None and existing[1].grant_digest != global_lease_grant.grant_digest:
                raise ExecutionGrantRejected("execution Grant is already bound to another Global Lease")
            self._bindings[execution_digest] = (execution_grant, global_lease_grant)
        return self.binding_for_execution_grant(execution_grant)

    def binding_for_execution_grant(self, execution_grant: Any) -> dict[str, str]:
        """Return the trusted global binding for this exact signed execution Grant."""
        with self._lock:
            pair = self._bindings.get(execution_grant.grant_digest)
        if pair is None:
            raise ExecutionGrantRejected("execution Grant has no configured Global Lease binding")
        stored_execution_grant, global_grant = pair
        if stored_execution_grant.grant_digest != execution_grant.grant_digest:
            raise ExecutionGrantRejected("execution Grant binding digest changed")
        lease = self.global_broker.journal.get_lease(global_grant.lease_id)
        if lease is None or lease["grant_digest"] != global_grant.grant_digest:
            raise ExecutionGrantRejected("Global Lease is not registered in the shared budget ledger")
        return {
            "global_budget_id": global_grant.global_budget_id,
            "global_lease_grant_digest": global_grant.grant_digest,
        }

    def authorize_execution_operation(
        self,
        execution_grant: Any,
        *,
        operation_id: str,
        request_digest: str,
    ) -> None:
        """Allow new work only on an active Lease; inactive Leases may settle an exact durable operation."""
        self.binding_for_execution_grant(execution_grant)
        with self._lock:
            pair = self._bindings.get(execution_grant.grant_digest)
        if pair is None:
            raise ExecutionGrantRejected("execution Grant lost its Global Lease binding")
        global_grant = pair[1]
        lease = self.global_broker.journal.get_lease(global_grant.lease_id)
        if lease is None or lease["grant_digest"] != global_grant.grant_digest:
            raise ExecutionGrantRejected("Global Lease binding is missing or changed")

        now = int(self.global_broker.clock())
        if lease["state"] == "ACTIVE" and now < int(lease["expires_at"]):
            return

        # Expiry/revocation is not a reason to strand a previously authorized
        # increment. Only the exact durable Broker intent/receipt may be settled.
        operation = self.global_broker.journal.get_operation(operation_id)
        if operation is not None:
            expected = (global_grant.lease_id, global_grant.grant_digest, request_digest)
            actual = (
                operation["lease_id"], operation["grant_digest"], operation["request_digest"]
            )
            if actual == expected and operation["status"] in {"PENDING", "COMMITTED"}:
                return

        reason = "revoked" if lease["state"] == "REVOKED" else "expired or inactive"
        raise ExecutionGrantRejected(
            f"Global Lease is {reason}; only an exact pending/committed operation may be recovered"
        )

    def consume_for_grant(
        self,
        execution_grant: Any,
        *,
        operation_id: str,
        request_digest: str,
    ) -> GlobalBudgetExecutionReceipt:
        self.authorize_execution_operation(
            execution_grant,
            operation_id=operation_id,
            request_digest=request_digest,
        )
        with self._lock:
            pair = self._bindings.get(execution_grant.grant_digest)
        if pair is None:
            raise ExecutionGrantRejected("execution Grant lost its Global Lease binding")
        global_grant = pair[1]
        try:
            receipt = self.global_broker.consume(
                global_grant,
                operation_id=operation_id,
                request_digest=request_digest,
            )
        except (GlobalBudgetExceeded, LeaseQuotaExceeded) as exc:
            raise ExecutionBudgetExceeded(str(exc)) from exc
        except GlobalBrokerIndeterminate as exc:
            raise ExecutionBrokerIndeterminate(str(exc)) from exc
        except GlobalOperationBindingConflict as exc:
            raise ExecutionOperationBindingConflict(str(exc)) from exc
        except GlobalOperationNotApplied as exc:
            raise ExecutionOperationNotApplied(str(exc)) from exc
        except (
            BrokerConfigurationMismatch,
            GlobalBudgetMismatch,
            GlobalGrantRejected,
            LeaseInactive,
            LeaseNotRegistered,
            LeaseRegistrationConflict,
            RevocationRejected,
        ) as exc:
            raise ExecutionGrantRejected(str(exc)) from exc

        return GlobalBudgetExecutionReceipt(
            lease_id=receipt.lease_id,
            operation_id=receipt.operation_id,
            request_digest=receipt.request_digest,
            counter_value=receipt.global_sequence,
            global_budget_id=receipt.global_budget_id,
            global_sequence=receipt.global_sequence,
            lease_used_count=receipt.lease_used_count,
            global_lease_grant_digest=global_grant.grant_digest,
        )
