"""Offline Agent Budget Lab: issuer, local ledger, receipts and reconciliation."""

from .crypto import (
    decode_public_key,
    encode_public_key,
    generate_ed25519_keypair,
    issuer_key_id,
    verify_lease_signature,
)
from .issuer import BudgetIssuer, IssuerSnapshot
from .ledger import (
    DuplicateOperationError,
    InsufficientBudgetError,
    InvalidOperationTransition,
    LedgerOperation,
    LedgerSnapshot,
    LocalBudgetLedger,
    OperationStatus,
)
from .models import BudgetLease, LeaseLedgerState, LeaseRequest
from .receipts import ExecutionReceipt, ReceiptChain, verify_receipt_chain
from .reconciliation import (
    AllocationManifest,
    BudgetReconciler,
    LeaseEvidenceBundle,
    LeaseManifestEntry,
    LeaseReconciliation,
    ReconciliationReport,
    ReconciliationStatus,
    TrustedChainHead,
    lease_credential_digest,
    verify_allocation_manifest,
)

__all__ = [
    "BudgetIssuer", "IssuerSnapshot", "BudgetLease", "LeaseLedgerState", "LeaseRequest",
    "DuplicateOperationError", "InsufficientBudgetError", "InvalidOperationTransition",
    "LedgerOperation", "LedgerSnapshot", "LocalBudgetLedger", "OperationStatus",
    "ExecutionReceipt", "ReceiptChain", "verify_receipt_chain",
    "AllocationManifest", "BudgetReconciler", "LeaseEvidenceBundle", "LeaseManifestEntry",
    "LeaseReconciliation", "ReconciliationReport", "ReconciliationStatus", "TrustedChainHead",
    "lease_credential_digest", "verify_allocation_manifest",
    "decode_public_key", "encode_public_key", "generate_ed25519_keypair", "issuer_key_id",
    "verify_lease_signature",
]

from .state_trust import (
    AllocationConflict,
    AuthorityUnavailable,
    BudgetExceeded,
    DeviceBindingError,
    DuplicateSpend,
    MonotonicStateEmulator,
    SharedAtomicSpendAuthority,
    SharedRootAllocationRegistry,
    SpendRecord,
    StateTrustError,
)

__all__ += [
    "AllocationConflict", "AuthorityUnavailable", "BudgetExceeded",
    "DeviceBindingError", "DuplicateSpend", "MonotonicStateEmulator",
    "SharedAtomicSpendAuthority", "SharedRootAllocationRegistry",
    "SpendRecord", "StateTrustError",
]
