from __future__ import annotations

from pathlib import Path
import tempfile
import time
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from src.global_budget import (
    GlobalBudgetBroker,
    ToolPermission,
    issue_lease_grant,
)


def main() -> None:
    now = int(time.time())
    issuer = Ed25519PrivateKey.generate()
    permission = ToolPermission("invoice_review", "sha256:" + "a" * 64)

    with tempfile.TemporaryDirectory(prefix="d81-demo-") as tmp:
        root = Path(tmp)
        broker = GlobalBudgetBroker(
            global_budget_id="demo-budget-epoch",
            global_quota_limit=8,
            issuer_public_key=issuer.public_key(),
            journal_path=root / "journal.sqlite3",
            counter_state_path=root / "counter.json",
            broker_lock_path=root / "broker.lock",
            clock=lambda: now,
        )

        grants = []
        for label, quota in (("agent-a", 3), ("agent-b", 4)):
            grant = issue_lease_grant(
                issuer,
                issuer_id="demo-issuer",
                grant_id=f"grant-{label}",
                lease_id=f"lease-{label}",
                global_budget_id="demo-budget-epoch",
                nonce=f"nonce-{label}",
                quota_limit=quota,
                issued_at=now,
                expires_at=now + 3600,
                audience="demo-gateway",
                subject_id=label,
                context_digest="sha256:" + "b" * 64,
                allowed_tools=(permission,),
            )
            broker.register_lease(grant)
            grants.append(grant)

        receipts = []
        for index, grant in enumerate(grants):
            receipts.append(
                broker.consume(
                    grant,
                    operation_id=f"demo-operation-{index + 1}",
                    request_digest="sha256:" + f"{index + 1:064x}",
                )
            )

        state = broker.assert_invariants()
        print("global sequences:", [item.global_sequence for item in receipts])
        print("reserved:", state["reserved"], "/", state["global_quota_limit"])
        print("used:", state["used"], "counter:", state["counter_value"])
        print("health:", broker.inspect()["health"])


if __name__ == "__main__":
    main()
