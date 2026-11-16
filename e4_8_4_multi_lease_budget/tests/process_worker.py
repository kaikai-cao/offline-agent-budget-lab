from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from global_budget import GlobalBudgetBroker, LeaseGrant


def main(config_path: str) -> None:
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(config["issuer_public_key_b64"], validate=True)
    )
    broker = GlobalBudgetBroker(
        global_budget_id=config["global_budget_id"],
        global_quota_limit=config["global_quota_limit"],
        issuer_public_key=public_key,
        journal_path=config["journal_path"],
        counter_state_path=config["counter_state_path"],
        broker_lock_path=config["broker_lock_path"],
        clock=lambda: config["now"],
    )
    grant = LeaseGrant.from_dict(config["grant"])
    results = []
    for item in config["operations"]:
        receipt = broker.consume(
            grant,
            operation_id=item["operation_id"],
            request_digest=item["request_digest"],
        )
        results.append(receipt.as_dict())
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
