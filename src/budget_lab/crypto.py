"""Ed25519 helpers and canonical serialization for lease credentials."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import BudgetLease

_SIGNATURE_DOMAIN = b"offline-agent-budget-lab:budget-lease:v1\x00"


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize a JSON object deterministically for signing and hashing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Generate a fresh Ed25519 private key and its raw 32-byte public key."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_key


def encode_public_key(public_key_bytes: bytes) -> str:
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("an Ed25519 public key must be exactly 32 bytes")
    return base64.b64encode(public_key_bytes).decode("ascii")


def decode_public_key(public_key_b64: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("public key must be valid standard Base64") from exc
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key must be exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def issuer_key_id(public_key_bytes: bytes) -> str:
    """Return a stable identifier for the issuer verification key."""
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("an Ed25519 public key must be exactly 32 bytes")
    return hashlib.sha256(public_key_bytes).hexdigest()[:24]


def sign_lease_payload(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    message = _SIGNATURE_DOMAIN + canonical_json_bytes(payload)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def verify_lease_signature(lease: BudgetLease, issuer_public_key_bytes: bytes) -> bool:
    """Verify issuer key identity and the Ed25519 signature for a lease.

    Returns False for cryptographic mismatch. Malformed caller input raises
    ValueError, allowing callers to distinguish malformed credentials from
    a well-formed but unauthenticated credential.
    """
    if not isinstance(lease, BudgetLease):
        raise TypeError("lease must be a BudgetLease")
    if not isinstance(issuer_public_key_bytes, bytes) or len(issuer_public_key_bytes) != 32:
        raise ValueError("issuer_public_key_bytes must be exactly 32 bytes")

    if issuer_key_id(issuer_public_key_bytes) != lease.issuer_key_id:
        return False

    try:
        signature = base64.b64decode(lease.issuer_signature.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        return False
    if len(signature) != 64:
        return False

    message = _SIGNATURE_DOMAIN + canonical_json_bytes(lease.unsigned_payload())
    public_key = Ed25519PublicKey.from_public_bytes(issuer_public_key_bytes)
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
