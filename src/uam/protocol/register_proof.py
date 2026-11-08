"""Proof that a caller holds an agent's key, for getting a new relay token.

The signature covers ``uam-register-v1\\n{address}\\n{timestamp}`` as UTF-8.  The
TypeScript SDK signs the same bytes.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey, VerifyKey

from uam.protocol.crypto import sign_message, verify_signature
from uam.protocol.errors import SignatureVerificationError

MAX_AGE = timedelta(minutes=5)


def _signed_bytes(address: str, timestamp: str) -> bytes:
    return f"uam-register-v1\n{address}\n{timestamp}".encode("utf-8")


def create_register_proof(
    address: str, signing_key: SigningKey, now: datetime | None = None
) -> dict[str, str]:
    """Return the ``proof`` field for ``POST /api/v1/register``."""
    when = now or datetime.now(timezone.utc)
    timestamp = when.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    signature = sign_message(_signed_bytes(address, timestamp), signing_key)
    return {"timestamp": timestamp, "signature": signature}


def register_proof_nonce(timestamp: str) -> str:
    """Return what makes a proof single use, sized for the nonce column.

    Keyed on the signed timestamp, not the signature, because the signature's
    base64 can be respelled without the key.
    """
    return hashlib.sha256(timestamp.encode("utf-8")).hexdigest()


def register_proof_is_valid(
    address: str, timestamp: str, signature: str, verify_key: VerifyKey
) -> bool:
    """Return True if the proof is fresh and signed by *verify_key*."""
    try:
        signed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if abs(datetime.now(timezone.utc) - signed_at) > MAX_AGE:
            return False
        verify_signature(_signed_bytes(address, timestamp), signature, verify_key)
    except (ValueError, TypeError, SignatureVerificationError):
        return False
    return True
