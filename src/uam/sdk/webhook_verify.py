"""Receiver-side webhook signature verification (HOOK-03).

Small utility for webhook receivers to verify that incoming webhook
payloads were signed by the UAM relay.  Uses HMAC-SHA256 with the
agent's token as the shared secret.

Usage::

    from uam.sdk.webhook_verify import verify_webhook_signature

    payload = request.body()  # raw bytes
    signature = request.headers["X-UAM-Signature"]
    token = "your-agent-token"

    if verify_webhook_signature(payload, signature, token):
        # payload is authentic
        ...
"""

from __future__ import annotations

import hashlib
import hmac


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    token: str,
) -> bool:
    """Verify an HMAC-SHA256 webhook signature.

    Args:
        payload_bytes: The raw request body bytes.
        signature_header: The ``X-UAM-Signature`` header value
            (format: ``sha256=<hex>``).
        token: The agent's token (shared secret).

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
        Uses ``hmac.compare_digest`` for constant-time comparison
        to prevent timing attacks.
    """
    if not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(
        token.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    received = signature_header[len("sha256="):]
    return hmac.compare_digest(expected, received)
