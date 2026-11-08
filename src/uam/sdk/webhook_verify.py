"""Receiver-side webhook signature verification (HOOK-03).

Small utility for webhook receivers to verify that incoming webhook
payloads were signed by the UAM relay.  Uses HMAC-SHA256 with the
agent's webhook secret, which the relay returns when the webhook is set
(``PUT /api/v1/agents/{address}/webhook``).  Setting the same URL again
returns it again.

Usage::

    from uam.sdk.webhook_verify import verify_webhook_signature

    payload = request.body()  # raw bytes
    signature = request.headers["X-UAM-Signature"]
    secret = "your-webhook-secret"

    if verify_webhook_signature(payload, signature, secret):
        # payload is authentic
        ...
"""

from __future__ import annotations

import hashlib
import hmac
import warnings


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str | None = None,
    *,
    token: str | None = None,
) -> bool:
    """Verify an HMAC-SHA256 webhook signature.

    Args:
        payload_bytes: The raw request body bytes.
        signature_header: The ``X-UAM-Signature`` header value
            (format: ``sha256=<hex>``).
        secret: The agent's webhook secret.
        token: Deprecated name for *secret*.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
        Uses ``hmac.compare_digest`` for constant-time comparison
        to prevent timing attacks.
    """
    if token is not None:
        warnings.warn(
            "verify_webhook_signature(token=...) is deprecated; pass secret=",
            DeprecationWarning,
            stacklevel=2,
        )
        secret = secret if secret is not None else token
    if secret is None:
        raise TypeError("verify_webhook_signature() needs the webhook secret")

    if not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    received = signature_header[len("sha256="):]
    return hmac.compare_digest(expected.encode("utf-8"), received.encode("utf-8"))
