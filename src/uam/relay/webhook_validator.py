"""Webhook URL validation with SSRF prevention (HOOK-05).

Validates webhook URLs at registration time and re-validates before each
delivery attempt (TOCTOU defense).  Rejects non-HTTPS schemes, private/
loopback IPs, and known cloud metadata endpoints.
"""

from __future__ import annotations

import asyncio
import logging
import urllib.parse

from uam.relay.verification import is_public_ip

logger = logging.getLogger(__name__)

# Cloud metadata endpoints that must never receive webhook traffic.
_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.amazonaws.com",
        "169.254.169.254",
    }
)


def validate_webhook_url(url: str) -> tuple[bool, str]:
    """Validate a webhook URL for safety.

    Enforces:
    - HTTPS-only scheme
    - No cloud metadata hostnames
    - DNS resolves to public IPs only (via ``is_public_ip``)

    Returns ``(True, "")`` on success or ``(False, reason)`` on failure.

    Used by registration and admin routes (sync context -- FastAPI runs
    these in a threadpool so blocking DNS is acceptable).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return (False, "Malformed URL")

    if parsed.scheme != "https":
        return (False, "Webhook URL must use HTTPS")

    hostname = parsed.hostname
    if not hostname:
        return (False, "Webhook URL has no hostname")

    if hostname in _BLOCKED_HOSTNAMES:
        return (False, f"Blocked hostname: {hostname}")

    if not is_public_ip(hostname):
        return (
            False,
            "Webhook URL resolves to a private or non-routable IP address",
        )

    return (True, "")


async def async_validate_webhook_url(url: str) -> tuple[bool, str]:
    """Async wrapper for ``validate_webhook_url``.

    Runs the synchronous validator in an executor to avoid blocking the
    event loop during DNS resolution in ``is_public_ip()``.

    Use this in async code paths (e.g.,
    ``WebhookDeliveryService._deliver_with_retries``) for TOCTOU
    re-validation inside the async retry loop.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_webhook_url, url)
