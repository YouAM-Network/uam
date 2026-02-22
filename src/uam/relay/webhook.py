"""Webhook delivery service with HMAC signing, retries, and circuit breaker.

HOOK-02: Delivery service with exponential backoff
HOOK-03: HMAC-SHA256 signing
HOOK-04: Retry schedule with TOCTOU re-validation
HOOK-07: Per-agent circuit breaker
MSG-05: receipt.delivered after successful webhook delivery
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from uam.relay.config import Settings
from uam.relay.connections import ConnectionManager
from uam.relay.database import (
    complete_webhook_delivery,
    create_webhook_delivery,
    get_agent_with_webhook,
    update_webhook_delivery_attempt,
)
from uam.relay.webhook_validator import async_validate_webhook_url

logger = logging.getLogger(__name__)

# Retry delays in seconds: immediate, 5s, 5min, 30min, 2h
RETRY_DELAYS: list[int] = [0, 5, 300, 1800, 7200]

# HTTP status codes that are NOT retriable (client errors except timeout/rate-limit)
_NON_RETRIABLE_4XX = set(range(400, 500)) - {408, 429}


# ---------------------------------------------------------------------------
# HMAC signing (HOOK-03)
# ---------------------------------------------------------------------------


def compute_webhook_signature(payload_bytes: bytes, token: str) -> str:
    """Compute HMAC-SHA256 signature for a webhook payload.

    Uses the agent's token as the HMAC secret.  Returns the signature
    in ``sha256=<hex>`` format for the ``X-UAM-Signature`` header.

    Callers MUST use compact JSON serialization
    (``json.dumps(data, separators=(",", ":"))```) for deterministic output.
    """
    mac = hmac.new(token.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


# ---------------------------------------------------------------------------
# Circuit breaker (HOOK-07)
# ---------------------------------------------------------------------------


@dataclass
class CircuitState:
    """Per-agent circuit state."""

    consecutive_failures: int = 0
    is_open: bool = False
    opened_at: float = 0.0


class WebhookCircuitBreaker:
    """Per-agent circuit breaker for webhook delivery.

    After ``FAILURE_THRESHOLD`` consecutive failures the circuit opens,
    blocking further delivery attempts until the cooldown expires.  Uses
    ``time.monotonic()`` for timing so clock adjustments don't cause
    spurious state changes.
    """

    FAILURE_THRESHOLD: int = 5

    def __init__(self, settings: Settings | None = None) -> None:
        self._circuits: dict[str, CircuitState] = {}
        cooldown = 3600
        if settings is not None:
            cooldown = settings.webhook_circuit_cooldown_seconds
        self._cooldown_seconds: int = cooldown

    def _get(self, address: str) -> CircuitState:
        if address not in self._circuits:
            self._circuits[address] = CircuitState()
        return self._circuits[address]

    def is_available(self, address: str) -> bool:
        """Return ``True`` if delivery should be attempted for *address*.

        A closed circuit is always available.  An open circuit becomes
        available again once the cooldown period has elapsed (half-open
        probe).
        """
        state = self._get(address)
        if not state.is_open:
            return True
        # Check cooldown expiration
        elapsed = time.monotonic() - state.opened_at
        if elapsed >= self._cooldown_seconds:
            logger.info(
                "Circuit breaker cooldown expired for %s, allowing probe",
                address,
            )
            return True
        return False

    def record_success(self, address: str) -> None:
        """Record a successful delivery -- resets failures and closes circuit."""
        state = self._get(address)
        state.consecutive_failures = 0
        if state.is_open:
            logger.info("Circuit breaker closed for %s after successful delivery", address)
            state.is_open = False

    def record_failure(self, address: str) -> None:
        """Record a failed delivery -- opens circuit at threshold."""
        state = self._get(address)
        state.consecutive_failures += 1
        if (
            not state.is_open
            and state.consecutive_failures >= self.FAILURE_THRESHOLD
        ):
            state.is_open = True
            state.opened_at = time.monotonic()
            logger.warning(
                "Circuit breaker OPEN for %s after %d consecutive failures",
                address,
                state.consecutive_failures,
            )


# ---------------------------------------------------------------------------
# Delivery service (HOOK-02, HOOK-04)
# ---------------------------------------------------------------------------


class WebhookDeliveryService:
    """Manages webhook delivery with retries and circuit breaking.

    Lifecycle:
        service = WebhookDeliveryService(db, circuit_breaker)
        await service.start()
        ...
        await service.stop()
    """

    def __init__(
        self,
        db: object,  # aiosqlite.Connection
        circuit_breaker: WebhookCircuitBreaker,
        manager: ConnectionManager | None = None,
    ) -> None:
        self._db = db
        self._circuit_breaker = circuit_breaker
        self._manager = manager
        self._http_client: httpx.AsyncClient | None = None
        self._active_tasks: set[asyncio.Task] = set()  # type: ignore[type-arg]

    async def start(self) -> None:
        """Create the HTTP client.  Call once at application startup."""
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,  # SSRF defense
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=10,
            ),
        )
        logger.info("WebhookDeliveryService started")

    async def stop(self) -> None:
        """Cancel active tasks and close the HTTP client."""
        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        self._active_tasks.clear()
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
        logger.info("WebhookDeliveryService stopped")

    async def try_deliver(
        self,
        address: str,
        envelope_dict: dict,
    ) -> bool:
        """Attempt webhook delivery for *address*.

        Returns ``True`` if delivery was initiated (background task
        created), ``False`` if the circuit is open or no webhook is
        configured.  Note: ``True`` does NOT mean delivery succeeded --
        it runs asynchronously.
        """
        if not self._circuit_breaker.is_available(address):
            logger.debug("Circuit open for %s, skipping webhook delivery", address)
            return False

        agent = await get_agent_with_webhook(self._db, address)
        if agent is None:
            return False

        webhook_url: str = agent["webhook_url"]
        token: str = agent["token"]

        envelope_json = json.dumps(envelope_dict, separators=(",", ":"))
        message_id = envelope_dict.get("id", "unknown")

        delivery_id = await create_webhook_delivery(
            self._db, address, str(message_id), envelope_json
        )

        task = asyncio.create_task(
            self._deliver_with_retries(
                address, envelope_dict, webhook_url, token, delivery_id
            )
        )
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

        return True

    async def _deliver_with_retries(
        self,
        address: str,
        envelope_dict: dict,
        webhook_url: str,
        token: str,
        delivery_id: int,
    ) -> None:
        """Deliver with exponential backoff retries.

        Re-validates the webhook URL before each attempt as a TOCTOU
        defense (the URL could become dangerous between registration
        and delivery).
        """
        if self._http_client is None:
            logger.error("HTTP client not initialized -- call start() first")
            await complete_webhook_delivery(
                self._db, delivery_id, "failed", "HTTP client not initialized"
            )
            return

        payload_bytes = json.dumps(envelope_dict, separators=(",", ":")).encode("utf-8")
        signature = compute_webhook_signature(payload_bytes, token)

        for attempt, delay in enumerate(RETRY_DELAYS, start=1):
            if delay > 0:
                await asyncio.sleep(delay)

            # TOCTOU re-validation
            valid, reason = await async_validate_webhook_url(webhook_url)
            if not valid:
                logger.warning(
                    "Webhook URL re-validation failed for %s: %s",
                    address,
                    reason,
                )
                await complete_webhook_delivery(
                    self._db,
                    delivery_id,
                    "failed",
                    f"URL re-validation failed: {reason}",
                )
                return

            try:
                resp = await self._http_client.post(
                    webhook_url,
                    content=payload_bytes,
                    headers={
                        "Content-Type": "application/json",
                        "X-UAM-Signature": signature,
                        "User-Agent": "UAM-Relay/0.1.0",
                    },
                )
                status_code = resp.status_code
            except httpx.HTTPError as exc:
                # Network error -- retriable
                error_msg = f"{type(exc).__name__}: {exc}"
                logger.debug(
                    "Webhook delivery attempt %d/%d for %s failed: %s",
                    attempt,
                    len(RETRY_DELAYS),
                    address,
                    error_msg,
                )
                await update_webhook_delivery_attempt(
                    self._db, delivery_id, attempt, None, error_msg
                )
                continue

            await update_webhook_delivery_attempt(
                self._db, delivery_id, attempt, status_code, None
            )

            if 200 <= status_code < 300:
                logger.info(
                    "Webhook delivery succeeded for %s (attempt %d/%d, %d)",
                    address,
                    attempt,
                    len(RETRY_DELAYS),
                    status_code,
                )
                await complete_webhook_delivery(self._db, delivery_id, "succeeded")
                self._circuit_breaker.record_success(address)

                # Send receipt.delivered to original sender (MSG-05 anti-loop guard)
                msg_type = str(envelope_dict.get("type", ""))
                original_from = envelope_dict.get("from", "")
                if self._manager and original_from and not msg_type.startswith("receipt."):
                    receipt = {
                        "type": "receipt.delivered",
                        "message_id": envelope_dict.get("message_id", ""),
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        "to": address,
                    }
                    await self._manager.send_to(original_from, receipt)

                return

            if status_code in _NON_RETRIABLE_4XX:
                error_msg = f"Non-retriable HTTP {status_code}"
                logger.warning(
                    "Webhook delivery for %s got non-retriable %d, giving up",
                    address,
                    status_code,
                )
                await complete_webhook_delivery(
                    self._db, delivery_id, "failed", error_msg
                )
                return

            # Retriable status code (5xx, 408, 429) -- continue loop
            logger.debug(
                "Webhook delivery attempt %d/%d for %s returned %d, retrying",
                attempt,
                len(RETRY_DELAYS),
                address,
                status_code,
            )

        # All retries exhausted
        logger.warning(
            "Webhook delivery for %s exhausted all %d retries",
            address,
            len(RETRY_DELAYS),
        )
        await complete_webhook_delivery(
            self._db, delivery_id, "failed", "All retries exhausted"
        )
        self._circuit_breaker.record_failure(address)
