"""Tests for webhook delivery service, signing, circuit breaker, and retry logic.

Covers:
- compute_webhook_signature() HMAC-SHA256 signing
- WebhookCircuitBreaker state transitions
- WebhookDeliveryService.try_deliver() with mocked dependencies
- _deliver_with_retries() retry schedule and non-retriable status codes
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.relay.webhook import (
    RETRY_DELAYS,
    WebhookCircuitBreaker,
    WebhookDeliveryService,
    compute_webhook_signature,
)


# ---------------------------------------------------------------------------
# HMAC signing tests (HOOK-03)
# ---------------------------------------------------------------------------


class TestComputeWebhookSignature:
    """compute_webhook_signature() unit tests."""

    def test_signature_format(self):
        """Signature starts with 'sha256=' prefix."""
        sig = compute_webhook_signature(b'{"test": true}', "secret-key")
        assert sig.startswith("sha256=")

    def test_deterministic(self):
        """Same input produces the same signature."""
        payload = b'{"hello":"world"}'
        key = "my-api-key"
        sig1 = compute_webhook_signature(payload, key)
        sig2 = compute_webhook_signature(payload, key)
        assert sig1 == sig2

    def test_different_keys_different_sigs(self):
        """Different tokens produce different signatures."""
        payload = b'{"hello":"world"}'
        sig1 = compute_webhook_signature(payload, "key-one")
        sig2 = compute_webhook_signature(payload, "key-two")
        assert sig1 != sig2

    def test_different_payloads_different_sigs(self):
        """Different payloads produce different signatures."""
        key = "same-key"
        sig1 = compute_webhook_signature(b'{"a":1}', key)
        sig2 = compute_webhook_signature(b'{"b":2}', key)
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Circuit breaker tests (HOOK-07)
# ---------------------------------------------------------------------------


class TestWebhookCircuitBreaker:
    """WebhookCircuitBreaker state transition tests."""

    def test_new_address_available(self):
        """Unknown address has a closed circuit (available)."""
        cb = WebhookCircuitBreaker()
        assert cb.is_available("alice::test.local") is True

    def test_opens_after_threshold(self):
        """Circuit opens after 5 consecutive failures."""
        cb = WebhookCircuitBreaker()
        addr = "bob::test.local"
        for _ in range(5):
            cb.record_failure(addr)
        assert cb.is_available(addr) is False

    def test_four_failures_still_available(self):
        """4 failures is below threshold -- circuit stays closed."""
        cb = WebhookCircuitBreaker()
        addr = "carol::test.local"
        for _ in range(4):
            cb.record_failure(addr)
        assert cb.is_available(addr) is True

    def test_success_resets_failures(self):
        """A success resets the consecutive failure count."""
        cb = WebhookCircuitBreaker()
        addr = "dave::test.local"
        for _ in range(3):
            cb.record_failure(addr)
        cb.record_success(addr)
        # After reset, 3 more failures should NOT open circuit (only 3 total)
        for _ in range(3):
            cb.record_failure(addr)
        assert cb.is_available(addr) is True

    def test_cooldown_closes_circuit(self):
        """Open circuit becomes available after cooldown expires."""
        cb = WebhookCircuitBreaker()
        addr = "eve::test.local"

        # Open the circuit
        for _ in range(5):
            cb.record_failure(addr)
        assert cb.is_available(addr) is False

        # Simulate time passing beyond cooldown
        with patch("uam.relay.webhook.time.monotonic", return_value=time.monotonic() + 3700):
            assert cb.is_available(addr) is True

    def test_configurable_cooldown(self):
        """Custom cooldown_seconds via Settings."""
        settings = MagicMock()
        settings.webhook_circuit_cooldown_seconds = 60
        cb = WebhookCircuitBreaker(settings=settings)
        addr = "frank::test.local"

        for _ in range(5):
            cb.record_failure(addr)
        assert cb.is_available(addr) is False

        # 59s -- still locked
        with patch("uam.relay.webhook.time.monotonic", return_value=time.monotonic() + 59):
            assert cb.is_available(addr) is False

        # 61s -- cooldown expired
        with patch("uam.relay.webhook.time.monotonic", return_value=time.monotonic() + 61):
            assert cb.is_available(addr) is True


# ---------------------------------------------------------------------------
# Delivery service tests (HOOK-02)
# ---------------------------------------------------------------------------


def _mock_agent(address: str = "agent::test.local", webhook_url: str | None = "https://example.com/hook", token: str = "test-key"):
    """Create a mock Agent object with attribute access."""
    agent = MagicMock()
    agent.address = address
    agent.webhook_url = webhook_url
    agent.token = token
    return agent


def _mock_delivery(delivery_id: int = 1):
    """Create a mock delivery object."""
    delivery = MagicMock()
    delivery.id = delivery_id
    return delivery


class TestWebhookDeliveryServiceTryDeliver:
    """WebhookDeliveryService.try_deliver() -- high-level dispatch tests."""

    @pytest.mark.asyncio
    async def test_try_deliver_returns_false_no_webhook(self):
        """Agent without webhook_url returns False."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        with (
            patch(
                "uam.relay.webhook.get_agent_by_address",
                new_callable=AsyncMock,
                return_value=_mock_agent(webhook_url=None),
            ),
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx
            result = await service.try_deliver("nope::test.local", {"id": "m1"})
        assert result is False

    @pytest.mark.asyncio
    async def test_try_deliver_returns_false_circuit_open(self):
        """Open circuit breaker returns False without querying DB."""
        cb = WebhookCircuitBreaker()
        addr = "agent::test.local"
        # Open the circuit
        for _ in range(5):
            cb.record_failure(addr)

        service = WebhookDeliveryService(cb)
        result = await service.try_deliver(addr, {"id": "m1"})
        assert result is False

    @pytest.mark.asyncio
    async def test_try_deliver_starts_background_task(self):
        """Successful try_deliver creates an asyncio background task."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        agent = _mock_agent()
        delivery = _mock_delivery(delivery_id=1)

        with (
            patch(
                "uam.relay.webhook.get_agent_by_address",
                new_callable=AsyncMock,
                return_value=agent,
            ),
            patch(
                "uam.relay.webhook.create_delivery",
                new_callable=AsyncMock,
                return_value=delivery,
            ),
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
            patch("asyncio.create_task") as mock_create_task,
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx
            mock_task = MagicMock()
            mock_create_task.return_value = mock_task
            result = await service.try_deliver("agent::test.local", {"id": "m1"})

        assert result is True
        mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_cancels_active_tasks(self):
        """stop() cancels all active background tasks."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        # Create a mock HTTP client
        service._http_client = AsyncMock()

        # Create a real asyncio task that blocks forever so we can cancel it
        async def _hang_forever():
            await asyncio.sleep(9999)

        task = asyncio.create_task(_hang_forever())
        service._active_tasks.add(task)

        await service.stop()
        assert task.cancelled()


# ---------------------------------------------------------------------------
# Retry logic tests (HOOK-04)
# ---------------------------------------------------------------------------


class TestDeliverWithRetries:
    """_deliver_with_retries() retry schedule and error handling."""

    @pytest.mark.asyncio
    async def test_retry_stops_on_success(self):
        """Delivery succeeds on attempt 2 -- only 2 attempts made."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        # Mock httpx responses: fail, then succeed
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500
        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_response_500, mock_response_200])
        service._http_client = mock_client

        with (
            patch(
                "uam.relay.webhook.async_validate_webhook_url",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ),
            patch(
                "uam.relay.webhook.record_attempt",
                new_callable=AsyncMock,
            ),
            patch(
                "uam.relay.webhook.complete_delivery",
                new_callable=AsyncMock,
            ) as mock_complete,
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx

            await service._deliver_with_retries(
                "agent::test.local",
                {"id": "msg1"},
                "https://example.com/hook",
                "api-key",
                1,
            )

        # Should have called post exactly 2 times
        assert mock_client.post.call_count == 2
        # Final completion should be success
        mock_complete.assert_called_once()
        args = mock_complete.call_args[0]
        assert args[1] == 1  # delivery_id
        assert args[2] == "succeeded"  # status

    @pytest.mark.asyncio
    async def test_retry_stops_on_non_retriable_4xx(self):
        """Non-retriable 400 stops retries immediately (1 attempt)."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        mock_response = MagicMock()
        mock_response.status_code = 400

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        service._http_client = mock_client

        with (
            patch(
                "uam.relay.webhook.async_validate_webhook_url",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ),
            patch(
                "uam.relay.webhook.record_attempt",
                new_callable=AsyncMock,
            ),
            patch(
                "uam.relay.webhook.complete_delivery",
                new_callable=AsyncMock,
            ) as mock_complete,
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx

            await service._deliver_with_retries(
                "agent::test.local",
                {"id": "msg1"},
                "https://example.com/hook",
                "api-key",
                1,
            )

        assert mock_client.post.call_count == 1
        mock_complete.assert_called_once()
        args = mock_complete.call_args
        assert args[0][2] == "failed"
        assert "Non-retriable" in args[0][3]

    @pytest.mark.asyncio
    async def test_408_and_429_are_retriable(self):
        """408 (timeout) and 429 (rate-limited) are retriable status codes."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        mock_408 = MagicMock()
        mock_408.status_code = 408
        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_200 = MagicMock()
        mock_200.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[mock_408, mock_429, mock_200])
        service._http_client = mock_client

        with (
            patch(
                "uam.relay.webhook.async_validate_webhook_url",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ),
            patch(
                "uam.relay.webhook.record_attempt",
                new_callable=AsyncMock,
            ),
            patch(
                "uam.relay.webhook.complete_delivery",
                new_callable=AsyncMock,
            ) as mock_complete,
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx

            await service._deliver_with_retries(
                "agent::test.local",
                {"id": "msg1"},
                "https://example.com/hook",
                "api-key",
                1,
            )

        # 408, 429, 200 = 3 attempts
        assert mock_client.post.call_count == 3
        mock_complete.assert_called_once()
        args = mock_complete.call_args[0]
        assert args[1] == 1  # delivery_id
        assert args[2] == "succeeded"  # status

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        """All 5 retries fail with 500 -- circuit breaker records failure."""
        cb = WebhookCircuitBreaker()
        service = WebhookDeliveryService(cb)

        mock_response = MagicMock()
        mock_response.status_code = 500

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        service._http_client = mock_client

        with (
            patch(
                "uam.relay.webhook.async_validate_webhook_url",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ),
            patch(
                "uam.relay.webhook.record_attempt",
                new_callable=AsyncMock,
            ),
            patch(
                "uam.relay.webhook.complete_delivery",
                new_callable=AsyncMock,
            ) as mock_complete,
            patch("uam.relay.webhook.get_engine", return_value=MagicMock()),
            patch("uam.relay.webhook.async_session_factory") as mock_factory,
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            mock_session = AsyncMock()
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_factory.return_value = mock_ctx

            await service._deliver_with_retries(
                "agent::test.local",
                {"id": "msg1"},
                "https://example.com/hook",
                "api-key",
                1,
            )

        # All 5 retry delays attempted
        assert mock_client.post.call_count == len(RETRY_DELAYS)
        mock_complete.assert_called_once()
        args = mock_complete.call_args
        assert args[0][2] == "failed"
        assert "retries exhausted" in args[0][3].lower()
