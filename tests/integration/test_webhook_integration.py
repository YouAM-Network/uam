"""End-to-end integration tests for three-tier webhook delivery.

Tests the complete delivery chain: WebSocket > webhook > store-and-forward,
using the FastAPI TestClient with mocked httpx for webhook delivery and
real relay app, database, and endpoint code.

Covers:
- Tier 1: WebSocket delivery (real-time, highest priority)
- Tier 2: Webhook fallback when WebSocket unavailable
- Tier 3: Store-and-forward when both WebSocket and webhook unavailable
- Circuit breaker disabling webhook after consecutive failures
"""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.app import create_app
from uam.sdk.webhook_verify import verify_webhook_signature


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    """Create a relay app backed by a temporary database."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "webhook_integration.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    yield create_app()
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)


@pytest.fixture()
def client(app):
    """Return a TestClient with lifespan triggered."""
    with TestClient(app) as c:
        yield c


def _register_agent(client, name, webhook_url=None):
    """Register an agent and return its details dict."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    body = {"agent_name": name, "public_key": pk_str}
    if webhook_url:
        body["webhook_url"] = webhook_url
    resp = client.post("/api/v1/register", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


def _make_wire(from_agent, to_agent):
    """Create a signed envelope as a wire dict."""
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello from integration test!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


# ---------------------------------------------------------------------------
# Test 1: Tier 1 -- WebSocket delivery takes priority
# ---------------------------------------------------------------------------


class TestThreeTierWebSocketFirst:
    """WebSocket delivery is Tier 1 (highest priority)."""

    def test_websocket_delivery_takes_priority(self, client, app):
        """Message arrives via WebSocket when recipient is connected."""
        alice = _register_agent(client, "alice")
        bob = _register_agent(client, "bob")

        # Connect bob via WebSocket
        with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
            # Send from alice to bob via HTTP
            wire = _make_wire(alice, bob)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["delivered"] is True

            # Bob receives via WebSocket
            msg = ws.receive_json()
            assert msg["from"] == alice["address"]
            assert msg["to"] == bob["address"]


# ---------------------------------------------------------------------------
# Test 2: Tier 2 -- Webhook fallback
# ---------------------------------------------------------------------------


class TestThreeTierWebhookFallback:
    """Webhook delivery is Tier 2 when WebSocket is unavailable."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_webhook_fallback_when_no_websocket(self, _mock_ip, client, app):
        """Message goes via webhook when recipient has no WebSocket."""
        alice = _register_agent(client, "alice")
        bob = _register_agent(client, "bob")

        # Set bob's webhook URL
        client.put(
            f"/api/v1/agents/{bob['address']}/webhook",
            json={"webhook_url": "https://hooks.example.com/uam"},
            headers={"Authorization": f"Bearer {bob['token']}"},
        )

        # Mock the httpx client used by WebhookDeliveryService
        captured_requests = []

        async def _mock_post(url, *, content=None, headers=None):
            captured_requests.append({
                "url": url,
                "content": content,
                "headers": headers,
            })
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        # Patch the HTTP client on the webhook service
        webhook_service = app.state.webhook_service
        original_client = webhook_service._http_client
        mock_client = AsyncMock()
        mock_client.post = _mock_post
        webhook_service._http_client = mock_client

        try:
            # Also need to mock async_validate_webhook_url for the retry loop
            with patch(
                "uam.relay.webhook.async_validate_webhook_url",
                new_callable=AsyncMock,
                return_value=(True, ""),
            ):
                # Send from alice to bob via HTTP (bob NOT connected via WS)
                wire = _make_wire(alice, bob)
                resp = client.post(
                    "/api/v1/send",
                    json={"envelope": wire},
                    headers={"Authorization": f"Bearer {alice['token']}"},
                )
                assert resp.status_code == 200
                data = resp.json()
                # delivered=True because webhook delivery was initiated
                assert data["delivered"] is True

                # Give the background task a moment to execute
                import time
                time.sleep(0.2)

            # Verify webhook POST was made
            assert len(captured_requests) >= 1
            req = captured_requests[0]
            assert req["url"] == "https://hooks.example.com/uam"

            # Verify envelope payload is valid JSON matching the wire dict
            payload_bytes = req["content"]
            payload_dict = json.loads(payload_bytes)
            assert payload_dict["from"] == alice["address"]
            assert payload_dict["to"] == bob["address"]

            # Verify X-UAM-Signature header is present and valid
            sig_header = req["headers"]["X-UAM-Signature"]
            assert sig_header.startswith("sha256=")
            assert verify_webhook_signature(payload_bytes, sig_header, bob["token"])
        finally:
            webhook_service._http_client = original_client


# ---------------------------------------------------------------------------
# Test 3: Tier 3 -- Store-and-forward fallback
# ---------------------------------------------------------------------------


class TestThreeTierStoreFallback:
    """Store-and-forward is Tier 3 when both WS and webhook are unavailable."""

    def test_store_fallback_when_no_ws_no_webhook(self, client, app):
        """Message stored when neither WebSocket nor webhook available."""
        alice = _register_agent(client, "alice")
        bob = _register_agent(client, "bob")

        # Bob has no WebSocket connection and no webhook URL
        wire = _make_wire(alice, bob)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["delivered"] is False

        # Verify message is in bob's inbox
        inbox_resp = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        inbox_data = inbox_resp.json()
        assert inbox_data["count"] >= 1
        # Check the stored message envelope
        stored_envelope = inbox_data["messages"][0]
        assert stored_envelope["from"] == alice["address"]


# ---------------------------------------------------------------------------
# Test 4: Circuit breaker disables webhook after failures
# ---------------------------------------------------------------------------


class TestWebhookCircuitBreakerIntegration:
    """Circuit breaker opens after consecutive webhook delivery failures."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_circuit_breaker_opens_after_failures(self, _mock_ip, client, app):
        """After 5 webhook failures, subsequent messages go to store-and-forward."""
        alice = _register_agent(client, "alice")
        bob = _register_agent(client, "bob")

        # Set bob's webhook URL
        client.put(
            f"/api/v1/agents/{bob['address']}/webhook",
            json={"webhook_url": "https://hooks.example.com/fail"},
            headers={"Authorization": f"Bearer {bob['token']}"},
        )

        # Mock httpx to always fail with 500
        call_count = 0

        async def _mock_post_fail(url, *, content=None, headers=None):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.status_code = 500
            return mock_resp

        webhook_service = app.state.webhook_service
        original_client = webhook_service._http_client
        mock_client = AsyncMock()
        mock_client.post = _mock_post_fail
        webhook_service._http_client = mock_client

        try:
            with (
                patch(
                    "uam.relay.webhook.async_validate_webhook_url",
                    new_callable=AsyncMock,
                    return_value=(True, ""),
                ),
                patch("asyncio.sleep", new_callable=AsyncMock),
            ):
                # Send 5 messages that will all fail webhook delivery
                # Each message exhausts all 5 retry attempts -> record_failure
                for i in range(5):
                    wire = _make_wire(alice, bob)
                    resp = client.post(
                        "/api/v1/send",
                        json={"envelope": wire},
                        headers={"Authorization": f"Bearer {alice['token']}"},
                    )
                    assert resp.status_code == 200

                # Give background tasks time to complete
                import time
                time.sleep(0.3)

            # After 5 delivery failures (each exhausting retries), circuit should be open
            # The next message should go to store-and-forward (delivered=False)
            wire = _make_wire(alice, bob)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            # Circuit is open -> webhook skipped -> store-and-forward
            assert data["delivered"] is False
        finally:
            webhook_service._http_client = original_client
