"""Tests for webhook admin CRUD endpoints.

Covers:
- PUT /agents/{address}/webhook (set URL with SSRF validation)
- DELETE /agents/{address}/webhook (remove URL)
- GET /agents/{address}/webhook (query current URL)
- GET /agents/{address}/webhook/deliveries (delivery history)
- Webhook URL on registration
- Auth and ownership enforcement
"""

from __future__ import annotations

from unittest.mock import patch

from uam.protocol import generate_keypair, serialize_verify_key


# ---------------------------------------------------------------------------
# PUT /agents/{address}/webhook
# ---------------------------------------------------------------------------


class TestSetWebhookUrl:
    """PUT /agents/{address}/webhook endpoint tests."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_set_webhook_url(self, _mock_ip, client, registered_agent):
        """Valid HTTPS URL sets the webhook and returns 200."""
        address = registered_agent["address"]
        resp = client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "https://example.com/hook"},
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["address"] == address
        assert data["webhook_url"] == "https://example.com/hook"

    def test_set_webhook_rejects_http(self, client, registered_agent):
        """HTTP URL returns 400."""
        address = registered_agent["address"]
        resp = client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "http://example.com/hook"},
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 400

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=False)
    def test_set_webhook_rejects_private_ip(self, _mock_ip, client, registered_agent):
        """URL resolving to private IP returns 400."""
        address = registered_agent["address"]
        resp = client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "https://internal.corp/hook"},
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 400

    def test_set_webhook_requires_auth(self, client, registered_agent):
        """No Bearer token returns 401/403."""
        address = registered_agent["address"]
        resp = client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "https://example.com/hook"},
        )
        assert resp.status_code in (401, 403)

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_set_webhook_only_own_address(self, _mock_ip, client, registered_agent_pair):
        """Agent A cannot set webhook for agent B (403)."""
        alice, bob = registered_agent_pair
        resp = client.put(
            f"/api/v1/agents/{bob['address']}/webhook",
            json={"webhook_url": "https://example.com/hook"},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /agents/{address}/webhook
# ---------------------------------------------------------------------------


class TestDeleteWebhookUrl:
    """DELETE /agents/{address}/webhook endpoint tests."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_delete_webhook_url(self, _mock_ip, client, registered_agent):
        """Deleting a webhook returns 200 with webhook_url=None."""
        address = registered_agent["address"]

        # First set a webhook
        client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "https://example.com/hook"},
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )

        # Then delete it
        resp = client.delete(
            f"/api/v1/agents/{address}/webhook",
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_url"] is None

    def test_delete_webhook_requires_auth(self, client, registered_agent):
        """DELETE without auth returns 401/403."""
        address = registered_agent["address"]
        resp = client.delete(f"/api/v1/agents/{address}/webhook")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /agents/{address}/webhook
# ---------------------------------------------------------------------------


class TestGetWebhookUrl:
    """GET /agents/{address}/webhook endpoint tests."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_get_webhook_url(self, _mock_ip, client, registered_agent):
        """GET returns the current webhook URL after it was set."""
        address = registered_agent["address"]

        # Set the URL first
        client.put(
            f"/api/v1/agents/{address}/webhook",
            json={"webhook_url": "https://example.com/hook"},
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )

        # Get it back
        resp = client.get(
            f"/api/v1/agents/{address}/webhook",
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_url"] == "https://example.com/hook"

    def test_get_webhook_url_none(self, client, registered_agent):
        """GET with no webhook set returns webhook_url=None."""
        address = registered_agent["address"]
        resp = client.get(
            f"/api/v1/agents/{address}/webhook",
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["webhook_url"] is None


# ---------------------------------------------------------------------------
# GET /agents/{address}/webhook/deliveries
# ---------------------------------------------------------------------------


class TestGetWebhookDeliveries:
    """GET /agents/{address}/webhook/deliveries endpoint tests."""

    def test_get_deliveries_empty(self, client, registered_agent):
        """No deliveries returns empty list."""
        address = registered_agent["address"]
        resp = client.get(
            f"/api/v1/agents/{address}/webhook/deliveries",
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deliveries"] == []
        assert data["count"] == 0

    def test_get_deliveries_requires_auth(self, client, registered_agent):
        """GET deliveries without auth returns 401/403."""
        address = registered_agent["address"]
        resp = client.get(
            f"/api/v1/agents/{address}/webhook/deliveries",
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Webhook URL on registration
# ---------------------------------------------------------------------------


class TestRegisterWithWebhookUrl:
    """POST /api/v1/register with optional webhook_url."""

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_register_with_webhook_url(self, _mock_ip, client):
        """Registration with valid webhook_url stores it."""
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)

        resp = client.post(
            "/api/v1/register",
            json={
                "agent_name": "webhookbot",
                "public_key": pk_str,
                "webhook_url": "https://hooks.example.com/uam",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        address = data["address"]
        token = data["token"]

        # Verify webhook was stored via GET endpoint
        get_resp = client.get(
            f"/api/v1/agents/{address}/webhook",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["webhook_url"] == "https://hooks.example.com/uam"

    def test_register_with_invalid_webhook_url(self, client):
        """Registration with HTTP webhook_url returns 400."""
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)

        resp = client.post(
            "/api/v1/register",
            json={
                "agent_name": "badbot",
                "public_key": pk_str,
                "webhook_url": "http://example.com/hook",
            },
        )
        assert resp.status_code == 400

    def test_register_without_webhook_url(self, client):
        """Registration without webhook_url works (backward compatible)."""
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)

        resp = client.post(
            "/api/v1/register",
            json={
                "agent_name": "plainbot",
                "public_key": pk_str,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        address = data["address"]
        token = data["token"]

        # Verify no webhook set
        get_resp = client.get(
            f"/api/v1/agents/{address}/webhook",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["webhook_url"] is None
