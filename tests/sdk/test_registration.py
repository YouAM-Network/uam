"""Tests for Agent registration flow and constructor behavior."""

from __future__ import annotations

import pytest

from uam.protocol import generate_keypair, serialize_verify_key
from uam.sdk.agent import Agent
from uam.sdk.key_manager import KeyManager


class TestAgentConstructor:
    """Agent constructor is instant (no I/O)."""

    def test_agent_constructor_instant(self):
        agent = Agent("test")
        assert agent.is_connected is False

    def test_agent_address_raises_before_connect(self):
        agent = Agent("test")
        with pytest.raises(RuntimeError, match="not yet connected"):
            _ = agent.address

    def test_agent_has_async_context_manager(self):
        agent = Agent("test")
        assert hasattr(agent, "__aenter__")
        assert hasattr(agent, "__aexit__")

    def test_agent_config_params(self, tmp_path):
        agent = Agent(
            "mybot",
            relay="http://localhost:9000",
            key_dir=str(tmp_path / "keys"),
            display_name="My Bot",
            transport="http",
            trust_policy="approval-required",
        )
        assert agent._config.name == "mybot"
        assert agent._config.relay_url == "http://localhost:9000"
        assert agent._config.display_name == "My Bot"
        assert agent._config.transport_type == "http"
        assert agent._config.trust_policy == "approval-required"

    async def test_send_requires_connection(self):
        """send() triggers connect(), which fails without auto_register."""
        from uam.protocol.errors import UAMError

        agent = Agent("test", auto_register=False)
        with pytest.raises(UAMError, match="No stored token"):
            await agent.send("addr::test.local", "msg")

    async def test_inbox_requires_connection(self):
        """inbox() triggers connect(), which fails without auto_register."""
        from uam.protocol.errors import UAMError

        agent = Agent("test", auto_register=False)
        with pytest.raises(UAMError, match="No stored token"):
            await agent.inbox()


class TestRegistrationFlow:
    """Registration via real relay."""

    def test_register_new_agent(self, relay_client):
        """Verify the relay register endpoint works for SDK flow."""
        sk, vk = generate_keypair()
        resp = relay_client.post(
            "/api/v1/register",
            json={
                "agent_name": "sdkagent",
                "public_key": serialize_verify_key(vk),
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "address" in data
        assert "token" in data
        assert data["address"] == "sdkagent::test.local"

    def test_register_same_key_returns_existing(self, relay_client):
        """Re-registration with same public key returns existing credentials."""
        sk, vk = generate_keypair()
        pk = serialize_verify_key(vk)
        resp1 = relay_client.post(
            "/api/v1/register",
            json={"agent_name": "dupebot", "public_key": pk},
        )
        assert resp1.status_code == 200
        resp2 = relay_client.post(
            "/api/v1/register",
            json={"agent_name": "dupebot", "public_key": pk},
        )
        assert resp2.status_code == 200
        assert resp2.json()["token"] == resp1.json()["token"]

    def test_register_different_key_returns_409(self, relay_client):
        """Re-registration with different public key returns 409."""
        sk1, vk1 = generate_keypair()
        sk2, vk2 = generate_keypair()
        relay_client.post(
            "/api/v1/register",
            json={"agent_name": "dupebot2", "public_key": serialize_verify_key(vk1)},
        )
        resp = relay_client.post(
            "/api/v1/register",
            json={"agent_name": "dupebot2", "public_key": serialize_verify_key(vk2)},
        )
        assert resp.status_code == 409

    def test_key_manager_stores_token(self, key_dir, relay_client):
        """KeyManager can persist and reload tokens for returning user flow."""
        # Simulate registration
        sk, vk = generate_keypair()
        resp = relay_client.post(
            "/api/v1/register",
            json={
                "agent_name": "persist",
                "public_key": serialize_verify_key(vk),
            },
        )
        token = resp.json()["token"]

        # Save and reload
        km = KeyManager(key_dir)
        km.save_token("persist", token)

        km2 = KeyManager(key_dir)
        loaded = km2.load_token("persist")
        assert loaded == token
