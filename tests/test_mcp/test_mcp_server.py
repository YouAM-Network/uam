"""Tests for the UAM MCP server tools (MCP-01 through MCP-04).

Tests call the MCP tool functions directly (not via MCP transport)
with real Agent instances talking to an in-process relay via ASGI.
This validates the full stack: tool function -> Agent -> relay -> crypto.

Phase 48 (Q9): All tools now return ``{"ok": True, "data": ...}`` or
``{"ok": False, "error": {"code": ..., "message": ...}}`` dicts (never
prose strings). The legacy ``_safe_error`` helper has been replaced by
``_error_envelope`` + ``_error_code``. Existing assertions updated to
match the new envelope shape.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from uam.mcp import server as mcp_server
from uam.mcp.server import (
    NotConfiguredError,
    _error_code,
    _error_envelope,
    _ok_envelope,
    create_server,
)
from uam.protocol.contact import contact_card_from_dict
from uam.relay.app import create_app
from uam.sdk.agent import Agent
from uam.sdk.transport import create_transport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def relay_app(tmp_path):
    """Create a relay app with lifespan triggered via TestClient."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "relay.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_RELAY_HTTP_URL"] = "http://testserver"
    os.environ["UAM_RELAY_WS_URL"] = "ws://testserver/ws"
    app = create_app()
    with TestClient(app):
        yield app
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_RELAY_HTTP_URL", None)
    os.environ.pop("UAM_RELAY_WS_URL", None)


async def _make_agent(relay_app, tmp_path, name: str) -> Agent:
    """Create, register, and connect an Agent against the in-process relay.

    Patches:
      - HTTPTransport._client to use ASGI transport (with auth headers)
      - Resolver to use ASGI transport for public key lookups
    """
    key_dir = tmp_path / name / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    data_dir = tmp_path / name
    data_dir.mkdir(parents=True, exist_ok=True)

    agent = Agent(
        name,
        relay="http://testserver",
        key_dir=str(key_dir),
        display_name=name.capitalize(),
        transport="http",
        trust_policy="auto-accept",
    )
    # Override data_dir to isolate contact book per test (avoid ~/.uam collisions)
    agent._config.data_dir = data_dir
    # Recreate contact book with isolated data_dir
    from uam.sdk.contact_book import ContactBook

    agent._contact_book = ContactBook(data_dir)
    # Load or generate keypair (needed before accessing public_key)
    agent._key_manager.load_or_generate(name)

    # Register via ASGI transport
    asgi_transport = httpx.ASGITransport(app=relay_app)
    async with httpx.AsyncClient(
        transport=asgi_transport,
        base_url="http://testserver",
    ) as client:
        resp = await client.post(
            "/api/v1/register",
            json={
                "agent_name": name,
                "public_key": agent.public_key,
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        agent._address = data["address"]
        agent._token = data["token"]
        agent._key_manager.save_token(name, data["token"])

    # Create transport and connect (this creates a default httpx client)
    agent._transport = create_transport(agent._config, agent._token, agent._address)
    # Replace the transport's client with an ASGI-backed one that has auth headers
    agent._transport._client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=relay_app),
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {agent._token}"},
        timeout=30.0,
    )

    # Patch the resolver to use ASGI transport for key lookups
    original_resolve = agent._resolver.resolve_public_key

    async def _asgi_resolve(address: str, token: str, relay_url: str) -> str:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=relay_app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(
                f"/api/v1/agents/{address}/public-key",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code == 404:
                from uam.protocol import UAMError

                raise UAMError(f"Agent not found: {address}")
            resp.raise_for_status()
            return resp.json()["public_key"]

    agent._resolver.resolve_public_key = _asgi_resolve

    # Open contact book
    await agent._contact_book.open()
    agent._connected = True
    return agent


# ---------------------------------------------------------------------------
# Tests: uam_send (MCP-01)
# ---------------------------------------------------------------------------


class TestUamSend:
    """MCP-01: uam_send tool delivers encrypted messages through the relay."""

    async def test_uam_send_delivers_message(self, relay_app, tmp_path):
        """Send via MCP tool and verify message arrives in receiver's inbox."""
        sender = await _make_agent(relay_app, tmp_path, "alice")
        receiver = await _make_agent(relay_app, tmp_path, "bob")

        # Patch the module-level agent to be the sender
        with patch.object(mcp_server, "_agent", sender):
            result = await mcp_server.uam_send(
                to_address=receiver.address,
                message="Hello from MCP!",
            )

        # Phase 48 Q9: success envelope shape.
        assert isinstance(result, dict)
        assert result["ok"] is True
        assert "data" in result
        assert "message_id" in result["data"]
        assert isinstance(result["data"]["message_id"], str)

        # Verify receiver got the message
        messages = await receiver.inbox()
        assert len(messages) >= 1
        assert messages[0].content == "Hello from MCP!"
        assert messages[0].from_address == sender.address

        await sender.close()
        await receiver.close()

    async def test_uam_send_returns_error_on_invalid_address(
        self, relay_app, tmp_path
    ):
        """Phase 48 Q9: malformed/unresolvable address yields an error envelope.

        The SDK currently raises a generic ``UAMError`` for both shape
        validation failures and resolver "agent not found" lookups, which
        both map to the catch-all ``"internal_error"`` code via MRO walk.
        Assert the envelope shape is correct and the code is one of the
        expected stable codes -- typed-error refinement (e.g. raising
        InvalidAddressError specifically for shape violations) is tracked
        for a future plan (Q1 follow-up).
        """
        sender = await _make_agent(relay_app, tmp_path, "errbot")

        with patch.object(mcp_server, "_agent", sender):
            result = await mcp_server.uam_send(
                to_address="no-domain",
                message="This should fail",
            )

        assert isinstance(result, dict)
        assert result["ok"] is False
        assert "error" in result
        # Stable code from the canonical mapping table (mirrors
        # uam.relay.exception_handlers status map). Until the SDK uses
        # typed exceptions consistently, the catch-all code is acceptable.
        assert result["error"]["code"] in {
            "invalid_address",
            "validation_error",
            "internal_error",
        }
        assert "message" in result["error"]
        assert isinstance(result["error"]["message"], str)
        # No prose-string fallback path -- ensure the entire result is dict-shaped.
        assert "ok" in result and isinstance(result["ok"], bool)

        await sender.close()


# ---------------------------------------------------------------------------
# Tests: uam_inbox (MCP-02)
# ---------------------------------------------------------------------------


class TestUamInbox:
    """MCP-02: uam_inbox tool retrieves and formats pending messages."""

    async def test_uam_inbox_returns_messages(self, relay_app, tmp_path):
        """Messages sent via Agent appear formatted in uam_inbox output."""
        sender = await _make_agent(relay_app, tmp_path, "carol")
        receiver = await _make_agent(relay_app, tmp_path, "dave")

        # Send a message directly via the sender agent
        await sender.send(receiver.address, "MCP inbox test message")

        # Now call uam_inbox as if we are the receiver
        with patch.object(mcp_server, "_agent", receiver):
            result = await mcp_server.uam_inbox(limit=50)

        # Phase 48 Q9: success envelope shape with structured message dicts.
        assert isinstance(result, dict)
        assert result["ok"] is True
        assert "data" in result
        assert isinstance(result["data"], list)
        assert len(result["data"]) >= 1
        first = result["data"][0]
        assert first["from_address"] == sender.address
        assert first["content"] == "MCP inbox test message"
        assert "message_id" in first
        assert "timestamp" in first
        assert "verified" in first

        await sender.close()
        await receiver.close()

    async def test_uam_inbox_empty(self, relay_app, tmp_path):
        """Phase 48 Q9: empty inbox returns ``{"ok": True, "data": []}``."""
        agent = await _make_agent(relay_app, tmp_path, "emptybot")

        with patch.object(mcp_server, "_agent", agent):
            result = await mcp_server.uam_inbox()

        assert isinstance(result, dict)
        assert result["ok"] is True
        assert result["data"] == []

        await agent.close()


# ---------------------------------------------------------------------------
# Tests: uam_contact_card (MCP-03)
# ---------------------------------------------------------------------------


class TestUamContactCard:
    """MCP-03: uam_contact_card tool returns a valid signed contact card."""

    async def test_uam_contact_card_returns_valid_json(self, relay_app, tmp_path):
        """Phase 48 Q9: contact card lives under ``data`` in the success envelope."""
        agent = await _make_agent(relay_app, tmp_path, "cardbot")

        with patch.object(mcp_server, "_agent", agent):
            result = await mcp_server.uam_contact_card()

        assert isinstance(result, dict)
        assert result["ok"] is True
        card = result["data"]
        assert "version" in card
        assert "address" in card
        assert "display_name" in card
        assert "relay" in card
        assert "public_key" in card
        assert "signature" in card
        assert card["address"] == agent.address

        await agent.close()

    async def test_uam_contact_card_signature_valid(self, relay_app, tmp_path):
        """Contact card signature verifies using the embedded public key."""
        agent = await _make_agent(relay_app, tmp_path, "sigbot")

        with patch.object(mcp_server, "_agent", agent):
            result = await mcp_server.uam_contact_card()

        # Phase 48 Q9: card dict is now under result["data"], not json.loads(result).
        assert result["ok"] is True
        card_dict = result["data"]
        # contact_card_from_dict with verify=True raises if signature is bad
        card = contact_card_from_dict(card_dict, verify=True)
        assert card.address == agent.address

        await agent.close()


# ---------------------------------------------------------------------------
# Tests: create_server (registration)
# ---------------------------------------------------------------------------


class TestCreateServer:
    """Verify create_server() registers all three tools on the FastMCP instance."""

    async def test_create_server_registers_all_tools(self):
        """FastMCP instance has uam_send, uam_inbox, uam_contact_card."""
        server = create_server()
        tools = await server.list_tools()
        tool_names = {t.name for t in tools}
        assert "uam_send" in tool_names
        assert "uam_inbox" in tool_names
        assert "uam_contact_card" in tool_names


# ---------------------------------------------------------------------------
# Tests: error envelope helpers (Phase 48 Q9)
# ---------------------------------------------------------------------------


class TestErrorEnvelope:
    """Structured error envelope replaces the legacy ``_safe_error`` prose helper.

    Phase 48 Q9 -- error codes mirror ``uam.relay.exception_handlers``
    so MCP and HTTP surfaces report the same code for the same exception.
    Stable codes are part of the contract; LLM clients match on them.
    """

    def test_uam_error_maps_to_internal_error(self):
        """Unmapped UAMError subclasses return the catch-all code."""
        from uam.protocol import UAMError

        env = _error_envelope(UAMError("Agent not found: bob::test.local"))
        assert env["ok"] is False
        assert env["error"]["code"] == "internal_error"
        # Message is preserved for diagnostic visibility.
        assert "Agent not found" in env["error"]["message"]

    def test_invalid_address_error_maps_to_invalid_address(self):
        """Mapped subclass yields its stable code (mirrors HTTP map)."""
        from uam.protocol.errors import InvalidAddressError

        assert _error_code(InvalidAddressError("bad")) == "invalid_address"

    def test_validation_error_maps_to_validation_error(self):
        """ValidationError -> ``validation_error`` (matches HTTP 400 map)."""
        from uam.protocol.errors import ValidationError

        assert _error_code(ValidationError("bad input")) == "validation_error"

    def test_signature_verification_error_maps_to_signature_invalid(self):
        """SignatureVerificationError -> ``signature_invalid``."""
        from uam.protocol.errors import SignatureVerificationError

        assert _error_code(SignatureVerificationError("bad sig")) == "signature_invalid"

    def test_not_configured_error_maps_to_not_configured(self):
        """MCP-only NotConfiguredError -> ``not_configured`` code."""
        assert _error_code(NotConfiguredError("UAM_AGENT_NAME unset")) == "not_configured"

    def test_connection_error_maps_to_network_error(self):
        """Stdlib ConnectionError -> ``network_error`` (transport class)."""
        assert _error_code(ConnectionError("relay unreachable")) == "network_error"

    def test_unknown_exception_maps_to_internal_error(self):
        """Anything not in the map degrades to ``internal_error``."""
        assert _error_code(RuntimeError("surprise")) == "internal_error"

    def test_envelope_message_is_str_not_traceback(self):
        """T-48-08-01: only ``str(exc)`` leaks to the client; never a traceback."""
        try:
            raise ValueError("boom")
        except ValueError as exc:
            env = _error_envelope(exc)
        assert env["error"]["message"] == "boom"
        assert "Traceback" not in env["error"]["message"]

    def test_ok_envelope_round_trip(self):
        """``_ok_envelope(payload)`` produces ``{ok: True, data: payload}``."""
        env = _ok_envelope({"hello": "world"})
        assert env == {"ok": True, "data": {"hello": "world"}}
