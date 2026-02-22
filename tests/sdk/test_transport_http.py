"""Tests for HTTPTransport against a real relay via ASGI transport."""

from __future__ import annotations

import pytest
import httpx as httpx_lib

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.sdk.transport.http import HTTPTransport


async def _register_agent_async(relay_app, name: str) -> tuple:
    """Register an agent using async ASGI transport."""
    sk, vk = generate_keypair()
    async with httpx_lib.AsyncClient(
        transport=httpx_lib.ASGITransport(app=relay_app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(
            "/api/v1/register",
            json={
                "agent_name": name,
                "public_key": serialize_verify_key(vk),
            },
        )
        assert resp.status_code == 200
        agent_data = resp.json()
    return agent_data, sk, vk


@pytest.fixture()
async def http_transport(relay_app):
    """Create an HTTPTransport wired to the test relay via ASGI transport.

    Registers an agent, then creates an HTTP transport that uses
    httpx's ASGITransport to talk directly to the in-process relay.
    """
    agent_data, sk, vk = await _register_agent_async(relay_app, "sdktest")

    transport = HTTPTransport(
        relay_url="http://testserver",
        token=agent_data["token"],
        address=agent_data["address"],
    )

    # Override the httpx client to use ASGI transport (in-process)
    transport._client = httpx_lib.AsyncClient(
        transport=httpx_lib.ASGITransport(app=relay_app),
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {agent_data['token']}"},
        timeout=30.0,
    )

    yield transport, agent_data, sk, vk
    await transport.disconnect()


class TestHTTPTransport:
    """HTTP transport send/receive via real relay."""

    async def test_http_send_envelope(self, http_transport):
        transport, agent, sk, vk = http_transport

        # Create a valid signed envelope (self-send for simplicity)
        envelope = create_envelope(
            from_address=agent["address"],
            to_address=agent["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hello from SDK test!",
            signing_key=sk,
            recipient_verify_key=vk,
        )
        wire = to_wire_dict(envelope)

        # Send should succeed without raising
        await transport.send(wire)

    async def test_http_receive_messages(self, http_transport):
        transport, agent, sk, vk = http_transport

        # Send a message first
        envelope = create_envelope(
            from_address=agent["address"],
            to_address=agent["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Test inbox fetch",
            signing_key=sk,
            recipient_verify_key=vk,
        )
        wire = to_wire_dict(envelope)
        await transport.send(wire)

        # Receive should return the message
        messages = await transport.receive()
        assert len(messages) == 1
        assert messages[0]["from"] == agent["address"]

    async def test_http_receive_empty_inbox(self, http_transport):
        transport, agent, sk, vk = http_transport

        messages = await transport.receive()
        assert messages == []

    async def test_http_listen_raises(self, http_transport):
        transport, agent, sk, vk = http_transport

        with pytest.raises(NotImplementedError, match="HTTP transport does not support"):
            await transport.listen(lambda msg: None)
