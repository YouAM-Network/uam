"""An agent keeps its address across restarts.

The relay chooses the domain, and it need not match the relay's hostname:
``relay.youam.network`` hands out ``name::youam.network``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from uam.protocol import UAMError, generate_keypair, serialize_verify_key
from uam.relay.app import create_app
from uam.sdk.agent import Agent


@pytest.fixture()
def relay(tmp_path, monkeypatch):
    """A real relay, with the SDK's HTTP calls routed into it."""
    monkeypatch.setenv("UAM_DB_PATH", str(tmp_path / "relay.db"))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    with TestClient(create_app()) as client:
        # The relay reads this; an SDK on another machine would not have it.
        monkeypatch.delenv("UAM_RELAY_DOMAIN")

        def forward(request: httpx.Request) -> httpx.Response:
            resp = client.request(
                request.method,
                request.url.raw_path.decode(),
                headers=dict(request.headers),
                content=request.content,
            )
            return httpx.Response(
                resp.status_code,
                content=resp.content,
                headers={"content-type": resp.headers.get("content-type", "")},
            )

        class RoutedClient(httpx.AsyncClient):
            def __init__(self, **kwargs):
                super().__init__(transport=httpx.MockTransport(forward), **kwargs)

        with patch("httpx.AsyncClient", RoutedClient):
            yield client


def _agent(tmp_path: Path, name: str = "bob", **options) -> Agent:
    return Agent(
        name, relay="http://testserver", key_dir=str(tmp_path / "keys"), transport="http",
        **options,
    )


async def _first_run(tmp_path: Path) -> str:
    agent = _agent(tmp_path)
    await agent.connect()
    address = agent.address
    await agent.close()
    assert address == "bob::test.local"
    return address


async def test_a_restarted_agent_keeps_its_address_and_inbox(relay, tmp_path):
    address = await _first_run(tmp_path)

    agent = _agent(tmp_path)
    await agent.connect()
    try:
        assert agent.address == address
        assert await agent.inbox() == []
    finally:
        await agent.close()


async def test_an_agent_with_only_a_saved_token_gets_its_address_from_the_relay(
    relay, tmp_path
):
    """Tokens saved by earlier versions have no address beside them."""
    address = await _first_run(tmp_path)
    saved = tmp_path / "keys" / "bob.address"
    saved.unlink()

    agent = _agent(tmp_path)
    await agent.connect()
    try:
        assert agent.address == address
        assert await agent.inbox() == []
    finally:
        await agent.close()
    assert json.loads(saved.read_text()) == {
        "address": address,
        "relay_url": "http://testserver",
    }


async def test_a_relay_that_cannot_say_its_domain_leaves_the_configured_one(tmp_path):
    agent = _agent(tmp_path)
    agent._key_manager.save_token("bob", "a-token")
    agent._fetch_relay_domain = AsyncMock(return_value=None)
    with patch("uam.sdk.agent.create_transport", return_value=AsyncMock()):
        await agent.connect()
    try:
        assert agent.address == "bob::testserver"
    finally:
        await agent.close()
    assert not (tmp_path / "keys" / "bob.address").exists()


async def test_contacts_on_the_same_relay_are_looked_up_on_the_relay(relay, tmp_path):
    _, alice_vk = generate_keypair()
    public_key = serialize_verify_key(alice_vk)
    alice = relay.post(
        "/api/v1/register", json={"agent_name": "alice", "public_key": public_key}
    ).json()

    await _first_run(tmp_path)
    agent = _agent(tmp_path)
    await agent.connect()
    try:
        found = await agent._resolver.resolve_public_key(
            alice["address"], agent._token, agent._config.relay_url
        )
    finally:
        await agent.close()
    assert found == public_key


async def test_an_agent_that_lost_its_token_recovers_with_its_key(relay, tmp_path):
    address = await _first_run(tmp_path)
    (tmp_path / "keys" / "bob.token").unlink()
    (tmp_path / "keys" / "bob.address").unlink()

    # "testserver" doesn't fit test.local, so the agent has to say it expects it.
    agent = _agent(tmp_path, domain="test.local")
    await agent.connect()
    try:
        assert agent.address == address
        assert await agent.inbox() == []
    finally:
        await agent.close()


async def test_someone_elses_key_cannot_take_a_name(relay, tmp_path):
    await _first_run(tmp_path)

    other = _agent(tmp_path / "other", domain="test.local")
    with pytest.raises(UAMError, match="already registered"):
        await other.connect()


async def test_a_saved_address_from_another_relay_is_not_used(relay, tmp_path):
    address = await _first_run(tmp_path)
    saved = tmp_path / "keys" / "bob.address"
    saved.write_text(json.dumps({"address": "bob::old.example", "relay_url": "https://old"}))

    agent = _agent(tmp_path, domain="test.local")
    await agent.connect()
    try:
        assert agent.address == address
    finally:
        await agent.close()
    assert json.loads(saved.read_text())["address"] == address


@pytest.mark.parametrize("junk", ["", "not json", "[]", '{"address": 1}', "bob::plain.text"])
async def test_a_damaged_saved_address_is_ignored(relay, tmp_path, junk):
    address = await _first_run(tmp_path)
    (tmp_path / "keys" / "bob.address").write_text(junk)

    agent = _agent(tmp_path)
    await agent.connect()
    try:
        assert agent.address == address
    finally:
        await agent.close()


async def test_a_trailing_slash_on_the_relay_url_is_the_same_relay(relay, tmp_path):
    address = await _first_run(tmp_path)
    saved = tmp_path / "keys" / "bob.address"
    saved.write_text(json.dumps({"address": address, "relay_url": "http://testserver/"}))

    agent = _agent(tmp_path)
    agent._fetch_relay_domain = AsyncMock(return_value=None)
    await agent.connect()
    try:
        assert agent.address == address
    finally:
        await agent.close()
    agent._fetch_relay_domain.assert_not_awaited()


async def test_an_explicit_domain_beats_a_saved_address(tmp_path):
    agent = Agent(
        "bob",
        relay="http://testserver",
        key_dir=str(tmp_path / "keys"),
        transport="http",
        domain="chosen.example",
    )
    agent._key_manager.save_token("bob", "a-token")
    agent._key_manager.save_address("bob", "bob::stale.example", "http://testserver")
    agent._fetch_relay_domain = AsyncMock(return_value="other.example")
    with patch("uam.sdk.agent.create_transport", return_value=AsyncMock()):
        await agent.connect()
    try:
        assert agent.address == "bob::chosen.example"
    finally:
        await agent.close()
    agent._fetch_relay_domain.assert_not_awaited()


async def test_a_read_only_key_folder_does_not_stop_an_upgrade(tmp_path):
    agent = _agent(tmp_path)
    agent._key_manager.save_token("bob", "a-token")
    agent._fetch_relay_domain = AsyncMock(return_value="youam.network")
    with (
        patch("uam.sdk.agent.create_transport", return_value=AsyncMock()),
        patch.object(
            agent._key_manager, "save_address", side_effect=PermissionError("read only")
        ),
    ):
        await agent.connect()
    try:
        assert agent.address == "bob::youam.network"
    finally:
        await agent.close()


@pytest.mark.parametrize("answer", [{"relay_domain": ""}, {"relay_domain": 7}, {}, []])
async def test_a_bad_answer_about_the_domain_counts_as_no_answer(tmp_path, answer):
    def reply(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/uam-relay.json"
        return httpx.Response(200, json=answer)

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(reply), **kwargs)

    agent = Agent(
        "bob", relay="http://testserver/", key_dir=str(tmp_path / "keys"), transport="http"
    )
    with patch("httpx.AsyncClient", Client):
        assert await agent._fetch_relay_domain() is None


async def test_one_bad_message_does_not_lose_the_batch(tmp_path):
    agent = _agent(tmp_path)
    agent._key_manager.save_token("bob", "a-token")
    agent._key_manager.save_address("bob", "bob::test.local", "http://testserver")
    transport = AsyncMock()
    transport.receive.return_value = [{"message_id": "bad"}, {"message_id": "good"}]
    good = AsyncMock(message_id="good", type="handshake.accept")

    async def process(raw):
        if raw["message_id"] == "bad":
            raise UAMError("bad handshake")
        return good

    with patch("uam.sdk.agent.create_transport", return_value=transport):
        await agent.connect()
    agent._process_inbound = process
    agent._send_read_receipt = AsyncMock()
    try:
        assert await agent.inbox() == [good]
    finally:
        await agent.close()


async def test_a_token_is_not_offered_to_a_different_relay(relay, tmp_path):
    """The saved address says which relay the saved token belongs to."""
    await _first_run(tmp_path)
    token = (tmp_path / "keys" / "bob.token").read_text()

    elsewhere = Agent(
        "bob",
        relay="https://elsewhere.example",
        key_dir=str(tmp_path / "keys"),
        transport="http",
        auto_register=False,
    )
    with pytest.raises(UAMError, match="No stored token"):
        await elsewhere.connect()
    assert elsewhere._token != token
