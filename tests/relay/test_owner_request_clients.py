"""The agent's side of asking for an owner by email, end to end (P2s-3).

A real relay with owners on; the SDK's, CLI's and MCP tools' HTTP calls
are routed into it. The owner accepts and approves on the owner origin
with a soft passkey. The agent signs its own accepted request without
asking, and nothing else.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from click.testing import CliRunner

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    EMAIL,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_link_clients import _agent, routed, terminal  # noqa: F401
from tests.relay.test_owner_links import _code, ada  # noqa: F401
from tests.relay.test_owner_requests import _approve, sent  # noqa: F401
from uam.cli import main as cli_main
from uam.cli.main import cli
from uam.protocol import UAMError
from uam.protocol.links import words_for
from uam.sdk import owner_link


def _accept(ada):
    [request] = ada.get("/api/owner/requests").json()["requests"]
    resp = ada.post(f"/api/owner/requests/{request['id']}/accept")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _waiting_link(ada):
    [link] = [x for x in ada.get("/api/owner/links").json()["links"] if x["state"] == "waiting"]
    return link


# ---------------------------------------------------------------- SDK


async def test_the_sdk_asks_then_signs_once_the_owner_accepts(ada, routed, sent, tmp_path):
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        asked = await bob.request_owner(EMAIL, watch=False)
        assert asked["words"] == words_for(_key(bob)) == sent[0][1]["words"]
        assert (await bob.check_owner_request())["request"]["state"] == "open"
        accepted = _accept(ada)
        status = await bob.check_owner_request()
        assert status["state"] == "waiting_for_owner"
        assert status["request"]["state"] == "waiting_for_you"
    finally:
        await bob.close()
    _, resp = _approve(ada, ada.phone, accepted["link"])
    assert resp.status_code == 200, resp.text


def _key(agent):
    from uam.protocol.didkey import ED25519, encode_did_key

    return encode_did_key(ED25519, bytes(agent._key_manager.verify_key))


async def test_the_sdk_signs_an_accepted_request_when_it_connects(
    ada, routed, sent, tmp_path, caplog, monkeypatch
):
    bob = _agent(tmp_path)
    await bob.connect()
    await bob.request_owner(EMAIL, watch=False)
    await bob.close()
    _accept(ada)

    again = _agent(tmp_path)
    # A CLI test earlier in the run sends this logger to its own banner handler
    # (propagate off, as each real command is its own process); undo that here.
    monkeypatch.setattr(logging.getLogger("uam.sdk.owner_link"), "propagate", True)
    with caplog.at_level(logging.WARNING, logger="uam.sdk.owner_link"):
        await again.connect()
    await again.close()
    assert again.owner_link["state"] == "waiting_for_owner"
    assert _waiting_link(ada)["agent"] == again.address
    assert any("waiting for the owner" in r.getMessage() for r in caplog.records)


async def test_the_sdk_watches_its_request_while_connected(
    ada, routed, sent, tmp_path, monkeypatch
):
    monkeypatch.setattr(owner_link, "REQUEST_POLL_FAST", 0.01)
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        await bob.request_owner(EMAIL)
        _accept(ada)
        for _ in range(200):
            await asyncio.sleep(0.01)
            if bob._owner_request_task.done():
                break
        assert bob._owner_request_task.done()
        assert bob.owner_link["request"]["state"] == "waiting_for_you"
    finally:
        await bob.close()


async def test_the_sdk_does_not_sign_a_link_it_did_not_ask_for(ada, routed, sent, tmp_path):
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        await bob.start_owner_link(_code(ada, "link"), via="link")  # checked, not signed
        status = await bob.check_owner_request()
        assert status["state"] == "waiting_for_agent"
        assert "request" not in status
    finally:
        await bob.close()


async def test_the_sdk_checks_the_offer_before_signing(ada, routed, sent, tmp_path, monkeypatch):
    from uam.relay.owners import links

    real = links._link_body

    def unshared(*args, **kwargs):
        return {**real(*args, **kwargs), "shared": False}

    monkeypatch.setattr(links, "_link_body", unshared)
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        await bob.request_owner(EMAIL, watch=False)
        _accept(ada)
        with pytest.raises(UAMError, match="isn't shared"):
            await bob.check_owner_request()
    finally:
        await bob.close()
    assert [x for x in ada.get("/api/owner/links").json()["links"]] == []


async def test_an_agent_with_an_owner_is_told_so(ada, routed, sent, tmp_path):
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        await bob.sign_owner_link(await bob.start_owner_link(_code(ada, "link"), via="link"))
        with pytest.raises(owner_link.OwnerLinkRefused) as refused:
            await bob.request_owner("nina@example.org")
        assert refused.value.code == "has_owner"
    finally:
        await bob.close()


# ---------------------------------------------------------------- CLI


def _owner_answers(ada):
    """The CLI's wait: the owner accepts on the first tick, approves on the second."""
    calls = []

    async def tick(seconds):
        if not calls:
            _accept(ada)
        elif len(calls) == 1:
            _, resp = _approve(ada, ada.phone, _waiting_link(ada)["id"])
            assert resp.status_code == 200, resp.text
        calls.append(seconds)

    return tick


def test_uam_owner_request(ada, routed, sent, terminal, monkeypatch):
    monkeypatch.setattr(cli_main, "_sleep", _owner_answers(ada))
    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    result = runner.invoke(cli, ["--name", "bob", "owner", "request", EMAIL])
    assert result.exit_code == 0, result.output
    assert f"Asked {EMAIL} to own bob::test.local." in result.output
    assert "Words: " + " ".join(sent[0][1]["words"]) in result.output
    assert "They accepted, and this agent signed." in result.output
    assert "Linked to a•••@example.com." in result.output


def test_uam_owner_request_says_when_it_is_declined(ada, routed, sent, terminal, monkeypatch):
    async def decline(seconds):
        [request] = ada.get("/api/owner/requests").json()["requests"]
        ada.post(f"/api/owner/requests/{request['id']}/decline", json={"block": False})

    monkeypatch.setattr(cli_main, "_sleep", decline)
    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    result = runner.invoke(cli, ["--name", "bob", "owner", "request", EMAIL])
    assert result.exit_code == 0, result.output
    assert "They declined." in result.output


def test_uam_owner_status_signs_an_accepted_request(ada, routed, sent, terminal, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    monkeypatch.setattr(cli_main, "_REQUEST_WAIT_TICKS", 0)
    result = runner.invoke(cli, ["--name", "bob", "owner", "request", EMAIL])
    assert "Still waiting for them." in result.output
    result = runner.invoke(cli, ["--name", "bob", "owner", "status"])
    assert "asked for an owner by email" in result.output
    _accept(ada)
    result = runner.invoke(cli, ["--name", "bob", "owner", "status"])
    assert "waiting for the owner to approve it" in result.output
    assert _waiting_link(ada)["agent"] == "bob::test.local"


# ---------------------------------------------------------------- MCP


async def test_the_mcp_tools_ask_and_report(ada, routed, sent, tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    from uam.mcp import server

    bob = _agent(tmp_path)
    await bob.connect()

    async def get_agent():
        return bob

    monkeypatch.setattr(server, "_get_agent", get_agent)
    try:
        asked = await server.uam_request_owner(EMAIL)
        assert asked["ok"] and asked["data"]["words"] == sent[0][1]["words"]
        bob._owner_request_task.cancel()
        _accept(ada)
        status = await server.uam_owner_status()
        assert status["ok"] and status["data"]["request"]["state"] == "waiting_for_you"
        assert "offer" not in status["data"]
        # Waiting for the owner isn't having one: it may ask someone else,
        # and the new request ends the old one and its link.
        assert (await server.uam_request_owner("nina@example.org"))["ok"]
        assert ada.get("/api/owner/links").json()["links"][0]["state"] == "cancelled"
    finally:
        await bob.close()


async def test_the_mcp_tool_says_has_owner(ada, routed, sent, tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    from uam.mcp import server

    bob = _agent(tmp_path)
    await bob.connect()
    await bob.sign_owner_link(await bob.start_owner_link(_code(ada, "link"), via="link"))

    async def get_agent():
        return bob

    monkeypatch.setattr(server, "_get_agent", get_agent)
    try:
        refused = await server.uam_request_owner("nina@example.org")
        assert refused["ok"] is False
        assert refused["error"]["code"] == "has_owner"
    finally:
        await bob.close()


def test_the_mcp_server_offers_the_owner_tools_but_no_approval():
    pytest.importorskip("mcp")
    from uam.mcp.server import create_server

    names = {t.name for t in asyncio.run(create_server().list_tools())}
    assert {"uam_request_owner", "uam_owner_status"} <= names
    assert not [n for n in names if "approve" in n]
