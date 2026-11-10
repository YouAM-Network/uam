"""The agent's side of linking, end to end (P2d-2).

A real relay with owners on; the SDK's and CLI's HTTP calls are routed
into it, and the owner approves on the owner origin with a soft passkey.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_links import (  # noqa: F401
    _approve,
    _approve_start,
    _code,
    _links,
    ada,
)
from uam.cli import main as cli_main
from uam.cli.main import cli
from uam.protocol import UAMError
from uam.protocol.links import _when, words_for
from uam.protocol.signed import parse_body
from uam.sdk.agent import Agent


def _forwarding(client):
    def forward(request: httpx.Request) -> httpx.Response:
        resp = client.request(
            request.method, request.url.raw_path.decode(),
            headers=dict(request.headers), content=request.content,
        )
        return httpx.Response(
            resp.status_code, content=resp.content,
            headers={"content-type": resp.headers.get("content-type", "")},
        )

    class RoutedClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(forward), **kwargs)

    return patch("httpx.AsyncClient", RoutedClient)


@pytest.fixture()
def routed(relay, tmp_path, monkeypatch):
    """The SDK and CLI talk to the test relay; their files live in tmp."""
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("UAM_RELAY_URL", "http://testserver")
    # Only HTTP is routed into the test relay, so the CLI's agents use it.
    real = cli_main.Agent
    monkeypatch.setattr(cli_main, "Agent", lambda *a, **k: real(*a, **{**k, "transport": "http"}))
    with _forwarding(relay):
        yield relay


def _agent(tmp_path: Path, name="bob") -> Agent:
    return Agent(name, relay="http://testserver", key_dir=str(tmp_path / "keys"), transport="http")


# ---------------------------------------------------------------- SDK


async def test_the_sdk_redeems_checks_and_signs(ada, routed, tmp_path):
    code = _code(ada)
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        offer = await bob.start_owner_link(code, via="setup")
        assert offer.account == "a•••@example.com"
        assert offer.words == words_for(offer.body["agentKey"])
        assert offer.body["agent"] == bob.address
        await bob.sign_owner_link(offer)
        status = await bob.owner_link_status()
        assert status["state"] == "waiting_for_owner"
        assert status["words"] == offer.words
    finally:
        await bob.close()
    [link] = _links(ada)
    assert link["state"] == "waiting" and link["agent"] == "bob::test.local"


async def test_the_sdk_will_not_sign_a_link_that_starts_at_the_wrong_time(
    ada, routed, tmp_path, monkeypatch
):
    from uam.relay.owners import links

    monkeypatch.setattr(links, "LINK_DELAY", links.LINK_DELAY / 2)
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        with pytest.raises(UAMError, match="wrong time"):
            await bob.start_owner_link(_code(ada, "link"), via="link")
        assert (await bob.owner_link_status())["state"] == "waiting_for_agent"
    finally:
        await bob.close()
    assert _links(ada) == []


async def test_a_wrong_code_says_so(ada, routed, tmp_path):
    bob = _agent(tmp_path)
    await bob.connect()
    try:
        with pytest.raises(UAMError, match="didn't work"):
            await bob.start_owner_link("AAAA-AAAA", via="setup")
    finally:
        await bob.close()


async def test_connecting_shows_a_waiting_link(ada, routed, tmp_path, caplog):
    code = _code(ada)
    bob = _agent(tmp_path)
    await bob.connect()
    await bob.sign_owner_link(await bob.start_owner_link(code, via="setup"))
    await bob.close()

    again = _agent(tmp_path)
    with caplog.at_level(logging.WARNING, logger="uam.sdk.owner_link"):
        await again.connect()
    await again.close()
    assert again.owner_link["state"] == "waiting_for_owner"
    assert any("waiting for the owner" in r.getMessage() for r in caplog.records)


async def test_a_relay_without_owners_says_unavailable(app, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    with TestClient(app) as plain, _forwarding(plain):
        bob = _agent(tmp_path)
        await bob.connect()
        try:
            assert bob.owner_link == {"state": "unavailable"}
            with pytest.raises(UAMError, match="doesn't link agents"):
                await bob.start_owner_link("ABCD-EFGH", via="setup")
        finally:
            await bob.close()


# ---------------------------------------------------------------- CLI


def _rows_body(owner):
    [row] = _rows(owner, "SELECT body FROM owner_links")
    return row["body"]


@pytest.fixture()
def terminal(monkeypatch):
    monkeypatch.setattr(cli_main, "_stdin_is_terminal", lambda: True)


def _approving(ada):
    """A stand-in for the CLI's wait: the owner approves on the first tick."""
    calls = []

    async def tick(seconds):
        if not calls:
            [link] = [x for x in _links(ada) if x["state"] == "waiting"]
            assert _approve(ada, ada.phone, _approve_start(ada, link["id"])).status_code == 200
        calls.append(seconds)

    return tick


def test_uam_init_setup_links_a_new_agent(ada, routed, terminal, monkeypatch):
    monkeypatch.setattr(cli_main, "_sleep", _approving(ada))
    code = _code(ada)
    result = CliRunner().invoke(cli, ["init", "--setup"], input=f"{code}\nbob\n")
    assert result.exit_code == 0, result.output
    out = result.output
    assert "Initialized agent: bob::test.local" in out
    assert "Joining a•••@example.com" in out
    [link] = _links(ada)
    assert " ".join(link["words"]) in out
    assert "Linked to a•••@example.com." in out
    assert link["state"] == "active"


def test_uam_init_setup_needs_a_terminal(ada, routed):
    result = CliRunner().invoke(cli, ["init", "--setup"], input="ABCD-EFGH\nbob\n")
    assert result.exit_code != 0
    assert "terminal" in result.output
    assert _links(ada) == []


def test_uam_init_setup_is_for_a_new_agent(ada, routed, terminal):
    assert CliRunner().invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    result = CliRunner().invoke(cli, ["init", "--setup", "--name", "bob"], input=_code(ada) + "\n")
    assert result.exit_code != 0
    assert "already set up here" in result.output
    assert "uam owner link" in result.output


def test_uam_init_setup_stops_waiting_after_a_while(ada, routed, terminal, monkeypatch):
    async def tick(seconds):
        pass

    monkeypatch.setattr(cli_main, "_sleep", tick)
    monkeypatch.setattr(cli_main, "_OWNER_WAIT_TICKS", 3)
    result = CliRunner().invoke(cli, ["init", "--setup"], input=f"{_code(ada)}\nbob\n")
    assert result.exit_code == 0, result.output
    assert "uam owner status" in result.output
    assert _links(ada)[0]["state"] == "waiting"


def test_uam_owner_link_links_an_existing_agent_in_72_hours(ada, routed, terminal):
    assert CliRunner().invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    code = _code(ada, "link")
    result = CliRunner().invoke(cli, ["--name", "bob", "owner", "link"], input=code + "\n")
    assert result.exit_code == 0, result.output
    assert "Joining a•••@example.com" in result.output
    assert "72 hours from now" in result.output
    starts = parse_body(_rows_body(ada))["effectiveAt"]
    assert _when(starts) in result.output
    [link] = _links(ada)
    assert link["via"] == "link" and link["state"] == "waiting"
    assert " ".join(link["words"]) in result.output


def test_uam_owner_link_needs_a_terminal(ada, routed):
    assert CliRunner().invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    result = CliRunner().invoke(cli, ["--name", "bob", "owner", "link"], input="ABCD-EFGH\n")
    assert result.exit_code != 0
    assert "terminal" in result.output


def test_uam_owner_status(ada, routed, terminal):
    runner = CliRunner()
    assert runner.invoke(cli, ["init", "--name", "bob"]).exit_code == 0
    result = runner.invoke(cli, ["--name", "bob", "owner", "status"])
    assert result.exit_code == 0, result.output
    assert "not linked" in result.output
    runner.invoke(cli, ["--name", "bob", "owner", "link"], input=_code(ada, "link") + "\n")
    [link] = _links(ada)
    assert _approve(ada, ada.phone, _approve_start(ada, link["id"])).status_code == 200
    result = runner.invoke(cli, ["--name", "bob", "owner", "status"])
    assert "a•••@example.com" in result.output
    assert "starts on" in result.output
    assert result.output.count("starts on") == 1  # no second copy from the connect banner


def test_uam_init_asks_for_a_name_in_a_terminal(routed, terminal):
    result = CliRunner().invoke(cli, ["init"], input="carol\n")
    assert result.exit_code == 0, result.output
    assert "Initialized agent: carol::test.local" in result.output
