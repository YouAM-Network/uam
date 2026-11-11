"""Setting up a reserved name from the agent's side (P2s-2): the SDK and
`uam init --setup`, against a real relay with owners on."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    EMAIL,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_link_clients import _approving, routed, terminal  # noqa: F401
from tests.relay.test_owner_links import _code, _links, ada  # noqa: F401
from uam.cli import main as cli_main
from uam.cli.main import cli
from uam.protocol import UAMError
from uam.sdk.agent import Agent


def _hold(relay, owner, name="bob"):
    """Reserve *name* for the owner's email; a setup code for it."""
    resp = relay.post("/api/v1/reserve", json={"name": name, "email": EMAIL})
    assert resp.status_code == 201, resp.text
    [held] = owner.get("/api/owner/reservations").json()["reservations"]
    made = owner.post(f"/api/owner/reservations/{held['id']}/code")
    assert made.status_code == 200, made.text
    return made.json()["code"]


def _sdk(tmp_path: Path, name="bob", setup_code=None) -> Agent:
    return Agent(name, relay="http://testserver", key_dir=str(tmp_path / "keys"),
                 transport="http", setup_code=setup_code)


async def test_the_sdk_registers_a_reserved_name_with_its_code(ada, routed, tmp_path):
    code = _hold(routed, ada)
    agent = _sdk(tmp_path, setup_code=code)
    await agent.connect()
    try:
        assert agent.address == "bob::test.local"
        offer = await agent.start_owner_link(code, via="setup")
        await agent.sign_owner_link(offer)
    finally:
        await agent.close()
    assert _links(ada)[0]["state"] == "waiting"


async def test_the_sdk_says_why_a_reserved_name_is_refused(ada, routed, tmp_path):
    _hold(routed, ada)
    agent = _sdk(tmp_path)
    with pytest.raises(UAMError, match="reserved for a YouAM account"):
        await agent.connect()


def test_uam_init_setup_registers_a_reserved_name(ada, routed, terminal, monkeypatch):
    monkeypatch.setattr(cli_main, "_sleep", _approving(ada))
    code = _hold(routed, ada)
    result = CliRunner().invoke(cli, ["init", "--setup"], input=f"{code}\nbob\n")
    assert result.exit_code == 0, result.output
    assert "Initialized agent: bob::test.local" in result.output
    assert _links(ada)[0]["state"] == "active"


def test_uam_init_setup_with_the_wrong_code_can_try_again(ada, routed, terminal, monkeypatch):
    code = _hold(routed, ada)
    plain = _code(ada)  # newer than the named code, so that one no longer counts either
    result = CliRunner().invoke(cli, ["init", "--setup"], input=f"{plain}\nbob\n")
    assert result.exit_code != 0
    assert "reserved for a YouAM account" in result.output
    # Nothing is left behind: the same name can be set up again.
    monkeypatch.setattr(cli_main, "_sleep", _approving(ada))
    [held] = ada.get("/api/owner/reservations").json()["reservations"]
    code = ada.post(f"/api/owner/reservations/{held['id']}/code").json()["code"]
    result = CliRunner().invoke(cli, ["init", "--setup"], input=f"{code}\nbob\n")
    assert result.exit_code == 0, result.output
