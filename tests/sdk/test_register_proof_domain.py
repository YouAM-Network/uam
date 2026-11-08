"""A proof names an address; the relay being asked doesn't get to choose it.

A hostile relay could otherwise answer 409, claim another relay's domain, and
replay the signed proof there for a token.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from uam.protocol import UAMError
from uam.sdk.agent import Agent


def _agent(tmp_path, relay, claims, **options):
    agent = Agent("alice", relay=relay, key_dir=str(tmp_path / "keys"), auto_register=False, **options)
    agent._fetch_relay_domain = AsyncMock(return_value=claims)
    return agent


async def test_a_relay_can_t_claim_someone_else_s_domain(tmp_path):
    agent = _agent(tmp_path, "https://evil.example", "youam.network")
    with pytest.raises(UAMError, match="youam.network"):
        await agent._address_on_relay()


async def test_a_lookalike_suffix_isn_t_a_parent_domain(tmp_path):
    agent = _agent(tmp_path, "https://notyouam.network", "youam.network")
    with pytest.raises(UAMError):
        await agent._address_on_relay()


@pytest.mark.parametrize("relay,claims", [
    ("https://relay.youam.network", "youam.network"),
    ("https://youam.network", "youam.network"),
    ("http://127.0.0.1:8787", "swarmify.local"),
    ("http://localhost:8787", "swarmify.local"),
    ("http://[::1]:8787", "swarmify.local"),
])
async def test_a_relay_may_use_its_own_or_a_parent_domain(tmp_path, relay, claims):
    assert await _agent(tmp_path, relay, claims)._address_on_relay() == f"alice::{claims}"


async def test_an_explicit_domain_is_used_without_asking(tmp_path):
    agent = _agent(tmp_path, "https://evil.example", "youam.network", domain="chosen.example")
    assert await agent._address_on_relay() == "alice::chosen.example"
    agent._fetch_relay_domain.assert_not_awaited()
