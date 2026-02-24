"""Tests for Agent CRUD operations."""

from __future__ import annotations

import pytest

from uam.db.crud.agents import (
    create_agent,
    deactivate_agent,
    get_agent_by_address,
    get_agent_by_address_with_deleted,
    get_agent_by_token,
    list_agents,
    reactivate_agent,
    suspend_agent,
    update_agent,
)


async def _make_agent(session, address="alice::youam.network", **kwargs):
    """Helper to create a test agent with sensible defaults."""
    defaults = dict(
        public_key="pk_test",
        token=f"tok_{address}",
        display_name="Alice",
    )
    defaults.update(kwargs)
    return await create_agent(session, address=address, **defaults)


async def test_create_agent(session):
    agent = await _make_agent(session)
    assert agent.address == "alice::youam.network"
    assert agent.public_key == "pk_test"
    assert agent.token == "tok_alice::youam.network"
    assert agent.display_name == "Alice"
    assert agent.status == "active"
    assert agent.deleted_at is None


async def test_get_by_token(session):
    await _make_agent(session)
    found = await get_agent_by_token(session, "tok_alice::youam.network")
    assert found is not None
    assert found.address == "alice::youam.network"


async def test_get_by_address(session):
    await _make_agent(session)
    found = await get_agent_by_address(session, "alice::youam.network")
    assert found is not None
    assert found.display_name == "Alice"


async def test_get_nonexistent_returns_none(session):
    found = await get_agent_by_address(session, "nobody::youam.network")
    assert found is None


async def test_update_agent(session):
    await _make_agent(session)
    updated = await update_agent(
        session,
        "alice::youam.network",
        display_name="Alice Updated",
        webhook_url="https://example.com/webhook",
    )
    assert updated is not None
    assert updated.display_name == "Alice Updated"
    assert updated.webhook_url == "https://example.com/webhook"


async def test_deactivate_agent(session):
    await _make_agent(session)
    deactivated = await deactivate_agent(session, "alice::youam.network")
    assert deactivated is not None
    assert deactivated.status == "deactivated"
    assert deactivated.deleted_at is not None


async def test_deactivate_hides_from_default_query(session):
    await _make_agent(session)
    await deactivate_agent(session, "alice::youam.network")

    # Default query should not find deactivated agent
    found = await get_agent_by_address(session, "alice::youam.network")
    assert found is None

    # _with_deleted should find it
    found_deleted = await get_agent_by_address_with_deleted(
        session, "alice::youam.network"
    )
    assert found_deleted is not None
    assert found_deleted.status == "deactivated"


async def test_reactivate_agent(session):
    await _make_agent(session)
    await deactivate_agent(session, "alice::youam.network")
    reactivated = await reactivate_agent(session, "alice::youam.network")
    assert reactivated is not None
    assert reactivated.status == "active"
    assert reactivated.deleted_at is None


async def test_suspend_agent(session):
    await _make_agent(session)
    suspended = await suspend_agent(session, "alice::youam.network")
    assert suspended is not None
    assert suspended.status == "suspended"


async def test_list_agents(session):
    for name in ["alice", "bob", "carol"]:
        await _make_agent(session, address=f"{name}::youam.network")
    agents = await list_agents(session)
    assert len(agents) == 3
    addresses = {a.address for a in agents}
    assert "alice::youam.network" in addresses
    assert "bob::youam.network" in addresses
    assert "carol::youam.network" in addresses
