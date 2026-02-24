"""Tests for Handshake CRUD operations."""

from __future__ import annotations

import pytest

from uam.db.crud.handshakes import (
    create_handshake,
    get_pending,
    respond_handshake,
)


async def test_create_handshake(session):
    hs = await create_handshake(
        session,
        from_addr="alice::youam.network",
        to_addr="bob::youam.network",
        contact_card={"display_name": "Alice"},
    )
    assert hs.status == "pending"
    assert hs.from_addr == "alice::youam.network"
    assert hs.to_addr == "bob::youam.network"
    assert hs.contact_card == {"display_name": "Alice"}
    assert hs.resolved_at is None


async def test_get_pending(session):
    await create_handshake(session, from_addr="alice::youam.network", to_addr="bob::youam.network")
    await create_handshake(session, from_addr="carol::youam.network", to_addr="bob::youam.network")
    # Different target
    await create_handshake(session, from_addr="dave::youam.network", to_addr="eve::youam.network")

    pending = await get_pending(session, "bob::youam.network")
    assert len(pending) == 2
    assert all(h.to_addr == "bob::youam.network" for h in pending)


async def test_respond_approve(session):
    hs = await create_handshake(
        session, from_addr="alice::youam.network", to_addr="bob::youam.network"
    )
    responded = await respond_handshake(session, hs.id, "approved")
    assert responded is not None
    assert responded.status == "approved"
    assert responded.resolved_at is not None


async def test_respond_deny(session):
    hs = await create_handshake(
        session, from_addr="alice::youam.network", to_addr="bob::youam.network"
    )
    responded = await respond_handshake(session, hs.id, "denied")
    assert responded is not None
    assert responded.status == "denied"
    assert responded.resolved_at is not None


async def test_respond_invalid_status_raises(session):
    hs = await create_handshake(
        session, from_addr="alice::youam.network", to_addr="bob::youam.network"
    )
    with pytest.raises(ValueError, match="Invalid handshake response status"):
        await respond_handshake(session, hs.id, "invalid_status")
