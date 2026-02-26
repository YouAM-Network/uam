"""Tests for Reservation CRUD operations."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

import pytest

from uam.db.crud.agents import create_agent
from uam.db.crud.reservations import (
    AddressAlreadyReserved,
    check_address_available,
    claim_reservation,
    count_active_reservations_by_ip,
    create_reservation,
    expire_reservations,
    get_active_reservation,
    get_reservation_by_token,
)


def _future(hours: int = 48) -> datetime:
    """Return a datetime in the future."""
    return datetime.utcnow() + timedelta(hours=hours)


def _past(hours: int = 1) -> datetime:
    """Return a datetime in the past."""
    return datetime.utcnow() - timedelta(hours=hours)


def _token() -> str:
    """Generate a unique claim token."""
    return secrets.token_hex(32)


# ---- create_reservation ----


async def test_create_reservation(session):
    token = _token()
    res = await create_reservation(
        session,
        address="test::youam.network",
        claim_token=token,
        ip_address="192.168.1.1",
        expires_at=_future(),
    )
    assert res.address == "test::youam.network"
    assert res.claim_token == token
    assert res.status == "reserved"
    assert res.ip_address == "192.168.1.1"
    assert res.expires_at > datetime.utcnow()
    assert res.claimed_at is None
    assert res.deleted_at is None
    assert res.id is not None


async def test_create_reservation_duplicate_address_raises(session):
    addr = "dupe::youam.network"
    await create_reservation(
        session,
        address=addr,
        claim_token=_token(),
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    with pytest.raises(AddressAlreadyReserved):
        await create_reservation(
            session,
            address=addr,
            claim_token=_token(),
            ip_address="10.0.0.2",
            expires_at=_future(),
        )


# ---- check_address_available ----


async def test_check_address_available_no_agent_no_reservation(session):
    available = await check_address_available(session, "fresh::youam.network")
    assert available is True


async def test_check_address_available_agent_exists(session):
    await create_agent(
        session,
        address="taken::youam.network",
        public_key="pk_test",
        token="tok_taken",
    )
    available = await check_address_available(session, "taken::youam.network")
    assert available is False


async def test_check_address_available_active_reservation(session):
    await create_reservation(
        session,
        address="reserved::youam.network",
        claim_token=_token(),
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    available = await check_address_available(session, "reserved::youam.network")
    assert available is False


async def test_check_address_available_expired_reservation(session):
    await create_reservation(
        session,
        address="expired::youam.network",
        claim_token=_token(),
        ip_address="10.0.0.1",
        expires_at=_past(),
    )
    available = await check_address_available(session, "expired::youam.network")
    assert available is True


# ---- get_active_reservation ----


async def test_get_active_reservation(session):
    token = _token()
    await create_reservation(
        session,
        address="active::youam.network",
        claim_token=token,
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    res = await get_active_reservation(session, "active::youam.network")
    assert res is not None
    assert res.claim_token == token
    assert res.status == "reserved"


async def test_get_active_reservation_expired(session):
    await create_reservation(
        session,
        address="gone::youam.network",
        claim_token=_token(),
        ip_address="10.0.0.1",
        expires_at=_past(),
    )
    res = await get_active_reservation(session, "gone::youam.network")
    assert res is None


# ---- get_reservation_by_token ----


async def test_get_reservation_by_token(session):
    token = _token()
    await create_reservation(
        session,
        address="bytoken::youam.network",
        claim_token=token,
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    res = await get_reservation_by_token(session, token)
    assert res is not None
    assert res.address == "bytoken::youam.network"


# ---- claim_reservation ----


async def test_claim_reservation(session):
    token = _token()
    await create_reservation(
        session,
        address="claimme::youam.network",
        claim_token=token,
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    claimed = await claim_reservation(session, token)
    assert claimed is not None
    assert claimed.status == "claimed"
    assert claimed.claimed_at is not None


async def test_claim_reservation_expired(session):
    token = _token()
    await create_reservation(
        session,
        address="expired-claim::youam.network",
        claim_token=token,
        ip_address="10.0.0.1",
        expires_at=_past(),
    )
    result = await claim_reservation(session, token)
    assert result is None


async def test_claim_reservation_already_claimed(session):
    token = _token()
    await create_reservation(
        session,
        address="double-claim::youam.network",
        claim_token=token,
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    # First claim succeeds
    claimed = await claim_reservation(session, token)
    assert claimed is not None
    assert claimed.status == "claimed"

    # Second claim returns None
    result = await claim_reservation(session, token)
    assert result is None


# ---- expire_reservations ----


async def test_expire_reservations(session):
    # One expired reservation
    expired_token = _token()
    await create_reservation(
        session,
        address="will-expire::youam.network",
        claim_token=expired_token,
        ip_address="10.0.0.1",
        expires_at=_past(),
    )
    # One still-active reservation
    await create_reservation(
        session,
        address="still-active::youam.network",
        claim_token=_token(),
        ip_address="10.0.0.1",
        expires_at=_future(),
    )
    count = await expire_reservations(session)
    assert count == 1

    # Verify the expired one changed status
    expired = await get_reservation_by_token(session, expired_token)
    assert expired is not None
    assert expired.status == "expired"

    # Active one is still findable
    active = await get_active_reservation(session, "still-active::youam.network")
    assert active is not None
    assert active.status == "reserved"


# ---- count_active_reservations_by_ip ----


async def test_count_active_reservations_by_ip(session):
    ip = "10.99.99.1"
    for i in range(3):
        await create_reservation(
            session,
            address=f"rate-{i}::youam.network",
            claim_token=_token(),
            ip_address=ip,
            expires_at=_future(),
        )
    count = await count_active_reservations_by_ip(session, ip)
    assert count == 3


async def test_count_active_reservations_by_ip_different_ips(session):
    for i in range(2):
        await create_reservation(
            session,
            address=f"ip-a-{i}::youam.network",
            claim_token=_token(),
            ip_address="10.1.1.1",
            expires_at=_future(),
        )
    await create_reservation(
        session,
        address="ip-b-0::youam.network",
        claim_token=_token(),
        ip_address="10.2.2.2",
        expires_at=_future(),
    )

    count_a = await count_active_reservations_by_ip(session, "10.1.1.1")
    count_b = await count_active_reservations_by_ip(session, "10.2.2.2")
    assert count_a == 2
    assert count_b == 1
