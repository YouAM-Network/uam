"""Tests for Spam defense CRUD operations (blocklist + allowlist)."""

from __future__ import annotations

from uam.db.crud.spam import (
    add_allowlist,
    add_blocklist,
    check_allowlist,
    check_blocklist,
    list_allowlist,
    remove_allowlist,
    remove_blocklist,
)


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------


async def test_add_blocklist(session):
    entry = await add_blocklist(session, "evil::domain.com", reason="spam")
    assert entry.pattern == "evil::domain.com"
    assert entry.reason == "spam"


async def test_check_exact_match(session):
    await add_blocklist(session, "evil::domain.com")
    assert await check_blocklist(session, "evil::domain.com") is True
    assert await check_blocklist(session, "good::domain.com") is False


async def test_check_domain_match(session):
    await add_blocklist(session, "*::spam.org")
    assert await check_blocklist(session, "anyone::spam.org") is True
    assert await check_blocklist(session, "nobody::spam.org") is True
    assert await check_blocklist(session, "anyone::legit.org") is False


async def test_remove_blocklist(session):
    await add_blocklist(session, "evil::domain.com")
    removed = await remove_blocklist(session, "evil::domain.com")
    assert removed is True
    assert await check_blocklist(session, "evil::domain.com") is False


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


async def test_allowlist_operations(session):
    # Add
    entry = await add_allowlist(session, "trusted::partner.com", reason="partner")
    assert entry.pattern == "trusted::partner.com"

    # Check
    assert await check_allowlist(session, "trusted::partner.com") is True
    assert await check_allowlist(session, "unknown::other.com") is False

    # List
    entries = await list_allowlist(session)
    assert len(entries) == 1

    # Remove
    removed = await remove_allowlist(session, "trusted::partner.com")
    assert removed is True
    assert await check_allowlist(session, "trusted::partner.com") is False
