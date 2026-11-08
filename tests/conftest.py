"""Shared test fixtures for UAM protocol tests."""

from __future__ import annotations

import os

# T2.1 (Phase 43 Plan 04): the relay refuses to start without
# ``UAM_TOKEN_PEPPER`` set, and the alembic 0003 migration also requires
# it.  Set a deterministic test value at conftest-import time so every
# test (and pytest collection itself) sees the same pepper.  Tests that
# need a specific pepper override this via monkeypatch.
os.environ.setdefault("UAM_TOKEN_PEPPER", "test-pepper-not-for-prod-1234567890abcdef")

# The relay sleeps UAM_DRAIN_SECONDS (default 15) on every shutdown, and every
# TestClient lifespan is a shutdown.  Read at import of uam.relay.shutdown, so
# it must be set here.  test_shutdown.py passes its own drain values.
os.environ.setdefault("UAM_DRAIN_SECONDS", "0")

import aiosqlite.core
import pytest
from nacl.signing import SigningKey

from uam.protocol.address import Address, parse_address
from uam.protocol.contact import create_contact_card
from uam.protocol.envelope import MessageEnvelope, create_envelope
from uam.protocol.types import MessageType


# aiosqlite 0.22.1: stop() queues work for the connection's thread even if that
# thread has exited, and close() then waits for it forever.  A query cancelled
# half way gets there: SQLAlchemy force-stops the connection while close() is
# running.  TestClient cancels handlers abruptly, so this hung event loop
# shutdown at random.
_aiosqlite_stop = aiosqlite.core.Connection.stop


def _stop_once(self):
    return _aiosqlite_stop(self) if self._running else None


aiosqlite.core.Connection.stop = _stop_once


@pytest.fixture(autouse=True)
def _private_uam_home(tmp_path, monkeypatch):
    """Keep every test out of the real ~/.uam (contacts, keys, replay cache)."""
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "uam-home"))


@pytest.fixture(autouse=True)
def _fresh_relay_database():
    """Each test picks its own relay database.

    The relay's lifespan sets DATABASE_URL from UAM_DB_PATH when it is unset
    and leaves it set, and the engine and session factory are process-wide.
    Without this, a fixture that sets only UAM_DB_PATH reuses the database
    of whichever test ran first.
    """
    import uam.db.engine as _eng
    import uam.db.session as _sess

    saved = os.environ.pop("DATABASE_URL", None)
    _eng._engine = None
    _sess._session_factory = None
    yield
    os.environ.pop("DATABASE_URL", None)
    if saved is not None:
        os.environ["DATABASE_URL"] = saved
    _eng._engine = None
    _sess._session_factory = None


@pytest.fixture()
def keypair():
    """Return an Ed25519 (signing_key, verify_key) tuple."""
    sk = SigningKey.generate()
    return sk, sk.verify_key


@pytest.fixture()
def keypair_pair():
    """Return two keypairs -- (alice_sk, alice_vk), (bob_sk, bob_vk)."""
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    return (alice_sk, alice_sk.verify_key), (bob_sk, bob_sk.verify_key)


@pytest.fixture()
def sample_address_str() -> str:
    return "alice::youam.network"


@pytest.fixture()
def sample_address() -> Address:
    return parse_address("alice::youam.network")


@pytest.fixture()
def bob_address_str() -> str:
    return "bob::youam.network"


@pytest.fixture()
def sample_envelope(keypair_pair) -> MessageEnvelope:
    """Create a valid signed+encrypted envelope (alice -> bob)."""
    (alice_sk, _), (_, bob_vk) = keypair_pair
    return create_envelope(
        from_address="alice::youam.network",
        to_address="bob::youam.network",
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello Bob!",
        signing_key=alice_sk,
        recipient_verify_key=bob_vk,
    )


@pytest.fixture()
def sample_contact_card(keypair):
    """Create a valid signed contact card."""
    sk, _ = keypair
    return create_contact_card(
        address="alice::youam.network",
        display_name="Alice Agent",
        relay="wss://relay.youam.network",
        signing_key=sk,
        description="A helpful agent",
    )
