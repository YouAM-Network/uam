"""Stored mail: signed while the recipient was away, delivered later.

The signed timestamp alone cannot tell such a message from an old one being
replayed.  The relay's stamp can: it says when the relay received the
envelope.  The SDK believes the stamp only when all of this holds:

* the relay is the recipient's own and says it writes these stamps (an older
  relay passes a sender's ``relay_*`` keys straight through);
* the stamp says the message was stored, and that the relay received it
  within ``MAX_ENVELOPE_AGE`` of the signed time;
* the message is at most a week old, and not older than the replay cache,
  which could not have remembered it.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.protocol import generate_keypair, serialize_verify_key, to_wire_dict
from uam.protocol.types import MAX_ENVELOPE_AGE
from uam.sdk.agent import Agent
from uam.sdk.freshness import STORED_MAIL_MAX_AGE, relay_vouches

from tests.sdk.test_inbound_replay_window import _build_signed_envelope

RELAY = "testserver"
SENDER = "alice::testserver"


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _meta(received: datetime, **changes) -> dict:
    return {"v": 1, "relay": RELAY, "received_at": _iso(received), "stored": True, **changes}


@pytest.fixture()
async def bob(tmp_path):
    agent = Agent(
        "bob",
        relay=f"http://{RELAY}",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
        trust_policy="auto-accept",
    )
    agent._key_manager.load_or_generate("bob")
    agent._address = f"bob::{RELAY}"
    await agent._contact_book.open()
    agent._fetch_relay_features = AsyncMock(return_value={"relay_meta"})
    yield agent
    await agent.close()


async def _deliver(bob, signed: datetime, meta: dict | None, *, sender=None) -> object:
    """Hand *bob* a message signed at *signed*, as its relay would."""
    sk, vk = sender or generate_keypair()
    await bob._contact_book.add_contact(
        SENDER, serialize_verify_key(vk), trust_state="trusted"
    )
    wire = to_wire_dict(_build_signed_envelope(
        sk, vk, bob._key_manager.verify_key, SENDER, bob._address, timestamp=_iso(signed),
    ))
    if meta is not None:
        wire["relay_meta"] = meta
    return await bob._process_inbound(wire)


async def _backdate_cache(bob, when: datetime) -> None:
    await bob._replay_cache.created_at()
    bob._replay_cache._created_at = when.timestamp()


def _days_ago(days: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def test_a_day_old_stored_message_is_accepted(bob):
    signed = _days_ago(1)
    await _backdate_cache(bob, _days_ago(30))
    received = await _deliver(bob, signed, _meta(signed + timedelta(seconds=1)))
    assert received is not None
    assert received.content == "hello"


async def test_it_is_accepted_only_once(bob):
    signed = _days_ago(1)
    await _backdate_cache(bob, _days_ago(30))
    sender = generate_keypair()
    sk, vk = sender
    await bob._contact_book.add_contact(
        SENDER, serialize_verify_key(vk), trust_state="trusted"
    )
    wire = to_wire_dict(_build_signed_envelope(
        sk, vk, bob._key_manager.verify_key, SENDER, bob._address, timestamp=_iso(signed),
    ))
    wire["relay_meta"] = _meta(signed)
    assert await bob._process_inbound(dict(wire)) is not None
    assert await bob._process_inbound(dict(wire)) is None


async def test_no_stamp_is_still_refused(bob):
    await _backdate_cache(bob, _days_ago(30))
    assert await _deliver(bob, _days_ago(1), None) is None


async def test_a_relay_that_does_not_write_stamps_is_not_believed(bob):
    """Such a relay passes a sender's relay_meta through untouched."""
    bob._fetch_relay_features.return_value = set()
    signed = _days_ago(1)
    await _backdate_cache(bob, _days_ago(30))
    assert await _deliver(bob, signed, _meta(signed)) is None


async def test_a_relay_that_cannot_be_asked_is_not_believed(bob):
    bob._fetch_relay_features.side_effect = OSError("relay unreachable")
    signed = _days_ago(1)
    await _backdate_cache(bob, _days_ago(30))
    assert await _deliver(bob, signed, _meta(signed)) is None


async def test_a_failed_feature_lookup_is_retried(bob):
    signed = _days_ago(1)
    await _backdate_cache(bob, _days_ago(30))
    bob._fetch_relay_features.side_effect = OSError("relay unreachable")
    assert await _deliver(bob, signed, _meta(signed)) is None
    bob._fetch_relay_features.side_effect = None
    assert await _deliver(bob, signed, _meta(signed)) is not None


async def test_features_are_fetched_once(bob):
    await _backdate_cache(bob, _days_ago(30))
    for _ in range(3):
        signed = _days_ago(1)
        await _deliver(bob, signed, _meta(signed))
    assert bob._fetch_relay_features.await_count == 1


async def test_fresh_mail_never_asks_the_relay(bob):
    now = datetime.now(timezone.utc)
    assert await _deliver(bob, now, _meta(now)) is not None
    bob._fetch_relay_features.assert_not_awaited()


async def test_mail_older_than_the_replay_cache_is_refused(bob):
    """A cache created yesterday cannot vouch for a message from two days ago."""
    signed = _days_ago(2)
    await _backdate_cache(bob, _days_ago(1))
    assert await _deliver(bob, signed, _meta(signed)) is None


@pytest.mark.parametrize(
    "case",
    ["other relay", "wrong version", "version is a boolean", "not stored", "received long after signing",
     "received in the future", "not a time", "not a dict", "over a week old",
     "signed in the future"],
)
def test_relay_vouches_refuses(case):
    now = datetime.now(timezone.utc)
    signed = now - timedelta(days=1)
    meta = _meta(signed)
    if case == "other relay":
        meta["relay"] = "elsewhere.example"
    elif case == "wrong version":
        meta["v"] = 2
    elif case == "version is a boolean":
        meta["v"] = True
    elif case == "not stored":
        meta["stored"] = False
    elif case == "received long after signing":
        meta["received_at"] = _iso(signed + timedelta(seconds=MAX_ENVELOPE_AGE + 1))
    elif case == "received in the future":
        signed = now + timedelta(seconds=10)
        meta["received_at"] = _iso(now + timedelta(days=1))
    elif case == "not a time":
        meta["received_at"] = "yesterday"
    elif case == "not a dict":
        meta = "stored"
    elif case == "over a week old":
        signed = now - timedelta(seconds=STORED_MAIL_MAX_AGE + MAX_ENVELOPE_AGE + 1)
        meta["received_at"] = _iso(signed)
    elif case == "signed in the future":
        signed = now + timedelta(days=1)
        meta["received_at"] = _iso(signed)
    assert relay_vouches({"relay_meta": meta}, signed, now, RELAY) is False


def test_relay_vouches_accepts_a_week_old_message():
    now = datetime.now(timezone.utc)
    signed = now - timedelta(seconds=STORED_MAIL_MAX_AGE)
    assert relay_vouches({"relay_meta": _meta(signed)}, signed, now, RELAY) is True


async def test_a_no_from_the_relay_is_remembered_for_a_minute(bob):
    bob._fetch_relay_features = AsyncMock(return_value=set())
    assert await bob._relay_stamps_mail() is False
    assert await bob._relay_stamps_mail() is False
    assert bob._fetch_relay_features.await_count == 1

    bob._relay_no_until = 0.0  # the minute is up, and the relay has been upgraded
    bob._fetch_relay_features = AsyncMock(return_value={"relay_meta"})
    assert await bob._relay_stamps_mail() is True


@pytest.mark.parametrize("body", [["relay_meta"], {"features": None}, {"features": [{}]}])
async def test_a_malformed_features_answer_is_a_no(bob, body):
    response = MagicMock()
    response.json.return_value = body
    client = AsyncMock()
    client.get.return_value = response
    client.__aenter__.return_value = client
    del bob._fetch_relay_features  # the fixture's mock: use the real lookup
    with patch("uam.sdk.agent.httpx.AsyncClient", return_value=client):
        assert await bob._relay_stamps_mail() is False


async def test_connect_starts_the_cache_so_mail_from_then_on_can_be_accepted(tmp_path):
    """Mail can arrive before the agent's first inbox()."""
    agent = Agent(
        "carol",
        relay=f"http://{RELAY}",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    agent._key_manager.load_or_generate("carol")
    agent._key_manager.save_token("carol", "a-token")
    agent._key_manager.save_address("carol", f"carol::{RELAY}", f"http://{RELAY}")
    before = time.time()
    with patch("uam.sdk.agent.create_transport") as transport:
        transport.return_value.connect = AsyncMock()
        transport.return_value.disconnect = AsyncMock()
        await agent.connect()
    try:
        created = await agent._replay_cache.created_at()
        assert before <= created <= time.time()
        assert agent._replay_cache._db is not None
    finally:
        await agent.close()


async def test_a_cache_that_cannot_open_does_not_stop_connect(tmp_path):
    agent = Agent(
        "dave",
        relay=f"http://{RELAY}",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    agent._key_manager.load_or_generate("dave")
    agent._key_manager.save_token("dave", "a-token")
    agent._key_manager.save_address("dave", f"dave::{RELAY}", f"http://{RELAY}")
    agent._replay_cache.created_at = AsyncMock(side_effect=PermissionError("read-only"))
    with patch("uam.sdk.agent.create_transport") as transport:
        transport.return_value.connect = AsyncMock()
        transport.return_value.disconnect = AsyncMock()
        await agent.connect()
    await agent.close()
