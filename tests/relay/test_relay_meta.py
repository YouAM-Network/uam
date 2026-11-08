"""relay_meta: the relay says when it received an envelope.

Stored mail can reach its recipient long after it was signed.  The relay
writes ``relay_meta`` = {v, relay, received_at, stored} beside the signed
fields so the recipient can tell "signed now, stored, delivered later" from
an old envelope replayed.  Senders cannot set it: any top-level ``relay_*``
key they send is replaced.  Federated mail keeps the origin relay's receive
time when that relay vouches for it in its signed body.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import uam.relay.routes.federation as federation_routes
from uam.protocol import (
    MessageType,
    create_envelope,
    deserialize_verify_key,
    from_wire_dict,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
    verify_envelope,
)
from uam.relay.app import create_app
from uam.relay.relay_auth import sign_federation_request
from uam.relay.relay_meta import FEATURE, for_federation, peer_received_at, stamp

REMOTE_RELAY = "remote.example"
REMOTE_SENDER = "carol::remote.example"


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _inbox(client, agent) -> list[dict]:
    resp = client.get(
        f"/api/v1/inbox/{agent['address']}",
        headers={"Authorization": f"Bearer {agent['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["messages"]


def _send(client, sender, wire):
    resp = client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return resp


# ---------------------------------------------------------------------------
# Local delivery
# ---------------------------------------------------------------------------


def test_stored_message_carries_relay_meta(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    _send(client, alice, make_envelope(alice, bob))

    [msg] = _inbox(client, bob)
    meta = msg["relay_meta"]
    assert meta["v"] == 1
    assert meta["relay"] == "test.local"
    assert meta["stored"] is True
    assert before <= _parse(meta["received_at"]) <= datetime.now(timezone.utc)


def test_sender_supplied_relay_keys_are_replaced(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    wire["relay_meta"] = {"v": 1, "relay": "test.local", "received_at": "2020-01-01T00:00:00Z"}
    wire["relay_note"] = "spoofed"
    _send(client, alice, wire)

    [msg] = _inbox(client, bob)
    assert "relay_note" not in msg
    assert _parse(msg["relay_meta"]["received_at"]).year == datetime.now(timezone.utc).year


def test_delivered_envelope_still_verifies(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    _send(client, alice, make_envelope(alice, bob))

    [msg] = _inbox(client, bob)
    verify_envelope(from_wire_dict(msg), deserialize_verify_key(alice["public_key_str"]))


def test_live_websocket_delivery_is_not_marked_stored(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {bob['token']}"}
    ) as ws:
        _send(client, alice, make_envelope(alice, bob))
        frame = ws.receive_json()
    assert frame["relay_meta"]["stored"] is False
    assert frame["relay_meta"]["relay"] == "test.local"


def test_drain_on_connect_is_marked_stored(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    _send(client, alice, wire)

    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {bob['token']}"}
    ) as ws:
        frame = ws.receive_json()
    assert frame["message_id"] == wire["message_id"]
    assert frame["relay_meta"]["stored"] is True


def test_websocket_send_is_stamped(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    wire["relay_meta"] = {"v": 1, "received_at": "2020-01-01T00:00:00Z"}
    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        ws.send_json(wire)
        assert ws.receive_json()["type"] == "ack"

    [msg] = _inbox(client, bob)
    assert _parse(msg["relay_meta"]["received_at"]).year == datetime.now(timezone.utc).year


def test_versions_advertises_the_feature(client):
    resp = client.get("/api/v1/versions")
    assert resp.status_code == 200
    assert FEATURE in resp.json()["features"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signed_wire(ts: datetime) -> dict:
    return {"message_id": "m1", "from": REMOTE_SENDER, "timestamp": _iso(ts)}


def test_stamp_copies_and_strips():
    original = {"message_id": "m1", "relay_meta": {"v": 9}, "relay_x": 1, "payload": "p"}
    received = datetime(2026, 1, 1, tzinfo=timezone.utc)
    out = stamp(original, "test.local", received_at=received)
    assert out["relay_meta"] == {
        "v": 1,
        "relay": "test.local",
        "received_at": "2026-01-01T00:00:00.000Z",
        "stored": True,  # received long ago
    }
    assert "relay_x" not in out
    assert original["relay_meta"] == {"v": 9}  # input untouched


def test_peer_received_at_trusts_only_the_signing_relay():
    now = datetime.now(timezone.utc)
    signed = now - timedelta(hours=2)
    claimed = signed + timedelta(seconds=5)
    wire = _signed_wire(signed)

    wire["relay_meta"] = {"v": 1, "relay": REMOTE_RELAY, "received_at": _iso(claimed)}
    assert peer_received_at(wire, REMOTE_RELAY, now) == claimed.replace(
        microsecond=claimed.microsecond // 1000 * 1000
    )

    wire["relay_meta"] = {"v": 1, "relay": "other.example", "received_at": _iso(claimed)}
    assert peer_received_at(wire, REMOTE_RELAY, now) is None


@pytest.mark.parametrize(
    "claim",
    [
        "not a time",
        None,
        "far-from-signed",
        "future",
    ],
)
def test_peer_received_at_refuses_unbelievable_claims(claim):
    now = datetime.now(timezone.utc)
    signed = now - timedelta(hours=2)
    wire = _signed_wire(signed)
    received = {
        "not a time": "yesterday",
        None: None,
        "far-from-signed": _iso(signed + timedelta(hours=1)),
        "future": _iso(now + timedelta(hours=1)),
    }[claim]
    wire["relay_meta"] = {"v": 1, "relay": REMOTE_RELAY, "received_at": received}
    assert peer_received_at(wire, REMOTE_RELAY, now) is None


def test_for_federation_drops_the_stamp_rather_than_exceed_the_size_limit():
    wire = stamp({"message_id": "m1", "payload": "x" * 100}, "test.local")
    assert for_federation(wire, limit=10_000) is wire
    trimmed = for_federation(wire, limit=len(json.dumps(wire)) - 1)
    assert "relay_meta" not in trimmed


# ---------------------------------------------------------------------------
# Federation ingress
# ---------------------------------------------------------------------------


@pytest.fixture()
def fed_client(tmp_path, monkeypatch):
    import uam.db.engine as _eng
    import uam.db.session as _sess

    _eng._engine = None
    _sess._session_factory = None
    db_path = str(tmp_path / "fed.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", db_path)
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_FEDERATION_ENABLED", "true")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))

    relay_sk, relay_vk = generate_keypair()
    sender_sk, sender_vk = generate_keypair()

    async def fake_relay_key(_session, from_relay):
        return serialize_verify_key(relay_vk) if from_relay == REMOTE_RELAY else None

    async def fake_sender_key(_session, address, _service, _settings):
        return serialize_verify_key(sender_vk) if address == REMOTE_SENDER else None

    monkeypatch.setattr(federation_routes, "_get_relay_public_key", fake_relay_key)
    monkeypatch.setattr(federation_routes, "_resolve_remote_sender_key", fake_sender_key)

    with TestClient(create_app()) as c:
        yield c, relay_sk, sender_sk

    _eng._engine = None
    _sess._session_factory = None


def _register(client, name):
    sk, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": name, "public_key": serialize_verify_key(vk)},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {"address": data["address"], "token": data["token"], "verify_key": vk}


def _deliver(client, relay_sk, wire):
    body = {
        "envelope": wire,
        "via": [],
        "hop_count": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from_relay": REMOTE_RELAY,
        "nonce": secrets.token_urlsafe(16),
    }
    resp = client.post(
        "/api/v1/federation/deliver",
        json=body,
        headers={"X-UAM-Relay-Signature": sign_federation_request(body, relay_sk)},
    )
    assert resp.status_code == 200, resp.text


def _remote_wire(sender_sk, recipient):
    return to_wire_dict(create_envelope(
        from_address=REMOTE_SENDER,
        to_address=recipient["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello from another relay",
        signing_key=sender_sk,
        recipient_verify_key=recipient["verify_key"],
    ))


def test_federated_mail_keeps_the_origin_relays_receive_time(fed_client):
    client, relay_sk, sender_sk = fed_client
    bob = _register(client, "bob")
    wire = _remote_wire(sender_sk, bob)
    # The origin relay's clock runs a little behind the sender's.
    origin_received = _parse(wire["timestamp"]) - timedelta(seconds=2)
    wire["relay_meta"] = {
        "v": 1, "relay": REMOTE_RELAY, "received_at": _iso(origin_received), "stored": False,
    }
    _deliver(client, relay_sk, wire)

    [msg] = _inbox(client, bob)
    assert msg["relay_meta"]["relay"] == "test.local"
    assert msg["relay_meta"]["received_at"] == _iso(origin_received)


def test_federated_mail_without_a_believable_claim_gets_local_time(fed_client):
    client, relay_sk, sender_sk = fed_client
    bob = _register(client, "bob")
    wire = _remote_wire(sender_sk, bob)
    wire["relay_meta"] = {"v": 1, "relay": "someone-else.example", "received_at": wire["timestamp"]}
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    _deliver(client, relay_sk, wire)

    [msg] = _inbox(client, bob)
    assert _parse(msg["relay_meta"]["received_at"]) >= before


def test_mail_a_relay_received_long_ago_counts_as_stored_even_if_delivered_live():
    """A peer outage can hold mail for hours before an online recipient gets it."""
    now = datetime.now(timezone.utc)
    stamped = stamp({"to": "bob::a.test"}, "a.test", received_at=now - timedelta(minutes=20))
    assert stamped["relay_meta"]["stored"] is True


def test_mail_received_just_now_is_not_stored():
    stamped = stamp({"to": "bob::a.test"}, "a.test")
    assert stamped["relay_meta"]["stored"] is False
