"""End-to-end federation delivery from a sender on another relay.

Every other federation test stops before the delivery step (federation
disabled, missing body, xfail stubs), so the path a real cross-relay
message takes — signed body in, stored for an offline local recipient,
picked up from the inbox — had no coverage. Only the two network lookups
(peer relay key, remote sender key) are replaced; the database, signature
checks and storage are real.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import uam.relay.routes.federation as federation_routes
from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.app import create_app
from uam.relay.rate_limit import SlidingWindowCounter
from uam.relay.relay_auth import sign_federation_request

REMOTE_RELAY = "remote.example"
REMOTE_SENDER = "carol::remote.example"


@pytest.fixture()
def fed_enabled_client(tmp_path, monkeypatch, relay_database_url):
    import uam.db.engine as _eng
    import uam.db.session as _sess

    _eng._engine = None
    _sess._session_factory = None
    monkeypatch.setenv("DATABASE_URL", relay_database_url)
    monkeypatch.setenv("UAM_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_FEDERATION_ENABLED", "true")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))

    with TestClient(create_app()) as c:
        yield c

    _eng._engine = None
    _sess._session_factory = None


@pytest.fixture()
def remote_parties(monkeypatch):
    """Keys for the remote relay and its agent, wired into the two lookups."""
    relay_sk, relay_vk = generate_keypair()
    sender_sk, sender_vk = generate_keypair()

    async def fake_relay_key(_session, from_relay):
        return serialize_verify_key(relay_vk) if from_relay == REMOTE_RELAY else None

    async def fake_sender_key(_session, address, _service, _settings):
        return serialize_verify_key(sender_vk) if address == REMOTE_SENDER else None

    monkeypatch.setattr(federation_routes, "_get_relay_public_key", fake_relay_key)
    monkeypatch.setattr(federation_routes, "_resolve_remote_sender_key", fake_sender_key)
    return relay_sk, sender_sk


def _register(client, name):
    sk, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": name, "public_key": serialize_verify_key(vk)},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {"address": data["address"], "token": data["token"], "verify_key": vk}


def _post_federated(client, wire, relay_sk):
    """POST *wire* as a fresh signed federation request (new nonce)."""
    body, signature = _signed_body(wire, relay_sk)
    return client.post(
        "/api/v1/federation/deliver",
        json=body,
        headers={"X-UAM-Relay-Signature": signature},
    )


def _remote_message(sender_sk, recipient):
    return to_wire_dict(create_envelope(
        from_address=REMOTE_SENDER,
        to_address=recipient["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello from another relay",
        signing_key=sender_sk,
        recipient_verify_key=recipient["verify_key"],
    ))


def _inbox_ids(client, agent):
    resp = client.get(
        f"/api/v1/inbox/{agent['address']}",
        headers={"Authorization": f"Bearer {agent['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return [m["message_id"] for m in resp.json()["messages"]]


def _signed_body(envelope_wire, relay_sk):
    body = {
        "envelope": envelope_wire,
        "via": [],
        "hop_count": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from_relay": REMOTE_RELAY,
        "nonce": secrets.token_urlsafe(16),
    }
    return body, sign_federation_request(body, relay_sk)


def test_message_from_remote_sender_reaches_offline_local_inbox(
    fed_enabled_client, remote_parties
):
    """A valid federated message for an offline local agent is stored and
    shows up in that agent's inbox — not reported as a duplicate and lost."""
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")

    envelope = create_envelope(
        from_address=REMOTE_SENDER,
        to_address=bob["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello from another relay",
        signing_key=sender_sk,
        recipient_verify_key=bob["verify_key"],
    )
    wire = to_wire_dict(envelope)
    body, signature = _signed_body(wire, relay_sk)

    resp = fed_enabled_client.post(
        "/api/v1/federation/deliver",
        json=body,
        headers={"X-UAM-Relay-Signature": signature},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] != "duplicate"

    inbox = fed_enabled_client.get(
        f"/api/v1/inbox/{bob['address']}",
        headers={"Authorization": f"Bearer {bob['token']}"},
    )
    assert inbox.status_code == 200, inbox.text
    ids = [m["message_id"] for m in inbox.json()["messages"]]
    assert ids == [envelope.message_id]


# ---------------------------------------------------------------------------
# The delivery checks (relay/policy.py) apply to federated mail too, keyed on
# the verified remote sender. Refusing one sender's message is not the peer
# relay's fault, so it does not lower the peer's reputation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern", [REMOTE_SENDER, "*::remote.example"])
def test_blocked_remote_sender_is_refused(fed_enabled_client, remote_parties, pattern):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    state = fed_enabled_client.app.state
    if pattern.startswith("*::"):
        state.spam_filter._blocked_domains.add(pattern[3:])
    else:
        state.spam_filter._blocked_exact.add(pattern)
    peer_score = state.relay_reputation.get_score(REMOTE_RELAY)

    resp = _post_federated(fed_enabled_client, _remote_message(sender_sk, bob), relay_sk)

    assert resp.status_code == 403
    assert _inbox_ids(fed_enabled_client, bob) == []
    assert state.relay_reputation.get_score(REMOTE_RELAY) == peer_score


def test_remote_sender_rate_limited_per_sender(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    state = fed_enabled_client.app.state
    limit = state.reputation_manager.get_send_limit(REMOTE_SENDER)
    peer_score = state.relay_reputation.get_score(REMOTE_RELAY)

    for _ in range(limit):
        resp = _post_federated(fed_enabled_client, _remote_message(sender_sk, bob), relay_sk)
        assert resp.status_code == 200, resp.text
    resp = _post_federated(fed_enabled_client, _remote_message(sender_sk, bob), relay_sk)

    assert resp.status_code == 429
    assert len(_inbox_ids(fed_enabled_client, bob)) == limit
    assert state.relay_reputation.get_score(REMOTE_RELAY) >= peer_score


def test_federated_message_refused_by_recipient_limit_can_be_resent(
    fed_enabled_client, remote_parties
):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    state = fed_enabled_client.app.state
    wire = _remote_message(sender_sk, bob)
    state.recipient_limiter = SlidingWindowCounter(limit=0, window_seconds=60.0)

    assert _post_federated(fed_enabled_client, wire, relay_sk).status_code == 429

    state.recipient_limiter = SlidingWindowCounter(limit=100, window_seconds=60.0)
    resp = _post_federated(fed_enabled_client, wire, relay_sk)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] != "duplicate"
    assert _inbox_ids(fed_enabled_client, bob) == [wire["message_id"]]


# ---------------------------------------------------------------------------
# Who pays for a request: only a relay that signed it
# ---------------------------------------------------------------------------


def _bad_signature_post(client, wire):
    body, _ = _signed_body(wire, generate_keypair()[0])
    return client.post(
        "/api/v1/federation/deliver",
        json=body,
        headers={"X-UAM-Relay-Signature": "AAAA"},
    )


def _limit_peer_to(client, limit):
    client.app.state.relay_reputation.get_rate_limit = lambda _domain: limit


def _score(client):
    return client.app.state.relay_reputation.get_score(REMOTE_RELAY)


def test_a_peer_over_its_limit_is_refused(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    _limit_peer_to(fed_enabled_client, 2)

    statuses = [
        _post_federated(fed_enabled_client, _remote_message(sender_sk, bob), relay_sk).status_code
        for _ in range(3)
    ]

    assert statuses == [200, 200, 429]


def test_a_refused_peer_keeps_its_reputation(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    _limit_peer_to(fed_enabled_client, 1)
    assert _post_federated(
        fed_enabled_client, _remote_message(sender_sk, bob), relay_sk
    ).status_code == 200
    before = _score(fed_enabled_client)

    assert _post_federated(
        fed_enabled_client, _remote_message(sender_sk, bob), relay_sk
    ).status_code == 429

    assert _score(fed_enabled_client) == before


def test_a_bad_signature_is_refused(fed_enabled_client, remote_parties):
    _, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")

    resp = _bad_signature_post(fed_enabled_client, _remote_message(sender_sk, bob))

    assert resp.status_code == 401
    assert _inbox_ids(fed_enabled_client, bob) == []


def test_unsigned_requests_cost_a_peer_nothing(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    _limit_peer_to(fed_enabled_client, 1)
    before = _score(fed_enabled_client)

    for _ in range(10):
        wire = _remote_message(sender_sk, bob)
        assert _bad_signature_post(fed_enabled_client, wire).status_code == 401

    assert _score(fed_enabled_client) == before
    assert _post_federated(
        fed_enabled_client, _remote_message(sender_sk, bob), relay_sk
    ).status_code == 200


def test_a_replayed_request_is_refused(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    body, signature = _signed_body(_remote_message(sender_sk, bob), relay_sk)
    headers = {"X-UAM-Relay-Signature": signature}

    first = fed_enabled_client.post("/api/v1/federation/deliver", json=body, headers=headers)
    assert first.status_code == 200, first.text
    before = _score(fed_enabled_client)

    second = fed_enabled_client.post("/api/v1/federation/deliver", json=body, headers=headers)

    assert second.status_code == 409
    assert _score(fed_enabled_client) == before
    assert len(_inbox_ids(fed_enabled_client, bob)) == 1


def test_the_same_message_twice_is_delivered_once(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    wire = _remote_message(sender_sk, bob)

    assert _post_federated(fed_enabled_client, wire, relay_sk).status_code == 200
    again = _post_federated(fed_enabled_client, wire, relay_sk)

    assert again.status_code == 200
    assert again.json()["status"] == "duplicate"
    assert len(_inbox_ids(fed_enabled_client, bob)) == 1


def test_an_envelope_the_sender_did_not_sign_is_refused(fed_enabled_client, remote_parties):
    relay_sk, _ = remote_parties
    bob = _register(fed_enabled_client, "bob")
    forger_sk, _ = generate_keypair()

    resp = _post_federated(fed_enabled_client, _remote_message(forger_sk, bob), relay_sk)

    assert resp.status_code == 400
    assert _inbox_ids(fed_enabled_client, bob) == []


def test_replaying_a_refused_request_charges_the_peer_once(
    fed_enabled_client, remote_parties
):
    relay_sk, _ = remote_parties
    bob = _register(fed_enabled_client, "bob")
    forger_sk, _ = generate_keypair()
    body, signature = _signed_body(_remote_message(forger_sk, bob), relay_sk)
    headers = {"X-UAM-Relay-Signature": signature}

    first = fed_enabled_client.post("/api/v1/federation/deliver", json=body, headers=headers)
    assert first.status_code == 400
    charged = _score(fed_enabled_client)

    again = fed_enabled_client.post("/api/v1/federation/deliver", json=body, headers=headers)

    assert again.status_code == 409
    assert _score(fed_enabled_client) == charged


def test_mail_for_nobody_here_is_refused_cleanly(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    _, verify_key = generate_keypair()
    nobody = {"address": "nobody::test.local", "verify_key": verify_key}

    resp = _post_federated(fed_enabled_client, _remote_message(sender_sk, nobody), relay_sk)

    assert resp.status_code == 404


def test_a_wrong_sender_key_is_the_sender_s_doing_not_the_peer_s(
    fed_enabled_client, remote_parties
):
    """sender_key isn't signed: one sender can put anything there."""
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    before = _score(fed_enabled_client)
    wire = {**_remote_message(sender_sk, bob), "sender_key": "AAAA"}

    assert _post_federated(fed_enabled_client, wire, relay_sk).status_code == 403

    assert _score(fed_enabled_client) == before


def test_a_sender_the_home_relay_can_t_vouch_for_costs_the_peer_nothing(
    fed_enabled_client, remote_parties, monkeypatch
):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    before = _score(fed_enabled_client)

    async def no_key(_session, _address, _service, _settings):
        return None

    monkeypatch.setattr(federation_routes, "_resolve_remote_sender_key", no_key)

    wire = _remote_message(sender_sk, bob)
    assert _post_federated(fed_enabled_client, wire, relay_sk).status_code == 403

    assert _score(fed_enabled_client) == before


def test_a_request_answered_duplicate_can_t_be_replayed(fed_enabled_client, remote_parties):
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    wire = _remote_message(sender_sk, bob)
    assert _post_federated(fed_enabled_client, wire, relay_sk).status_code == 200

    body, signature = _signed_body(wire, relay_sk)
    headers = {"X-UAM-Relay-Signature": signature}
    url = "/api/v1/federation/deliver"
    first = fed_enabled_client.post(url, json=body, headers=headers)
    assert first.json()["status"] == "duplicate"

    assert fed_enabled_client.post(url, json=body, headers=headers).status_code == 409


def test_a_blocked_relay_s_request_leaves_no_row(fed_enabled_client, remote_parties):
    """The blocklist runs before the signature: anyone can name a blocked relay."""
    relay_sk, sender_sk = remote_parties
    bob = _register(fed_enabled_client, "bob")
    fed_enabled_client.app.state.relay_blocklist._blocked.add(REMOTE_RELAY)
    wire = _remote_message(sender_sk, bob)

    with patch.object(federation_routes, "log_federation", new=AsyncMock()) as log:
        response = _post_federated(fed_enabled_client, wire, relay_sk)

    assert response.status_code == 403
    log.assert_not_awaited()
