"""An address that is taken stays with its agent.

Whoever holds the agent's key can get a new token: that is how an agent that
lost its token recovers.  Knowing the public key is not enough.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from uam.db.models import FederationNonce
from uam.protocol import generate_keypair, serialize_verify_key
from uam.protocol.register_proof import create_register_proof, register_proof_nonce
from uam.relay.rate_limit import SlidingWindowCounter


@pytest.fixture(autouse=True)
def _no_register_limit(app, client):
    app.state.register_limiter = SlidingWindowCounter(limit=1000, window_seconds=60.0)


@pytest.fixture()
def alice(client):
    signing_key, verify_key = generate_keypair()
    public_key = serialize_verify_key(verify_key)
    resp = _register(client, public_key)
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "signing_key": signing_key, "public_key": public_key}


def _register(client, public_key, proof=None):
    body = {"agent_name": "alice", "public_key": public_key}
    if proof is not None:
        body["proof"] = proof
    return client.post("/api/v1/register", json=body)


def _inbox_status(client, address, token) -> int:
    return client.get(
        f"/api/v1/inbox/{address}", headers={"Authorization": f"Bearer {token}"}
    ).status_code


def test_the_public_key_alone_gets_no_token(client, alice):
    assert _register(client, alice["public_key"]).status_code == 409
    assert _inbox_status(client, alice["address"], alice["token"]) == 200


def test_a_different_key_is_refused(client, alice):
    signing_key, verify_key = generate_keypair()
    proof = create_register_proof(alice["address"], signing_key)

    assert _register(client, serialize_verify_key(verify_key), proof).status_code == 409
    assert _inbox_status(client, alice["address"], alice["token"]) == 200


def test_the_key_holder_gets_a_new_token(client, alice):
    proof = create_register_proof(alice["address"], alice["signing_key"])

    resp = _register(client, alice["public_key"], proof)

    assert resp.status_code == 200, resp.text
    assert resp.json()["address"] == alice["address"]
    assert _inbox_status(client, alice["address"], resp.json()["token"]) == 200
    assert _inbox_status(client, alice["address"], alice["token"]) == 401


def test_a_proof_signed_by_another_key_is_refused(client, alice):
    other_key, _ = generate_keypair()
    proof = create_register_proof(alice["address"], other_key)

    assert _register(client, alice["public_key"], proof).status_code == 403
    assert _inbox_status(client, alice["address"], alice["token"]) == 200


def test_a_proof_for_another_address_is_refused(client, alice):
    proof = create_register_proof("alice::elsewhere.example", alice["signing_key"])

    assert _register(client, alice["public_key"], proof).status_code == 403


@pytest.mark.parametrize("minutes", [-6, 6])
def test_a_proof_outside_the_window_is_refused(client, alice, minutes):
    when = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    proof = create_register_proof(alice["address"], alice["signing_key"], now=when)

    assert _register(client, alice["public_key"], proof).status_code == 403


def test_a_proof_works_once(client, alice):
    proof = create_register_proof(alice["address"], alice["signing_key"])

    first = _register(client, alice["public_key"], proof)
    assert first.status_code == 200, first.text

    assert _register(client, alice["public_key"], proof).status_code == 403
    assert _inbox_status(client, alice["address"], first.json()["token"]) == 200


def test_respelling_the_signature_does_not_reuse_a_proof(client, alice):
    proof = create_register_proof(alice["address"], alice["signing_key"])
    assert _register(client, alice["public_key"], proof).status_code == 200

    respelled = {**proof, "signature": proof["signature"].rstrip("=")}
    assert _register(client, alice["public_key"], respelled).status_code == 403


def test_the_nonce_fits_its_column():
    # SQLite ignores column lengths; Postgres does not.
    column = FederationNonce.__table__.c.nonce
    assert len(register_proof_nonce("2026-11-06T00:00:00.000Z")) <= column.type.length


@pytest.mark.parametrize(
    "bad",
    [
        {"timestamp": "yesterday", "signature": "AAAA"},
        {"timestamp": "2026-01-01T00:00:00", "signature": "AAAA"},
        {"timestamp": "2026-01-01T00:00:00Z", "signature": "!!!"},
    ],
)
def test_a_malformed_proof_is_refused(client, alice, bad):
    assert _register(client, alice["public_key"], bad).status_code == 403


def test_a_new_address_needs_no_proof(client):
    _, verify_key = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": "newcomer", "public_key": serialize_verify_key(verify_key)},
    )
    assert resp.status_code == 200, resp.text


def test_a_deleted_address_stays_with_its_key(client, alice):
    headers = {"Authorization": f"Bearer {alice['token']}"}
    assert client.delete(f"/api/v1/agents/{alice['address']}", headers=headers).status_code == 200

    _, verify_key = generate_keypair()
    resp = _register(client, serialize_verify_key(verify_key))

    assert resp.status_code == 409
