"""Relay signing key: loaded from a secret, given a key id, history published.

The relay key signs federation requests now, and will sign owner-facing
records later. It has to survive a rebuilt VM (so it comes from a secret,
not a file the container generates), and signatures made under an older key
have to stay checkable after a rotation (so ``/.well-known/uam-relay.json``
lists the old keys with the dates they were in use).
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from uam.protocol.crypto import (
    generate_keypair,
    serialize_signing_key,
    serialize_verify_key,
)
from uam.relay.relay_auth import (
    load_relay_keypair,
    parse_key_history,
    relay_key_id,
)


def _vk_b64() -> str:
    _, vk = generate_keypair()
    return serialize_verify_key(vk)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_key_from_secret_is_used_and_no_file_is_written(tmp_path):
    sk, vk = generate_keypair()
    key_file = tmp_path / "relay_key.pem"

    loaded_sk, loaded_vk = load_relay_keypair(
        secret=serialize_signing_key(sk), key_path=str(key_file)
    )

    assert loaded_vk.encode() == vk.encode()
    assert loaded_sk.encode() == sk.encode()
    assert not key_file.exists()


def test_secret_wins_over_an_existing_key_file(tmp_path):
    file_sk, _ = generate_keypair()
    key_file = tmp_path / "relay_key.pem"
    key_file.write_text(serialize_signing_key(file_sk))
    secret_sk, secret_vk = generate_keypair()

    _, loaded_vk = load_relay_keypair(
        secret=serialize_signing_key(secret_sk), key_path=str(key_file)
    )

    assert loaded_vk.encode() == secret_vk.encode()


def test_a_bad_secret_stops_boot_without_echoing_it(tmp_path):
    bad = "not-a-key-but-secret-looking-XYZ123"
    with pytest.raises(RuntimeError) as exc:
        load_relay_keypair(secret=bad, key_path=str(tmp_path / "k.pem"))
    assert "UAM_RELAY_KEY" in str(exc.value)
    assert bad not in str(exc.value)


def test_without_a_secret_the_key_file_is_used(tmp_path):
    sk, vk = generate_keypair()
    key_file = tmp_path / "relay_key.pem"
    key_file.write_text(serialize_signing_key(sk))

    _, loaded_vk = load_relay_keypair(secret=None, key_path=str(key_file))

    assert loaded_vk.encode() == vk.encode()


# ---------------------------------------------------------------------------
# Key id
# ---------------------------------------------------------------------------


def test_key_id_is_stable_and_differs_per_key():
    _, vk1 = generate_keypair()
    _, vk2 = generate_keypair()

    assert relay_key_id(vk1) == relay_key_id(vk1)
    assert relay_key_id(vk1) != relay_key_id(vk2)
    assert len(relay_key_id(vk1)) == 16
    int(relay_key_id(vk1), 16)  # hex


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def test_history_unset_is_empty():
    assert parse_key_history(None, current_public_key=_vk_b64()) == []
    assert parse_key_history("", current_public_key=_vk_b64()) == []


def test_history_entries_get_their_key_ids():
    old = _vk_b64()
    raw = json.dumps([
        {"public_key": old, "valid_from": "2026-01-01T00:00:00Z",
         "retired_at": "2026-11-01T00:00:00Z"},
    ])

    [entry] = parse_key_history(raw, current_public_key=_vk_b64())

    from uam.protocol.crypto import deserialize_verify_key
    assert entry["key_id"] == relay_key_id(deserialize_verify_key(old))
    assert entry["public_key"] == old
    assert entry["valid_from"] == "2026-01-01T00:00:00Z"
    assert entry["retired_at"] == "2026-11-01T00:00:00Z"


@pytest.mark.parametrize("raw", [
    "{not json",
    json.dumps({"public_key": "x"}),  # not a list
    json.dumps([{"valid_from": "2026-01-01T00:00:00Z",
                 "retired_at": "2026-02-01T00:00:00Z"}]),  # no key
    json.dumps([{"public_key": "@@@", "retired_at": "2026-02-01T00:00:00Z"}]),
])
def test_malformed_history_stops_boot(raw):
    with pytest.raises(RuntimeError, match="UAM_RELAY_KEY_HISTORY"):
        parse_key_history(raw, current_public_key=_vk_b64())


def test_a_history_entry_must_say_when_it_was_retired():
    raw = json.dumps([{"public_key": _vk_b64(), "valid_from": "2026-01-01T00:00:00Z"}])
    with pytest.raises(RuntimeError, match="retired_at"):
        parse_key_history(raw, current_public_key=_vk_b64())


def test_the_current_key_cannot_also_be_retired():
    current = _vk_b64()
    raw = json.dumps([{"public_key": current, "retired_at": "2026-02-01T00:00:00Z"}])
    with pytest.raises(RuntimeError, match="current"):
        parse_key_history(raw, current_public_key=current)


# ---------------------------------------------------------------------------
# Published document
# ---------------------------------------------------------------------------


@pytest.fixture()
def keyed_client(tmp_path, relay_database_url, monkeypatch):
    sk, vk = generate_keypair()
    old = _vk_b64()
    monkeypatch.setenv("DATABASE_URL", relay_database_url)
    monkeypatch.setenv("UAM_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))
    monkeypatch.setenv("UAM_RELAY_KEY", serialize_signing_key(sk))
    monkeypatch.setenv("UAM_RELAY_KEY_VALID_FROM", "2026-11-01T00:00:00Z")
    monkeypatch.setenv("UAM_RELAY_KEY_HISTORY", json.dumps([
        {"public_key": old, "valid_from": "2026-01-01T00:00:00Z",
         "retired_at": "2026-11-01T00:00:00Z"},
    ]))

    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None
    from uam.relay.app import create_app

    with TestClient(create_app()) as c:
        yield c, vk, old

    _eng._engine = None
    _sess._session_factory = None


def test_well_known_publishes_the_current_key_and_its_history(keyed_client):
    client, vk, old = keyed_client

    doc = client.get("/.well-known/uam-relay.json").json()

    current = serialize_verify_key(vk)
    assert doc["public_key"] == current  # unchanged field, older peers read it
    assert doc["key_id"] == relay_key_id(vk)
    assert doc["keys"][0] == {
        "key_id": relay_key_id(vk),
        "public_key": current,
        "valid_from": "2026-11-01T00:00:00Z",
        "retired_at": None,
    }
    assert doc["keys"][1]["public_key"] == old
    assert doc["keys"][1]["retired_at"] == "2026-11-01T00:00:00Z"
    assert not (os.path.exists(os.environ["UAM_RELAY_KEY_PATH"]))


def test_a_key_listed_twice_in_history_stops_boot():
    old = _vk_b64()
    entry = {"public_key": old, "retired_at": "2026-02-01T00:00:00Z"}
    with pytest.raises(RuntimeError, match="more than once"):
        parse_key_history(json.dumps([entry, entry]), current_public_key=_vk_b64())
