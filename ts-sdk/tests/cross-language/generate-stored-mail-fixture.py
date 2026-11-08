"""Generate python-stored-mail.json: stored mail as a real relay delivers it.

Registers two agents with the relay app, sends one message and reads it back
from the inbox, so the fixture carries the relay's real relay_meta stamp and
its real /api/v1/versions answer. The relay's domain and the hostname in its
URL differ, as they do in production.

Needs a checkout whose relay writes relay_meta on PYTHONPATH:

    UAM_DB_PATH=/tmp/fixture-relay.db UAM_RELAY_KEY_PATH=/tmp/fixture-key.pem \\
        UAM_TOKEN_PEPPER=test-pepper python generate-stored-mail-fixture.py
"""
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from uam.protocol import (
    MessageType,
    create_envelope,
    serialize_verify_key,
    to_wire_dict,
)
from uam.protocol.types import b64_encode
from uam.relay.app import create_app

FIXTURE = Path(__file__).parent / "fixtures" / "python-stored-mail.json"

# The fixed test seeds from generate-fixtures.py.
ALICE_SEED = bytes(range(32))
BOB_SEED = bytes(range(32, 64))

os.environ["UAM_RELAY_DOMAIN"] = "test.local"
alice_sk = SigningKey(ALICE_SEED)
bob_sk = SigningKey(BOB_SEED)

with TestClient(create_app()) as relay:

    def register(name: str, key: SigningKey) -> dict:
        resp = relay.post("/api/v1/register", json={
            "agent_name": name, "public_key": serialize_verify_key(key.verify_key),
        })
        resp.raise_for_status()
        return resp.json()

    alice = register("alice", alice_sk)
    bob = register("bob", bob_sk)

    wire = to_wire_dict(create_envelope(
        from_address=alice["address"],
        to_address=bob["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello from yesterday",
        signing_key=alice_sk,
        recipient_verify_key=bob_sk.verify_key,
    ))
    relay.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {alice['token']}"},
    ).raise_for_status()

    [stored] = relay.get(
        f"/api/v1/inbox/{bob['address']}",
        headers={"Authorization": f"Bearer {bob['token']}"},
    ).json()["messages"]
    versions = relay.get("/api/v1/versions").json()

FIXTURE.write_text(json.dumps({
    "alice_address": alice["address"],
    "alice_verify_key_b64": serialize_verify_key(alice_sk.verify_key),
    "bob_address": bob["address"],
    "bob_seed_b64": b64_encode(BOB_SEED),
    "stored": stored,
    "versions": versions,
}, indent=2) + "\n")
print(f"Wrote {FIXTURE}")
