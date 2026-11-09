"""Build a relay database the way an installed youam 1.0.1 relay does.

Run with the interpreter of a venv that has ``youam[relay]==1.0.1`` installed
(NOT the checkout under test), from a directory with no ``alembic.ini``::

    python build_legacy_db.py <db_path> <out_json>

It boots the 1.0.1 relay on a fresh SQLite file, so its tables come from that
release's own startup path (``create_tables`` for a pip install), registers
two agents and leaves one message from alice in bob's inbox. The agents'
addresses, tokens and keys go to <out_json> for
``test_boot_on_legacy_db.py`` to pick up with the current code.

Only the installed ``uam`` package is imported: nothing from this repo.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile


def main(db_path: str, out_json: str) -> None:
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["UAM_DB_PATH"] = db_path
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_RELAY_KEY_PATH"] = os.path.join(
        tempfile.mkdtemp(), "relay_key.pem"
    )
    os.environ.setdefault("UAM_TOKEN_PEPPER", "ci-pepper-1234567890")

    import uam
    import uam.cli.main

    # 1.0.1's wheel ships no alembic.ini, and its lookup raises SystemExit,
    # which the relay's create_tables fallback doesn't catch. Launch it the
    # way Swarmify's cli/uam-relay.py does: make the lookup fail normally.
    def _no_alembic(_database_url):
        raise RuntimeError("youam ships no Alembic migrations; using create_tables")

    uam.cli.main._get_alembic_config = _no_alembic

    from fastapi.testclient import TestClient
    from uam.protocol import MessageType, create_envelope, to_wire_dict
    from uam.protocol.crypto import (
        generate_keypair,
        serialize_signing_key,
        serialize_verify_key,
    )
    from uam.relay.app import create_app

    agents = {}
    with TestClient(create_app()) as client:
        for name in ("alice", "bob"):
            sk, vk = generate_keypair()
            resp = client.post("/api/v1/register", json={
                "agent_name": name,
                "public_key": serialize_verify_key(vk),
            })
            resp.raise_for_status()
            data = resp.json()
            agents[name] = {
                "address": data["address"],
                "token": data["token"],
                "signing_key": serialize_signing_key(sk),
                "public_key": serialize_verify_key(vk),
            }
            agents[name]["_sk"], agents[name]["_vk"] = sk, vk

        alice, bob = agents["alice"], agents["bob"]
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"sent by 1.0.1",
            signing_key=alice["_sk"],
            recipient_verify_key=bob["_vk"],
        )
        wire = to_wire_dict(envelope)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        resp.raise_for_status()

    for agent in agents.values():
        del agent["_sk"], agent["_vk"]
    with open(out_json, "w") as fh:
        json.dump({
            "version": uam.__version__,
            "message_id": wire["message_id"],
            "agents": agents,
        }, fh)
    print(f"built {db_path} with youam {uam.__version__}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
