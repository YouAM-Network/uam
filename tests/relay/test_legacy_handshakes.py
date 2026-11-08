"""Legacy relay-mediated handshakes (``/handshakes/*``) are read-only.

Contact approval happens between the agents' own SDKs with signed
``handshake.*`` envelopes. The relay's old endpoints let an agent's token
create a request and approve it with no owner involved, so they no longer
create or approve anything; listing and denying what is already pending
still work.
"""

from __future__ import annotations

import pytest

from uam.db.crud.handshakes import create_handshake
from uam.db.engine import get_engine
from uam.db.session import init_session_factory


def _auth(agent) -> dict:
    return {"Authorization": f"Bearer {agent['token']}"}


async def _seed_pending(from_addr: str, to_addr: str) -> int:
    factory = await init_session_factory(get_engine())
    async with factory() as session:
        hs = await create_handshake(session, from_addr=from_addr, to_addr=to_addr)
        return hs.id


def test_send_handshake_is_gone(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    resp = client.post(
        "/api/v1/handshakes/send",
        json={"to_address": bob["address"]},
        headers=_auth(alice),
    )
    assert resp.status_code == 410
    assert resp.headers.get("Deprecation") == "true"
    assert client.get(
        f"/api/v1/handshakes/pending/{bob['address']}", headers=_auth(bob)
    ).json()["count"] == 0


@pytest.fixture()
def pending_id(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    return client.portal.call(_seed_pending, alice["address"], bob["address"])


def test_approving_a_pending_handshake_is_refused(client, registered_agent_pair, pending_id):
    _alice, bob = registered_agent_pair
    resp = client.post(
        f"/api/v1/handshakes/{pending_id}/respond",
        json={"response": "approved"},
        headers=_auth(bob),
    )
    assert resp.status_code == 403
    pending = client.get(
        f"/api/v1/handshakes/pending/{bob['address']}", headers=_auth(bob)
    ).json()
    assert [h["id"] for h in pending["handshakes"]] == [pending_id]


def test_denying_a_pending_handshake_still_works(client, registered_agent_pair, pending_id):
    _alice, bob = registered_agent_pair
    resp = client.post(
        f"/api/v1/handshakes/{pending_id}/respond",
        json={"response": "denied"},
        headers=_auth(bob),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "denied"
