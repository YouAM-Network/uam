"""Admin routes for an agent's inbound policy and contacts (P1, ships dark).

Only the relay admin can gate an agent in P1; owners get their own routes
in P2. No agent token can reach these.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ADMIN_KEY = "admin-key-for-inbound-tests-0123456789"


@pytest.fixture()
def admin_key(monkeypatch):
    monkeypatch.setenv("UAM_ADMIN_API_KEY", ADMIN_KEY)


@pytest.fixture()
def aclient(admin_key, app):
    with TestClient(app) as c:
        yield c


def _admin():
    return {"X-Admin-Key": ADMIN_KEY}


def _register(client, name):
    from uam.protocol.crypto import generate_keypair, serialize_verify_key
    sk, vk = generate_keypair()
    resp = client.post("/api/v1/register", json={
        "agent_name": name, "public_key": serialize_verify_key(vk),
    })
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "public_key": serialize_verify_key(vk)}


def test_an_agent_starts_with_no_policy(aclient):
    bob = _register(aclient, "bob")
    resp = aclient.get(f"/api/v1/admin/agents/{bob['address']}/inbound", headers=_admin())
    assert resp.status_code == 200
    assert resp.json() == {"policy": "open", "revision": 0, "contacts": []}


def test_setting_the_policy_needs_the_current_revision(aclient):
    bob = _register(aclient, "bob")
    url = f"/api/v1/admin/agents/{bob['address']}/inbound/policy"

    missing = aclient.put(url, json={"policy": "contacts"}, headers=_admin())
    assert missing.status_code == 428

    stale = aclient.put(url, json={"policy": "contacts"},
                        headers={**_admin(), "If-Match": "7"})
    assert stale.status_code == 412

    ok = aclient.put(url, json={"policy": "contacts"},
                     headers={**_admin(), "If-Match": "0"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["revision"] == 1
    view = aclient.get(f"/api/v1/admin/agents/{bob['address']}/inbound", headers=_admin()).json()
    assert view["policy"] == "contacts" and view["revision"] == 1


def test_an_unknown_policy_is_refused(aclient):
    bob = _register(aclient, "bob")
    resp = aclient.put(f"/api/v1/admin/agents/{bob['address']}/inbound/policy",
                       json={"policy": "everyone"}, headers={**_admin(), "If-Match": "0"})
    assert resp.status_code == 422


def test_contacts_can_be_added_changed_and_removed(aclient):
    bob = _register(aclient, "bob")
    alice = _register(aclient, "alice")
    base = f"/api/v1/admin/agents/{bob['address']}/inbound/contacts/{alice['address']}"

    added = aclient.put(base, json={"key": alice["public_key"], "state": "allowed"},
                        headers=_admin())
    assert added.status_code == 200, added.text
    changed = aclient.put(base, json={"key": alice["public_key"], "state": "blocked"},
                          headers=_admin())
    assert changed.json()["revision"] > added.json()["revision"]

    view = aclient.get(f"/api/v1/admin/agents/{bob['address']}/inbound", headers=_admin()).json()
    assert view["contacts"] == [{
        "address": alice["address"], "key": alice["public_key"],
        "state": "blocked", "source": "admin", "expires_at": None,
    }]

    assert aclient.delete(base, headers=_admin()).status_code == 200
    assert aclient.delete(base, headers=_admin()).status_code == 404
    view = aclient.get(f"/api/v1/admin/agents/{bob['address']}/inbound", headers=_admin()).json()
    assert view["contacts"] == []


def test_a_contact_state_must_be_allowed_or_blocked(aclient):
    bob = _register(aclient, "bob")
    resp = aclient.put(f"/api/v1/admin/agents/{bob['address']}/inbound/contacts/alice::x",
                       json={"key": "k", "state": "requested"}, headers=_admin())
    assert resp.status_code == 422


def test_an_unknown_agent_is_404(aclient):
    resp = aclient.get("/api/v1/admin/agents/nobody::test.local/inbound", headers=_admin())
    assert resp.status_code == 404


@pytest.mark.parametrize("method,path,body", [
    ("get", "/inbound", None),
    ("put", "/inbound/policy", {"policy": "open"}),
    ("put", "/inbound/contacts/alice::x", {"key": "k", "state": "allowed"}),
    ("delete", "/inbound/contacts/alice::x", None),
])
def test_an_agent_token_cannot_use_them(aclient, method, path, body):
    bob = _register(aclient, "bob")
    headers = {"Authorization": f"Bearer {bob['token']}", "If-Match": "0"}
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    resp = getattr(aclient, method)(f"/api/v1/admin/agents/{bob['address']}{path}", **kwargs)
    assert resp.status_code == 401


def test_policy_changes_are_audited(aclient):
    bob = _register(aclient, "bob")
    aclient.put(f"/api/v1/admin/agents/{bob['address']}/inbound/policy",
                json={"policy": "closed"}, headers={**_admin(), "If-Match": "0"})
    entries = aclient.get("/api/v1/admin/audit", params={"action": "inbound_policy_set"},
                          headers=_admin()).json()["entries"]
    assert entries and entries[0]["entity_id"] == bob["address"]
    assert entries[0]["details"] == {"policy": "closed", "revision": 1}
