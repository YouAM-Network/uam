"""Who may message an agent, set by its owner (P2e-1, v2 §5.2).

- An owner sees each linked agent's policy: Anyone (``open``) or Only my
  contacts (``contacts``), and whether their own other agents get through.
- Narrowing needs no passkey. Widening (to Anyone, or letting their own
  agents through again) needs a signed ``UamAgentPolicy``.
- Narrowing to Only my contacts sets aside the contacts the agent had
  before (carried over): nothing is kept unless the owner keeps it, with a
  passkey, as a grant for that sender's address and key. Recent ones, and
  ones with no two-way traffic, are marked to warn.
- Nothing an agent's own token can reach widens anything.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    OWNER_ORIGIN,
    _exec,
    _on_owner_host,
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_gate import _db, _send
from tests.relay.test_owner_invites import _approve, bob, cat  # noqa: F401
from tests.relay.test_owner_links import _agent, _linked, ada  # noqa: F401
from uam.db.crud.inbound import put_contact
from uam.protocol.contacts import keep_screen, policy_screen
from uam.protocol.signed import parse_body


@pytest.fixture()
def bea(relay, bob):
    agent, _, link = _linked(relay, bob, "bea")
    agent["link"] = link["id"]
    return agent


def _policy(client, agent):
    resp = client.get(f"/api/owner/links/{agent['link']}/policy")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _narrow(client, agent, policy="contacts", same_owner=True):
    return client.post(f"/api/owner/links/{agent['link']}/policy",
                       json={"policy": policy, "sameOwner": same_owner})


def _widen(client, agent, policy="open", same_owner=True):
    asked = client.post(f"/api/owner/links/{agent['link']}/policy/approve/start",
                        json={"policy": policy, "sameOwner": same_owner})
    assert asked.status_code == 200, asked.text
    return asked.json(), _approve(client, asked.json(),
                                  f"/api/owner/links/{agent['link']}/policy/approve")


def _carry(relay, agent, sender, **kw):
    _db(relay, put_contact, agent["address"], sender["address"],
        key=sender["public_key"], state="allowed", source="admin")
    for column, value in kw.items():
        _exec(relay, f"UPDATE inbound_contacts SET {column} = :v WHERE contact_address = :a",
              v=value, a=sender["address"])


def _with_public_key(agent):
    from uam.protocol.crypto import serialize_verify_key

    agent["public_key"] = serialize_verify_key(agent["signing_key"].verify_key)
    return agent


# ---------------------------------------------------------------- reading


def test_a_new_link_takes_only_contacts_and_the_owners_agents(bob, bea):
    got = _policy(bob, bea)
    assert got["policy"] == "contacts" and got["sameOwner"] is True
    assert got["carriedOver"] == [] and got["kept"] == []


def test_the_agent_list_says_who_can_message_each(bob, bea):
    """The page's list shows every agent's setting without asking for each."""
    def listed():
        [link] = [x for x in bob.get("/api/owner/links").json()["links"] if x["id"] == bea["link"]]
        return link["policy"], link["sameOwner"]

    assert listed() == ("contacts", True)
    assert _narrow(bob, bea, "contacts", False).status_code == 200
    assert listed() == ("contacts", False)


def test_only_the_owner_sees_an_agents_policy(ada, bea):
    assert ada.get(f"/api/owner/links/{bea['link']}/policy").status_code == 404


def test_a_link_that_has_not_started_has_no_policy_yet(relay, ada):
    from tests.relay.test_owner_links import _agent_signs, _approve as _approve_link
    from tests.relay.test_owner_links import _approve_start, _code, _links
    from tests.relay.test_owner_links import _redeem as _redeem_code

    old = _agent(relay, "old")
    started = _redeem_code(relay, old, _code(ada, "link")).json()
    _agent_signs(relay, old, started)
    [link] = _links(ada)
    _approve_link(ada, ada.phone, _approve_start(ada, link["id"]))
    resp = ada.get(f"/api/owner/links/{link['id']}/policy")
    assert resp.status_code == 409 and resp.json()["error"] == "not_started"


# ---------------------------------------------------------------- narrowing


def test_narrowing_needs_no_passkey(bob, bea):
    resp = _narrow(bob, bea)
    assert resp.status_code == 200, resp.text
    assert resp.json()["policy"] == "contacts"
    [row] = _rows(bob, "SELECT policy, set_by, same_owner FROM inbound_policies")
    assert row["policy"] == "contacts" and row["set_by"] == "owner" and row["same_owner"]


def test_turning_off_the_same_owner_needs_no_passkey(bob, bea):
    _narrow(bob, bea)
    resp = _narrow(bob, bea, same_owner=False)
    assert resp.status_code == 200 and resp.json()["sameOwner"] is False


@pytest.mark.parametrize("start, then", [
    (("contacts", True), ("open", True)),
    (("contacts", False), ("contacts", True)),
])
def test_widening_without_a_passkey_is_refused(bob, bea, start, then):
    _narrow(bob, bea, *start)
    resp = _narrow(bob, bea, *then)
    assert resp.status_code == 409 and resp.json()["error"] == "needs_passkey"
    assert _policy(bob, bea)["policy"] == start[0]


def test_a_closed_agent_is_widened_only_with_a_passkey(relay, bob, bea):
    _narrow(bob, bea)
    _exec(relay, "UPDATE inbound_policies SET policy = 'closed'")
    resp = _narrow(bob, bea, "contacts")
    assert resp.status_code == 409 and resp.json()["error"] == "needs_passkey"


@pytest.mark.parametrize("policy", ["closed", "anyone", ""])
def test_an_owner_sets_open_or_contacts(bob, bea, policy):
    assert _narrow(bob, bea, policy).status_code == 422


# ---------------------------------------------------------------- widening


def test_widening_signs_who_may_message_the_agent(bob, bea):
    _narrow(bob, bea)
    asked, resp = _widen(bob, bea)
    [item] = asked["items"]
    body = parse_body(item["body"])
    assert body["type"] == "UamAgentPolicy" and body["agent"] == bea["address"]
    assert body["agentKey"] == bea["key"] and body["policy"] == "open"
    assert body["owner"]["ownerId"] == bob.owner_id
    assert asked["screen"] == policy_screen(body) == f'Let anyone message "{bea["address"]}".'
    assert resp.status_code == 200, resp.text
    assert resp.json()["policy"] == "open"
    [row] = _rows(bob, "SELECT agent_address, screen FROM agent_policy_approvals")
    assert row["agent_address"] == bea["address"] and row["screen"] == asked["screen"]


def test_turning_the_same_owner_back_on_is_signed(bob, bea):
    _narrow(bob, bea, "contacts", False)
    asked, resp = _widen(bob, bea, "contacts", True)
    assert asked["screen"].startswith("Let your contacts and your own agents message")
    assert resp.json()["sameOwner"] is True


def test_a_policy_approval_works_once(bob, bea):
    _narrow(bob, bea)
    asked, resp = _widen(bob, bea)
    again = _approve(bob, asked, f"/api/owner/links/{bea['link']}/policy/approve")
    assert again.status_code == 400


def test_a_policy_approval_is_for_its_own_agent(relay, bob, bea):
    bo, _, link = _linked(relay, bob, "bo")
    _narrow(bob, bea)
    asked = bob.post(f"/api/owner/links/{bea['link']}/policy/approve/start",
                     json={"policy": "open", "sameOwner": True}).json()
    resp = _approve(bob, asked, f"/api/owner/links/{link['id']}/policy/approve")
    assert resp.status_code == 409
    assert _policy(bob, bea)["policy"] == "contacts"


# ---------------------------------------------------------------- carried over


def test_narrowing_sets_carried_over_contacts_aside(relay, bob, bea):
    old = _with_public_key(_agent(relay, "old"))
    _carry(relay, bea, old)
    [now] = _rows(relay, "SELECT revision FROM inbound_policies WHERE agent_address = :a",
                  a=bea["address"])
    _db(relay, lambda s: __import__("uam.db.crud.inbound", fromlist=["x"]).set_policy(
        s, bea["address"], "open", expected_revision=now["revision"], set_by="admin"))
    assert _send(relay, old, bea) == "stored"
    got = _narrow(bob, bea).json()
    assert [c["address"] for c in got["carriedOver"]] == [old["address"]]
    assert got["carriedOver"][0]["kept"] is False
    assert _send(relay, old, bea) == "pending"


def test_recent_or_one_way_contacts_are_marked_to_warn(relay, bob, bea):
    fresh = _with_public_key(_agent(relay, "fresh"))
    _carry(relay, bea, fresh)
    [got] = _narrow(bob, bea).json()["carriedOver"]
    assert got["recent"] is True and got["twoWay"] is False and got["warn"] is True


def test_an_old_two_way_contact_is_not_warned(relay, bob, bea):
    pal = _with_public_key(_agent(relay, "pal"))
    _carry(relay, bea, pal, created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    assert _send(relay, pal, bea) == "stored"
    assert _send(relay, bea, pal) == "stored"
    [got] = _narrow(bob, bea).json()["carriedOver"]
    assert got["recent"] is False and got["twoWay"] is True and got["warn"] is False


def _keep(client, agent, addresses):
    asked = client.post(f"/api/owner/links/{agent['link']}/keep/start",
                        json={"contacts": addresses})
    assert asked.status_code == 200, asked.text
    return asked.json(), _approve(client, asked.json(), f"/api/owner/links/{agent['link']}/keep")


def test_keeping_a_carried_over_contact_is_signed_per_sender(relay, bob, bea):
    old = _with_public_key(_agent(relay, "old"))
    _carry(relay, bea, old)
    _narrow(bob, bea)
    asked, resp = _keep(bob, bea, [old["address"]])
    [grant] = [parse_body(x["body"]) for x in asked["items"]]
    assert grant["credentialSubject"] == {"kind": "agent", "id": old["key"],
                                          "address": old["address"]}
    assert grant["authorization_details"][0]["locations"] == [bea["address"]]
    assert grant["via"] == "carried_over"
    assert asked["screen"] == keep_screen([grant], bea["address"])
    assert resp.status_code == 200, resp.text
    [kept] = resp.json()["kept"]
    assert kept["address"] == old["address"] and kept["until"]
    assert _send(relay, old, bea) == "stored"


def test_a_kept_contact_is_bound_to_its_key(relay, bob, bea):
    old = _with_public_key(_agent(relay, "old"))
    _carry(relay, bea, old)
    _narrow(bob, bea)
    _keep(bob, bea, [old["address"]])
    _exec(relay, "UPDATE owner_grants SET subject_key = 'did:key:z6MkOther'")
    assert _send(relay, old, bea) == "pending"


def test_a_kept_contact_ends_if_the_recipient_changes_key(relay, bob, bea):
    old = _with_public_key(_agent(relay, "old"))
    _carry(relay, bea, old)
    _narrow(bob, bea)
    _keep(bob, bea, [old["address"]])
    _exec(relay, "UPDATE owner_grants SET location_keys = :k",
          k='{"%s": "did:key:z6MkOther"}' % bea["address"])
    assert _send(relay, old, bea) == "pending"


def test_only_carried_over_contacts_can_be_kept(relay, bob, bea):
    stranger = _agent(relay, "zed")
    _narrow(bob, bea)
    resp = bob.post(f"/api/owner/links/{bea['link']}/keep/start",
                    json={"contacts": [stranger["address"]]})
    assert resp.status_code == 409 and resp.json()["error"] == "not_carried_over"


def test_keeping_several_takes_one_passkey(relay, bob, bea):
    a = _with_public_key(_agent(relay, "aa"))
    z = _with_public_key(_agent(relay, "zz"))
    _carry(relay, bea, a)
    _carry(relay, bea, z)
    _narrow(bob, bea)
    asked, resp = _keep(bob, bea, [z["address"], a["address"]])
    assert asked["screen"].startswith(f'Let 2 agents keep messaging "{bea["address"]}"')
    assert resp.status_code == 200
    assert {k["address"] for k in resp.json()["kept"]} == {a["address"], z["address"]}


# ---------------------------------------------------------------- an agent can't widen


WIDENING = [
    ("post", "/api/owner/links/1/policy", {"policy": "open", "sameOwner": True}),
    ("post", "/api/owner/links/1/policy/approve/start", {"policy": "open", "sameOwner": True}),
    ("post", "/api/owner/links/1/policy/approve", {}),
    ("post", "/api/owner/links/1/keep/start", {"contacts": ["a::b.c"]}),
    ("post", "/api/owner/links/1/keep", {}),
    ("post", "/api/owner/invites/redeem/start", {"code": "AAAA-AAAA"}),
    ("post", "/api/owner/invites/redeem", {}),
    ("post", "/api/owner/invites/1/confirm/start", {}),
    ("post", "/api/owner/invites/1/confirm", {}),
    ("post", "/api/owner/invites/email/start", {"email": "a@b.co"}),
    ("post", "/api/owner/invites/email", {}),
    ("post", "/api/owner/invites", {"how": "code"}),
]


@pytest.mark.parametrize("method, path, body", WIDENING)
def test_an_agents_token_opens_no_widening_route_on_the_owner_origin(
    relay, app, bea, method, path, body
):
    as_agent = _on_owner_host(app, relay)
    as_agent.cookies.clear()
    resp = getattr(as_agent, method)(path, json=body, headers=bea["headers"])
    assert resp.status_code == 401


@pytest.mark.parametrize("method, path, body", [
    ("PUT", "/policy", {"policy": "open", "expected_revision": 1}),
    ("PUT", "/contacts/x::y.z", {"key": "k", "state": "allowed"}),
    ("DELETE", "/contacts/x::y.z", None),
])
def test_an_agents_token_cannot_use_the_admin_inbound_routes(relay, bea, method, path, body):
    url = f"/api/v1/admin/agents/{bea['address']}/inbound{path}"
    resp = relay.request(method, url, json=body, headers=bea["headers"])
    assert resp.status_code == 401


def test_the_agent_api_has_no_route_that_sets_who_may_message_it(app):
    agent_routes = [
        (sorted(r.methods), r.path) for r in app.routes
        if getattr(r, "path", "").startswith("/api/v1/") and "/admin/" not in r.path
        and any(w in r.path for w in ("policy", "inbound", "contact", "grant", "invite", "keep"))
    ]
    assert agent_routes == [], agent_routes
