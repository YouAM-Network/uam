"""Fleets, and one setting for several agents (P2e-1b, UAM-17).

- A fleet is a named group of one owner's agents; a link is in one fleet
  at most. A code for several agents can name one: the agents linked with
  it join. An owner can also make a fleet from chosen agents, move agents
  in or out, rename it and ungroup it.
- Grouping is not a permission: none of that changes who may message
  anyone, and none of it needs a passkey.
- Several agents (or a fleet's) can be set at once. Narrowing needs no
  passkey, and a request that would widen any of them is refused whole.
  Widening is one passkey approval over one sentence naming every agent;
  each agent keeps its own signed body and the set it was signed in.
- An agent that joins a fleet later takes the fleet's setting when its link
  is in effect at once, and only if that lets fewer in. A link that starts
  after 72 hours keeps its own setting.
"""

from __future__ import annotations

import json

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    OWNER_ORIGIN,
    _on_owner_host,
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_invites import _approve, bob, cat  # noqa: F401
from tests.relay.test_owner_links import (
    _agent,
    _agent_signs,
    _linked,
    _links,
    _redeem,
    _unlink,
    ada,  # noqa: F401
)
from uam.protocol.contacts import policies_screen
from uam.protocol.signed import parse_body


def _code(owner, count, fleet=None, kind="setup"):
    resp = owner.post("/api/owner/codes", json={"kind": kind, "count": count, "fleet": fleet})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _join(relay, owner, code, *names):
    """Agents that redeem *code* and sign; the owner approves them together."""
    agents = []
    for name in names:
        agent = _agent(relay, name)
        started = _redeem(relay, agent, code)
        assert started.status_code == 200, started.text
        assert _agent_signs(relay, agent, started.json()).status_code == 200
        agent["link"] = started.json()["link"]
        agents.append(agent)
    asked = owner.post("/api/owner/link-sets/approve/start",
                       json={"ids": [a["link"] for a in agents]})
    assert asked.status_code == 200, asked.text
    assert _approve(owner, asked.json(), "/api/owner/link-sets/approve").status_code == 200
    return agents


def _fleets(owner):
    resp = owner.get("/api/owner/fleets")
    assert resp.status_code == 200, resp.text
    return {f["name"]: f for f in resp.json()["fleets"]}


def _fleet_of(owner, agent):
    return next(link["fleet"] for link in _links(owner) if link["id"] == agent["link"])


def _policy(owner, agent):
    resp = owner.get(f"/api/owner/links/{agent['link']}/policy")
    assert resp.status_code == 200, resp.text
    got = resp.json()
    return got["policy"], got["sameOwner"]


def _one(relay, owner, name):
    agent, _, link = _linked(relay, owner, name)
    agent["link"] = link["id"]
    return agent


def _set(owner, policy="contacts", same_owner=True, **which):
    return owner.post("/api/owner/policy", json={"policy": policy, "sameOwner": same_owner, **which})


def _widen(owner, policy="open", same_owner=True, **which):
    asked = owner.post("/api/owner/policy/approve/start",
                       json={"policy": policy, "sameOwner": same_owner, **which})
    assert asked.status_code == 200, asked.text
    return asked.json(), _approve(owner, asked.json(), "/api/owner/policy/approve")


def _ids(*agents):
    return [a["link"] for a in agents]


# ---------------------------------------------------------------- making fleets


def test_a_code_for_several_agents_can_name_a_fleet(relay, ada):
    made = _code(ada, 2, "support")
    assert made["fleet"]["name"] == "support"
    one, two = _join(relay, ada, made["code"], "s1", "s2")
    fleet = _fleets(ada)["support"]
    assert sorted(fleet["links"]) == sorted(_ids(one, two))
    assert _fleet_of(ada, one) == _fleet_of(ada, two) == fleet["id"]
    assert fleet["policy"] is None and fleet["sameOwner"] is None


def test_a_code_naming_a_fleet_that_exists_adds_to_it(relay, ada):
    first = _code(ada, 1, "support")
    again = _code(ada, 1, "  SUPPORT ")
    assert again["fleet"]["id"] == first["fleet"]["id"]
    assert list(_fleets(ada)) == ["support"]


def test_a_code_without_a_fleet_links_agents_on_their_own(relay, ada):
    made = _code(ada, 1)
    assert made["fleet"] is None
    [agent] = _join(relay, ada, made["code"], "solo")
    assert _fleet_of(ada, agent) is None


def test_a_fleet_made_for_a_code_is_listed_before_anyone_joins(ada):
    _code(ada, 3, "crawlers")
    assert _fleets(ada)["crawlers"]["links"] == []


def test_an_agent_that_has_not_signed_is_not_listed_yet(relay, ada):
    made = _code(ada, 2, "support")
    agent = _agent(relay, "slow")
    started = _redeem(relay, agent, made["code"]).json()
    assert _fleets(ada)["support"]["links"] == []
    resp = ada.post("/api/owner/fleets/move", json={"links": [started["link"]], "fleet": None})
    assert resp.status_code == 404
    assert _agent_signs(relay, agent, started).status_code == 200
    assert _fleets(ada)["support"]["links"] == [started["link"]]


def test_chosen_agents_make_a_fleet(relay, ada):
    one, two = _one(relay, ada, "a1"), _one(relay, ada, "a2")
    resp = ada.post("/api/owner/fleets", json={"name": "back office", "links": _ids(one, two)})
    assert resp.status_code == 200, resp.text
    assert sorted(_fleets(ada)["back office"]["links"]) == sorted(_ids(one, two))


def test_moving_agents_takes_them_out_of_their_old_fleet(relay, ada):
    one, two = _join(relay, ada, _code(ada, 2, "old")["code"], "m1", "m2")
    new = ada.post("/api/owner/fleets", json={"name": "new", "links": []}).json()
    resp = ada.post("/api/owner/fleets/move", json={"links": _ids(one), "fleet": new["id"]})
    assert resp.status_code == 200, resp.text
    fleets = _fleets(ada)
    assert fleets["new"]["links"] == _ids(one) and fleets["old"]["links"] == _ids(two)
    resp = ada.post("/api/owner/fleets/move", json={"links": _ids(two), "fleet": None})
    assert resp.status_code == 200 and _fleet_of(ada, two) is None


def test_a_fleet_is_renamed(relay, ada):
    fleet = _code(ada, 1, "suport")["fleet"]
    resp = ada.post(f"/api/owner/fleets/{fleet['id']}/rename", json={"name": "support"})
    assert resp.status_code == 200, resp.text
    assert list(_fleets(ada)) == ["support"]


def test_two_fleets_cannot_share_a_name(ada):
    _code(ada, 1, "support")
    other = _code(ada, 1, "crawlers")["fleet"]
    for resp in (
        ada.post("/api/owner/fleets", json={"name": "Support", "links": []}),
        ada.post(f"/api/owner/fleets/{other['id']}/rename", json={"name": "support"}),
    ):
        assert resp.status_code == 409 and resp.json()["error"] == "name_taken"


@pytest.mark.parametrize("name", ["", "   ", "x" * 41, "a\nb"])
def test_a_fleet_name_is_one_short_line(ada, name):
    resp = ada.post("/api/owner/fleets", json={"name": name, "links": []})
    assert resp.status_code == 422


def test_ungrouping_keeps_the_agents_and_their_settings(relay, ada):
    one, two = _join(relay, ada, _code(ada, 2, "support")["code"], "u1", "u2")
    fleet = _fleets(ada)["support"]
    assert _set(ada, fleet=fleet["id"]).status_code == 200
    resp = ada.post(f"/api/owner/fleets/{fleet['id']}/ungroup")
    assert resp.status_code == 200, resp.text
    assert _fleets(ada) == {}
    assert _fleet_of(ada, one) is None and _policy(ada, one) == ("contacts", True)


def test_an_unlinked_agent_leaves_its_fleet(relay, ada):
    one, two = _join(relay, ada, _code(ada, 2, "support")["code"], "g1", "g2")
    assert _unlink(ada, one["link"])[1].status_code == 200
    assert _fleets(ada)["support"]["links"] == _ids(two)


def test_grouping_changes_nobodys_setting(relay, ada):
    one = _one(relay, ada, "plain")
    assert _set(ada, links=_ids(one), same_owner=False).status_code == 200
    ada.post("/api/owner/fleets", json={"name": "support", "links": _ids(one)})
    assert _policy(ada, one) == ("contacts", False)
    [row] = _rows(ada, "SELECT policy, same_owner FROM inbound_policies")
    assert row["policy"] == "contacts" and not row["same_owner"]


def test_another_owners_fleets_and_agents_are_out_of_reach(relay, ada, bob):
    fleet = _code(ada, 1, "support")["fleet"]
    mine = _one(relay, ada, "mine")
    assert bob.get("/api/owner/fleets").json()["fleets"] == []
    for resp in (
        bob.post(f"/api/owner/fleets/{fleet['id']}/rename", json={"name": "x"}),
        bob.post(f"/api/owner/fleets/{fleet['id']}/ungroup"),
        bob.post("/api/owner/fleets/move", json={"links": _ids(mine), "fleet": None}),
        bob.post("/api/owner/fleets", json={"name": "x", "links": _ids(mine)}),
    ):
        assert resp.status_code == 404, resp.text
    theirs = bob.post("/api/owner/fleets", json={"name": "theirs", "links": []}).json()
    resp = ada.post("/api/owner/fleets/move", json={"links": _ids(mine), "fleet": theirs["id"]})
    assert resp.status_code == 404


def test_fleets_need_a_full_sign_in(relay):
    assert relay.get("/api/owner/fleets").status_code in (401, 404)


# ---------------------------------------------------------------- several at once


def test_narrowing_several_needs_no_passkey(relay, ada):
    one, two = _one(relay, ada, "n1"), _one(relay, ada, "n2")
    resp = _set(ada, links=_ids(one, two))
    assert resp.status_code == 200, resp.text
    assert [p["agent"] for p in resp.json()["policies"]] == sorted([one["address"], two["address"]])
    assert _policy(ada, one) == _policy(ada, two) == ("contacts", True)


def test_a_request_that_would_widen_any_of_them_changes_none(relay, ada):
    one, two = _one(relay, ada, "w1"), _one(relay, ada, "w2")
    _set(ada, links=_ids(one), same_owner=False)
    resp = _set(ada, links=_ids(one, two))
    assert resp.status_code == 409 and resp.json()["error"] == "needs_passkey"
    assert _policy(ada, one) == ("contacts", False) and _policy(ada, two) == ("open", True)


def test_widening_several_is_one_approval_naming_them_all(relay, ada):
    one, two = _one(relay, ada, "zed"), _one(relay, ada, "amy")
    _set(ada, links=_ids(one, two))
    asked, resp = _widen(ada, links=_ids(one, two))
    assert resp.status_code == 200, resp.text
    bodies = [parse_body(item["body"]) for item in asked["items"]]
    assert [b["agent"] for b in bodies] == sorted([one["address"], two["address"]])
    assert asked["screen"] == policies_screen(bodies)
    assert asked["screen"].startswith("Let anyone message these 2 agents:")
    assert _policy(ada, one) == _policy(ada, two) == ("open", True)
    rows = _rows(ada, "SELECT agent_address, hash, approval_set FROM agent_policy_approvals"
                      " ORDER BY agent_address")
    hashes = [item["hash"] for item in asked["items"]]
    assert [r["hash"] for r in rows] == hashes
    assert all(json.loads(r["approval_set"]) == hashes for r in rows)


def test_widening_one_agent_this_way_keeps_no_set(relay, ada):
    one = _one(relay, ada, "single")
    _set(ada, links=_ids(one))
    asked, resp = _widen(ada, links=_ids(one))
    assert resp.status_code == 200
    assert asked["screen"] == f'Let anyone message "{one["address"]}".'
    [row] = _rows(ada, "SELECT approval_set FROM agent_policy_approvals")
    assert row["approval_set"] is None


def test_a_fleet_is_set_by_name_and_keeps_its_setting(relay, ada):
    one, two = _join(relay, ada, _code(ada, 2, "support")["code"], "f1", "f2")
    fleet = _fleets(ada)["support"]
    assert _set(ada, fleet=fleet["id"]).status_code == 200
    assert _fleets(ada)["support"]["policy"] == "contacts"
    asked, resp = _widen(ada, fleet=fleet["id"])
    assert resp.status_code == 200, resp.text
    assert asked["screen"].startswith('Let anyone message the 2 agents in the "support" fleet:')
    got = _fleets(ada)["support"]
    assert (got["policy"], got["sameOwner"]) == ("open", True)


def test_the_approval_is_all_or_nothing(relay, ada):
    one, two = _one(relay, ada, "x1"), _one(relay, ada, "x2")
    _set(ada, links=_ids(one, two))
    asked = ada.post("/api/owner/policy/approve/start",
                     json={"policy": "open", "sameOwner": True, "links": _ids(one, two)}).json()
    assert _unlink(ada, two["link"])[1].status_code == 200
    resp = _approve(ada, asked, "/api/owner/policy/approve")
    assert resp.status_code == 409, resp.text
    assert _policy(ada, one) == ("contacts", True)


@pytest.mark.parametrize("which", [
    {"links": []},
    {"links": [1, 1]},
    {"links": list(range(1, 52))},
    {},
    {"links": [1], "fleet": 1},
])
def test_a_request_names_some_agents_or_one_fleet(ada, which):
    assert _set(ada, **which).status_code == 422


def test_only_the_owners_agents_in_effect_can_be_set(relay, ada, bob):
    mine = _one(relay, ada, "mine")
    later, _, link = _linked(relay, ada, "later", kind="link")
    for owner, ids in ((bob, _ids(mine)), (ada, [link["id"]])):
        resp = _set(owner, links=ids)
        assert resp.status_code in (404, 409), resp.text
    fleet = _code(ada, 1, "support")["fleet"]
    assert _set(bob, fleet=fleet["id"]).status_code == 404


def test_an_empty_fleet_has_nothing_to_set(ada):
    fleet = _code(ada, 2, "empty")["fleet"]
    resp = _set(ada, fleet=fleet["id"])
    assert resp.status_code == 409 and resp.json()["error"] == "no_agents"


# ---------------------------------------------------------------- joining later


def test_an_agent_that_joins_takes_the_fleets_setting(relay, ada):
    _join(relay, ada, _code(ada, 1, "support")["code"], "early")
    fleet = _fleets(ada)["support"]
    assert _set(ada, fleet=fleet["id"], same_owner=False).status_code == 200
    [late] = _join(relay, ada, _code(ada, 1, "support")["code"], "late")
    assert _fleet_of(ada, late) == fleet["id"]
    assert _policy(ada, late) == ("contacts", False)


def test_a_link_that_starts_later_keeps_its_own_setting(relay, ada):
    _join(relay, ada, _code(ada, 1, "support")["code"], "early")
    fleet = _fleets(ada)["support"]
    _set(ada, fleet=fleet["id"])
    agent = _agent(relay, "runs-already")
    code = _code(ada, 1, "support", kind="link")["code"]
    started = _redeem(relay, agent, code).json()
    assert _agent_signs(relay, agent, started).status_code == 200
    asked = ada.post(f"/api/owner/links/{started['link']}/approve/start").json()
    assert _approve(ada, asked, f"/api/owner/links/{started['link']}/approve").status_code == 200
    [row] = _rows(ada, "SELECT fleet_id FROM owner_links WHERE id = :id", id=started["link"])
    assert row["fleet_id"] == fleet["id"]
    assert _rows(ada, "SELECT policy FROM inbound_policies WHERE agent_address = :a",
                 a=agent["address"]) == []
