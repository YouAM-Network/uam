"""Linking, P2d-4 (DEC-006): the agent's own cancel, fleet codes, and one
passkey for a set of links.

- Whoever runs an agent can cancel a link that hasn't started yet, with
  the agent's own token. Otherwise an agent handed to a stranger's account
  (by whoever controls its process, or by a prompt) couldn't be taken back
  in the 72 hours. It only narrows, so nothing is signed, and an agent
  still can't unlink itself once the link is in effect.
- A code can be made for up to 25 agents; it lasts 30 minutes.
- The owner approves several waiting links with one Face ID over one
  sentence that names every agent and its words.
"""

from __future__ import annotations

import json
import pytest

from tests._passkey import SoftPasskey, b64u
from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    OWNER_ORIGIN,
    _on_owner_host,
    _rows,
    _sign_in,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_links import (
    _agent,
    _agent_signs,
    _approve_start,
    _linked,
    _links,
    _redeem,
    _status,
    _waiting,
    ada,  # noqa: F401
)
from tests.relay.test_owner_passkeys import RP_ID, _first_passkey, _register, _sign
from uam.protocol.links import links_challenge, links_screen
from uam.protocol.signed import object_hash, parse_body
from uam.protocol.webauthn import approval_challenge


# ---------------------------------------------------------------- the agent cancels


def _agent_cancel(relay, agent):
    return relay.post("/api/v1/owner/link/cancel", headers=agent["headers"])


def test_the_agent_cancels_a_link_waiting_for_its_owner(ada, relay):
    bob, _, link = _waiting(relay, ada, kind="link")
    resp = _agent_cancel(relay, bob)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"state": "cancelled"}
    assert _status(relay, bob)["state"] == "cancelled"
    assert _links(ada)[0]["state"] == "cancelled"
    assert ada.post(f"/api/owner/links/{link['id']}/approve/start").status_code == 409


def test_the_agent_cancels_a_link_it_never_signed(ada, relay):
    bob = _agent(relay)
    code = ada.post("/api/owner/codes", json={"kind": "link"}).json()["code"]
    assert _redeem(relay, bob, code).status_code == 200
    assert _agent_cancel(relay, bob).status_code == 200
    assert _status(relay, bob)["state"] == "cancelled"


def test_the_agent_cancels_an_approved_link_before_it_starts(ada, relay):
    bob, _, _ = _linked(relay, ada, kind="link")
    assert _status(relay, bob)["state"] == "starts"
    assert _agent_cancel(relay, bob).status_code == 200
    assert _status(relay, bob)["state"] == "cancelled"


def test_the_agent_cannot_cancel_a_link_in_effect(ada, relay):
    bob, _, _ = _linked(relay, ada)
    resp = _agent_cancel(relay, bob)
    assert resp.status_code == 409
    assert resp.json()["error"] == "not_cancellable"
    assert _status(relay, bob)["state"] == "linked"


def test_the_agent_cannot_cancel_once_72_hours_pass(ada, relay, clock):
    bob, _, _ = _linked(relay, ada, kind="link")
    clock(hours=72, seconds=1)
    assert _agent_cancel(relay, bob).status_code == 409
    assert _status(relay, bob)["state"] == "linked"


def test_an_agent_with_no_link_has_nothing_to_cancel(relay, owner_env):
    bob = _agent(relay)
    resp = _agent_cancel(relay, bob)
    assert resp.status_code == 404
    assert resp.json()["error"] == "no_link"


def test_cancelling_needs_the_agents_token(ada, relay):
    _waiting(relay, ada, kind="link")
    assert relay.post("/api/v1/owner/link/cancel").status_code in (401, 403)


def test_an_agent_cancels_only_its_own_link(ada, relay):
    bob, _, _ = _waiting(relay, ada, kind="link")
    eve = _agent(relay, "eve")
    assert _agent_cancel(relay, eve).status_code == 404
    assert _status(relay, bob)["state"] == "waiting_for_owner"


def test_the_audit_says_the_agent_cancelled(ada, relay):
    bob, _, link = _waiting(relay, ada, kind="link")
    _agent_cancel(relay, bob)
    [row] = _rows(relay, "SELECT details FROM owner_audit WHERE action = 'link_cancelled'")
    assert json.loads(row["details"]) == {"link": link["id"], "by": "agent"}


def test_the_owner_is_told_when_the_agent_cancels(ada, relay, app):
    told = []
    app.state.owner_link_notice = lambda owner_pk, view: told.append(view["state"])
    bob, _, _ = _waiting(relay, ada, kind="link")
    _agent_cancel(relay, bob)
    assert told == ["waiting", "cancelled"]


def test_the_owner_is_not_told_about_a_link_they_never_saw(ada, relay, app):
    told = []
    app.state.owner_link_notice = lambda owner_pk, view: told.append(view["state"])
    bob = _agent(relay)
    code = ada.post("/api/owner/codes", json={"kind": "link"}).json()["code"]
    assert _redeem(relay, bob, code).status_code == 200  # not signed yet
    assert _agent_cancel(relay, bob).status_code == 200
    assert told == []


def test_after_cancelling_the_agent_can_be_linked_again(ada, relay):
    bob, _, _ = _waiting(relay, ada, kind="link")
    _agent_cancel(relay, bob)
    code = ada.post("/api/owner/codes", json={"kind": "link"}).json()["code"]
    assert _redeem(relay, bob, code).status_code == 200


# ---------------------------------------------------------------- fleet codes


def _fleet_code(owner, count, kind="link"):
    resp = owner.post("/api/owner/codes", json={"kind": kind, "count": count})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_plain_code_is_for_one_agent(ada, relay):
    made = ada.post("/api/owner/codes", json={"kind": "link"}).json()
    assert made["count"] == 1
    first, second = _agent(relay, "one"), _agent(relay, "two")
    assert _redeem(relay, first, made["code"]).status_code == 200
    assert _redeem(relay, second, made["code"]).status_code == 400


def test_a_fleet_code_links_up_to_its_count(ada, relay):
    agents = [_agent(relay, f"bot{i}") for i in range(4)]
    made = _fleet_code(ada, 3)
    assert made["count"] == 3
    for agent in agents[:3]:
        assert _redeem(relay, agent, made["code"]).status_code == 200
    resp = _redeem(relay, agents[3], made["code"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_code"


def test_a_fleet_code_lasts_thirty_minutes(ada, relay, clock):
    made = _fleet_code(ada, 2)
    first, second = _agent(relay, "one"), _agent(relay, "two")
    clock(minutes=29)
    assert _redeem(relay, first, made["code"]).status_code == 200
    clock(minutes=2)
    assert _redeem(relay, second, made["code"]).status_code == 400


def test_a_plain_code_still_lasts_ten_minutes(ada, relay, clock):
    code = ada.post("/api/owner/codes", json={"kind": "link"}).json()["code"]
    bob = _agent(relay)
    clock(minutes=11)
    assert _redeem(relay, bob, code).status_code == 400


@pytest.mark.parametrize("count", [0, 26, -1, "3", 2.5, True])
def test_a_count_is_1_to_25(ada, count):
    resp = ada.post("/api/owner/codes", json={"kind": "link", "count": count})
    assert resp.status_code == 422


def test_a_fleet_setup_code_sets_up_new_agents(ada, relay):
    made = _fleet_code(ada, 2, kind="setup")
    for name in ("one", "two"):
        agent = _agent(relay, name)
        assert _redeem(relay, agent, made["code"]).status_code == 200


# ---------------------------------------------------------------- one passkey for a set


def _set_start(owner, ids):
    return owner.post("/api/owner/link-sets/approve/start", json={"ids": ids})


def _set_approve(owner, passkey, approval, *, origin=OWNER_ORIGIN):
    got = passkey.get(approval["challenge"], rp_id=RP_ID, origin=origin)
    return owner.post("/api/owner/link-sets/approve", json=got)


def _fleet_waiting(relay, owner, names, kind="link"):
    made = _fleet_code(owner, len(names), kind=kind)
    out = []
    for name in names:
        agent = _agent(relay, name)
        started = _redeem(relay, agent, made["code"])
        assert started.status_code == 200, started.text
        assert _agent_signs(relay, agent, started.json()).status_code == 200
        out.append(agent)
    by_agent = {x["agent"]: x for x in _links(owner)}
    return out, [by_agent[a["address"]] for a in out]


def test_one_passkey_approves_a_set(ada, relay):
    agents, links = _fleet_waiting(relay, ada, ["zed", "amy", "kit"])
    approval = _set_start(ada, [x["id"] for x in links])
    assert approval.status_code == 200, approval.text
    approval = approval.json()
    bodies = [parse_body(b) for b in approval["bodies"]]
    assert [b["agent"] for b in bodies] == sorted(a["address"] for a in agents)
    assert approval["screen"] == links_screen(bodies)
    assert approval["screen"].startswith("Link 3 agents to your YouAM account: ")
    assert b64u(links_challenge(bodies)) == approval["challenge"]
    resp = _set_approve(ada, ada.phone, approval)
    assert resp.status_code == 200, resp.text
    assert {x["state"] for x in resp.json()["links"]} == {"active"}
    assert {_status(relay, a)["state"] for a in agents} == {"starts"}


def test_a_set_keeps_its_hashes_for_the_proof(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["zed", "amy"])
    approval = _set_start(ada, [x["id"] for x in links]).json()
    _set_approve(ada, ada.phone, approval)
    bodies = [parse_body(b) for b in approval["bodies"]]
    hashes = [object_hash(b) for b in bodies]
    rows = _rows(relay, "SELECT hash, approval_set, screen FROM owner_links ORDER BY id")
    for row in rows:
        assert json.loads(row["approval_set"]) == hashes
        assert row["screen"] == approval["screen"]
        assert row["hash"] in hashes
    assert approval_challenge([("UamOwnerLink", h) for h in hashes], rows[0]["screen"]) == (
        links_challenge(bodies)
    )


def test_a_set_of_one_is_a_plain_approval(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy"])
    approval = _set_start(ada, [links[0]["id"]]).json()
    single = _approve_start(ada, links[0]["id"])
    assert approval["screen"] == single["screen"]
    assert approval["challenge"] == single["challenge"]
    # Same bytes, so the newest ask decides which route may use them.
    assert _set_approve(ada, ada.phone, approval).status_code == 400
    approval = _set_start(ada, [links[0]["id"]]).json()
    assert _set_approve(ada, ada.phone, approval).status_code == 200
    [row] = _rows(relay, "SELECT approval_set FROM owner_links")
    assert row["approval_set"] is None


def test_a_set_with_a_link_that_is_not_waiting_is_refused(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy", "kit"])
    ada.post(f"/api/owner/links/{links[1]['id']}/cancel")
    resp = _set_start(ada, [x["id"] for x in links])
    assert resp.status_code == 409
    assert resp.json()["error"] == "not_waiting"


def test_a_link_cancelled_after_the_ask_fails_the_whole_set(ada, relay):
    agents, links = _fleet_waiting(relay, ada, ["amy", "kit"])
    approval = _set_start(ada, [x["id"] for x in links]).json()
    _agent_cancel(relay, agents[1])
    resp = _set_approve(ada, ada.phone, approval)
    assert resp.status_code == 409
    assert {x["state"] for x in _links(ada)} == {"waiting", "cancelled"}
    assert _status(relay, agents[0])["state"] == "waiting_for_owner"


def test_a_set_cannot_hold_another_owners_link(ada, relay, app, codes):
    _, mine = _fleet_waiting(relay, ada, ["amy"])
    bo = _on_owner_host(app, relay)
    _sign_in(relay, bo, codes, email="bo@example.com")
    _first_passkey(bo)
    resp = _set_start(bo, [mine[0]["id"]])
    assert resp.status_code == 404
    assert resp.json()["error"] == "no_link"


@pytest.mark.parametrize("ids", [[], [1, 1], list(range(1, 27)), [0], ["x"]])
def test_a_set_is_1_to_25_distinct_links(ada, ids):
    assert _set_start(ada, ids).status_code == 422


def test_a_set_approval_cannot_approve_a_single_link(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy", "kit"])
    approval = _set_start(ada, [x["id"] for x in links]).json()
    got = ada.phone.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    resp = ada.post(f"/api/owner/links/{links[0]['id']}/approve", json=got)
    assert resp.status_code == 400
    assert {x["state"] for x in _links(ada)} == {"waiting"}


def test_a_single_approval_cannot_approve_a_set(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy"])
    single = _approve_start(ada, links[0]["id"])
    got = ada.phone.get(single["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    assert ada.post("/api/owner/link-sets/approve", json=got).status_code == 400


def test_a_set_approval_works_once(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy", "kit"])
    approval = _set_start(ada, [x["id"] for x in links]).json()
    got = ada.phone.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    assert ada.post("/api/owner/link-sets/approve", json=got).status_code == 200
    assert ada.post("/api/owner/link-sets/approve", json=got).status_code == 400


def test_a_set_approval_from_another_origin_is_refused(ada, relay):
    _, links = _fleet_waiting(relay, ada, ["amy", "kit"])
    approval = _set_start(ada, [x["id"] for x in links]).json()
    resp = _set_approve(ada, ada.phone, approval, origin="https://evil.example")
    assert resp.status_code == 400
    assert {x["state"] for x in _links(ada)} == {"waiting"}


def test_a_set_whose_links_name_different_key_logs_is_approved_one_by_one(ada, relay):
    _, before = _fleet_waiting(relay, ada, ["amy"])
    added = _register(ada, SoftPasskey(backup_eligible=False), "Ada laptop")
    assert _sign(ada, ada.phone, added).status_code == 200  # a new key log entry
    _, after = _fleet_waiting(relay, ada, ["kit"])
    resp = _set_start(ada, [before[0]["id"], after[0]["id"]])
    assert resp.status_code == 409
    assert resp.json()["error"] == "approve_one_by_one"
