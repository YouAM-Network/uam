"""Who may message the agents an owner links (Amir, chat 2026-11-12).

- By default only the owner's contacts and their own agents: an agent
  takes that when its link is in effect.
- The owner chooses once, after the first passkey: Only my contacts and my
  agents, or Anyone. Anyone is free before they link an agent; after, it
  needs a passkey. Choosing fewer is always free.
- A fleet's own setting comes before the owner's default, and only a
  setting that lets fewer in is applied.
- A link that starts later (an agent that was already running), or one
  made before the default existed, takes it on the relay's sweep. One whose
  owner already set it keeps that.
"""

from __future__ import annotations

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
from tests.relay.test_owner_gate import _db
from tests.relay.test_owner_invites import _approve, bob, cat  # noqa: F401
from tests.relay.test_owner_links import _linked, ada  # noqa: F401
from uam.protocol.signed import parse_body
from uam.relay.owners.policy import DEFAULT_SCREEN, settle_due


def _setting(client, link_id):
    resp = client.get(f"/api/owner/links/{link_id}/policy")
    assert resp.status_code == 200, resp.text
    return resp.json()["policy"], resp.json()["sameOwner"]


def _choose(client, policy):
    return client.post("/api/owner/agent-policy", json={"policy": policy})


def _me(client):
    return client.get("/api/owner/me").json()


def _widen_default(client):
    asked = client.post("/api/owner/agent-policy/approve/start", json={})
    assert asked.status_code == 200, asked.text
    return asked.json(), _approve(client, asked.json(), "/api/owner/agent-policy/approve")


# ---------------------------------------------------------------- the default


def test_an_owner_who_has_not_chosen_gets_only_contacts_and_their_agents(bob):
    me = _me(bob)
    assert me["agent_policy"] == "contacts" and me["agent_policy_chosen"] is False


def test_a_new_agent_takes_only_contacts_and_the_owners_agents(relay, bob):
    _, _, link = _linked(relay, bob, "bea")
    assert _setting(bob, link["id"]) == ("contacts", True)
    [row] = _rows(bob, "SELECT set_by, settled_at FROM owner_links o "
                       "JOIN inbound_policies p ON p.agent_address = o.agent_address")
    assert row["set_by"] == "owner" and row["settled_at"] is not None


def test_an_owner_who_chose_anyone_at_sign_up_links_open_agents(relay, bob):
    resp = _choose(bob, "open")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"policy": "open", "chosen": True}
    _, _, link = _linked(relay, bob, "bea")
    assert _setting(bob, link["id"]) == ("open", True)
    assert _rows(bob, "SELECT * FROM inbound_policies") == []  # nothing to narrow


def test_choosing_is_remembered(bob):
    assert _choose(bob, "contacts").status_code == 200
    me = _me(bob)
    assert me["agent_policy"] == "contacts" and me["agent_policy_chosen"] is True


@pytest.mark.parametrize("policy", ["closed", "", None, "anyone"])
def test_only_the_two_choices(bob, policy):
    assert _choose(bob, policy).status_code == 422


# ---------------------------------------------------------------- widening later


def test_anyone_needs_a_passkey_once_an_agent_is_linked(relay, bob):
    _linked(relay, bob, "bea")
    resp = _choose(bob, "open")
    assert resp.status_code == 409 and resp.json()["error"] == "needs_passkey"
    assert _me(bob)["agent_policy"] == "contacts"


def test_anyone_is_signed_with_a_passkey(relay, bob):
    _linked(relay, bob, "bea")
    asked, resp = _widen_default(bob)
    [item] = asked["items"]
    body = parse_body(item["body"])
    assert body["type"] == "UamAgentDefault" and body["policy"] == "open"
    assert body["owner"]["ownerId"] == bob.owner_id
    assert asked["screen"] == DEFAULT_SCREEN
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"policy": "open", "chosen": True}
    _, _, link = _linked(relay, bob, "cid")
    assert _setting(bob, link["id"]) == ("open", True)


def test_an_anyone_approval_works_once(relay, bob):
    _linked(relay, bob, "bea")
    asked, resp = _widen_default(bob)
    assert resp.status_code == 200
    again = _approve(bob, asked, "/api/owner/agent-policy/approve")
    assert again.status_code == 400


def test_choosing_fewer_is_always_free(relay, bob):
    _linked(relay, bob, "bea")
    _widen_default(bob)
    assert _choose(bob, "contacts").json() == {"policy": "contacts", "chosen": True}


def test_the_default_leaves_agents_already_set_alone(relay, bob):
    """It's for agents linked from now on; each agent has its own setting."""
    _, _, link = _linked(relay, bob, "bea")
    _widen_default(bob)
    assert _setting(bob, link["id"]) == ("contacts", True)


def test_another_owners_session_cannot_use_the_approval(relay, bob, ada):
    _linked(relay, bob, "bea")
    asked = bob.post("/api/owner/agent-policy/approve/start", json={}).json()
    got = bob.phone.get(asked["challenge"], rp_id=asked["rpId"], origin=OWNER_ORIGIN)
    assert ada.post("/api/owner/agent-policy/approve", json=got).status_code in (400, 409)
    assert _me(ada)["agent_policy_chosen"] is False


# ---------------------------------------------------------------- what's applied


def test_an_agent_its_owner_turned_own_agents_off_for_keeps_that(relay, bob):
    """The default lets the owner's agents in; it never widens an agent."""
    agent, _, link = _linked(relay, bob, "bea")
    _exec(relay, "UPDATE inbound_policies SET same_owner = false WHERE agent_address = :a",
          a=agent["address"])
    _exec(relay, "UPDATE owner_links SET settled_at = NULL")
    assert _db(relay, settle_due) == 1
    assert _setting(bob, link["id"]) == ("contacts", False)


def test_a_fleets_setting_comes_before_the_default(relay, ada):
    """A fleet its owner let anyone message takes new agents in open."""
    from tests.relay.test_owner_fleets import _code, _fleets, _join
    from tests.relay.test_owner_fleets import _widen as _widen_fleet

    [early] = _join(relay, ada, _code(ada, 1, "support")["code"], "early")
    assert _setting(ada, early["link"]) == ("contacts", True)
    _, resp = _widen_fleet(ada, fleet=_fleets(ada)["support"]["id"])
    assert resp.status_code == 200, resp.text
    [late] = _join(relay, ada, _code(ada, 1, "support")["code"], "late")
    assert _setting(ada, late["link"]) == ("open", True)


# ---------------------------------------------------------------- the sweep


def test_an_agent_linked_before_the_default_is_narrowed_by_the_sweep(relay, bob):
    _, _, link = _linked(relay, bob, "bea")
    # As it was before migration 0023: no setting, not settled.
    _exec(relay, "DELETE FROM inbound_policies")
    _exec(relay, "UPDATE owner_links SET settled_at = NULL")
    assert _setting(bob, link["id"]) == ("open", True)
    assert _db(relay, settle_due) == 1
    assert _setting(bob, link["id"]) == ("contacts", True)
    assert _db(relay, settle_due) == 0  # once


def test_an_agent_whose_owner_chose_keeps_it(relay, bob):
    """Migration 0023 marks those settled; the sweep leaves them."""
    _, _, link = _linked(relay, bob, "bea")
    _exec(relay, "UPDATE inbound_policies SET policy = 'open'")
    assert _db(relay, settle_due) == 0
    assert _setting(bob, link["id"]) == ("open", True)


def test_a_running_agent_takes_the_default_when_its_link_starts(relay, ada, clock):
    """An agent that was already running starts 72 hours after approval."""
    from tests.relay.test_owner_links import _agent, _agent_signs, _approve_start, _code
    from tests.relay.test_owner_links import _approve as _approve_link
    from tests.relay.test_owner_links import _links
    from tests.relay.test_owner_links import _redeem as _redeem_code

    old = _agent(relay, "old")
    started = _redeem_code(relay, old, _code(ada, "link")).json()
    _agent_signs(relay, old, started)
    [link] = _links(ada)
    _approve_link(ada, ada.phone, _approve_start(ada, link["id"]))
    assert _db(relay, settle_due) == 0  # not in effect yet
    assert _rows(ada, "SELECT * FROM inbound_policies") == []
    clock(hours=73)
    assert _db(relay, settle_due) == 1
    # The session idled out over 73 hours: read the setting itself.
    [row] = _rows(relay, "SELECT policy, same_owner FROM inbound_policies WHERE agent_address = :a",
                  a=old["address"])
    assert (row["policy"], bool(row["same_owner"])) == ("contacts", True)
