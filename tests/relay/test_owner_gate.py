"""The gate's owner rules (P2e-1, v2 §5.1).

An agent whose owner chose "Only my contacts" (policy ``contacts``) takes
mail from:
- a shared agent, linked and started, of an owner its own owner approved,
  signing with the key on that link; the recipient must be shared too,
  since approvals cover only agents their owner shares;
- another agent of the same owner, unless the owner turned that off;
- as before, ``allowed`` contact rows and receipts for its own mail.

Grants and links are read on every message, so removing someone, making
an agent private or unlinking it stops delivery at once, and mail already
stored is held back.
"""

from __future__ import annotations

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    _exec,
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_invites import _connected, _invite, _redeem, bob, cat  # noqa: F401
from tests.relay.test_owner_links import _agent, _code, _linked, _redeem as _redeem_code, ada  # noqa: F401
from uam.db.crud.inbound import put_contact, set_policy
from uam.protocol import MessageType, create_envelope, to_wire_dict
from uam.protocol.didkey import ED25519, encode_did_key


def _wire(frm, to, type=MessageType.MESSAGE, **kw):
    return to_wire_dict(create_envelope(
        from_address=frm["address"], to_address=to["address"], message_type=type,
        payload_plaintext=b"hi", signing_key=frm["signing_key"],
        recipient_verify_key=to["signing_key"].verify_key, **kw,
    ))


def _send(relay, frm, to, **kw):
    resp = relay.post("/api/v1/send", json={"envelope": _wire(frm, to, **kw)},
                      headers=frm["headers"])
    assert resp.status_code == 200, resp.text
    return resp.json()["status"]


def _db(relay, fn, *args, **kw):
    import uam.db.session as sess

    async def run():
        async with sess._session_factory() as s:
            return await fn(s, *args, **kw)

    return relay.portal.call(run)


def _only_contacts(relay, agent, same_owner=True):
    _db(relay, set_policy, agent["address"], "contacts", expected_revision=0, set_by="owner")
    if not same_owner:
        _exec(relay, "UPDATE inbound_policies SET same_owner = false WHERE agent_address = :a",
              a=agent["address"])


def _private(relay, agent):
    _exec(relay, "UPDATE owner_links SET private = true WHERE agent_address = :a",
          a=agent["address"])


@pytest.fixture()
def pair(relay, ada, bob):
    """Ada and Bob connected; each has a linked agent; Bob's takes only contacts."""
    _connected(ada, bob)
    amy, _, _ = _linked(relay, ada, "amy")
    bea, _, _ = _linked(relay, bob, "bea")
    _only_contacts(relay, bea)
    return amy, bea


def test_an_approved_owners_agent_gets_through(relay, pair):
    amy, bea = pair
    assert _send(relay, amy, bea) == "stored"


def test_a_stranger_still_waits(relay, pair):
    _, bea = pair
    stranger = _agent(relay, "zed")
    assert _send(relay, stranger, bea) == "pending"


def test_an_unlinked_agent_of_no_one_waits(relay, pair, ada):
    _, bea = pair
    loose = _agent(relay, "loose")
    assert _send(relay, loose, bea) == "pending"


def test_an_approval_works_one_way(relay, ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)  # Bob approved Ada; Ada hasn't confirmed Bob
    amy, _, _ = _linked(relay, ada, "amy")
    bea, _, _ = _linked(relay, bob, "bea")
    _only_contacts(relay, amy)
    _only_contacts(relay, bea)
    assert _send(relay, amy, bea) == "stored"
    assert _send(relay, bea, amy) == "pending"


def test_removing_someone_stops_their_agents_at_once(relay, pair, bob, ada):
    amy, bea = pair
    assert bob.post(f"/api/owner/contacts/{ada.owner_id}/remove").status_code == 200
    assert _send(relay, amy, bea) == "pending"


def test_mail_already_stored_is_held_back_after_removing(relay, pair, bob, ada):
    amy, bea = pair
    assert _send(relay, amy, bea) == "stored"
    bob.post(f"/api/owner/contacts/{ada.owner_id}/remove")
    inbox = relay.get(f"/api/v1/inbox/{bea['address']}", headers=bea["headers"]).json()
    assert inbox["count"] == 0


def test_a_private_sender_is_not_covered(relay, pair):
    amy, bea = pair
    _private(relay, amy)
    assert _send(relay, amy, bea) == "pending"


def test_a_private_recipient_is_not_covered(relay, pair):
    amy, bea = pair
    _private(relay, bea)
    assert _send(relay, amy, bea) == "pending"


def test_an_unlinked_sender_is_not_covered(relay, pair):
    amy, bea = pair
    _exec(relay, "UPDATE owner_links SET state = 'unlinked', live_for = NULL "
                 "WHERE agent_address = :a", a=amy["address"])
    assert _send(relay, amy, bea) == "pending"


def test_a_link_that_has_not_started_is_not_covered(relay, pair, ada):
    from tests.relay.test_owner_links import _agent_signs, _approve, _approve_start, _links

    _, bea = pair
    old = _agent(relay, "old")
    started = _redeem_code(relay, old, _code(ada, "link")).json()
    assert _agent_signs(relay, old, started).status_code == 200
    [link] = [x for x in _links(ada) if x["agent"] == old["address"]]
    assert _approve(ada, ada.phone, _approve_start(ada, link["id"])).status_code == 200
    assert _send(relay, old, bea) == "pending"


def test_the_sender_must_sign_with_the_key_on_its_link(relay, pair):
    amy, bea = pair
    other = encode_did_key(ED25519, b"\x09" * 32)
    _exec(relay, "UPDATE owner_links SET agent_key = :k WHERE agent_address = :a",
          k=other, a=amy["address"])
    assert _send(relay, amy, bea) == "pending"


def test_an_expired_grant_lets_nothing_through(relay, pair):
    amy, bea = pair
    _exec(relay, "UPDATE owner_grants SET valid_until = '2000-01-01 00:00:00+00:00'")
    assert _send(relay, amy, bea) == "pending"


def test_a_blocked_row_beats_an_approval(relay, pair):
    amy, bea = pair
    _db(relay, put_contact, bea["address"], amy["address"],
        key="x", state="blocked", source="admin")
    assert _send(relay, amy, bea) == "pending"


def test_a_closed_agent_takes_nothing_from_contacts(relay, pair):
    amy, bea = pair
    _exec(relay, "UPDATE inbound_policies SET policy = 'closed' WHERE agent_address = :a",
          a=bea["address"])
    assert _send(relay, amy, bea) == "pending"


def test_an_open_agent_takes_anyone(relay, ada, bob):
    bea, _, _ = _linked(relay, bob, "bea")
    assert _send(relay, _agent(relay, "zed"), bea) == "stored"


# ---------------------------------------------------------------- the same owner


def test_the_same_owners_agents_get_through(relay, bob):
    bea, _, _ = _linked(relay, bob, "bea")
    bo, _, _ = _linked(relay, bob, "bo")
    _only_contacts(relay, bea)
    assert _send(relay, bo, bea) == "stored"


def test_the_same_owner_switch_turns_that_off(relay, bob):
    bea, _, _ = _linked(relay, bob, "bea")
    bo, _, _ = _linked(relay, bob, "bo")
    _only_contacts(relay, bea, same_owner=False)
    assert _send(relay, bo, bea) == "pending"


def test_a_private_agent_of_the_same_owner_gets_through(relay, bob):
    bea, _, _ = _linked(relay, bob, "bea")
    bo, _, _ = _linked(relay, bob, "bo")
    _private(relay, bo)
    _only_contacts(relay, bea)
    assert _send(relay, bo, bea) == "stored"


def test_another_owners_agent_is_not_the_same_owner(relay, ada, bob):
    amy, _, _ = _linked(relay, ada, "amy")
    bea, _, _ = _linked(relay, bob, "bea")
    _only_contacts(relay, bea)
    assert _send(relay, amy, bea) == "pending"


def test_a_third_owner_is_not_covered_by_someone_elses_approval(relay, pair, cat, ada):
    _, bea = pair
    _connected(ada, cat)  # Ada approved Cat; Bob didn't
    cid, _, _ = _linked(relay, cat, "cid")
    assert _send(relay, cid, bea) == "pending"
