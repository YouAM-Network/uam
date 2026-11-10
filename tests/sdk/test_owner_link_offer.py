"""The agent checks the link the relay built before signing it (P2d).

The relay writes the UamOwnerLink body; the agent's signature says "this
is me, joining that account, on these terms". So the agent refuses a body
that names another agent or key, another relay, another kind of link, or
times that don't fit, and works the four words out itself.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from nacl.signing import SigningKey

from uam.protocol import UAMError
from uam.protocol.didkey import ED25519, encode_did_key
from uam.protocol.links import words_for
from uam.sdk.owner_link import banner, check_offer

KEY = SigningKey(b"\x05" * 32)
AGENT_KEY = encode_did_key(ED25519, bytes(KEY.verify_key))
NOW = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)


def _stamp(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _body(**over) -> dict:
    body = {
        "type": "UamOwnerLink", "v": 1,
        "owner": {"relay": "test.local", "ownerId": "A" * 22, "keysHash": "B" * 43},
        "agent": "bob::test.local", "agentKey": AGENT_KEY, "relay": "test.local",
        "via": "setup", "shared": True,
        "effectiveAt": _stamp(NOW), "validFrom": _stamp(NOW), "nonce": "n" * 22,
    }
    body.update(over)
    return body


def _check(body, *, via="setup", words=None, now=NOW):
    return check_offer(
        body, address="bob::test.local", agent_key=AGENT_KEY, via=via,
        words=words if words is not None else words_for(AGENT_KEY), now=now,
    )


def test_a_good_setup_offer_passes_and_gives_the_words():
    assert _check(_body()) == words_for(AGENT_KEY)


def test_a_good_link_offer_starts_72_hours_later():
    _check(_body(via="link", effectiveAt=_stamp(NOW + timedelta(hours=72))), via="link")


@pytest.mark.parametrize("change", [
    {"agent": "eve::test.local"},
    {"agentKey": encode_did_key(ED25519, bytes(SigningKey(b"\x06" * 32).verify_key))},
    {"relay": "other.example"},
    {"owner": {"relay": "other.example", "ownerId": "A" * 22, "keysHash": "B" * 43}},
    {"shared": False},
    {"via": "link"},
    {"effectiveAt": _stamp(NOW + timedelta(hours=1))},
    {"validFrom": _stamp(NOW - timedelta(minutes=11)), "effectiveAt": _stamp(NOW - timedelta(minutes=11))},
    {"validFrom": _stamp(NOW + timedelta(minutes=11)), "effectiveAt": _stamp(NOW + timedelta(minutes=11))},
    {"type": "UamOwnerUnlink"},
    {"nonce": "short"},
])
def test_a_setup_offer_that_does_not_fit_is_refused(change):
    with pytest.raises(UAMError):
        _check(_body(**change))


def test_a_link_offer_must_wait_72_hours():
    with pytest.raises(UAMError):
        _check(_body(via="link"), via="link")


def test_words_from_the_relay_must_match_the_agents_own():
    with pytest.raises(UAMError):
        _check(_body(), words=["apple", "river", "stone", "lamp"])


def test_banners_say_where_the_link_stands():
    assert banner({"state": "none"}) is None
    assert banner({"state": "linked", "account": "a•••@example.com"}) is None
    starts = banner({
        "state": "starts", "account": "a•••@example.com",
        "effectiveAt": "2026-11-13T15:04:00Z",
    })
    assert "a•••@example.com" in starts
    assert "13 Nov 2026 at 15:04 UTC" in starts
    assert "didn't" in starts
    waiting = banner({
        "state": "waiting_for_owner", "account": "a•••@example.com",
        "words": ["apple", "river", "stone", "lamp"],
    })
    assert "a•••@example.com" in waiting and "apple river stone lamp" in waiting


def test_a_valid_object_of_another_type_is_refused_cleanly():
    unlink = {
        "type": "UamOwnerUnlink", "v": 1,
        "owner": {"relay": "test.local", "ownerId": "A" * 22, "keysHash": "B" * 43},
        "agent": "bob::test.local", "agentKey": AGENT_KEY, "reason": "owner",
        "validFrom": _stamp(NOW), "nonce": "n" * 22,
    }
    with pytest.raises(UAMError, match="other than a link"):
        _check(unlink)
