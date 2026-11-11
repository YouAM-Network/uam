"""Linking an agent to an owner (P2d): the four words, the agent's signature
and the sentences the owner signs.

The words let a person check, by eye, that the agent on their screen is the
one their terminal shows. The agent signs the link first with its own key;
the owner's passkey signs the sentence second.
"""

from __future__ import annotations

import hashlib
from importlib import resources

import pytest
from nacl.signing import SigningKey

from uam.protocol.crypto import sign_message
from uam.protocol.didkey import ED25519, P256, encode_did_key
from uam.protocol.links import (
    LinkError,
    agent_sig_message,
    link_challenge,
    link_screen,
    links_challenge,
    links_screen,
    relay_sig_message,
    sign_as_agent,
    unlink_challenge,
    unlink_screen,
    verify_agent_signature,
    word_list,
    words_for,
)
from uam.protocol.signed import object_hash
from uam.protocol.webauthn import approval_challenge

AGENT = SigningKey(b"\x07" * 32)
AGENT_KEY = encode_did_key(ED25519, bytes(AGENT.verify_key))
OWNER = {"relay": "youam.network", "ownerId": "A" * 22, "keysHash": "B" * 43}


def _link(**over) -> dict:
    body = {
        "type": "UamOwnerLink", "v": 1, "owner": OWNER,
        "agent": "bob::youam.network", "agentKey": AGENT_KEY, "relay": "youam.network",
        "via": "setup", "shared": True,
        "effectiveAt": "2026-11-13T15:04:59Z", "validFrom": "2026-11-13T15:04:59Z",
        "nonce": "n" * 22,
    }
    body.update(over)
    return body


def _unlink(**over) -> dict:
    body = {
        "type": "UamOwnerUnlink", "v": 1, "owner": OWNER,
        "agent": "bob::youam.network", "agentKey": AGENT_KEY, "reason": "owner",
        "validFrom": "2026-11-13T15:04:59Z", "nonce": "n" * 22,
    }
    body.update(over)
    return body


# --- the word list ------------------------------------------------------------


def test_the_word_list_is_the_bip39_english_list():
    data = resources.files("uam.data").joinpath("bip39-english.txt").read_bytes()
    assert hashlib.sha256(data).hexdigest() == (
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    )
    words = word_list()
    assert len(words) == 2048 and len(set(words)) == 2048
    assert words[0] == "abandon" and words[2047] == "zoo"


# --- the four words -----------------------------------------------------------


def _expected_words(agent_key: str) -> list[str]:
    digest = hashlib.sha256(b"UAM-WORDS-v1\n" + agent_key.encode("ascii")).digest()
    bits = "".join(f"{b:08b}" for b in digest)
    return [word_list()[int(bits[i * 11:(i + 1) * 11], 2)] for i in range(4)]


def test_four_words_come_from_the_first_44_bits_of_the_key_hash():
    words = words_for(AGENT_KEY)
    assert len(words) == 4
    assert words == _expected_words(AGENT_KEY)


def test_different_keys_give_different_words():
    other = encode_did_key(ED25519, bytes(SigningKey(b"\x08" * 32).verify_key))
    assert words_for(other) != words_for(AGENT_KEY)
    assert words_for(other) == _expected_words(other)


def test_words_are_only_for_an_agent_key():
    with pytest.raises(LinkError):
        words_for(encode_did_key(P256, b"\x02" + b"\x01" * 32))
    with pytest.raises(LinkError):
        words_for("did:key:nonsense")


# --- the agent's signature ----------------------------------------------------


def test_the_agent_signs_the_type_and_the_hash():
    assert agent_sig_message("UamOwnerLink", "h" * 43) == (
        b"UAM-AGENT-SIG-v1\nUamOwnerLink\n" + b"h" * 43
    )


def test_an_agent_signature_verifies_against_its_did_key():
    body = _link()
    digest = object_hash(body)
    signature = sign_as_agent(body, AGENT)
    assert signature == sign_message(agent_sig_message("UamOwnerLink", digest), AGENT)
    verify_agent_signature(body, signature)


def test_an_agent_signature_for_another_body_is_refused():
    signature = sign_as_agent(_link(), AGENT)
    with pytest.raises(LinkError):
        verify_agent_signature(_link(nonce="m" * 22), signature)


def test_a_signature_by_another_key_is_refused():
    signature = sign_as_agent(_link(), SigningKey(b"\x08" * 32))
    with pytest.raises(LinkError):
        verify_agent_signature(_link(), signature)


def test_a_signature_over_the_hash_alone_is_refused():
    # Without the prefix and type, a signature made for something else
    # (a message envelope, another object type) could be replayed here.
    body = _link()
    bare = sign_message(object_hash(body).encode("ascii"), AGENT)
    with pytest.raises(LinkError):
        verify_agent_signature(body, bare)


def test_a_signature_made_for_an_unlink_is_not_a_link_signature():
    link = _link()
    as_unlink = sign_message(agent_sig_message("UamOwnerUnlink", object_hash(link)), AGENT)
    with pytest.raises(LinkError):
        verify_agent_signature(link, as_unlink)


def test_a_garbled_signature_is_refused():
    with pytest.raises(LinkError):
        verify_agent_signature(_link(), "not base64!")


def test_an_invalid_body_is_refused_before_signing():
    with pytest.raises(LinkError):
        sign_as_agent(_link(via="other"), AGENT)


# --- the sentences ------------------------------------------------------------


def test_the_setup_sentence_names_the_agent_and_its_words():
    words = " ".join(words_for(AGENT_KEY))
    assert link_screen(_link()) == (
        f'Link the agent "bob::youam.network" to your UAM owner account. '
        f"Its words are {words}."
    )


def test_a_link_for_an_existing_agent_says_when_it_starts():
    words = " ".join(words_for(AGENT_KEY))
    body = _link(via="link", effectiveAt="2026-11-03T09:05:59Z")
    assert link_screen(body) == (
        f'Link the agent "bob::youam.network" to your UAM owner account. '
        f"Its words are {words}. It starts on 3 Nov 2026 at 09:05 UTC."
    )


def test_the_unlink_sentence():
    assert unlink_screen(_unlink()) == (
        'Unlink the agent "bob::youam.network" from your UAM owner account.'
    )


def test_screens_refuse_the_wrong_type():
    with pytest.raises(LinkError):
        link_screen(_unlink())
    with pytest.raises(LinkError):
        unlink_screen(_link())


def test_the_link_challenge_commits_to_the_body_and_the_sentence():
    body = _link()
    assert link_challenge(body) == approval_challenge(
        [("UamOwnerLink", object_hash(body))], link_screen(body)
    )


def test_the_unlink_challenge_commits_to_the_body_and_the_sentence():
    body = _unlink()
    assert unlink_challenge(body) == approval_challenge(
        [("UamOwnerUnlink", object_hash(body))], unlink_screen(body)
    )


def test_agents_only_sign_links():
    # An agent can't unlink itself, so an agent signature on an unlink
    # (or anything else) is never accepted.
    body = _unlink()
    signature = sign_message(agent_sig_message("UamOwnerUnlink", object_hash(body)), AGENT)
    with pytest.raises(LinkError):
        verify_agent_signature(body, signature)
    with pytest.raises(LinkError):
        sign_as_agent(body, AGENT)


def test_a_relay_attests_with_its_own_prefix():
    # Not the agent prefix: a relay signature can never pass as an agent's.
    assert relay_sig_message("UamOwnerUnlink", "h" * 43) == (
        b"UAM-RELAY-SIG-v1\nUamOwnerUnlink\n" + b"h" * 43
    )


# --- a set of links, one passkey (P2d-4, DEC-006) -----------------------------

OTHER = SigningKey(b"\x08" * 32)
OTHER_KEY = encode_did_key(ED25519, bytes(OTHER.verify_key))


def test_a_set_of_one_reads_exactly_like_a_single_link():
    for body in (_link(), _link(via="link", effectiveAt="2026-11-16T15:04:59Z")):
        assert links_screen([body]) == link_screen(body)
        assert links_challenge([body]) == link_challenge(body)


def test_a_set_names_every_agent_with_its_words_sorted_by_address():
    zed = _link(agent="zed::youam.network", agentKey=OTHER_KEY)
    bob = _link()
    screen = links_screen([zed, bob])
    assert screen == (
        "Link 2 agents to your UAM owner account: "
        f'"bob::youam.network" ({" ".join(words_for(AGENT_KEY))}), '
        f'"zed::youam.network" ({" ".join(words_for(OTHER_KEY))}).'
    )
    assert links_screen([bob, zed]) == screen


def test_existing_agents_in_a_set_each_say_when_they_start():
    bob = _link(via="link", effectiveAt="2026-11-16T15:04:59Z")
    zed = _link(agent="zed::youam.network", agentKey=OTHER_KEY)
    screen = links_screen([bob, zed])
    assert f'"bob::youam.network" ({" ".join(words_for(AGENT_KEY))}, starts 16 Nov 2026 at 15:04 UTC)' in screen
    assert f'"zed::youam.network" ({" ".join(words_for(OTHER_KEY))})' in screen


def test_the_set_challenge_covers_every_hash_in_screen_order():
    zed = _link(agent="zed::youam.network", agentKey=OTHER_KEY)
    bob = _link()
    assert links_challenge([zed, bob]) == approval_challenge(
        [("UamOwnerLink", object_hash(bob)), ("UamOwnerLink", object_hash(zed))],
        links_screen([zed, bob]),
    )


@pytest.mark.parametrize("bodies", [
    [],
    [_link(), _link()],  # the same agent twice
    [_link(), _link(agent="zed::youam.network", agentKey=OTHER_KEY,
                    owner={**OWNER, "ownerId": "C" * 22})],  # two owners
    [_link(), _unlink()],
])
def test_a_set_that_does_not_fit_is_refused(bodies):
    with pytest.raises(LinkError):
        links_screen(bodies)
