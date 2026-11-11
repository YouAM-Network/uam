"""The owner page's own checks for links (P2d-3).

Before a passkey approves a link, a set of links or an unlink, the page
works out the agent's four words and the sentence itself, from the bodies
the relay sent, and recomputes each hash and the challenge. It refuses
anything it didn't work out the same way. These run in Node on bodies the
Python code builds.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from importlib import resources

import pytest
from nacl.signing import SigningKey

from tests._passkey import b64u
from tests.relay.test_owner_page import CHECK, STATIC
from uam.protocol.didkey import ED25519, encode_did_key
from uam.protocol.links import (
    link_challenge,
    link_screen,
    links_challenge,
    links_screen,
    unlink_challenge,
    unlink_screen,
    words_for,
)
from uam.protocol.signed import canonical, object_hash
from uam.protocol.webauthn import approval_challenge

OWNER_ID = "A" * 22
OWNER = {"relay": "youam.network", "ownerId": OWNER_ID, "keysHash": "B" * 43}
KEYS = [encode_did_key(ED25519, bytes(SigningKey(bytes([n]) * 32).verify_key)) for n in range(1, 6)]


def _link(n=0, agent="bob::youam.network", **over):
    body = {
        "type": "UamOwnerLink", "v": 1, "owner": OWNER, "agent": agent, "agentKey": KEYS[n],
        "relay": "youam.network", "via": "setup", "shared": True,
        "effectiveAt": "2026-11-13T15:04:59Z", "validFrom": "2026-11-13T15:04:59Z",
        "nonce": "n" * 22,
    }
    body.update(over)
    return body


def _unlink(**over):
    body = {
        "type": "UamOwnerUnlink", "v": 1, "owner": OWNER, "agent": "bob::youam.network",
        "agentKey": KEYS[0], "reason": "owner", "validFrom": "2026-11-13T15:04:59Z",
        "nonce": "n" * 22,
    }
    body.update(over)
    return body


def _one(body, screen_fn, challenge_fn, **lie):
    answer = {
        "body": canonical(body).decode(), "hash": object_hash(body), "screen": screen_fn(body),
        "challenge": b64u(challenge_fn(body)),
    }
    answer.update(lie)
    return answer


def _set(group, **lie):
    ordered = sorted(group, key=lambda b: b["agent"])
    answer = {
        "bodies": [canonical(b).decode() for b in ordered],
        "hashes": [object_hash(b) for b in ordered],
        "screen": links_screen(group), "challenge": b64u(links_challenge(group)),
    }
    answer.update(lie)
    return answer


LATER = {"via": "link", "effectiveAt": "2026-11-16T15:04:59Z"}
FLEET = [_link(0, "zed::youam.network"), _link(1, "amy::youam.network", **LATER),
         _link(2, "kit::youam.network")]

GOOD = {
    "link_setup": ("link", _one(_link(), link_screen, link_challenge)),
    "link_existing": ("link", _one(_link(**LATER), link_screen, link_challenge)),
    "unlink": ("unlink", _one(_unlink(), unlink_screen, unlink_challenge)),
    "set_of_three": ("links", _set(FLEET)),
    "set_of_one": ("links", _set([_link()])),
}
EXPECTED = {
    "link_setup": link_screen(_link()),
    "link_existing": link_screen(_link(**LATER)),
    "unlink": unlink_screen(_unlink()),
    "set_of_three": links_screen(FLEET),
    "set_of_one": link_screen(_link()),
}
other = _link(3, "eve::youam.network")
BAD = {
    # A relay that shows one sentence and asks for another to be signed.
    "lying_screen": ("link", _one(_link(), link_screen, link_challenge,
                                  screen=link_screen(other))),
    "wrong_words": ("link", _one(_link(), link_screen, link_challenge,
                                 screen=link_screen(_link()).replace(
                                     " ".join(words_for(KEYS[0])), "apple river stone lamp"))),
    "wrong_hash": ("link", _one(_link(), link_screen, link_challenge, hash=object_hash(other))),
    "wrong_challenge": ("link", _one(_link(), link_screen, link_challenge,
                                     challenge=b64u(link_challenge(other)))),
    "dropped_start_time": ("link", _one(_link(**LATER), link_screen, link_challenge,
                                        screen=link_screen(_link()))),
    "unlink_as_link": ("link", _one(_unlink(), unlink_screen, unlink_challenge)),
    "link_as_unlink": ("unlink", _one(_link(), link_screen, link_challenge)),
    "another_owner": ("link", _one(_link(owner={**OWNER, "ownerId": "C" * 22}), link_screen,
                                   link_challenge)),
    "quote_in_address": ("link", None),  # filled in below: consistent but for the address
    "set_missing_an_agent": ("links", _set(FLEET, screen=links_screen(FLEET[:2]))),
    "set_with_a_swapped_hash": ("links", _set(FLEET, hashes=[object_hash(other)] + [
        object_hash(b) for b in sorted(FLEET, key=lambda b: b["agent"])][1:])),
    "set_challenge_for_fewer": ("links", _set(FLEET, challenge=b64u(links_challenge(FLEET[:2])))),
    "set_out_of_order": ("links", _set(FLEET, bodies=[canonical(b).decode() for b in FLEET],
                                       hashes=[object_hash(b) for b in FLEET])),
}


def _consistent(body: dict) -> dict:
    """Hash, sentence and challenge that agree with *body*, as the page would
    work them out, even for a body the relay's schema would refuse."""
    text = canonical(body).decode()
    h = b64u(hashlib.sha256(b"UAM-UamOwnerLink-v1\n" + text.encode()).digest())
    screen = (f'Link the agent "{body["agent"]}" to your YouAM account. '
              f'Its words are {" ".join(words_for(body["agentKey"]))}.')
    return {"body": text, "hash": h, "screen": screen,
            "challenge": b64u(approval_challenge([("UamOwnerLink", h)], screen))}


BAD["quote_in_address"] = ("link", _consistent(_link(agent='bob" to you. Its::youam.network')))


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    cases = {
        "approvals": [], "labels": [], "dates": [],
        "links": [{"name": n, "kind": k, "answer": a, "ownerId": OWNER_ID}
                  for n, (k, a) in {**GOOD, **BAD}.items()],
        "agentKeys": KEYS,
    }
    path = tmp_path_factory.mktemp("links") / "cases.json"
    path.write_text(json.dumps(cases))
    run = subprocess.run([node, str(CHECK), str(STATIC / "owner.js"), str(path)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    out["links"] = {x["name"]: x for x in out["links"]}
    return out


def test_the_page_ships_the_bip39_list(checked):
    text = resources.files("uam.data").joinpath("bip39-english.txt").read_text("ascii")
    assert checked["wordList"] == " ".join(text.split())


def test_the_page_works_out_the_same_four_words(checked):
    assert checked["words"] == {key: words_for(key) for key in KEYS}


@pytest.mark.parametrize("name", sorted(GOOD))
def test_the_page_signs_the_sentence_the_relay_would(checked, name):
    result = checked["links"][name]
    assert result["ok"], result
    assert result["screen"] == EXPECTED[name]


@pytest.mark.parametrize("name", sorted(BAD))
def test_the_page_refuses_what_it_did_not_work_out_itself(checked, name):
    assert not checked["links"][name]["ok"], checked["links"][name]
