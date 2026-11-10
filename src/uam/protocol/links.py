"""Linking an agent to its owner (P2d).

A ``UamOwnerLink`` carries two signatures. The agent signs first, with its
own Ed25519 key, over ``"UAM-AGENT-SIG-v1\\n" + type + "\\n" + hash``; the
prefix and type keep a signature made for one thing from being replayed as
another. The owner signs second, with a passkey, over the sentence their
page showed (``link_screen``), which names the agent and its four words.

The four words are BIP39 English words taken 11 bits at a time from
``SHA-256("UAM-WORDS-v1\\n" + agentKey)``. The terminal prints them and the
owner page works them out on its own, so a person can see the two match.
"""

from __future__ import annotations

import binascii
import hashlib
from functools import lru_cache
from importlib import resources
from typing import Any

import nacl.exceptions
from nacl.signing import SigningKey, VerifyKey

from uam.protocol.crypto import sign_message, verify_signature
from uam.protocol.didkey import ED25519, InvalidDidKeyError, decode_did_key
from uam.protocol.errors import SignatureVerificationError, UAMError
from uam.protocol.signed import SignedObjectError, _parse_time, object_hash
from uam.protocol.webauthn import approval_challenge

LINK = "UamOwnerLink"
UNLINK = "UamOwnerUnlink"
WORDS = 4
_BITS = 11
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class LinkError(UAMError):
    """A link, an unlink or an agent's signature on one is not acceptable."""


@lru_cache(maxsize=1)
def word_list() -> tuple[str, ...]:
    """The BIP39 English list (2048 words), shipped in ``uam.data``."""
    text = resources.files("uam.data").joinpath("bip39-english.txt").read_text("ascii")
    return tuple(text.split())


def _agent_verify_key(agent_key: str) -> VerifyKey:
    try:
        kind, public_key = decode_did_key(agent_key)
    except InvalidDidKeyError as exc:
        raise LinkError(f"bad agent key: {exc}") from None
    if kind != ED25519:
        raise LinkError("an agent key is an Ed25519 did:key")
    return VerifyKey(public_key)


def words_for(agent_key: str) -> list[str]:
    """The four words a person checks for the agent with *agent_key*."""
    _agent_verify_key(agent_key)
    digest = hashlib.sha256(b"UAM-WORDS-v1\n" + agent_key.encode("ascii")).digest()
    head = int.from_bytes(digest, "big") >> (256 - WORDS * _BITS)
    words = word_list()
    mask = (1 << _BITS) - 1
    return [words[(head >> (_BITS * (WORDS - 1 - i))) & mask] for i in range(WORDS)]


def agent_sig_message(object_type: str, object_hash_: str) -> bytes:
    """The bytes an agent signs to put its name to a signed object."""
    return f"UAM-AGENT-SIG-v1\n{object_type}\n{object_hash_}".encode("ascii")


def relay_sig_message(object_type: str, object_hash_: str) -> bytes:
    """The bytes a relay signs to attest an object it made (an admin unlink)."""
    return f"UAM-RELAY-SIG-v1\n{object_type}\n{object_hash_}".encode("ascii")


def _hashed(body: dict[str, Any], *types: str) -> str:
    if not isinstance(body, dict) or body.get("type") not in types:
        raise LinkError(f"expected {' or '.join(types)}")
    try:
        return object_hash(body)
    except SignedObjectError as exc:
        raise LinkError(f"bad {body['type']}: {exc}") from None


def sign_as_agent(body: dict[str, Any], signing_key: SigningKey) -> str:
    """The agent's signature on a link (base64url)."""
    digest = _hashed(body, LINK)
    return sign_message(agent_sig_message(body["type"], digest), signing_key)


def verify_agent_signature(body: dict[str, Any], signature: str) -> None:
    """Check that the agent named by ``body["agentKey"]`` signed *body*."""
    digest = _hashed(body, LINK)
    key = _agent_verify_key(body["agentKey"])
    try:
        verify_signature(agent_sig_message(body["type"], digest), signature, key)
    except (SignatureVerificationError, ValueError, binascii.Error,
            nacl.exceptions.CryptoError, TypeError):
        raise LinkError("the agent's signature doesn't match this link") from None


def _when(value: str) -> str:
    at = _parse_time(value)
    return f"{at.day} {_MONTHS[at.month - 1]} {at.year} at {at:%H:%M} UTC"


def link_screen(body: dict[str, Any]) -> str:
    """The sentence the owner signs to approve a link (v1; fixed by the body)."""
    _hashed(body, LINK)
    words = " ".join(words_for(body["agentKey"]))
    text = (
        f'Link the agent "{body["agent"]}" to your UAM owner account. '
        f"Its words are {words}."
    )
    if body["via"] == "link":
        text += f" It starts on {_when(body['effectiveAt'])}."
    return text


def unlink_screen(body: dict[str, Any]) -> str:
    """The sentence the owner signs to unlink an agent."""
    _hashed(body, UNLINK)
    return f'Unlink the agent "{body["agent"]}" from your UAM owner account.'


def link_challenge(body: dict[str, Any]) -> bytes:
    """The WebAuthn challenge for approving *body* as its sentence shows it."""
    return approval_challenge([(LINK, _hashed(body, LINK))], link_screen(body))


def unlink_challenge(body: dict[str, Any]) -> bytes:
    """The WebAuthn challenge for an owner's unlink."""
    return approval_challenge([(UNLINK, _hashed(body, UNLINK))], unlink_screen(body))
