"""Introductions between owners (P2e, PROPOSAL v2 §4.3-4.4).

Alice invites Bob by a code she reads out, a link, or his email. An invite
holds the hash of a 128-bit secret: the link carries the secret in its
fragment, and for a code or an email the relay holds it. Bob's one passkey
approval signs his ``UamRedemption`` and his ``UamContactGrant`` naming
Alice; Alice's grant names Bob once she confirms him, or names the invite
itself when she typed his email (pre-approved).

Each sentence a passkey signs names the other person by the email the
relay checked, and says until when the approval lasts. The four words come
from the invite's hash, so both people can read them to each other.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from uam.protocol.errors import UAMError
from uam.protocol.links import relay_sig_message, word_list
from uam.protocol.signed import SignedObjectError, _parse_time, canonical, object_hash

INVITE = "UamInvite"
REDEMPTION = "UamRedemption"
GRANT = "UamContactGrant"
POLICY = "UamAgentPolicy"
WORDS = 4
_BITS = 11
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


class ContactError(UAMError):
    """An invite, a grant or a policy can't be shown or approved."""


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_secret() -> str:
    """An invite's secret: 128 random bits, base64url (22 characters)."""
    return secrets.token_urlsafe(16)


def secret_hash(secret: str) -> str:
    return _b64u(hashlib.sha256(b"UAM-INVITE-SECRET-v1\n" + secret.encode("ascii")).digest())


def email_hash(nonce: str, email: str) -> str:
    """A pre-approved invite's invitee, salted by the invite's nonce."""
    cleaned = email.strip().lower()
    return _b64u(hashlib.sha256(
        b"UAM-INVITE-EMAIL-v1\n" + nonce.encode("ascii") + cleaned.encode("utf-8")
    ).digest())


def invite_id(invite_hash: str) -> str:
    """The id in an invite's link (``/i/<id>#<secret>``)."""
    return invite_hash[:16]


def invite_words(invite_hash: str) -> list[str]:
    """Four words both owners can read aloud to check they hold one invite."""
    digest = hashlib.sha256(b"UAM-SAS-v1\n" + invite_hash.encode("ascii")).digest()
    head = int.from_bytes(digest, "big") >> (256 - WORDS * _BITS)
    words = word_list()
    mask = (1 << _BITS) - 1
    return [words[(head >> (_BITS * (WORDS - 1 - i))) & mask] for i in range(WORDS)]


def _checked(body: dict[str, Any], kind: str) -> None:
    if not isinstance(body, dict) or body.get("type") != kind:
        raise ContactError(f"expected {kind}")
    try:
        object_hash(body)
    except SignedObjectError as exc:
        raise ContactError(f"bad {kind}: {exc}") from None


def _day(value: str) -> str:
    at = _parse_time(value)
    return f"{at.day} {_MONTHS[at.month - 1]} {at.year}"


def invite_screen(grant: dict[str, Any], email: str) -> str:
    """The inviter's sentence for a pre-approved invite (invite + grant)."""
    _checked(grant, GRANT)
    return (
        f"Invite {email} to connect on YouAM. When they accept, their shared agents "
        f"can message yours until {_day(grant['validUntil'])}."
    )


def redeem_screen(grant: dict[str, Any], email: str) -> str:
    """The sentence for approving another owner (redeeming, or confirming)."""
    _checked(grant, GRANT)
    return (
        f"Connect with {email} on YouAM. Their shared agents can message yours "
        f"until {_day(grant['validUntil'])}."
    )


confirm_screen = redeem_screen


def keep_screen(grants: list[dict[str, Any]], agent: str) -> str:
    """Keeping carried-over contacts: one grant per sender, by address."""
    if not grants:
        raise ContactError("keep at least one contact")
    for grant in grants:
        _checked(grant, GRANT)
        if grant["credentialSubject"]["kind"] != "agent":
            raise ContactError("a kept contact is an agent")
    until = _day(grants[0]["validUntil"])
    names = sorted(g["credentialSubject"]["address"] for g in grants)
    if len(names) == 1:
        return f'Let "{names[0]}" keep messaging "{agent}" until {until}.'
    listed = ", ".join(f'"{n}"' for n in names)
    return f'Let {len(names)} agents keep messaging "{agent}" until {until}: {listed}.'


def policy_screen(body: dict[str, Any]) -> str:
    """Who may message the agent once the owner approves *body*."""
    _checked(body, POLICY)
    agent = body["agent"]
    if body["policy"] == "open":
        return f'Let anyone message "{agent}".'
    if body["sameOwner"]:
        return f'Let your contacts and your own agents message "{agent}".'
    return f'Let only your contacts message "{agent}".'


def policies_screen(bodies: list[dict[str, Any]], fleet: str | None = None) -> str:
    """One setting for several agents (or a fleet), named in address order."""
    if not bodies:
        raise ContactError("set at least one agent")
    for body in bodies:
        _checked(body, POLICY)
    names = sorted(body["agent"] for body in bodies)
    if len(set(names)) != len(names):
        raise ContactError("each agent once")
    if len({(body["policy"], body["sameOwner"]) for body in bodies}) != 1:
        raise ContactError("one setting for all of them")
    if fleet is not None and (
        not fleet or '"' in fleet or any(ord(c) < 32 or ord(c) == 127 for c in fleet)
    ):
        raise ContactError("a fleet's name is one line without quotes")
    if len(bodies) == 1 and fleet is None:
        return policy_screen(bodies[0])
    first = bodies[0]
    if first["policy"] == "open":
        who = "Let anyone message"
    elif first["sameOwner"]:
        who = "Let your contacts and your own agents message"
    else:
        who = "Let only your contacts message"
    count = f"{len(names)} agent" + ("" if len(names) == 1 else "s")
    which = f'the {count} in the "{fleet}" fleet' if fleet is not None else f"these {count}"
    listed = ", ".join(f'"{n}"' for n in names)
    return f"{who} {which}: {listed}."


REVOCATIONS = "UamRevocations"


def revocations_message(listing: dict[str, Any]) -> bytes:
    """What a relay signs over a page of its revocation list: the relay, the
    range (``since`` < seq <= ``through``) and the entries, in order."""
    core = {k: listing[k] for k in ("relay", "since", "through", "entries")}
    digest = _b64u(hashlib.sha256(b"UAM-REVOCATIONS-v1\n" + canonical(core)).digest())
    return relay_sig_message(REVOCATIONS, digest)
