"""Linking this agent to its owner's YouAM account (P2d).

The relay builds the ``UamOwnerLink`` body when the agent redeems its
owner's code; the agent signs it first. Before signing, the agent checks
that the body says what it should: this agent and key, this relay, the
kind of link it asked for, times that fit, and the four words it works
out itself. ``banner`` gives the line the CLI and SDK show while a link
is waiting or hasn't started yet.

An agent can also ask an email address to own it (P2s-3): ``ask``. Once
the owner accepts, the relay offers the link body for the agent's own
request, and the agent signs it without asking again, since asking was
its consent. It checks the body the same way first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx

from uam.protocol.address import parse_address
from uam.protocol.errors import UAMError
from uam.protocol.links import LINK, LinkError, _when, words_for
from uam.protocol.signed import SignedObjectError, _parse_time, validate

log = logging.getLogger(__name__)

#: How far the relay's clock may be from ours.
CLOCK_SKEW = timedelta(minutes=10)
#: A link for an existing agent starts this long after it is redeemed.
LINK_DELAY = timedelta(hours=72)

#: While a request is open the agent checks for the owner's answer every
#: REQUEST_POLL_FAST seconds for REQUEST_FAST_FOR seconds, then every
#: REQUEST_POLL_SLOW seconds (and on every connect).
REQUEST_POLL_FAST = 5.0
REQUEST_FAST_FOR = 30 * 60.0
REQUEST_POLL_SLOW = 10 * 60.0
#: Request states the agent still has something to do in.
REQUEST_PENDING = ("open", "waiting_for_agent")


@dataclass(frozen=True)
class LinkOffer:
    """A link body the relay built, checked and ready for the agent to sign."""

    link: int
    body: dict[str, Any]
    hash: str
    account: str
    words: list[str]


def check_offer(
    body: dict[str, Any], *, address: str, agent_key: str, via: str,
    words: list[str], now: datetime,
) -> list[str]:
    """Refuse a link body this agent shouldn't sign; return its four words."""
    try:
        validate(body)
    except SignedObjectError as exc:
        raise UAMError(f"The relay sent a link that isn't valid: {exc}") from None
    if body["type"] != LINK:
        raise UAMError("The relay sent something other than a link.")
    domain = parse_address(address).domain
    problems = []
    if body["agent"] != address:
        problems.append("it names another agent")
    if body["agentKey"] != agent_key:
        problems.append("it names another key")
    if body["relay"] != domain or body["owner"]["relay"] != domain:
        problems.append("it names another relay")
    if body["via"] != via:
        problems.append(f"it is a {body['via']} link, not a {via} link")
    if body["shared"] is not True:
        problems.append("it isn't shared with the owner's contacts")
    valid_from = _parse_time(body["validFrom"])
    if abs(valid_from - now) > CLOCK_SKEW:
        problems.append("its time is off by more than ten minutes")
    delay = LINK_DELAY if via == "link" else timedelta(0)
    if _parse_time(body["effectiveAt"]) - valid_from != delay:
        problems.append("it starts at the wrong time")
    if problems:
        raise UAMError("Not signing the link the relay sent: " + "; ".join(problems) + ".")
    try:
        own = words_for(agent_key)
    except LinkError as exc:
        raise UAMError(str(exc)) from None
    if list(words) != own:
        raise UAMError("Not signing: the relay's words for this agent don't match its key.")
    return own


def banner(status: dict[str, Any]) -> str | None:
    """The line to show for a link that is waiting or hasn't started, else None."""
    state = status.get("state")
    account = status.get("account", "")
    if state == "starts":
        return (
            f"This agent is being linked to the YouAM account {account}. "
            f"It starts on {_when(status['effectiveAt'])}. If you didn't do this, "
            "run `uam owner cancel` before then."
        )
    request = status.get("request") or {}
    if state in ("none", "cancelled", "unlinked") and request.get("state") == "open":
        return (
            "This agent asked for an owner by email. It is waiting for them to confirm, "
            f"until {_when(request['expiresAt'])}."
        )
    if state == "waiting_for_owner":
        words = " ".join(status.get("words", []))
        return (
            f"This agent asked to be linked to the YouAM account {account} and is "
            f"waiting for the owner to approve it. Its words are {words}. "
            "To stop it, run `uam owner cancel`."
        )
    return None


# --- talking to the relay ----------------------------------------------------

_UNAVAILABLE = "This relay doesn't link agents to owners yet."


class OwnerLinkRefused(UAMError):
    """The relay refused a linking step; ``code`` is its reason (e.g. ``bad_code``)."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def _refusal(resp: httpx.Response) -> OwnerLinkRefused:
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    # Our own 404 says "no_link"; any other 404 means the routes are off.
    if resp.status_code == 404 and data.get("error") != "no_link":
        return OwnerLinkRefused(_UNAVAILABLE, "unavailable")
    if "error" not in data:
        return OwnerLinkRefused(f"The relay refused: {resp.status_code}", "refused")
    return OwnerLinkRefused(str(data.get("detail") or data["error"]), str(data["error"]))


async def fetch_status(relay_url: str, token: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Where this agent's link stands; ``{"state": "unavailable"}`` if the
    relay doesn't link agents to owners."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(
            f"{relay_url}/api/v1/owner/link", headers={"Authorization": f"Bearer {token}"}
        )
    if resp.status_code == 404:  # owners are off on this relay
        return {"state": "unavailable"}
    if resp.status_code != 200:
        raise _refusal(resp)
    return resp.json()


async def redeem(relay_url: str, token: str, code: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{relay_url}/api/v1/owner/link/start", json={"code": code},
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code != 200:
        raise _refusal(resp)
    return resp.json()


async def send_signature(relay_url: str, token: str, link_hash: str, signature: str) -> None:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{relay_url}/api/v1/owner/link/sign",
            json={"hash": link_hash, "signature": signature},
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code != 200:
        raise _refusal(resp)


async def cancel(relay_url: str, token: str) -> None:
    """End this agent's link before it starts."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{relay_url}/api/v1/owner/link/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code != 200:
        raise _refusal(resp)


async def ask(relay_url: str, token: str, email: str) -> dict[str, Any]:
    """Ask *email* to own this agent: ``{detail, words, via, expiresAt}``."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{relay_url}/api/v1/owner/link/request", json={"email": email},
            headers={"Authorization": f"Bearer {token}"},
        )
    if resp.status_code != 202:
        raise _refusal(resp)
    return resp.json()
