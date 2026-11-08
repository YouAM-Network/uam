"""relay_meta: when a relay received an envelope, carried beside it.

An envelope's signature covers only its protocol fields, and every SDK
ignores top-level keys it doesn't know, so the relay can add one:

    "relay_meta": {"v": 1, "relay": "<this relay>",
                   "received_at": "<ISO time a relay first received it>",
                   "stored": <true when delivered from storage>}

Stored mail can reach its recipient long after it was signed; with
``received_at`` the recipient can accept "signed, then received promptly,
then stored" without accepting an old envelope replayed.  Its replay cache
is what stops exact replays.

Top-level ``relay_*`` keys belong to relays: whatever a sender put there is
replaced at ingress.  A federating relay's claim is kept only when that
relay names itself and the time fits the envelope's signed timestamp; the
claim sits inside the body the relay signed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from uam.protocol.types import MAX_ENVELOPE_AGE

RELAY_META_KEY = "relay_meta"
RELAY_META_VERSION = 1
# Listed in GET /api/v1/versions "features" so SDKs know they may trust it.
FEATURE = "relay_meta"

_SKEW = timedelta(seconds=MAX_ENVELOPE_AGE)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def stamp(
    envelope: dict, relay_domain: str, received_at: datetime | None = None
) -> dict:
    """A copy of *envelope* without any ``relay_*`` keys, plus this relay's stamp."""
    out = {k: v for k, v in envelope.items() if not k.startswith("relay_")}
    now = datetime.now(timezone.utc)
    received_at = received_at or now
    out[RELAY_META_KEY] = {
        "v": RELAY_META_VERSION,
        "relay": relay_domain,
        "received_at": _iso(received_at),
        # A peer outage can hold mail for hours; it may then go out live.
        "stored": now - received_at > _SKEW,
    }
    return out


def mark_stored(envelope: dict) -> dict:
    """A copy of a stored *envelope* to deliver, its stamp saying so.

    Envelopes stored before this relay stamped anything are returned as
    they are.
    """
    meta = envelope.get(RELAY_META_KEY)
    if not isinstance(meta, dict):
        return envelope
    return {**envelope, RELAY_META_KEY: {**meta, "stored": True}}


def peer_received_at(envelope: dict, from_relay: str, now: datetime) -> datetime | None:
    """The receive time the federating relay claims, if it can be believed.

    It must be ``from_relay``'s own stamp, not in the future, and within
    MAX_ENVELOPE_AGE of the envelope's signed timestamp (a relay that held
    an envelope longer than that before receiving it has nothing to vouch for).
    """
    meta = envelope.get(RELAY_META_KEY)
    if not isinstance(meta, dict) or meta.get("v") != RELAY_META_VERSION:
        return None
    if meta.get("relay") != from_relay:
        return None
    received = _parse(meta.get("received_at"))
    signed = _parse(envelope.get("timestamp"))
    if received is None or signed is None:
        return None
    if received > now + _SKEW or abs(received - signed) > _SKEW:
        return None
    return min(received, now)


def for_federation(envelope: dict, limit: int) -> dict:
    """*envelope* as it should be forwarded to a peer relay.

    The stamp adds ~110 bytes; an envelope the sender filled to the limit
    would then be refused by the peer, so it goes without its stamp (the
    peer uses its own receive time).
    """
    if RELAY_META_KEY in envelope and len(json.dumps(envelope)) > limit:
        return {k: v for k, v in envelope.items() if k != RELAY_META_KEY}
    return envelope
