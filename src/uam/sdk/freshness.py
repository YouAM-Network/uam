"""When to believe the relay about mail that waited in storage.

A signed timestamp cannot tell "signed, stored, delivered later" from an old
envelope replayed.  The relay's ``relay_meta`` stamp can, so long as the
recipient's own relay wrote it.  See ``uam.relay.relay_meta``.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from uam.protocol.types import MAX_ENVELOPE_AGE

RELAY_META_FEATURE = "relay_meta"

# How long stored mail stays deliverable.
STORED_MAIL_MAX_AGE = 7 * 86400


def relay_vouches(
    raw: dict, signed_at: datetime, now: datetime, relay_domain: str
) -> bool:
    """True if *raw* carries a stamp showing it was stored soon after signing.

    This only reads the stamp.  The caller must also know that the relay
    writes these stamps, or a sender could have written this one.
    """
    meta = raw.get("relay_meta")
    if not isinstance(meta, dict):
        return False
    if type(meta.get("v")) is not int or meta["v"] != 1:
        return False
    if meta.get("relay") != relay_domain:
        return False
    if meta.get("stored") is not True:
        return False

    try:
        received_at = datetime.fromisoformat(meta["received_at"].replace("Z", "+00:00"))
        gap = abs(received_at - signed_at)
    except (KeyError, AttributeError, TypeError, ValueError):
        return False

    window = timedelta(seconds=MAX_ENVELOPE_AGE)
    age = now - signed_at
    return gap <= window and timedelta(0) <= age <= (
        timedelta(seconds=STORED_MAIL_MAX_AGE) + window
    )
