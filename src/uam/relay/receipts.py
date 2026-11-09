"""receipt.delivered: when the relay sends one, and what it looks like.

A receipt.delivered tells the sender its message reached the recipient: pushed
to an open connection, handed over by an inbox fetch or a stored-mail drain,
or accepted by the recipient's webhook.  Mail that is only stored, queued for
a peer relay or passed to a peer that didn't say "delivered" gets none.

Handshakes get none either: whether a handshake.request was seen is the
recipient's business, and the answer is its handshake.accept or nothing.
Receipts never get receipts (MSG-05 anti-loop guard).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from uam.relay.policy import is_receipt

#: What POST /send, a WebSocket ack and federation answer about one message.
#:
#: delivered  handed to the recipient (an open connection here, or a peer
#:            relay said delivered)
#: stored     waiting for the recipient to fetch it, here or at a peer relay
#: relayed    passed on with delivery unconfirmed: started to the recipient's
#:            webhook, or accepted by a peer relay that doesn't report status
#: queued     the peer relay couldn't be reached; this relay keeps retrying
#: duplicate  this message_id was accepted before; nothing new happened
#: dropped    a receipt over its rate bucket: accepted, not delivered
SEND_STATUSES: tuple[str, ...] = (
    "delivered",
    "stored",
    "relayed",
    "queued",
    "duplicate",
    "dropped",
)

#: Listed in GET /api/v1/versions "features": this relay's send answers carry
#: one of SEND_STATUSES, and receipt.delivered means delivered.
SEND_STATUS_FEATURE = "send_status"

#: In a federation deliver answer: the status field means what SEND_STATUSES
#: says.  Relays before 1.1 answered "delivered" for stored mail too.
FEDERATION_STATUS_VERSION = 1


def wants_delivery_receipt(message_type: Any) -> bool:
    """True when a message of this type earns its sender a receipt.delivered."""
    if is_receipt(message_type):
        return False
    return not (isinstance(message_type, str) and message_type.startswith("handshake."))


def delivery_receipt(message_id: str, to_address: str) -> dict:
    """The relay's receipt.delivered frame for *message_id* sent to *to_address*."""
    return {
        "type": "receipt.delivered",
        "message_id": message_id,
        "timestamp": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "to": to_address,
    }
