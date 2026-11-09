"""ReceivedMessage -- frozen data object for inbound messages (SDK-10).

This module enforces prompt injection isolation: the __str__ method
deliberately omits message content, forcing framework integrations to
explicitly extract .content before passing it to LLM context.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

#: What the relay said about a sent message (relay/receipts.py), plus two of
#: the SDK's own: "accepted" (the relay took it but reports no status: before
#: 1.1) and "unknown" (no answer in time over WebSocket; it may have arrived).
SEND_STATUSES = (
    "delivered",
    "stored",
    "relayed",
    "queued",
    "duplicate",
    "dropped",
    "accepted",
    "unknown",
)


class SendResult(str):
    """The message id ``Agent.send()`` returns, with what the relay said.

    A ``str`` subclass, so code that treats the result as the message id keeps
    working.  ``status`` is one of SEND_STATUSES; ``delivered`` is True only
    when the relay says the recipient has it.
    """

    status: str

    def __new__(cls, message_id: str, status: str = "accepted") -> "SendResult":
        obj = super().__new__(cls, message_id)
        obj.status = status
        return obj

    @property
    def message_id(self) -> str:
        return str(self)

    @property
    def delivered(self) -> bool:
        return self.status == "delivered"

    def __repr__(self) -> str:
        return f"SendResult({str(self)!r}, status={self.status!r})"

    def __reduce__(self) -> tuple[Any, ...]:
        return (SendResult, (str(self), self.status))


def send_status(answer: Any) -> str:
    """The status in a relay's answer to a send (HTTP body or WS ack).

    ``None`` (no answer in time) is "unknown".  An answer without a known
    ``status`` comes from a relay before 1.1: "accepted".
    """
    if answer is None:
        return "unknown"
    status = answer.get("status") if isinstance(answer, dict) else None
    if status in SEND_STATUSES and status not in ("accepted", "unknown"):
        return status
    return "accepted"


@dataclass(frozen=True)
class ReceivedMessage:
    """A decrypted, verified inbound message.

    This is a DATA OBJECT. Framework integrations must explicitly
    extract .content to use in prompts. The SDK never concatenates
    message content into LLM context automatically.
    """

    message_id: str
    from_address: str
    to_address: str
    content: str  # Decrypted plaintext
    timestamp: str
    type: str
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    media_type: Optional[str] = None
    verified: bool = True  # Signature was valid
    # When the recipient's relay received it (relay_meta), or, without a
    # stamp this SDK trusts, when this SDK received it.  ISO 8601, UTC.
    received_at: Optional[str] = None

    @property
    def age_seconds(self) -> Optional[float]:
        """Seconds between the sender signing it and now; None if unknown.

        Mail can wait on a relay for days: show the age to whoever reads it.
        """
        try:
            signed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return None
        if signed.tzinfo is None:
            signed = signed.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - signed).total_seconds())

    def __str__(self) -> str:
        """Human-readable summary, NOT the content itself.

        This deliberately omits content -- it is the prompt injection
        isolation boundary (SDK-10).
        """
        return f"Message from {self.from_address} at {self.timestamp}"

    def __repr__(self) -> str:
        """Developer-friendly repr showing metadata only."""
        return (
            f"ReceivedMessage(message_id={self.message_id!r}, "
            f"from_address={self.from_address!r}, "
            f"to_address={self.to_address!r}, "
            f"type={self.type!r}, "
            f"verified={self.verified!r})"
        )
