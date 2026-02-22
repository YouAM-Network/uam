"""ReceivedMessage -- frozen data object for inbound messages (SDK-10).

This module enforces prompt injection isolation: the __str__ method
deliberately omits message content, forcing framework integrations to
explicitly extract .content before passing it to LLM context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
