"""Ephemeral session management for the landing-page demo widget.

Each demo session creates a real Ed25519 keypair and registers the
ephemeral agent in the relay database.  The relay holds the private key
so it can sign outgoing envelopes and decrypt incoming ones on behalf
of the browser -- the browser never sees raw key material.

Sessions expire after a configurable TTL (default 10 minutes) and are
pruned by a background task in ``app.py``.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from uam.protocol.crypto import (
    generate_keypair,
    serialize_signing_key,
    serialize_verify_key,
)


@dataclass
class EphemeralSession:
    """State for a single demo widget session."""

    session_id: str
    address: str
    token: str
    signing_key_b64: str
    verify_key_b64: str
    created_at: datetime
    expires_at: datetime


class SessionManager:
    """In-memory store for ephemeral demo sessions.

    Thread-safe via ``asyncio.Lock`` (all mutations go through the lock).
    """

    def __init__(self, ttl_minutes: int = 10, max_sessions: int = 1000) -> None:
        self._sessions: dict[str, EphemeralSession] = {}
        self._lock = asyncio.Lock()
        self._ttl = timedelta(minutes=ttl_minutes)
        self._max_sessions = max_sessions

    async def create(self, relay_domain: str) -> EphemeralSession:
        """Create a new ephemeral session with a fresh Ed25519 keypair.

        If the session store is at capacity, the oldest session is evicted.
        """
        sk, vk = generate_keypair()
        agent_name = f"demo-{secrets.token_urlsafe(6)}"
        session_id = secrets.token_urlsafe(32)
        token = secrets.token_urlsafe(32)
        address = f"{agent_name}::{relay_domain}"
        now = datetime.now(timezone.utc)

        session = EphemeralSession(
            session_id=session_id,
            address=address,
            token=token,
            signing_key_b64=serialize_signing_key(sk),
            verify_key_b64=serialize_verify_key(vk),
            created_at=now,
            expires_at=now + self._ttl,
        )

        async with self._lock:
            # Evict oldest if at capacity
            if len(self._sessions) >= self._max_sessions:
                oldest_key = min(
                    self._sessions,
                    key=lambda k: self._sessions[k].created_at,
                )
                del self._sessions[oldest_key]
            self._sessions[session_id] = session

        return session

    async def get(self, session_id: str) -> Optional[EphemeralSession]:
        """Return the session if it exists and has not expired.

        Expired sessions are removed on access and ``None`` is returned.
        """
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if datetime.now(timezone.utc) >= session.expires_at:
                del self._sessions[session_id]
                return None
            return session

    async def cleanup_expired(self) -> int:
        """Remove all expired sessions.  Returns the number removed."""
        now = datetime.now(timezone.utc)
        async with self._lock:
            expired_keys = [
                k for k, s in self._sessions.items() if now >= s.expires_at
            ]
            for k in expired_keys:
                del self._sessions[k]
        return len(expired_keys)
