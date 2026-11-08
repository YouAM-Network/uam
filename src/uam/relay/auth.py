"""Authentication helpers for the UAM relay server (SEC-02 + T2.1).

Provides Bearer token auth for HTTP endpoints and token verification
for WebSocket connections.

T2.1 (Phase 43 Plan 04): bearer tokens are stored as
``HMAC-SHA-256(token, UAM_TOKEN_PEPPER)`` in ``agents.token_hash``,
NEVER in plaintext.  Lookup is by ``token_hash`` (indexed); the final
comparison uses ``hmac.compare_digest`` for constant-time defense in
depth.  A DB-only compromise yields hashes that cannot be brute-forced
back into bearer tokens without also stealing the env-var pepper.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent
from uam.db.session import get_session
from uam.relay.config import settings
from uam.relay.token_hashing import hash_token

bearer_scheme = HTTPBearer()


async def _agent_for_token(session: AsyncSession, token: str) -> Agent:
    """Return the agent *token* belongs to, or raise ``HTTPException(401)``.

    T2.1: looks up by HMAC-SHA-256 hash of the incoming token.  Final
    ``hmac.compare_digest`` check is constant-time defense in depth --
    the row already matched by hash, but ``compare_digest`` documents
    intent and protects against future "look up by some other field"
    mistakes.
    """
    token_hash = hash_token(token, settings.token_pepper)
    stmt = select(Agent).where(Agent.token_hash == token_hash)
    result = await session.execute(stmt)
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    # Defense-in-depth constant-time check on the matched row
    if not hmac.compare_digest(agent.token_hash or "", token_hash):
        raise HTTPException(status_code=401, detail="Invalid token")
    return agent


async def verify_token_http(
    session: AsyncSession = Depends(get_session),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """FastAPI dependency: validate Bearer token and return agent info.

    Returns ``{"address": ..., "public_key": ...}`` on success.
    Raises ``HTTPException(401)`` on an invalid token, or if the agent is
    suspended or deactivated.

    NOTE: Returns a dict (not SQLModel instance) to maintain backward
    compatibility with route handlers that use ``agent["address"]``.
    """
    agent = await _agent_for_token(session, credentials.credentials)
    if agent.status != "active":
        raise HTTPException(status_code=401, detail="Agent is not active")
    return {"address": agent.address, "public_key": agent.public_key}


async def verify_token_for_reactivation(
    session: AsyncSession = Depends(get_session),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """As :func:`verify_token_http`, but a deactivated agent may come back.

    A suspended agent may not: suspending is not the agent's to undo.
    """
    agent = await _agent_for_token(session, credentials.credentials)
    if agent.status not in ("active", "deactivated"):
        raise HTTPException(status_code=401, detail="Agent is not active")
    return {"address": agent.address, "public_key": agent.public_key}


async def verify_token_ws(
    token: str,
) -> dict | None:
    """Verify a token for WebSocket connections.

    Returns ``{"address": ..., "public_key": ...}`` or ``None``.
    Does NOT raise -- WebSocket auth must close the connection manually.

    T2.1: same hash-based lookup + constant-time comparison as
    ``verify_token_http``.

    Uses the singleton session factory (initialized during lifespan) since
    WS auth happens before the connection is accepted (no FastAPI Depends).
    """
    if not token:
        return None

    from uam.db.engine import get_engine
    from uam.db.session import init_session_factory

    token_hash = hash_token(token, settings.token_pepper)
    factory = await init_session_factory(get_engine())
    async with factory() as session:
        stmt = select(Agent).where(Agent.token_hash == token_hash)
        result = await session.execute(stmt)
        agent = result.scalar_one_or_none()
        if agent is None:
            return None
        if not hmac.compare_digest(agent.token_hash or "", token_hash):
            return None
        if agent.status != "active":
            return None
        return {"address": agent.address, "public_key": agent.public_key}
