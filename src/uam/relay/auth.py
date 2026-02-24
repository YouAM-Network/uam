"""Authentication helpers for the UAM relay server (SEC-02).

Provides Bearer token auth for HTTP endpoints and token verification
for WebSocket connections.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent
from uam.db.session import get_session

bearer_scheme = HTTPBearer()


async def verify_token_http(
    session: AsyncSession = Depends(get_session),
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """FastAPI dependency: validate Bearer token and return agent info.

    Returns ``{"address": ..., "public_key": ...}`` on success.
    Raises ``HTTPException(401)`` on invalid token.

    NOTE: Returns a dict (not SQLModel instance) to maintain backward
    compatibility with route handlers that use ``agent["address"]``.
    """
    stmt = select(Agent).where(Agent.token == credentials.credentials)
    result = await session.execute(stmt)
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"address": agent.address, "public_key": agent.public_key}


async def verify_token_ws(
    token: str,
) -> dict | None:
    """Verify a token for WebSocket connections.

    Returns ``{"address": ..., "public_key": ...}`` or ``None``.
    Does NOT raise -- WebSocket auth must close the connection manually.

    Uses the singleton session factory (initialized during lifespan) since
    WS auth happens before the connection is accepted (no FastAPI Depends).
    """
    from uam.db.engine import get_engine
    from uam.db.session import init_session_factory

    factory = init_session_factory(get_engine())
    async with factory() as session:
        stmt = select(Agent).where(Agent.token == token)
        result = await session.execute(stmt)
        agent = result.scalar_one_or_none()
        if agent is None:
            return None
        return {"address": agent.address, "public_key": agent.public_key}
