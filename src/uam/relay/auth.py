"""Authentication helpers for the UAM relay server (SEC-02).

Provides Bearer token auth for HTTP endpoints and token verification
for WebSocket connections.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import aiosqlite

from uam.relay.database import get_agent_by_token

bearer_scheme = HTTPBearer()


async def verify_token_http(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> dict:
    """FastAPI dependency: validate Bearer token and return agent info.

    Returns ``{"address": ..., "public_key": ...}`` on success.
    Raises ``HTTPException(401)`` on invalid token.
    """
    db = request.app.state.db
    agent = await get_agent_by_token(db, credentials.credentials)
    if agent is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"address": agent["address"], "public_key": agent["public_key"]}


async def verify_token_ws(
    db: aiosqlite.Connection,
    token: str,
) -> dict | None:
    """Verify a token for WebSocket connections.

    Returns ``{"address": ..., "public_key": ...}`` or ``None``.
    Does NOT raise -- WebSocket auth must close the connection manually.
    """
    return await get_agent_by_token(db, token)
