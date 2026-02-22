"""GET /agents/{address}/presence -- agent presence endpoint (PRES-01)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from uam.relay.auth import verify_token_http
from uam.relay.database import get_agent_by_address
from uam.relay.models import PresenceResponse

router = APIRouter()


@router.get("/agents/{address}/presence", response_model=PresenceResponse)
async def get_presence(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
) -> PresenceResponse:
    """Check whether an agent is currently online.

    Returns the agent's online status (based on active WebSocket connection)
    and their last_seen timestamp from the database.

    Requires Bearer token authentication.
    """
    db = request.app.state.db
    manager = request.app.state.manager

    # Look up the target agent
    target = await get_agent_by_address(db, address)
    if target is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    online = manager.is_online(address)

    return PresenceResponse(
        address=address,
        online=online,
        last_seen=target.get("last_seen"),
    )
