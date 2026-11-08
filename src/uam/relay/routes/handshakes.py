"""Legacy relay-mediated handshake endpoints (RELAY-11), now read-only.

POST /handshakes/send -- gone (410); agents send a signed handshake.request
GET /handshakes/pending/{address} -- list pending handshakes for an agent
POST /handshakes/{handshake_id}/respond -- deny only; approving is refused

Contacts are approved between the agents' own SDKs with signed
``handshake.*`` envelopes. These endpoints let an agent's token create a
request and approve it with no one else involved, so they no longer
create or approve anything.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.handshakes import (
    get_handshake_by_id,
    get_pending,
    respond_handshake,
)
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.models import (
    HandshakeListResponse,
    HandshakeRespondRequest,
    HandshakeResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["handshakes"])


# ---------------------------------------------------------------------------
# POST /handshakes/send -- initiate a handshake
# ---------------------------------------------------------------------------


@router.post("/handshakes/send", status_code=410, deprecated=True)
async def send_handshake() -> None:
    """Gone: send a signed ``handshake.request`` envelope instead."""
    raise HTTPException(
        status_code=410,
        detail="Relay-mediated handshakes are retired; send a signed handshake.request envelope",
        headers={"Deprecation": "true"},
    )


# ---------------------------------------------------------------------------
# GET /handshakes/pending/{address} -- list pending handshakes
# ---------------------------------------------------------------------------


@router.get("/handshakes/pending/{address}", response_model=HandshakeListResponse)
async def list_pending_handshakes(
    address: str,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> HandshakeListResponse:
    """List pending handshakes for the authenticated agent.

    Agent can only view their own pending handshakes (incoming).
    """
    if agent["address"] != address:
        raise HTTPException(
            status_code=403,
            detail="Cannot view another agent's pending handshakes",
        )

    pending = await get_pending(session, address)
    items = [
        HandshakeResponse(
            id=hs.id,  # type: ignore[arg-type]
            status=hs.status,
            from_addr=hs.from_addr,
            to_addr=hs.to_addr,
        )
        for hs in pending
    ]
    return HandshakeListResponse(handshakes=items, count=len(items))


# ---------------------------------------------------------------------------
# POST /handshakes/{handshake_id}/respond -- respond to a handshake
# ---------------------------------------------------------------------------


@router.post("/handshakes/{handshake_id}/respond", response_model=HandshakeResponse)
async def respond_to_handshake(
    handshake_id: int,
    body: HandshakeRespondRequest,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> HandshakeResponse:
    """Deny a pending handshake (approving here is refused).

    The authenticated agent must be the ``to_addr`` of the handshake.
    """
    # Validate response value
    if body.response not in ("approved", "denied"):
        raise HTTPException(
            status_code=400,
            detail="Response must be 'approved' or 'denied'",
        )

    if body.response == "approved":
        raise HTTPException(
            status_code=403,
            detail="Approve contacts with a signed handshake.accept from your own agent",
        )

    # Look up the handshake
    hs = await get_handshake_by_id(session, handshake_id)
    if hs is None:
        raise HTTPException(
            status_code=404,
            detail=f"Handshake not found: {handshake_id}",
        )

    # Verify the authenticated agent is the recipient
    if hs.to_addr != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail="Only the handshake recipient can respond",
        )

    # Check it's still pending
    if hs.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Handshake already resolved with status: {hs.status}",
        )

    # --- Transaction-wrapped DB section (RES-01) ---
    try:
        result = await respond_handshake(session, handshake_id, body.response, commit=False)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Handshake not found: {handshake_id}",
            )
        await session.commit()
    except HTTPException:
        await session.rollback()
        raise
    except Exception:
        await session.rollback()
        raise

    return HandshakeResponse(
        id=result.id,  # type: ignore[arg-type]
        status=result.status,
        from_addr=result.from_addr,
        to_addr=result.to_addr,
    )
