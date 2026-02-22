"""GET /agents/{address}/public-key -- public key lookup endpoint.

This endpoint is **unauthenticated** by design.  An agent sending its
very first message (``handshake.request``) needs the recipient's public
key for SealedBox encryption *before* it has exchanged credentials.
Making this public closes the encryption-for-handshake loop.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from uam.relay.database import get_agent_by_address, get_domain_verification
from uam.relay.models import PublicKeyResponse

router = APIRouter()


@router.get("/agents/{address}/public-key", response_model=PublicKeyResponse)
async def get_public_key(
    address: str,
    request: Request,
) -> PublicKeyResponse:
    """Return the public key for a registered agent.

    Unauthenticated -- any caller can look up any agent's public key.
    This is required for encrypting the first message (handshake.request)
    when the sender has no prior relationship with the recipient.
    """
    db = request.app.state.db

    target = await get_agent_by_address(db, address)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    # Check for Tier 2 domain verification
    verification = await get_domain_verification(db, address)
    if verification:
        return PublicKeyResponse(
            address=address,
            public_key=target["public_key"],
            tier=2,
            verified_domain=verification["domain"],
        )

    return PublicKeyResponse(address=address, public_key=target["public_key"])
