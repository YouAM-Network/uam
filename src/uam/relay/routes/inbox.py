"""GET /inbox/{address} -- message inbox endpoint (RELAY-02)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from uam.relay.auth import verify_token_http
from uam.relay.database import (
    get_stored_messages,
    mark_messages_delivered,
)
from uam.relay.models import InboxResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/inbox/{address}", response_model=InboxResponse)
async def get_inbox(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
    limit: int = Query(default=50, ge=1, le=500),
) -> InboxResponse:
    """Retrieve stored messages for an agent.

    Bearer token auth via ``verify_token_http`` dependency.
    Agent can only read their own inbox.
    """
    db = request.app.state.db

    # Agent can only read their own inbox
    if address != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail="Cannot read another agent's inbox",
        )

    # Fetch undelivered messages (already parsed by get_stored_messages)
    stored = await get_stored_messages(db, address, limit)

    messages: list[dict] = []
    ids: list[int] = []
    for msg in stored:
        messages.append(msg["envelope"])
        ids.append(msg["id"])

    # Mark as delivered
    if ids:
        await mark_messages_delivered(db, ids)

    # Send receipt.delivered to each original sender (MSG-05 -- fire-and-forget)
    manager = request.app.state.manager
    for msg_envelope in messages:
        original_from = msg_envelope.get("from", "")
        msg_type = str(msg_envelope.get("type", ""))
        if original_from and not msg_type.startswith("receipt."):
            receipt = {
                "type": "receipt.delivered",
                "message_id": msg_envelope.get("message_id", ""),
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "to": address,
            }
            await manager.send_to(original_from, receipt)

    return InboxResponse(address=address, messages=messages, count=len(messages))
