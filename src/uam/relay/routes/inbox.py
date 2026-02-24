"""Inbox endpoints: message retrieval, thread view, and receipt submission.

GET /inbox/{address} -- message inbox (RELAY-02)
GET /messages/thread/{thread_id} -- thread retrieval (RELAY-10)
POST /messages/{message_id}/receipt -- receipt submission (RELAY-16)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.messages import get_inbox as get_inbox_crud, get_message_by_id, get_thread, mark_delivered
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.models import InboxResponse, ReceiptRequest, ReceiptResponse, ThreadResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/inbox/{address}", response_model=InboxResponse)
async def get_inbox(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=500),
) -> InboxResponse:
    """Retrieve stored messages for an agent.

    Bearer token auth via ``verify_token_http`` dependency.
    Agent can only read their own inbox.
    """
    # Agent can only read their own inbox
    if address != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail="Cannot read another agent's inbox",
        )

    # Fetch undelivered messages (CRUD returns Message model objects)
    stored = await get_inbox_crud(session, address, limit)

    messages: list[dict] = []
    ids: list[int] = []
    for msg in stored:
        messages.append(json.loads(msg.envelope))
        ids.append(msg.id)

    # Mark as delivered
    if ids:
        await mark_delivered(session, ids)

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


# ---------------------------------------------------------------------------
# RELAY-10: GET /messages/thread/{thread_id} -- thread retrieval
# ---------------------------------------------------------------------------


@router.get("/messages/thread/{thread_id}", response_model=ThreadResponse)
async def get_thread_messages(
    thread_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
    limit: int = Query(default=100, ge=1, le=500),
) -> ThreadResponse:
    """Retrieve messages in a thread.

    Requires Bearer token auth.  The authenticated agent must be a
    participant (from_addr or to_addr) in at least one message in the
    thread.  Returns 403 if not a participant or if thread is empty.
    """
    messages = await get_thread(session, thread_id, limit)

    if not messages:
        raise HTTPException(status_code=403, detail="Thread not found or access denied")

    # Verify the authenticated agent is a participant
    agent_addr = agent["address"]
    is_participant = any(
        msg.from_addr == agent_addr or msg.to_addr == agent_addr
        for msg in messages
    )
    if not is_participant:
        raise HTTPException(status_code=403, detail="Not a participant in this thread")

    # Parse stored envelope JSON strings into dicts
    envelopes = []
    for msg in messages:
        try:
            envelope = json.loads(msg.envelope) if isinstance(msg.envelope, str) else msg.envelope
        except (json.JSONDecodeError, TypeError):
            envelope = {"raw": msg.envelope}
        envelopes.append(envelope)

    return ThreadResponse(
        thread_id=thread_id,
        messages=envelopes,
        count=len(envelopes),
    )


# ---------------------------------------------------------------------------
# RELAY-16: POST /messages/{message_id}/receipt -- receipt submission
# ---------------------------------------------------------------------------


@router.post("/messages/{message_id}/receipt", response_model=ReceiptResponse)
async def submit_receipt(
    message_id: str,
    body: ReceiptRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> ReceiptResponse:
    """Submit a receipt (e.g. ``receipt.read``) for a received message.

    Requires Bearer token auth.  The authenticated agent must be the
    recipient of the message.  Routes the receipt envelope to the
    original sender via the connection manager.
    """
    msg = await get_message_by_id(session, message_id)
    if msg is None:
        raise HTTPException(status_code=404, detail=f"Message not found: {message_id}")

    # Verify the authenticated agent is the recipient
    if msg.to_addr != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail="Only the recipient can submit a receipt for this message",
        )

    # Build receipt envelope
    receipt_envelope = {
        "type": body.type,
        "message_id": message_id,
        "timestamp": body.timestamp or datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z"),
        "to": msg.from_addr,
        "from": agent["address"],
    }

    # Route receipt to the original sender (fire-and-forget)
    manager = request.app.state.manager
    await manager.send_to(msg.from_addr, receipt_envelope)

    return ReceiptResponse(status="submitted", message_id=message_id)
