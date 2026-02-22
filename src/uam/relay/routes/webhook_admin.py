"""Webhook URL management and delivery status endpoints (HOOK-01, HOOK-06).

Allows agents to manage their own webhook URL and query delivery history.
All endpoints require Bearer token auth and enforce address ownership.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from uam.relay.auth import verify_token_http
from uam.relay.database import (
    get_agent_by_address,
    get_webhook_deliveries,
    update_agent_webhook_url,
)
from uam.relay.models import (
    WebhookDeliveryListResponse,
    WebhookDeliveryRecord,
    WebhookUrlRequest,
    WebhookUrlResponse,
)
from uam.relay.webhook_validator import validate_webhook_url

router = APIRouter()


def _check_ownership(agent: dict, address: str) -> None:
    """Ensure the authenticated agent owns the target address."""
    if agent["address"] != address:
        raise HTTPException(
            status_code=403, detail="Cannot manage webhook for another agent"
        )


@router.put("/agents/{address}/webhook", response_model=WebhookUrlResponse)
async def set_webhook_url(
    address: str,
    body: WebhookUrlRequest,
    request: Request,
    agent: dict = Depends(verify_token_http),
) -> WebhookUrlResponse:
    """Set or update the webhook URL for an agent (HOOK-01)."""
    _check_ownership(agent, address)
    db = request.app.state.db

    # SSRF validation
    valid, reason = validate_webhook_url(body.webhook_url)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Invalid webhook URL: {reason}")

    await update_agent_webhook_url(db, address, body.webhook_url)
    return WebhookUrlResponse(address=address, webhook_url=body.webhook_url)


@router.delete("/agents/{address}/webhook", response_model=WebhookUrlResponse)
async def delete_webhook_url(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
) -> WebhookUrlResponse:
    """Remove the webhook URL for an agent."""
    _check_ownership(agent, address)
    db = request.app.state.db
    await update_agent_webhook_url(db, address, None)
    return WebhookUrlResponse(address=address, webhook_url=None)


@router.get("/agents/{address}/webhook", response_model=WebhookUrlResponse)
async def get_webhook_url(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
) -> WebhookUrlResponse:
    """Get the current webhook URL for an agent."""
    _check_ownership(agent, address)
    db = request.app.state.db
    agent_record = await get_agent_by_address(db, address)
    if agent_record is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    webhook_url = agent_record.get("webhook_url")
    return WebhookUrlResponse(address=address, webhook_url=webhook_url)


@router.get(
    "/agents/{address}/webhook/deliveries",
    response_model=WebhookDeliveryListResponse,
)
async def list_webhook_deliveries(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
    limit: int = Query(default=50, ge=1, le=200),
) -> WebhookDeliveryListResponse:
    """Get recent webhook delivery records for an agent (HOOK-06)."""
    _check_ownership(agent, address)
    db = request.app.state.db
    rows = await get_webhook_deliveries(db, address, limit)
    deliveries = [WebhookDeliveryRecord(**row) for row in rows]
    return WebhookDeliveryListResponse(
        address=address, deliveries=deliveries, count=len(deliveries)
    )
