"""Pydantic request/response models for the relay REST API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    agent_name: str
    public_key: str
    webhook_url: str | None = None


class RegisterResponse(BaseModel):
    address: str
    token: str
    relay: str


class SendRequest(BaseModel):
    envelope: dict[str, Any]


class SendResponse(BaseModel):
    message_id: str
    delivered: bool


class InboxResponse(BaseModel):
    address: str
    messages: list[dict[str, Any]]
    count: int


class PublicKeyResponse(BaseModel):
    address: str
    public_key: str
    tier: int = 1
    verified_domain: str | None = None


class HealthResponse(BaseModel):
    status: str
    agents_online: int
    version: str


# ---------------------------------------------------------------------------
# Demo widget models
# ---------------------------------------------------------------------------


class CreateSessionResponse(BaseModel):
    session_id: str
    address: str


class DemoSendRequest(BaseModel):
    session_id: str
    to_address: str
    message: str


class DemoSendResponse(BaseModel):
    message_id: str


class DemoMessage(BaseModel):
    from_address: str
    content: str
    timestamp: str
    message_id: str


class DemoInboxResponse(BaseModel):
    messages: list[DemoMessage]


# ---------------------------------------------------------------------------
# Domain verification models (DNS-04)
# ---------------------------------------------------------------------------


class VerifyDomainRequest(BaseModel):
    domain: str


class VerifyDomainResponse(BaseModel):
    status: str  # "verified" | "failed"
    domain: str
    tier: int
    detail: str | None = None


# ---------------------------------------------------------------------------
# Webhook delivery models (HOOK-01, HOOK-06)
# ---------------------------------------------------------------------------


class WebhookUrlRequest(BaseModel):
    webhook_url: str


class WebhookUrlResponse(BaseModel):
    address: str
    webhook_url: str | None


class WebhookDeliveryRecord(BaseModel):
    id: int
    message_id: str
    status: str
    attempt_count: int
    last_status_code: int | None = None
    last_error: str | None = None
    created_at: str
    completed_at: str | None = None


class WebhookDeliveryListResponse(BaseModel):
    address: str
    deliveries: list[WebhookDeliveryRecord]
    count: int


# ---------------------------------------------------------------------------
# Admin / spam defense models (SPAM-05)
# ---------------------------------------------------------------------------


class BlocklistRequest(BaseModel):
    pattern: str  # "spammer::evil.com" or "*::evil.com"
    reason: str | None = None


class BlocklistEntry(BaseModel):
    id: int
    pattern: str
    reason: str | None = None
    created_at: str


class BlocklistListResponse(BaseModel):
    entries: list[BlocklistEntry]
    count: int


class AllowlistRequest(BaseModel):
    pattern: str
    reason: str | None = None


class AllowlistEntry(BaseModel):
    id: int
    pattern: str
    reason: str | None = None
    created_at: str


class AllowlistListResponse(BaseModel):
    entries: list[AllowlistEntry]
    count: int


class ReputationResponse(BaseModel):
    address: str
    score: int
    tier: str
    messages_sent: int
    messages_rejected: int
    created_at: str
    updated_at: str


class SetReputationRequest(BaseModel):
    score: int  # 0-100


# ---------------------------------------------------------------------------
# Presence models (PRES-01)
# ---------------------------------------------------------------------------


class PresenceResponse(BaseModel):
    address: str
    online: bool
    last_seen: str | None = None
