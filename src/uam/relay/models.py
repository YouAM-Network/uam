"""Pydantic request/response models for the relay REST API."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# T6.2 Phase 46: input-validation pattern constants.
# See .planning/phases/46-.../46-RESEARCH.md § Pydantic Constraint Catalogue
# and 46-02-PLAN.md for the per-class application table.
#
# Strict patterns (user-supplied agent_name / reservation name): lowercase only,
# matches v3.0 address spec and the address-parser regex in protocol/address.py.
# Permissive address pattern: accepts demo session addresses too (the demo
# session manager generates names with secrets.token_urlsafe which uses
# [A-Za-z0-9_-]). The address pattern is therefore broader than the agent_name
# pattern by design — it must round-trip every address the relay constructs,
# not just user-supplied ones.
# ---------------------------------------------------------------------------
_AGENT_NAME_PATTERN = r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$"
_PUBKEY_B64_PATTERN = r"^[A-Za-z0-9+/_-]{40,48}={0,2}$"
_ADDRESS_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]*::[a-z0-9.-]+$"
_HTTPS_URL_PATTERN = r"^https://"
_DNS_LABEL_PATTERN = r"^[a-z0-9.-]+$"
_ID_PATTERN = r"^[A-Za-z0-9_-]+$"  # message_id, session_id, thread_id, claim_token
# Blocklist/allowlist patterns are operator-supplied "agent::domain" or
# "*::domain" globs. Allow underscores in the prefix segment so demo-style
# addresses (`demo_session::host`) are admin-blockable. The handler-level
# "::" check keeps emitting 400 for missing-separator inputs that this
# regex still accepts as bare-domain patterns.
_BLOCKLIST_PATTERN = r"^(\*::|[A-Za-z0-9_-]+::)?[a-z0-9.-]+$"

# Maximum sizes (RESEARCH § Cap rationale defaults)
_MAX_ENVELOPE_BYTES = 65536  # matches MAX_ENVELOPE_SIZE in protocol/types.py
_MAX_CONTACT_CARD_BYTES = 16384  # 16 KiB serialized JSON


def _check_dict_size(value: dict[str, Any] | None, limit: int, name: str) -> None:
    """Raise ValueError if json.dumps(value) exceeds *limit* bytes.

    Used by model_validator hooks on dict-typed fields (envelope, contact_card)
    to bound serialized size before any handler-level processing.
    """
    if value is None:
        return
    size = len(json.dumps(value, separators=(",", ":")))
    if size > limit:
        raise ValueError(f"{name} serialized size {size} bytes exceeds maximum {limit} bytes")


# ---------------------------------------------------------------------------
# Registration models (RELAY-04)
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    agent_name: Annotated[str, Field(max_length=64, pattern=_AGENT_NAME_PATTERN)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    webhook_url: Annotated[
        str | None,
        Field(default=None, max_length=2048, pattern=_HTTPS_URL_PATTERN),
    ] = None


class RegisterResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    token: Annotated[str, Field(max_length=128, pattern=_ID_PATTERN)]
    relay: Annotated[str, Field(max_length=512)]  # ws://... or wss://... URL


class SendRequest(BaseModel):
    envelope: dict[str, Any]

    @model_validator(mode="after")
    def _check_envelope_size(self) -> SendRequest:
        _check_dict_size(self.envelope, _MAX_ENVELOPE_BYTES, "envelope")
        return self


class SendResponse(BaseModel):
    message_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]
    delivered: bool


class InboxResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    messages: list[dict[str, Any]]
    count: Annotated[int, Field(ge=0)]


class PublicKeyResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    tier: Annotated[int, Field(ge=1, le=3)] = 1
    verified_domain: Annotated[
        str | None,
        Field(default=None, max_length=255, pattern=_DNS_LABEL_PATTERN),
    ] = None


class HealthResponse(BaseModel):
    status: Annotated[str, Field(max_length=32)]
    agents_online: Annotated[int, Field(ge=0)]
    version: Annotated[str, Field(max_length=32)]


# ---------------------------------------------------------------------------
# Demo widget models
# ---------------------------------------------------------------------------


class CreateSessionResponse(BaseModel):
    session_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]


class DemoSendRequest(BaseModel):
    session_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]
    to_address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    # Phase 32 archive set max_length=2048 for demo messages — preserve.
    message: Annotated[str, Field(max_length=2048)]


class DemoSendResponse(BaseModel):
    message_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]


class DemoMessage(BaseModel):
    from_address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    content: Annotated[str, Field(max_length=2048)]
    timestamp: Annotated[str, Field(max_length=64)]
    message_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]


class DemoInboxResponse(BaseModel):
    messages: list[DemoMessage]


# ---------------------------------------------------------------------------
# Domain verification models (DNS-04)
# ---------------------------------------------------------------------------


class VerifyDomainRequest(BaseModel):
    domain: Annotated[str, Field(max_length=255, pattern=_DNS_LABEL_PATTERN)]


class VerifyDomainResponse(BaseModel):
    status: Literal["verified", "failed"]
    domain: Annotated[str, Field(max_length=255, pattern=_DNS_LABEL_PATTERN)]
    tier: Annotated[int, Field(ge=1, le=3)]
    detail: Annotated[str | None, Field(default=None, max_length=512)] = None


# ---------------------------------------------------------------------------
# Webhook delivery models (HOOK-01, HOOK-06)
# ---------------------------------------------------------------------------


class WebhookUrlRequest(BaseModel):
    webhook_url: Annotated[
        str, Field(max_length=2048, pattern=_HTTPS_URL_PATTERN)
    ]


class WebhookUrlResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    webhook_url: Annotated[
        str | None,
        Field(default=None, max_length=2048, pattern=_HTTPS_URL_PATTERN),
    ] = None


class WebhookDeliveryRecord(BaseModel):
    id: Annotated[int, Field(ge=0)]
    message_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]
    status: Annotated[str, Field(max_length=32)]
    attempt_count: Annotated[int, Field(ge=0)]
    last_status_code: Annotated[
        int | None, Field(default=None, ge=100, le=599)
    ] = None
    last_error: Annotated[str | None, Field(default=None, max_length=512)] = None
    created_at: Annotated[str, Field(max_length=64)]
    completed_at: Annotated[str | None, Field(default=None, max_length=64)] = None


class WebhookDeliveryListResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    deliveries: list[WebhookDeliveryRecord]
    count: Annotated[int, Field(ge=0)]


# ---------------------------------------------------------------------------
# Admin / spam defense models (SPAM-05)
# ---------------------------------------------------------------------------


class BlocklistRequest(BaseModel):
    pattern: Annotated[str, Field(max_length=128, pattern=_BLOCKLIST_PATTERN)]
    reason: Annotated[str | None, Field(default=None, max_length=256)] = None


class BlocklistEntry(BaseModel):
    id: Annotated[int, Field(ge=0)]
    pattern: Annotated[str, Field(max_length=128, pattern=_BLOCKLIST_PATTERN)]
    reason: Annotated[str | None, Field(default=None, max_length=256)] = None
    created_at: Annotated[str, Field(max_length=64)]


class BlocklistListResponse(BaseModel):
    entries: Annotated[list[BlocklistEntry], Field(max_length=10000)]
    count: Annotated[int, Field(ge=0)]


class AllowlistRequest(BaseModel):
    pattern: Annotated[str, Field(max_length=128, pattern=_BLOCKLIST_PATTERN)]
    reason: Annotated[str | None, Field(default=None, max_length=256)] = None


class AllowlistEntry(BaseModel):
    id: Annotated[int, Field(ge=0)]
    pattern: Annotated[str, Field(max_length=128, pattern=_BLOCKLIST_PATTERN)]
    reason: Annotated[str | None, Field(default=None, max_length=256)] = None
    created_at: Annotated[str, Field(max_length=64)]


class AllowlistListResponse(BaseModel):
    entries: Annotated[list[AllowlistEntry], Field(max_length=10000)]
    count: Annotated[int, Field(ge=0)]


class ReputationResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    score: Annotated[int, Field(ge=0, le=100)]
    tier: Annotated[str, Field(max_length=32)]
    messages_sent: Annotated[int, Field(ge=0)]
    messages_rejected: Annotated[int, Field(ge=0)]
    created_at: Annotated[str, Field(max_length=64)]
    updated_at: Annotated[str, Field(max_length=64)]


class SetReputationRequest(BaseModel):
    score: Annotated[int, Field(ge=0, le=100)]


# ---------------------------------------------------------------------------
# Presence models (PRES-01)
# ---------------------------------------------------------------------------


class PresenceResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    online: bool
    last_seen: Annotated[str | None, Field(default=None, max_length=64)] = None


# ---------------------------------------------------------------------------
# Federation models (FED-01)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Agent management models (RELAY-08, RELAY-09, RELAY-15)
# ---------------------------------------------------------------------------


class UpdateAgentRequest(BaseModel):
    display_name: Annotated[str | None, Field(default=None, max_length=128)] = None
    contact_card: dict[str, Any] | None = None
    public_key: Annotated[
        str | None,
        Field(default=None, max_length=64, pattern=_PUBKEY_B64_PATTERN),
    ] = None

    @model_validator(mode="after")
    def _check_contact_card_size(self) -> UpdateAgentRequest:
        _check_dict_size(self.contact_card, _MAX_CONTACT_CARD_BYTES, "contact_card")
        return self


class AgentResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    status: Annotated[str, Field(max_length=32)]
    display_name: Annotated[str | None, Field(default=None, max_length=128)] = None
    webhook_url: Annotated[
        str | None,
        Field(default=None, max_length=2048, pattern=_HTTPS_URL_PATTERN),
    ] = None
    last_seen: Annotated[str | None, Field(default=None, max_length=64)] = None
    created_at: Annotated[str, Field(max_length=64)]


# ---------------------------------------------------------------------------
# Thread / receipt models (RELAY-10, RELAY-16)
# ---------------------------------------------------------------------------


class ThreadResponse(BaseModel):
    thread_id: Annotated[str, Field(max_length=128, pattern=_ID_PATTERN)]
    messages: Annotated[list[dict[str, Any]], Field(max_length=10000)]
    count: Annotated[int, Field(ge=0)]


class ReceiptRequest(BaseModel):
    # M8: Closes receipt-spam vector — Literal forces caller to use a real
    # receipt type instead of arbitrary envelope types.
    type: Literal["receipt.read", "receipt.delivered", "receipt.failed"]
    timestamp: Annotated[str | None, Field(default=None, max_length=64)] = None


class ReceiptResponse(BaseModel):
    status: Annotated[str, Field(max_length=32)]
    message_id: Annotated[str, Field(max_length=64, pattern=_ID_PATTERN)]


# ---------------------------------------------------------------------------
# Handshake models (RELAY-11)
# ---------------------------------------------------------------------------


class HandshakeSendRequest(BaseModel):
    to_address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    contact_card: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _check_contact_card_size(self) -> HandshakeSendRequest:
        _check_dict_size(self.contact_card, _MAX_CONTACT_CARD_BYTES, "contact_card")
        return self


class HandshakeResponse(BaseModel):
    id: Annotated[int, Field(ge=0)]
    status: Annotated[str, Field(max_length=32)]
    from_addr: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    to_addr: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]


class HandshakeRespondRequest(BaseModel):
    response: Literal["approved", "denied"]


class HandshakeListResponse(BaseModel):
    handshakes: list[HandshakeResponse]
    count: Annotated[int, Field(ge=0)]


# ---------------------------------------------------------------------------
# Expanded admin models (RELAY-12)
# ---------------------------------------------------------------------------


class AdminAgentResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    status: Annotated[str, Field(max_length=32)]
    display_name: Annotated[str | None, Field(default=None, max_length=128)] = None
    webhook_url: Annotated[
        str | None,
        Field(default=None, max_length=2048, pattern=_HTTPS_URL_PATTERN),
    ] = None
    last_seen: Annotated[str | None, Field(default=None, max_length=64)] = None
    created_at: Annotated[str, Field(max_length=64)]
    updated_at: Annotated[str, Field(max_length=64)]
    deleted_at: Annotated[str | None, Field(default=None, max_length=64)] = None


class AdminAgentListResponse(BaseModel):
    agents: list[AdminAgentResponse]
    count: Annotated[int, Field(ge=0)]


class AuditLogEntry(BaseModel):
    id: Annotated[int, Field(ge=0)]
    action: Annotated[str, Field(max_length=64)]
    entity_type: Annotated[str, Field(max_length=64)]
    entity_id: Annotated[str, Field(max_length=128)]
    actor_address: Annotated[
        str | None,
        Field(default=None, max_length=128, pattern=_ADDRESS_PATTERN),
    ] = None
    timestamp: Annotated[str, Field(max_length=64)]
    details: dict[str, Any] | None = None
    ip_address: Annotated[str | None, Field(default=None, max_length=64)] = None


class AuditLogResponse(BaseModel):
    entries: list[AuditLogEntry]
    count: Annotated[int, Field(ge=0)]


class PurgeExpiredResponse(BaseModel):
    purged: Annotated[int, Field(ge=0)]


class AdminHealthResponse(BaseModel):
    status: Annotated[str, Field(max_length=32)]  # "healthy" or "degraded"
    db_ok: bool
    queue_depth: Annotated[int, Field(ge=0)]
    ws_connections: Annotated[int, Field(ge=0)]
    uptime_seconds: Annotated[float, Field(ge=0)]
    migration_version: Annotated[str | None, Field(default=None, max_length=64)] = None


# ---------------------------------------------------------------------------
# Federation models (FED-01)
# ---------------------------------------------------------------------------


class FederationDeliverRequest(BaseModel):
    envelope: dict[str, Any]
    via: Annotated[list[str], Field(default_factory=list, max_length=16)]
    hop_count: Annotated[int, Field(ge=0, le=16)] = 0
    timestamp: Annotated[str, Field(max_length=64)]
    from_relay: Annotated[str, Field(max_length=255, pattern=_DNS_LABEL_PATTERN)]
    # T3.2 (Phase 45): 128-bit nonce, urlsafe-b64 of 16 bytes ≈ 22 chars.
    # Pydantic enforces presence (missing → 422) and length window
    # (min 22 = ``secrets.token_urlsafe(16)``; max 64 lets operators use
    # longer nonces). The nonce is in the canonical signed body scope —
    # ``sign_federation_request`` picks it up automatically because it
    # signs the whole body dict. Receiving relay dedups (from_relay,
    # nonce) at Step 6.5 of ``federation_deliver`` BEFORE crypto verify.
    # T6.2 (Phase 46): preserve Phase 45 length window verbatim.
    nonce: Annotated[str, Field(min_length=22, max_length=64)]

    @model_validator(mode="after")
    def _check_envelope_size(self) -> FederationDeliverRequest:
        _check_dict_size(self.envelope, _MAX_ENVELOPE_BYTES, "envelope")
        return self


class FederationDeliverResponse(BaseModel):
    status: Annotated[str, Field(max_length=32)]  # "delivered" | "queued" | "rejected"
    detail: Annotated[str | None, Field(default=None, max_length=512)] = None


class WellKnownRelayResponse(BaseModel):
    relay_domain: Annotated[str, Field(max_length=255, pattern=_DNS_LABEL_PATTERN)]
    federation_endpoint: Annotated[str, Field(max_length=2048)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    version: Annotated[str, Field(max_length=32)] = "0.1"


# ---------------------------------------------------------------------------
# Reservation models (RES-01, RES-02)
# ---------------------------------------------------------------------------


class ReserveCheckResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    available: bool


class ReserveRequest(BaseModel):
    # just the agent name part (before ::)
    name: Annotated[str, Field(max_length=64, pattern=_AGENT_NAME_PATTERN)]


class ReserveResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    claim_token: Annotated[str, Field(max_length=128, pattern=_ID_PATTERN)]
    expires_at: Annotated[str, Field(max_length=64)]
    # vcf_url allows http for local-dev relay_http_url defaults; HTTPS is
    # enforced by deployment config, not by this Pydantic field.
    vcf_url: Annotated[str, Field(max_length=2048)]


class ReserveClaimRequest(BaseModel):
    claim_token: Annotated[str, Field(max_length=128, pattern=_ID_PATTERN)]
    public_key: Annotated[str, Field(max_length=64, pattern=_PUBKEY_B64_PATTERN)]
    webhook_url: Annotated[
        str | None,
        Field(default=None, max_length=2048, pattern=_HTTPS_URL_PATTERN),
    ] = None


class ReserveClaimResponse(BaseModel):
    address: Annotated[str, Field(max_length=128, pattern=_ADDRESS_PATTERN)]
    token: Annotated[str, Field(max_length=128, pattern=_ID_PATTERN)]
    relay: Annotated[str, Field(max_length=512)]
