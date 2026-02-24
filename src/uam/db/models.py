"""SQLModel table definitions for the UAM relay database.

All 17 entities are defined here as SQLModel table classes. Each mutable
entity includes a ``deleted_at`` field for soft-delete support.

Usage::

    from uam.db.models import Agent, Message, Handshake, Contact, AuditLog
    from sqlmodel import SQLModel, create_engine

    engine = create_engine("sqlite:///relay.db")
    SQLModel.metadata.create_all(engine)
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, UniqueConstraint, func
from sqlmodel import Field, SQLModel

# ---------------------------------------------------------------------------
# 5 Core Entities
# ---------------------------------------------------------------------------


class Agent(SQLModel, table=True):
    """Registered agent on the relay."""

    __tablename__ = "agents"

    address: str = Field(primary_key=True)
    public_key: str
    token: str = Field(index=True, unique=True)
    display_name: str | None = None
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    status: str = Field(default="active")
    webhook_url: str | None = None
    relay_endpoint: str | None = None
    last_seen: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()})
    deleted_at: datetime | None = None


class Message(SQLModel, table=True):
    """Stored message envelope for offline/async delivery."""

    __tablename__ = "messages"

    id: int | None = Field(default=None, primary_key=True)
    message_id: str = Field(index=True, unique=True)
    from_addr: str
    to_addr: str = Field(index=True)
    thread_id: str | None = Field(default=None, index=True)
    envelope: str
    status: str = Field(default="queued")
    retry_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    delivered_at: datetime | None = None
    expires_at: datetime | None = None
    deleted_at: datetime | None = None


class Handshake(SQLModel, table=True):
    """Pending or completed handshake request between two agents."""

    __tablename__ = "handshakes"

    id: int | None = Field(default=None, primary_key=True)
    from_addr: str = Field(index=True)
    to_addr: str = Field(index=True)
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    status: str = Field(default="pending")
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    resolved_at: datetime | None = None
    deleted_at: datetime | None = None


class Contact(SQLModel, table=True):
    """An agent's contact book entry."""

    __tablename__ = "contacts"

    id: int | None = Field(default=None, primary_key=True)
    owner_address: str = Field(index=True)
    contact_address: str
    trust_state: str = Field(default="unknown")
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()})
    deleted_at: datetime | None = None


class AuditLog(SQLModel, table=True):
    """Append-only audit trail for state changes."""

    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    action: str
    entity_type: str
    entity_id: str
    actor_address: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    details: dict | None = Field(default=None, sa_type=JSON)
    ip_address: str | None = None


# ---------------------------------------------------------------------------
# 12 Operational Tables
# ---------------------------------------------------------------------------


class SeenMessageId(SQLModel, table=True):
    """Deduplication table for already-processed message IDs."""

    __tablename__ = "seen_message_ids"

    message_id: str = Field(primary_key=True)
    from_addr: str
    seen_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class DomainVerification(SQLModel, table=True):
    """DNS-based domain ownership verification for an agent."""

    __tablename__ = "domain_verifications"
    __table_args__ = (UniqueConstraint("agent_address", "domain"),)

    id: int | None = Field(default=None, primary_key=True)
    agent_address: str = Field(index=True)
    domain: str
    public_key: str
    method: str = Field(default="dns")
    verified_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    last_checked: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    ttl_hours: int = Field(default=24)
    status: str = Field(default="verified")
    deleted_at: datetime | None = None


class WebhookDelivery(SQLModel, table=True):
    """Tracks webhook delivery attempts for an agent."""

    __tablename__ = "webhook_deliveries"

    id: int | None = Field(default=None, primary_key=True)
    agent_address: str = Field(index=True)
    message_id: str
    envelope: str
    status: str = Field(default="pending")
    attempt_count: int = Field(default=0)
    last_status_code: int | None = None
    last_error: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    completed_at: datetime | None = None
    deleted_at: datetime | None = None


class Reputation(SQLModel, table=True):
    """Per-agent reputation score for spam defense."""

    __tablename__ = "reputation"

    address: str = Field(primary_key=True)
    score: int = Field(default=30)
    messages_sent: int = Field(default=0)
    messages_rejected: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()})


class BlocklistEntry(SQLModel, table=True):
    """Agent-level blocklist pattern."""

    __tablename__ = "blocklist"

    id: int | None = Field(default=None, primary_key=True)
    pattern: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class AllowlistEntry(SQLModel, table=True):
    """Agent-level allowlist pattern."""

    __tablename__ = "allowlist"

    id: int | None = Field(default=None, primary_key=True)
    pattern: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class KnownRelay(SQLModel, table=True):
    """Discovered relay for federation."""

    __tablename__ = "known_relays"

    domain: str = Field(primary_key=True)
    federation_url: str
    public_key: str
    discovered_via: str = Field(default="well-known")
    last_verified: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    ttl_hours: int = Field(default=1)
    status: str = Field(default="active")


class FederationLog(SQLModel, table=True):
    """Log of federated message routing between relays."""

    __tablename__ = "federation_log"

    id: int | None = Field(default=None, primary_key=True)
    message_id: str = Field(index=True)
    from_relay: str
    to_relay: str
    direction: str
    hop_count: int = Field(default=0)
    status: str
    error: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class RelayBlocklistEntry(SQLModel, table=True):
    """Relay-level blocklist for federation."""

    __tablename__ = "relay_blocklist"

    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class RelayAllowlistEntry(SQLModel, table=True):
    """Relay-level allowlist for federation."""

    __tablename__ = "relay_allowlist"

    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


class RelayReputation(SQLModel, table=True):
    """Per-relay reputation score for federation trust."""

    __tablename__ = "relay_reputation"

    domain: str = Field(primary_key=True)
    score: int = Field(default=50)
    messages_forwarded: int = Field(default=0)
    messages_rejected: int = Field(default=0)
    last_success: datetime | None = None
    last_failure: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()})


class FederationQueueEntry(SQLModel, table=True):
    """Queue of outbound federated messages awaiting delivery."""

    __tablename__ = "federation_queue"

    id: int | None = Field(default=None, primary_key=True)
    target_domain: str = Field(index=True)
    envelope: str
    via: str = Field(default="[]")
    hop_count: int = Field(default=0)
    attempt_count: int = Field(default=0)
    next_retry: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(default="pending")
    error: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"server_default": func.now()})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Agent",
    "Message",
    "Handshake",
    "Contact",
    "AuditLog",
    "SeenMessageId",
    "DomainVerification",
    "WebhookDelivery",
    "Reputation",
    "BlocklistEntry",
    "AllowlistEntry",
    "KnownRelay",
    "FederationLog",
    "RelayBlocklistEntry",
    "RelayAllowlistEntry",
    "RelayReputation",
    "FederationQueueEntry",
]
