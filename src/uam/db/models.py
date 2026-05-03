"""SQLModel table definitions for the UAM relay database.

All 19 entities are defined here as SQLModel table classes. Each mutable
entity includes a ``deleted_at`` field for soft-delete support.

Phase 47 T7.4 + T7.3b: every datetime field uses
``sa_column=Column(DateTime(timezone=True), ...)`` (explicit Column
construction) so the database stores timezone-aware values.

The model layer pairs ``server_default=func.now()`` with
``default_factory=lambda: datetime.now(timezone.utc)`` for every NOT NULL
auto-managed column. The default factory exists because alembic migration
0001 did not actually emit ``DEFAULT`` clauses for these columns at the DB
level (the autogen apparently dropped the ``server_default`` from the
``sa_column_kwargs`` dict) — without a Python-side default, ORM INSERTs
hit ``NOT NULL constraint failed`` on tables like ``blocklist`` and
``allowlist``. Pitfall 5 (planner doc) only fires when the Python default
is **naive** (``datetime.utcnow``); a tz-aware default neutralises it
because the value matches the column's ``DateTime(timezone=True)`` type.

For columns whose action is explicit (``deleted_at``, ``claimed_at``,
``completed_at``, ``resolved_at``, ``last_checked``, etc.), the CRUD
layer sets the value via ``datetime.now(timezone.utc)`` — see
``src/uam/db/crud/*.py``.

Usage::

    from uam.db.models import Agent, Message, Handshake, Contact, AuditLog
    from sqlmodel import SQLModel, create_engine

    engine = create_engine("sqlite:///relay.db")
    SQLModel.metadata.create_all(engine)
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlmodel import Field, SQLModel

# ---------------------------------------------------------------------------
# 5 Core Entities
# ---------------------------------------------------------------------------


class Agent(SQLModel, table=True):
    """Registered agent on the relay."""

    __tablename__ = "agents"

    address: str = Field(primary_key=True)
    public_key: str
    # Phase 47 T7.5: ``token_hash`` is the SINGLE source of truth for auth.
    # The plaintext ``token`` field was dropped at the DB level by alembic
    # migration 0007 and removed from this model in the same release. The
    # plaintext is returned to the caller at registration time and NEVER
    # stored on the relay; subsequent auth uses
    # ``hmac.compare_digest(hash_token(plaintext, pepper), token_hash)``
    # in ``uam.relay.auth`` (Phase 43 Plan 04 pattern).
    token_hash: str = Field(index=True, unique=True)
    display_name: str | None = None
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    status: str = Field(default="active")
    webhook_url: str | None = None
    relay_endpoint: str | None = None
    last_seen: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class Message(SQLModel, table=True):
    """Stored message envelope for offline/async delivery."""

    __tablename__ = "messages"

    id: int | None = Field(default=None, primary_key=True)
    message_id: str = Field(index=True, unique=True)
    # T7.3a: ForeignKey to agents.address with ON DELETE RESTRICT — audit
    # data must survive (sender identity is part of the record). See
    # alembic/versions/0006_foreign_keys.py and RESEARCH Pattern 3 +
    # Pitfall 7 (sa_column form required to surface ondelete kwarg).
    from_addr: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="RESTRICT", name="fk_messages_from_addr"),
            nullable=False,
        ),
    )
    to_addr: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="RESTRICT", name="fk_messages_to_addr"),
            nullable=False,
            index=True,
        ),
    )
    thread_id: str | None = Field(default=None, index=True)
    envelope: str
    status: str = Field(default="queued")
    retry_count: int = 0
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    delivered_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    expires_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class Handshake(SQLModel, table=True):
    """Pending or completed handshake request between two agents."""

    __tablename__ = "handshakes"

    id: int | None = Field(default=None, primary_key=True)
    # T7.3a: ForeignKey to agents.address with ON DELETE RESTRICT — handshake
    # records are audit data and must outlive an agent's deletion. See
    # alembic/versions/0006_foreign_keys.py.
    from_addr: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="RESTRICT", name="fk_handshakes_from"),
            nullable=False,
            index=True,
        ),
    )
    to_addr: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="RESTRICT", name="fk_handshakes_to"),
            nullable=False,
            index=True,
        ),
    )
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    status: str = Field(default="pending")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    resolved_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class Contact(SQLModel, table=True):
    """An agent's contact book entry."""

    __tablename__ = "contacts"

    id: int | None = Field(default=None, primary_key=True)
    # T7.3a: owner deletion cascades — when the owner agent is deleted, its
    # contact-book entries are meaningless and should be removed.
    owner_address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_contacts_owner"),
            nullable=False,
            index=True,
        ),
    )
    # T7.3a: contact deletion sets NULL — preserve the contact-book row as a
    # tombstone but sever the dangling reference. Per Pitfall 7 + the 0006
    # migration, the column must be nullable to satisfy the SET NULL action.
    contact_address: str | None = Field(
        default=None,
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="SET NULL", name="fk_contacts_contact"),
            nullable=True,
        ),
    )
    trust_state: str = Field(default="unknown")
    contact_card: dict | None = Field(default=None, sa_type=JSON)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class AuditLog(SQLModel, table=True):
    """Append-only audit trail for state changes."""

    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    action: str
    entity_type: str
    entity_id: str
    # T7.3a: actor deletion sets NULL — audit log MUST survive actor
    # deletion (compliance / forensics). Already Optional pre-Phase-47;
    # the FK + SET NULL are layered on without a type change.
    actor_address: str | None = Field(
        default=None,
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="SET NULL", name="fk_audit_log_actor"),
            nullable=True,
        ),
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    details: dict | None = Field(default=None, sa_type=JSON)
    ip_address: str | None = None


# ---------------------------------------------------------------------------
# 12 Operational Tables
# ---------------------------------------------------------------------------


class SeenMessageId(SQLModel, table=True):
    """Deduplication table for already-processed message IDs."""

    __tablename__ = "seen_message_ids"

    message_id: str = Field(primary_key=True)
    # T7.3a: per-recipient dedup state cascades on agent delete.
    from_addr: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_seen_messages_from"),
            nullable=False,
        ),
    )
    seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class FederationNonce(SQLModel, table=True):
    """Federation request nonce dedup (T3.2 — Phase 45).

    Records ``(from_relay, nonce)`` pairs received via
    ``/api/v1/federation/deliver``. Replays of a previously-seen pair are
    rejected with HTTP 409 by the route layer BEFORE crypto verify.

    The composite ``(from_relay, nonce)`` PRIMARY KEY guarantees that a
    second insert of the same pair raises ``IntegrityError`` — see
    :func:`uam.db.crud.federation_nonces.record_nonce`. Per-relay scope is
    intentional: relay-A and relay-B may legitimately both emit the same
    random 22-char string.

    Pruned by ``_federation_nonce_sweep_loop`` in ``app.py`` every
    ``UAM_FEDERATION_NONCE_SWEEP_INTERVAL`` seconds (default 600s) — old
    rows are deleted after ``2 × federation_timestamp_max_age`` (default
    600s = 10min), well past the 5-min freshness window enforced in
    ``federation_deliver`` Step 3.
    """

    __tablename__ = "federation_nonces"

    from_relay: str = Field(primary_key=True, max_length=255)
    nonce: str = Field(primary_key=True, max_length=64)
    seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class DomainVerification(SQLModel, table=True):
    """DNS-based domain ownership verification for an agent."""

    __tablename__ = "domain_verifications"
    __table_args__ = (UniqueConstraint("agent_address", "domain"),)

    id: int | None = Field(default=None, primary_key=True)
    # T7.3a: per-agent verification state cascades on agent delete.
    agent_address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_domain_verifications_agent"),
            nullable=False,
            index=True,
        ),
    )
    domain: str
    public_key: str
    method: str = Field(default="dns")
    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    last_checked: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    ttl_hours: int = Field(default=24)
    status: str = Field(default="verified")
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class WebhookDelivery(SQLModel, table=True):
    """Tracks webhook delivery attempts for an agent."""

    __tablename__ = "webhook_deliveries"

    id: int | None = Field(default=None, primary_key=True)
    # T7.3a: per-agent operational state cascades on agent delete.
    agent_address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_webhook_deliveries_agent"),
            nullable=False,
            index=True,
        ),
    )
    message_id: str
    envelope: str
    status: str = Field(default="pending")
    attempt_count: int = Field(default=0)
    last_status_code: int | None = None
    last_error: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    completed_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class Reputation(SQLModel, table=True):
    """Per-agent reputation score for spam defense."""

    __tablename__ = "reputation"

    # T7.3a: address is both PRIMARY KEY and FK to agents.address with
    # ON DELETE CASCADE — when an agent is deleted, its reputation row goes
    # with it. Per Pitfall 7, sa_column form is required to surface ondelete.
    address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_reputation_address"),
            primary_key=True,
            nullable=False,
        ),
    )
    score: int = Field(default=30)
    messages_sent: int = Field(default=0)
    messages_rejected: int = Field(default=0)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )


class BlocklistEntry(SQLModel, table=True):
    """Agent-level blocklist pattern."""

    __tablename__ = "blocklist"

    id: int | None = Field(default=None, primary_key=True)
    pattern: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class AllowlistEntry(SQLModel, table=True):
    """Agent-level allowlist pattern."""

    __tablename__ = "allowlist"

    id: int | None = Field(default=None, primary_key=True)
    pattern: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class KnownRelay(SQLModel, table=True):
    """Discovered relay for federation."""

    __tablename__ = "known_relays"

    domain: str = Field(primary_key=True)
    federation_url: str
    public_key: str
    discovered_via: str = Field(default="well-known")
    last_verified: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
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
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class RelayBlocklistEntry(SQLModel, table=True):
    """Relay-level blocklist for federation."""

    __tablename__ = "relay_blocklist"

    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class RelayAllowlistEntry(SQLModel, table=True):
    """Relay-level allowlist for federation."""

    __tablename__ = "relay_allowlist"

    id: int | None = Field(default=None, primary_key=True)
    domain: str = Field(unique=True)
    reason: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class RelayReputation(SQLModel, table=True):
    """Per-relay reputation score for federation trust."""

    __tablename__ = "relay_reputation"

    domain: str = Field(primary_key=True)
    score: int = Field(default=50)
    messages_forwarded: int = Field(default=0)
    messages_rejected: int = Field(default=0)
    last_success: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    last_failure: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )


class FederationQueueEntry(SQLModel, table=True):
    """Queue of outbound federated messages awaiting delivery."""

    __tablename__ = "federation_queue"

    id: int | None = Field(default=None, primary_key=True)
    target_domain: str = Field(index=True)
    envelope: str
    via: str = Field(default="[]")
    hop_count: int = Field(default=0)
    attempt_count: int = Field(default=0)
    next_retry: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    status: str = Field(default="pending")
    error: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


# ---------------------------------------------------------------------------
# Reservation Table
# ---------------------------------------------------------------------------


class Reservation(SQLModel, table=True):
    """Address reservation for the claim-based onboarding flow.

    An address can be reserved before an agent is registered.  The holder
    receives a claim token which, when presented via the API, converts the
    reservation into a full agent registration.

    Uniqueness of *active* reservations is enforced by a composite unique
    constraint on (address, status).  This allows an address to have one
    row per status value (e.g. one "reserved" and one "expired") while
    preventing two concurrent "reserved" rows for the same address.
    """

    __tablename__ = "reservations"
    __table_args__ = (
        UniqueConstraint("address", "status", name="uq_reservation_address_status"),
    )

    id: int | None = Field(default=None, primary_key=True)
    # T7.3a INTENTIONAL: NO ForeignKey on address. Reservations exist BEFORE
    # an agent is registered — the whole purpose is to claim an address that
    # is not yet in the agents table. Adding ForeignKey('agents.address')
    # would prevent the workflow (every reservation insert would fail with
    # IntegrityError because the parent row doesn't exist yet).
    # See RESEARCH OQ3 + tests/db/test_foreign_keys.py::
    # test_reservations_address_has_no_fk (positive contract test).
    # Uniqueness across (agents, reservations) is enforced at the CRUD layer
    # plus the (address, status) composite UniqueConstraint above.
    address: str = Field(index=True)
    claim_token: str = Field(unique=True, index=True)
    status: str = Field(default="reserved", index=True)
    ip_address: str | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )
    # expires_at must be set explicitly by caller (no server_default).
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    claimed_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    deleted_at: datetime | None = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


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
    "FederationNonce",
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
    "Reservation",
]
