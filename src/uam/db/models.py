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

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
)
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
    # Signs this agent's webhooks.  Set exactly when webhook_url is set.
    webhook_secret: str | None = Field(default=None, repr=False)
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
    # No FK: the sender of a stored message may be an agent on another
    # relay (federation). 0006 added one; 0009 drops it.
    from_addr: str = Field(sa_column=Column(String, nullable=False))
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
    # No FK: federated senders are not local agents. 0006 added one;
    # 0009 drops it.
    from_addr: str = Field(sa_column=Column(String, nullable=False))
    seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class InboundPolicy(SQLModel, table=True):
    """Who may deliver to an agent (P1, migration 0012).

    No row means ``open`` (everyone, as before P1). ``contacts`` and
    ``closed`` deliver only from ``allowed`` rows in ``inbound_contacts``.
    ``set_by`` is ``admin`` in P1; owners set it from P2.
    """

    __tablename__ = "inbound_policies"

    agent_address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_inbound_policies_agent"),
            primary_key=True,
        ),
    )
    policy: str = Field(sa_column=Column(String, nullable=False))
    revision: int = Field(
        default=0, sa_column=Column(Integer, nullable=False, server_default="0")
    )
    set_by: str = Field(sa_column=Column(String, nullable=False))
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
        ),
    )


class InboundContact(SQLModel, table=True):
    """A sender an agent with a policy accepts or refuses (P1, migration 0012).

    ``contact_key`` is the key the sender must sign with; a different key
    is held back, never auto-updated. ``grant_ref`` and ``expires_at`` are
    filled from P2 (owner grants, reply windows).
    """

    __tablename__ = "inbound_contacts"
    __table_args__ = (
        UniqueConstraint("agent_address", "contact_address", name="uq_inbound_contacts_pair"),
    )

    id: int | None = Field(default=None, primary_key=True)
    agent_address: str = Field(
        sa_column=Column(
            String,
            ForeignKey("agents.address", ondelete="CASCADE", name="fk_inbound_contacts_agent"),
            nullable=False,
        ),
    )
    contact_address: str = Field(sa_column=Column(String, nullable=False))
    contact_key: str = Field(sa_column=Column(String, nullable=False))
    state: str = Field(sa_column=Column(String, nullable=False))
    source: str = Field(sa_column=Column(String, nullable=False))
    grant_ref: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    expires_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
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
            nullable=False,
        ),
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _created_at() -> Column:
    return Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _owner_fk(table: str) -> Column:
    return Column(
        Integer,
        ForeignKey("owners.id", ondelete="CASCADE", name=f"fk_{table}_owner"),
        nullable=False,
    )


class Owner(SQLModel, table=True):
    """A person who approves contacts for their agents (P2c-1, migration 0013).

    ``owner_id`` is filled once the owner's key log has an entry 0 (P2c-2).
    ``status`` is ``active`` or ``frozen``; ``created_via`` is ``admin`` or
    ``invite``.
    """

    __tablename__ = "owners"
    __table_args__ = (UniqueConstraint("owner_id", name="uq_owners_owner_id"),)

    id: int | None = Field(default=None, primary_key=True)
    owner_id: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    status: str = Field(
        default="active", sa_column=Column(String, nullable=False, server_default="active")
    )
    created_via: str = Field(sa_column=Column(String, nullable=False))
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerEmail(SQLModel, table=True):
    """An owner's email: ``email_hmac`` to look it up, ``email_enc`` to send to it."""

    __tablename__ = "owner_emails"
    __table_args__ = (UniqueConstraint("email_hmac", name="uq_owner_emails_hmac"),)

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(sa_column=_owner_fk("owner_emails"))
    email_hmac: str = Field(sa_column=Column(String, nullable=False))
    email_enc: str = Field(sa_column=Column(String, nullable=False))
    verified_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerLoginCode(SQLModel, table=True):
    """An emailed sign-in code, stored hashed. Keyed by email so asking for a
    code says nothing about whether the address has an account."""

    __tablename__ = "owner_login_codes"

    id: int | None = Field(default=None, primary_key=True)
    email_hmac: str = Field(
        sa_column=Column(String, nullable=False, index=True)
    )
    code_hash: str = Field(sa_column=Column(String, nullable=False))
    tries: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default="0"))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerSession(SQLModel, table=True):
    """A signed-in session on the owner origin; the cookie's token, hashed."""

    __tablename__ = "owner_sessions"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_owner_sessions_token_hash"),)

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(sa_column=_owner_fk("owner_sessions"))
    token_hash: str = Field(sa_column=Column(String, nullable=False))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    last_seen: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    revoked_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerAudit(SQLModel, table=True):
    """What happened to an owner account. ``details`` is JSON text and never
    holds an email address or an IP."""

    __tablename__ = "owner_audit"

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_audit_owner"),
            nullable=False,
            index=True,
        )
    )
    action: str = Field(sa_column=Column(String, nullable=False))
    details: str = Field(
        default="{}", sa_column=Column(Text, nullable=False, server_default="{}")
    )
    at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerPasskey(SQLModel, table=True):
    """An owner's passkey (P2c-2, migration 0014): ``held`` from registration
    until the key log entry that adds it is signed, then ``active``."""

    __tablename__ = "owner_passkeys"
    __table_args__ = (
        UniqueConstraint("credential_id", name="uq_owner_passkeys_credential_id"),
    )

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_passkeys_owner"),
            nullable=False,
            index=True,
        )
    )
    credential_id: str = Field(sa_column=Column(String, nullable=False))
    public_key: str = Field(sa_column=Column(String, nullable=False))
    did: str = Field(sa_column=Column(String, nullable=False))
    backup_eligible: bool = Field(sa_column=Column(Boolean, nullable=False))
    sign_count: int = Field(
        default=0, sa_column=Column(Integer, nullable=False, server_default="0")
    )
    label: str = Field(sa_column=Column(String, nullable=False))
    state: str = Field(
        default="held", sa_column=Column(String, nullable=False, server_default="held")
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())
    removed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    removed_reason: str | None = Field(default=None, sa_column=Column(String, nullable=True))


class OwnerKeyLogEntry(SQLModel, table=True):
    """One signed UamOwnerKeys entry. Keyed by (owner, seq) so the chain
    can't fork."""

    __tablename__ = "owner_key_log"
    __table_args__ = (UniqueConstraint("hash", name="uq_owner_key_log_hash"),)

    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_key_log_owner"),
            primary_key=True,
        )
    )
    seq: int = Field(sa_column=Column(Integer, primary_key=True))
    body: str = Field(sa_column=Column(Text, nullable=False))
    hash: str = Field(sa_column=Column(String, nullable=False))
    signer: str = Field(sa_column=Column(String, nullable=False))
    authenticator_data: str = Field(sa_column=Column(Text, nullable=False))
    client_data_json: str = Field(sa_column=Column(Text, nullable=False))
    signature: str = Field(sa_column=Column(Text, nullable=False))
    screen: str = Field(sa_column=Column(Text, nullable=False))
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class WebAuthnChallenge(SQLModel, table=True):
    """A single-use WebAuthn challenge: ``register`` (a new passkey) or
    ``approve`` (signs ``body``, shown as ``screen``)."""

    __tablename__ = "webauthn_challenges"
    __table_args__ = (
        UniqueConstraint("challenge", name="uq_webauthn_challenges_challenge"),
    )

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_webauthn_challenges_owner"),
            nullable=False,
            index=True,
        )
    )
    purpose: str = Field(sa_column=Column(String, nullable=False))
    challenge: str = Field(sa_column=Column(String, nullable=False))
    passkey_pk: int | None = Field(
        default=None,
        sa_column=Column(
            Integer,
            ForeignKey(
                "owner_passkeys.id", ondelete="CASCADE", name="fk_webauthn_challenges_passkey"
            ),
            nullable=True,
        ),
    )
    body: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    screen: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


def _maybe_time() -> Column:
    return Column(DateTime(timezone=True), nullable=True)


def _agent_fk(table: str, *, index: bool = True) -> Column:
    return Column(
        String,
        ForeignKey("agents.address", ondelete="CASCADE", name=f"fk_{table}_agent"),
        nullable=False,
        index=index,
    )


class OwnerCode(SQLModel, table=True):
    """A setup or link code an owner made (P2d, migration 0015).

    Stored as an HMAC; 10 minutes, single use. Only the newest code of each
    kind counts. ``setup`` is for an agent registered after the code was
    made; ``link`` is for an existing agent."""

    __tablename__ = "owner_codes"
    __table_args__ = (UniqueConstraint("code_hash", name="uq_owner_codes_code_hash"),)

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_codes_owner"),
            nullable=False,
            index=True,
        )
    )
    kind: str = Field(sa_column=Column(String, nullable=False))
    code_hash: str = Field(sa_column=Column(String, nullable=False))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    used_at: datetime | None = Field(default=None, sa_column=_maybe_time())
    used_by: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class OwnerCodeTry(SQLModel, table=True):
    """One attempt by an agent to redeem a code: 5 per 10 minutes."""

    __tablename__ = "owner_code_tries"

    id: int | None = Field(default=None, primary_key=True)
    agent_address: str = Field(sa_column=_agent_fk("owner_code_tries"))
    at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))


class OwnerLink(SQLModel, table=True):
    """An agent linked to an owner: the signed UamOwnerLink.

    ``state`` is ``started`` (the relay built the body), ``agent_signed``,
    ``active`` (the owner signed; in effect from ``effective_at``),
    ``cancelled`` or ``unlinked``. ``live_for`` is the agent's address while
    the link is started, agent_signed or active, and NULL after; it is
    unique, so an agent has at most one live link."""

    __tablename__ = "owner_links"
    __table_args__ = (
        UniqueConstraint("hash", name="uq_owner_links_hash"),
        UniqueConstraint("live_for", name="uq_owner_links_live_for"),
    )

    id: int | None = Field(default=None, primary_key=True)
    owner_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_links_owner"),
            nullable=False,
            index=True,
        )
    )
    agent_address: str = Field(sa_column=_agent_fk("owner_links"))
    agent_key: str = Field(sa_column=Column(String, nullable=False))
    body: str = Field(sa_column=Column(Text, nullable=False))
    hash: str = Field(sa_column=Column(String, nullable=False))
    via: str = Field(sa_column=Column(String, nullable=False))
    effective_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False))
    state: str = Field(
        default="started", sa_column=Column(String, nullable=False, server_default="started")
    )
    live_for: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    agent_signature: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    owner_signer: str | None = Field(default=None, sa_column=Column(String, nullable=True))
    authenticator_data: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    client_data_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    signature: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    screen: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    private: bool = Field(
        default=False, sa_column=Column(Boolean, nullable=False, server_default=false())
    )
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())
    approved_at: datetime | None = Field(default=None, sa_column=_maybe_time())
    ended_at: datetime | None = Field(default=None, sa_column=_maybe_time())


class OwnerUnlink(SQLModel, table=True):
    """The signed UamOwnerUnlink that ended a link: by the owner's passkey
    (``signer`` its did) or by the relay (``signer`` ``relay``)."""

    __tablename__ = "owner_unlinks"
    __table_args__ = (
        UniqueConstraint("link_pk", name="uq_owner_unlinks_link_pk"),
        UniqueConstraint("hash", name="uq_owner_unlinks_hash"),
    )

    id: int | None = Field(default=None, primary_key=True)
    link_pk: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("owner_links.id", ondelete="CASCADE", name="fk_owner_unlinks_link"),
            nullable=False,
        )
    )
    body: str = Field(sa_column=Column(Text, nullable=False))
    hash: str = Field(sa_column=Column(String, nullable=False))
    reason: str = Field(sa_column=Column(String, nullable=False))
    signer: str = Field(sa_column=Column(String, nullable=False))
    authenticator_data: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    client_data_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    signature: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    screen: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(default_factory=_now, sa_column=_created_at())


class RoutedMessage(SQLModel, table=True):
    """Messages this relay accepted for delivery, so a receipt can be
    matched to the message it answers (MSG-05).

    A receipt from B to A whose signed ``reply_to`` names a row routed
    A -> B is bound; ``receipt_count`` caps how many receipts one message
    can bind. No FKs: either side may be on another relay.
    """

    __tablename__ = "routed_messages"

    message_id: str = Field(primary_key=True)
    from_addr: str = Field(sa_column=Column(String, nullable=False))
    to_addr: str = Field(sa_column=Column(String, nullable=False))
    receipt_count: int = Field(
        default=0, sa_column=Column(Integer, nullable=False, server_default="0")
    )
    routed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            nullable=False,
            index=True,
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
            index=True,  # ix_federation_nonces_seen_at (migration 0004): the sweep
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
