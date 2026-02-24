"""UAM database package.

Re-exports all 17 SQLModel table classes, the async engine factory, and the
session management layer for convenient top-level imports::

    from uam.db import Agent, Message, get_session, init_engine
"""

from uam.db.engine import (
    create_async_engine_from_env,
    create_async_engine_from_url,
    dispose_engine,
    get_engine,
    init_engine,
)
from uam.db.models import (
    Agent,
    AllowlistEntry,
    AuditLog,
    BlocklistEntry,
    Contact,
    DomainVerification,
    FederationLog,
    FederationQueueEntry,
    Handshake,
    KnownRelay,
    Message,
    RelayAllowlistEntry,
    RelayBlocklistEntry,
    RelayReputation,
    Reputation,
    SeenMessageId,
    WebhookDelivery,
)
from uam.db.retry import db_retry, is_transient_error
from uam.db.session import (
    async_session_factory,
    create_tables,
    get_session,
    init_session_factory,
)

__all__ = [
    # Engine
    "create_async_engine_from_env",
    "create_async_engine_from_url",
    "dispose_engine",
    "get_engine",
    "init_engine",
    # Retry
    "db_retry",
    "is_transient_error",
    # Session
    "async_session_factory",
    "create_tables",
    "get_session",
    "init_session_factory",
    # Models
    "Agent",
    "AllowlistEntry",
    "AuditLog",
    "BlocklistEntry",
    "Contact",
    "DomainVerification",
    "FederationLog",
    "FederationQueueEntry",
    "Handshake",
    "KnownRelay",
    "Message",
    "RelayAllowlistEntry",
    "RelayBlocklistEntry",
    "RelayReputation",
    "Reputation",
    "SeenMessageId",
    "WebhookDelivery",
]
