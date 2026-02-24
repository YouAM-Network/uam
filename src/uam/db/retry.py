"""Retry logic for transient database errors (RES-06).

Provides a decorator that catches SQLAlchemy operational errors (connection
drops, deadlocks) and retries with exponential backoff.  Non-transient
errors (constraint violations, programming errors) are re-raised immediately.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from sqlalchemy.exc import DBAPIError, OperationalError

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default retry config
MAX_RETRIES: int = 3
BASE_DELAY: float = 0.1  # 100ms
MAX_DELAY: float = 2.0  # 2s
BACKOFF_FACTOR: float = 2.0


def is_transient_error(exc: Exception) -> bool:
    """Determine if a database error is transient (retriable).

    Transient errors include:
    - Connection refused / connection reset / connection lost
    - Deadlock detected
    - Lock timeout
    - Database is locked (SQLite)
    - Server closed the connection unexpectedly (PostgreSQL)

    Non-transient: constraint violations, programming errors, etc.
    """
    if isinstance(exc, OperationalError):
        msg = str(exc).lower()
        transient_patterns = [
            "connection refused",
            "connection reset",
            "connection lost",
            "deadlock",
            "database is locked",
            "timeout",
            "server closed",
            "broken pipe",
        ]
        return any(p in msg for p in transient_patterns)

    if isinstance(exc, DBAPIError):
        # Check if the underlying DBAPI error is transient
        if exc.connection_invalidated:
            return True

    return False


def db_retry(
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    max_delay: float = MAX_DELAY,
    backoff_factor: float = BACKOFF_FACTOR,
) -> Callable:
    """Decorator that retries async functions on transient DB errors.

    Meant for service-level functions or background workers that create their
    own sessions.  For route handlers using ``Depends(get_session)``, the retry
    is less useful since the session is already bound.

    The primary use case is background workers like ``_dedup_cleanup_loop``,
    ``_expired_message_sweep_loop``, ``_federation_retry_loop``, etc. that
    create inline sessions.

    Usage::

        @db_retry()
        async def my_db_operation(session: AsyncSession) -> Result:
            ...

        @db_retry(max_retries=5, base_delay=0.5)
        async def critical_operation(session: AsyncSession) -> Result:
            ...
    """

    def decorator(
        func: Callable[..., Coroutine[Any, Any, T]],
    ) -> Callable[..., Coroutine[Any, Any, T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except (OperationalError, DBAPIError) as exc:
                    if not is_transient_error(exc):
                        raise  # Non-transient -- don't retry

                    last_exc = exc
                    if attempt < max_retries:
                        delay = min(
                            base_delay * (backoff_factor**attempt), max_delay
                        )
                        logger.warning(
                            "Transient DB error in %s (attempt %d/%d), "
                            "retrying in %.2fs: %s",
                            func.__name__,
                            attempt + 1,
                            max_retries + 1,
                            delay,
                            exc,
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            "Transient DB error in %s exhausted %d retries: %s",
                            func.__name__,
                            max_retries + 1,
                            exc,
                        )
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator
