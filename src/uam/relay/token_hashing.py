"""Token hashing primitive for the relay (T2.1).

Tokens are stored on the relay as ``HMAC-SHA-256(token, server_pepper)``
rather than plaintext.  The pepper is a server-wide secret kept in the
``UAM_TOKEN_PEPPER`` environment variable -- never in the database --
so a DB-only compromise (SQL dump, read-replica access, backup theft)
yields hashes that cannot be brute-forced offline back into bearer
tokens.

Why HMAC-SHA-256 and not Argon2/bcrypt?  UAM tokens are
``secrets.token_urlsafe(32)`` -- 256 bits of entropy.  Slow KDFs are
designed for *low-entropy passwords*; for high-entropy random tokens
they add 50 ms+ per request with no security gain.  This matches what
Stripe / GitHub / Slack do for their API keys, and what OWASP
recommends for high-entropy bearer tokens.

The same primitive is used in three places:

* ``uam.relay.auth.verify_token_http`` and ``verify_token_ws`` --
  hash the incoming bearer token, look up by ``Agent.token_hash``.
* ``uam.relay.routes.register.register`` -- write the hash on insert.
* ``alembic/versions/0003_token_hash.py`` -- backfill existing rows.

Lookup vs comparison: lookup is by hash equality in SQL; the final
``hmac.compare_digest`` check in ``auth.py`` is constant-time defense
in depth (the row already matched by hash, but ``compare_digest``
documents intent and protects against future "look up by some other
field" mistakes).
"""

from __future__ import annotations

import hashlib
import hmac


def hash_token(token: str, pepper: str) -> str:
    """Return ``HMAC-SHA-256(token, pepper).hexdigest()``.

    Parameters
    ----------
    token:
        The plaintext bearer token (typically from
        ``secrets.token_urlsafe(32)``).
    pepper:
        The server-wide secret pepper from ``UAM_TOKEN_PEPPER``.
        Must be non-empty; raises ``ValueError`` otherwise to fail
        loudly rather than silently produce a hash with an empty key.

    Returns
    -------
    str
        64-character hex digest suitable for storage in
        ``agents.token_hash`` and for indexed equality lookup.
    """
    if not pepper:
        raise ValueError(
            "Token pepper not configured (UAM_TOKEN_PEPPER). "
            "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    return hmac.new(
        pepper.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


__all__ = ["hash_token"]
