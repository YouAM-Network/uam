"""Relay server configuration from environment variables."""

from __future__ import annotations

import os
import re

#: A sender: an address, or "Name <address>" (no quotes or angle brackets in the name).
_ADDRESS = r"[^@\s<>\"]+@[^@\s<>\"]+\.[^@\s<>\"]+"
_EMAIL_FROM_RE = re.compile(rf"(?:[^<>\"\r\n]{{1,64}} <{_ADDRESS}>|{_ADDRESS})")


class Settings:
    """Relay server settings, read from environment variables with defaults."""

    def __init__(self) -> None:
        # T2.1: Server-side pepper for HMAC-SHA-256(token, pepper).  The
        # relay refuses to start if this is unset (see _require()).
        # Generate with:
        #   python -c "import secrets; print(secrets.token_urlsafe(48))"
        # NEVER rotate this value without coordinated re-issuance of every
        # existing bearer token (or a dual-pepper rolling rotation, which
        # is deferred per 43-RESEARCH.md Open Question 1).
        self.token_pepper: str = self._require("UAM_TOKEN_PEPPER")
        # T6.5 Phase 46: relay_domain — in production, env var MUST be set
        # explicitly (default 'youam.network' would falsely claim production
        # identity in federation signing).
        if Settings._is_production() and "UAM_RELAY_DOMAIN" not in os.environ:
            raise RuntimeError(
                "UAM_RELAY_DOMAIN must be set explicitly in production "
                "(UAM_ENV=production). The default 'youam.network' would "
                "falsely claim production identity in federation signing."
            )
        self.relay_domain: str = os.getenv("UAM_RELAY_DOMAIN", "youam.network")
        self.relay_ws_url: str = os.getenv(
            "UAM_RELAY_WS_URL", "wss://relay.youam.network/ws"
        )
        self.relay_http_url: str = os.getenv(
            "UAM_RELAY_HTTP_URL", "https://relay.youam.network"
        )
        self.database_path: str = os.getenv("UAM_DB_PATH", "relay.db")
        self.host: str = os.getenv("UAM_HOST", "0.0.0.0")
        self.port: int = int(os.getenv("UAM_PORT", "8000"))
        # T6.5 Phase 46: cors_origins — in production, refuse "*" wildcard.
        # Wildcard CORS exposes authenticated endpoints to JS on any origin.
        cors_raw = os.getenv("UAM_CORS_ORIGINS", "*")
        if Settings._is_production() and cors_raw.strip() == "*":
            raise RuntimeError(
                "UAM_CORS_ORIGINS='*' refused in production "
                "(UAM_ENV=production). Set an explicit comma-separated "
                "allow-list of origins (e.g. 'https://app.example.com')."
            )
        self.cors_origins: str = cors_raw
        # T6.1 Phase 46: HTTP body-size cap (1 MiB default — fits vCard PHOTO base64 + slack)
        self.max_http_body_bytes: int = int(
            os.getenv("UAM_MAX_HTTP_BODY_BYTES", str(1024 * 1024))
        )
        # T6.1 Phase 46: trusted-proxy CIDR allow-list (comma-separated, "" = no proxies)
        # When empty, TrustedProxyMiddleware short-circuits and request.client.host
        # is the actual TCP peer IP. Set this in production behind any LB.
        # T6.5 Phase 46: in production, env var MUST be set explicitly (use empty
        # string '' to declare 'no trusted proxies'). This prevents silent
        # XFF-spoofing if an operator deploys to prod without thinking about
        # proxy trust at all.
        self.trusted_proxies: str = self._require_explicit_in_production(
            "UAM_TRUSTED_PROXIES"
        )
        self.log_level: str = os.getenv("UAM_LOG_LEVEL", "INFO").upper()
        self.debug: bool = os.getenv("UAM_DEBUG", "").lower() in ("1", "true", "yes")
        self.domain_verification_ttl_hours: int = int(
            os.getenv("UAM_DOMAIN_VERIFICATION_TTL_HOURS", "24")
        )
        self.webhook_circuit_cooldown_seconds: int = int(
            os.getenv("UAM_WEBHOOK_CIRCUIT_COOLDOWN_SECONDS", "3600")
        )
        self.webhook_delivery_timeout: float = float(
            os.getenv("UAM_WEBHOOK_DELIVERY_TIMEOUT", "30.0")
        )
        # Spam defense settings (SPAM-05)
        self.admin_api_key: str | None = os.getenv("UAM_ADMIN_API_KEY")
        self.domain_rate_limit: int = int(
            os.getenv("UAM_DOMAIN_RATE_LIMIT", "200")
        )
        self.reputation_default_score: int = int(
            os.getenv("UAM_REPUTATION_DEFAULT_SCORE", "30")
        )
        self.reputation_dns_verified_score: int = int(
            os.getenv("UAM_REPUTATION_DNS_VERIFIED_SCORE", "60")
        )
        # What to do with a message type the protocol does not define:
        # "log" delivers it with a warning, "reject" refuses it (400).
        # Pending answers (the delivery gate) per sender per minute. They
        # don't take the recipient's slots, so they have their own bucket.
        self.pending_rate_limit: int = int(
            os.getenv("UAM_PENDING_RATE_LIMIT", "300")
        )
        self.unknown_message_types: str = os.getenv(
            "UAM_UNKNOWN_MESSAGE_TYPES", "log"
        ).lower()
        if self.unknown_message_types not in ("log", "reject"):
            raise RuntimeError(
                "UAM_UNKNOWN_MESSAGE_TYPES must be 'log' or 'reject', "
                f"got {self.unknown_message_types!r}"
            )
        # Federation settings (FED-01 through FED-10)
        self.relay_key_path: str = os.getenv("UAM_RELAY_KEY_PATH", "relay_key.pem")
        # The relay key itself (base64 Ed25519 seed), from the operator's
        # secret store. Wins over UAM_RELAY_KEY_PATH when set.
        self.relay_key: str | None = os.getenv("UAM_RELAY_KEY") or None
        # When the current key came into use (ISO 8601), published with it.
        self.relay_key_valid_from: str | None = (
            os.getenv("UAM_RELAY_KEY_VALID_FROM") or None
        )
        # Retired relay public keys, JSON: [{public_key, valid_from?, retired_at}].
        self.relay_key_history: str | None = (
            os.getenv("UAM_RELAY_KEY_HISTORY") or None
        )
        self.federation_enabled: bool = os.getenv(
            "UAM_FEDERATION_ENABLED", "true"
        ).lower() in ("1", "true", "yes")
        self.federation_max_hops: int = int(
            os.getenv("UAM_FEDERATION_MAX_HOPS", "3")
        )
        self.federation_relay_rate_limit: int = int(
            os.getenv("UAM_FEDERATION_RELAY_RATE_LIMIT", "1000")
        )
        self.federation_timestamp_max_age: int = int(
            os.getenv("UAM_FEDERATION_TIMESTAMP_MAX_AGE", "300")
        )
        self.federation_discovery_ttl_hours: int = int(
            os.getenv("UAM_FEDERATION_DISCOVERY_TTL_HOURS", "1")
        )
        # T1.4: Federation peer-key cache TTL (seconds). Bounds the time window
        # during which a poisoned home-relay /public-key response could affect
        # inbound delivery. Default: 5 minutes.
        self.federation_peer_key_ttl: int = int(
            os.getenv("UAM_FEDERATION_PEER_KEY_TTL", "300")
        )
        self.federation_retry_delays: list[int] = [0, 30, 300, 1800, 7200]
        # Reservation settings (RES-02)
        self.reservation_ttl_hours: int = int(
            os.getenv("UAM_RESERVATION_TTL_HOURS", "48")
        )
        # Card styling settings
        self.avatar_style: str = os.getenv("UAM_AVATAR_STYLE", "bots")
        self.card_bg_color: str | None = os.getenv("UAM_CARD_BG_COLOR")
        self.card_accent_color: str | None = os.getenv("UAM_CARD_ACCENT_COLOR")
        self.card_badge_text: str | None = os.getenv("UAM_CARD_BADGE_TEXT")
        # Viral onboarding settings (VIRAL-01)
        self.website_url: str = os.getenv(
            "UAM_WEBSITE_URL", f"https://{self.relay_domain}"
        )
        # Names nobody can newly register, beyond the built-in list (P2s).
        from uam.relay.reserved_names import parse_extra

        self.reserved_names: frozenset[str] = parse_extra(os.getenv("UAM_RESERVED_NAMES", ""))
        # Owner accounts (P2c-1). Off by default; when on, the owner app is
        # served on UAM_OWNER_ORIGIN's host and these must all be valid.
        self.owners_enabled: bool = os.getenv(
            "UAM_OWNERS_ENABLED", ""
        ).lower() in ("1", "true", "yes")
        self.owner_origin: str = os.getenv("UAM_OWNER_ORIGIN", "").strip()
        self.rp_id: str = os.getenv("UAM_RP_ID", "").strip().lower()
        self.email_pepper: str = os.getenv("UAM_EMAIL_PEPPER", "")
        self.email_key: str = os.getenv("UAM_EMAIL_KEY", "")
        # Without owner mail (local runs), sign-in codes can go to the log,
        # but never on a production RP ID.
        self.owner_codes_to_log: bool = os.getenv(
            "UAM_OWNER_CODES_TO_LOG", ""
        ).lower() in ("1", "true", "yes")
        # Owner email (P2g-1): sent through Resend from an address on the
        # sending domain. Without a key, emails go to the log (local runs,
        # UAM_OWNER_CODES_TO_LOG) or nowhere.
        self.resend_api_key: str = os.getenv("UAM_RESEND_API_KEY", "").strip()
        self.email_from: str = os.getenv(
            "UAM_EMAIL_FROM", "YouAM <account@notify.youam.network>"
        ).strip()
        # Emails sent for agents asking for an owner (P2s-3), across the
        # whole relay, in any 24 hours. Over it, requests are still recorded.
        self.owner_request_emails_per_day: int = int(
            os.getenv("UAM_OWNER_REQUEST_EMAILS_PER_DAY", "500")
        )
        if self.owners_enabled:
            self._check_owner_settings()

    #: RP IDs that mean the public network; codes never go to the log there.
    PRODUCTION_RP_IDS = frozenset({"youam.network"})

    @property
    def owner_host(self) -> str:
        """The owner origin's host name (no port), or "" when owners are off."""
        if not self.owners_enabled:
            return ""
        from urllib.parse import urlsplit

        return urlsplit(self.owner_origin).hostname or ""

    def _check_owner_settings(self) -> None:
        from urllib.parse import urlsplit

        from uam.protocol.signed import _DOMAIN_RE
        from uam.relay.owners.crypto import decode_email_key

        def refuse(name: str, why: str) -> None:
            raise RuntimeError(f"{name}: {why} (UAM_OWNERS_ENABLED is on)")

        for name, value in (
            ("UAM_OWNER_ORIGIN", self.owner_origin),
            ("UAM_RP_ID", self.rp_id),
            ("UAM_EMAIL_PEPPER", self.email_pepper),
            ("UAM_EMAIL_KEY", self.email_key),
        ):
            if not value:
                refuse(name, "must be set")
        if len(self.email_pepper) < 32:
            refuse("UAM_EMAIL_PEPPER", "must be at least 32 characters")
        try:
            decode_email_key(self.email_key)
        except ValueError as exc:
            refuse("UAM_EMAIL_KEY", f"must be base64url of 32 bytes ({exc})")

        try:
            parts = urlsplit(self.owner_origin)
            host = parts.hostname or ""
            parts.port  # noqa: B018  (raises on a bad port)
        except ValueError:
            refuse("UAM_OWNER_ORIGIN", "is not a URL")
        local = host in ("localhost", "127.0.0.1") or host.endswith(".localhost")
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            refuse("UAM_OWNER_ORIGIN", "must be https (http only for localhost)")
        if (
            not host
            or parts.username is not None
            or parts.password is not None
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            refuse("UAM_OWNER_ORIGIN", "must be scheme://host[:port] and nothing else")
        self.owner_origin = f"{parts.scheme}://{parts.netloc}".lower()
        if host == (urlsplit(self.relay_http_url).hostname or "").lower():
            refuse("UAM_OWNER_ORIGIN", "must be its own host, not the relay API's")

        # Key log entries name both as domains (signed-object schema).
        for name, value in (("UAM_RELAY_DOMAIN", self.relay_domain), ("UAM_RP_ID", self.rp_id)):
            if not _DOMAIN_RE.match(value):
                refuse(name, "must be a domain with a dot, like uam.localhost for local use")
        if self.rp_id != host and not host.endswith("." + self.rp_id):
            refuse("UAM_RP_ID", f"must be {host!r} or a parent domain of it")
        if self.owner_codes_to_log and self.rp_id in self.PRODUCTION_RP_IDS:
            refuse("UAM_OWNER_CODES_TO_LOG", "refused with a production RP ID")
        if self.rp_id in self.PRODUCTION_RP_IDS and not self.resend_api_key:
            refuse("UAM_RESEND_API_KEY", "must be set with a production RP ID (sign-in is by email)")
        if self.resend_api_key and not _EMAIL_FROM_RE.fullmatch(self.email_from):
            refuse("UAM_EMAIL_FROM", "must be 'Name <address@domain>' or an address")

    @staticmethod
    def _require(name: str) -> str:
        """Read a required env var or raise.

        The relay refuses to start if any required env var is unset.
        Use this at construction time to fail loudly during boot rather
        than silently mis-configure the runtime.
        """
        v = os.getenv(name)
        if not v:
            raise RuntimeError(
                f"Required env var {name} is unset. The relay refuses to "
                f"start without it. Generate one with: "
                f"python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        return v

    @staticmethod
    def _is_production() -> bool:
        """True if UAM_ENV=production. Default 'development' (safe-by-default).

        T6.5 Phase 46: opt-in production gate. Operators must EXPLICITLY set
        UAM_ENV=production to enable strict required-secrets checks.
        """
        # Phase 47 R-T6.5-01: .strip() defense against operator-typo bypass.
        # Common .env-file mistake: `UAM_ENV=production ` (trailing space).
        # Without .strip(), the gate silently falls through to development mode.
        # See REVIEW-phase46.md § T6.5 Bypass attempt 2.
        return os.getenv("UAM_ENV", "development").strip().lower() == "production"

    @staticmethod
    def _require_explicit_in_production(name: str) -> str:
        """In production, the env var MUST be set explicitly (even to empty
        string). In development, returns the value or empty string.

        T6.5 Phase 46: Distinction vs ``_require``: this helper allows empty
        string in production (e.g. ``UAM_TRUSTED_PROXIES=''`` declares 'no
        trusted proxies'). ``_require`` rejects empty string and requires a
        non-empty value. Use this for fields where 'empty is a valid choice
        the operator must explicitly make' (e.g. trusted_proxies CIDR list).
        """
        if Settings._is_production():
            if name not in os.environ:
                raise RuntimeError(
                    f"Required env var {name} is not set in production "
                    f"(UAM_ENV=production). Set explicitly — use empty string "
                    f"'' to declare no value (e.g. {name}='' = explicitly no "
                    f"entries). This prevents silent misconfiguration when "
                    f"deploying to prod without thinking about this setting."
                )
        return os.getenv(name, "")


# ---------------------------------------------------------------------------
# Module-level singleton -- imported by ``auth.py`` and tests.
#
# Constructed lazily on first attribute access so that simply importing
# ``uam.relay.config`` (e.g. for type hints, for module discovery, or for
# pytest collection) does not require every required env var to be set.
# Production code paths that read from settings (``auth.verify_token_http``,
# ``register.register``, etc.) DO touch the attributes and will raise the
# clear ``RuntimeError`` from ``_require()`` if the relay was misconfigured.
# ---------------------------------------------------------------------------


class _LazySettings:
    """Proxy that constructs the real ``Settings`` on first attribute access."""

    _instance: Settings | None = None

    def _materialize(self) -> Settings:
        if self._instance is None:
            self._instance = Settings()
        return self._instance

    def __getattr__(self, name: str) -> object:
        return getattr(self._materialize(), name)

    def __setattr__(self, name: str, value: object) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._materialize(), name, value)


settings = _LazySettings()
