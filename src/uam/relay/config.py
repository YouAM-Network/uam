"""Relay server configuration from environment variables."""

from __future__ import annotations

import os


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
        # Federation settings (FED-01 through FED-10)
        self.relay_key_path: str = os.getenv("UAM_RELAY_KEY_PATH", "relay_key.pem")
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
