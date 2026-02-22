"""Relay server configuration from environment variables."""

from __future__ import annotations

import os


class Settings:
    """Relay server settings, read from environment variables with defaults."""

    def __init__(self) -> None:
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
        self.cors_origins: str = os.getenv("UAM_CORS_ORIGINS", "*")
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
