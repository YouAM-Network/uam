"""SDK configuration via dataclass (no pydantic -- instant construction)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DEFAULT_RELAY_URL = "https://relay.youam.network"
_DEFAULT_REGISTRAR_URL = "https://registrar.youam.network"

_VALID_POLICIES = {"auto-accept", "approval-required", "allowlist-only"}


@dataclass
class SDKConfig:
    """Configuration for a UAM SDK agent.

    All fields have sensible defaults.  ``relay_url`` and ``relay_ws_url``
    can be overridden via environment variables (``UAM_RELAY_URL``) or
    constructor arguments.

    Priority (highest wins): constructor arg > env var > config.toml > default.
    """

    name: str
    relay_url: str | None = None
    relay_ws_url: str | None = None
    key_dir: Path | str | None = None
    data_dir: Path | str | None = None
    display_name: str | None = None
    transport_type: str = "websocket"
    trust_policy: str = "auto-accept"
    relay_domain: str = ""
    registrar_url: str | None = None

    def __post_init__(self) -> None:
        # Apply defaults from env vars where None is passed
        if self.relay_url is None:
            self.relay_url = os.getenv("UAM_RELAY_URL", _DEFAULT_RELAY_URL)

        # Registrar URL: env var > constructor arg > default
        if self.registrar_url is None:
            self.registrar_url = os.getenv(
                "UAM_REGISTRAR_URL", _DEFAULT_REGISTRAR_URL
            )

        # Derive relay_ws_url from relay_url if not explicitly set
        if self.relay_ws_url is None:
            ws_url = self.relay_url.replace("https://", "wss://").replace("http://", "ws://")
            if not ws_url.endswith("/ws"):
                ws_url = ws_url.rstrip("/") + "/ws"
            self.relay_ws_url = ws_url

        # Derive relay_domain: env var > constructor arg > URL hostname
        env_domain = os.getenv("UAM_RELAY_DOMAIN")
        if env_domain:
            self.relay_domain = env_domain
        elif not self.relay_domain:
            parsed = urlparse(self.relay_url)
            self.relay_domain = parsed.hostname or self.relay_url.split("://")[-1].split("/")[0] or "localhost"

        # Default key_dir and data_dir.
        # UAM_HOME env var overrides ~/.uam (useful for testing / isolation).
        uam_home = os.getenv("UAM_HOME")
        default_home = Path(uam_home) if uam_home else Path.home() / ".uam"

        if self.key_dir is None:
            self.key_dir = default_home / "keys"
        else:
            self.key_dir = Path(self.key_dir)

        if self.data_dir is None:
            self.data_dir = default_home
        else:
            self.data_dir = Path(self.data_dir)

        # Default display_name
        if self.display_name is None:
            self.display_name = self.name

        # Load optional config.toml (lowest priority -- only overrides defaults)
        config_path = Path(self.data_dir) / "config.toml"
        if config_path.exists():
            self._load_config_file(config_path)

        # Override trust_policy from env var (higher priority than config file)
        env_policy = os.getenv("UAM_TRUST_POLICY")
        if env_policy:
            self.trust_policy = env_policy

        # Validate trust_policy
        if self.trust_policy not in _VALID_POLICIES:
            raise ValueError(
                f"Invalid trust_policy '{self.trust_policy}'. "
                f"Must be one of: {sorted(_VALID_POLICIES)}"
            )

    def _load_config_file(self, path: Path) -> None:
        """Load optional config.toml, applying values for fields still at defaults."""
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]  # Python 3.10 fallback

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            logger.warning("Failed to load config file %s", path, exc_info=True)
            return

        agent_section = data.get("agent", {})

        # Only override trust_policy if it still has the default value
        if "trust_policy" in agent_section and self.trust_policy == "auto-accept":
            self.trust_policy = agent_section["trust_policy"]
