"""FederationService -- relay discovery and outbound message forwarding.

Discovers remote relay endpoints via DNS SRV lookup with
``.well-known/uam-relay.json`` fallback, caches results in the
``known_relays`` table, and forwards signed envelopes to remote relays.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import dns.exception
import httpx

from uam.protocol.types import utc_timestamp
from uam.relay.database import get_known_relay, log_federation, upsert_known_relay
from uam.relay.relay_auth import sign_federation_request

logger = logging.getLogger(__name__)


@dataclass
class ForwardResult:
    """Result of an outbound federation forwarding attempt."""

    delivered: bool
    queued: bool = False
    error: str | None = None


class FederationService:
    """Outbound federation: relay discovery and envelope forwarding.

    Parameters
    ----------
    db:
        An open ``aiosqlite.Connection``.
    settings:
        The relay :class:`~uam.relay.config.Settings` instance.
    signing_key:
        The relay's Ed25519 ``SigningKey``.
    verify_key:
        The relay's Ed25519 ``VerifyKey`` (for identity advertisement).
    """

    def __init__(self, db, settings, signing_key, verify_key):  # noqa: ANN001
        self._db = db
        self._settings = settings
        self._signing_key = signing_key
        self._verify_key = verify_key
        self._client = httpx.AsyncClient(timeout=30.0)
        self._relay_domain: str = settings.relay_domain

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover_relay(self, domain: str) -> dict | None:
        """Discover a remote relay's federation endpoint.

        1. Check the ``known_relays`` cache.  If the entry is fresh
           (``last_verified + ttl_hours > now``), return it immediately.
        2. Try DNS SRV at ``_uam._tcp.{domain}``.
        3. On DNS SRV success, fetch the relay's public key from
           ``/.well-known/uam-relay.json`` at the SRV target.
        4. On DNS SRV failure, fall back to
           ``https://{domain}/.well-known/uam-relay.json``.
        5. Cache the result in ``known_relays`` and return it.

        Returns a dict ``{"domain", "federation_url", "public_key"}``
        or ``None`` on total failure.  Never raises.
        """
        # 1. Cache check
        cached = await get_known_relay(self._db, domain)
        if cached and cached.get("status") == "active":
            last_verified = cached.get("last_verified", "")
            ttl_hours = cached.get("ttl_hours", 1)
            try:
                lv_dt = datetime.fromisoformat(last_verified)
                if lv_dt.tzinfo is None:
                    lv_dt = lv_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_hours = (now - lv_dt).total_seconds() / 3600
                if age_hours < ttl_hours:
                    return {
                        "domain": cached["domain"],
                        "federation_url": cached["federation_url"],
                        "public_key": cached["public_key"],
                    }
            except (ValueError, TypeError):
                pass  # Stale or unparseable -- re-discover

        # 2. DNS SRV lookup
        srv_result = await self._discover_via_dns_srv(domain)
        if srv_result is not None:
            target, port = srv_result
            federation_url = f"https://{target}:{port}/api/v1/federation/deliver"
            # 3. Fetch public key from .well-known on the SRV target
            public_key = await self._fetch_well_known_key(target, port)
            if public_key is not None:
                ttl = self._settings.federation_discovery_ttl_hours
                await upsert_known_relay(
                    self._db, domain, federation_url, public_key, "dns-srv", ttl
                )
                return {
                    "domain": domain,
                    "federation_url": federation_url,
                    "public_key": public_key,
                }

        # 4. Fallback: .well-known at the domain itself
        well_known = await self._discover_via_well_known(domain)
        if well_known is not None:
            ttl = self._settings.federation_discovery_ttl_hours
            await upsert_known_relay(
                self._db,
                domain,
                well_known["federation_endpoint"],
                well_known["public_key"],
                "well-known",
                ttl,
            )
            return {
                "domain": domain,
                "federation_url": well_known["federation_endpoint"],
                "public_key": well_known["public_key"],
            }

        logger.warning("Federation discovery failed for domain %s", domain)
        return None

    async def _discover_via_dns_srv(self, domain: str) -> tuple[str, int] | None:
        """Query ``_uam._tcp.{domain}`` for SRV records.

        Returns ``(target_host, port)`` for the best record, or ``None``.
        """
        resolver = dns.asyncresolver.Resolver()
        try:
            answer = await resolver.resolve(
                f"_uam._tcp.{domain}",
                rdtype=dns.rdatatype.SRV,
                lifetime=10.0,
            )
            best = min(answer, key=lambda r: (r.priority, -r.weight))
            target = str(best.target).rstrip(".")
            logger.info(
                "DNS SRV for %s resolved to %s:%d", domain, target, best.port
            )
            return (target, best.port)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.DNSException,
        ):
            logger.debug("DNS SRV lookup failed for _uam._tcp.%s", domain)
            return None
        except Exception:
            logger.debug(
                "Unexpected error during DNS SRV lookup for %s", domain, exc_info=True
            )
            return None

    async def _fetch_well_known_key(
        self, host: str, port: int = 443
    ) -> str | None:
        """GET ``https://{host}:{port}/.well-known/uam-relay.json`` and
        extract the ``public_key`` field.  Returns ``None`` on failure.
        """
        url = f"https://{host}:{port}/.well-known/uam-relay.json"
        try:
            resp = await self._client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return data.get("public_key")
        except Exception:
            logger.debug(
                "Failed to fetch .well-known from %s", url, exc_info=True
            )
            return None

    async def _discover_via_well_known(self, domain: str) -> dict | None:
        """Fetch ``https://{domain}/.well-known/uam-relay.json``.

        Returns ``{"federation_endpoint": ..., "public_key": ...}`` or ``None``.
        """
        url = f"https://{domain}/.well-known/uam-relay.json"
        try:
            resp = await self._client.get(url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            federation_endpoint = data.get("federation_endpoint")
            public_key = data.get("public_key")
            if federation_endpoint and public_key:
                return {
                    "federation_endpoint": federation_endpoint,
                    "public_key": public_key,
                }
            logger.warning(
                ".well-known at %s missing required fields", domain
            )
            return None
        except Exception:
            logger.debug(
                "Failed to fetch .well-known from %s", url, exc_info=True
            )
            return None

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    async def forward(
        self,
        envelope_dict: dict,
        from_relay: str,
        via: list[str] | None = None,
        hop_count: int = 0,
    ) -> ForwardResult:
        """Forward an envelope to the remote relay that owns the recipient.

        1. Extract target domain from ``to_address``.
        2. Discover the remote relay.
        3. Build and sign the federation request body.
        4. POST to the remote relay's federation endpoint.
        5. Log the result to ``federation_log``.

        Returns a :class:`ForwardResult` indicating delivery outcome.
        """
        # 1. Parse target domain
        to_address = envelope_dict.get("to", "")
        if "::" not in to_address:
            return ForwardResult(
                delivered=False, queued=False, error="invalid_to_address"
            )
        target_domain = to_address.split("::")[1]

        # 2. Discover remote relay
        relay_info = await self.discover_relay(target_domain)
        if relay_info is None:
            return ForwardResult(
                delivered=False, queued=False, error="discovery_failed"
            )

        # 3. Build federation request body
        body = {
            "envelope": envelope_dict,
            "via": (via or []) + [from_relay],
            "hop_count": hop_count + 1,
            "timestamp": utc_timestamp(),
            "from_relay": from_relay,
        }

        # 4. Sign the request
        signature = sign_federation_request(body, self._signing_key)

        # 5. POST to remote relay
        message_id = envelope_dict.get("message_id", "unknown")
        headers = {
            "X-UAM-Relay-Signature": signature,
            "X-UAM-Relay-Domain": from_relay,
            "Content-Type": "application/json",
        }

        try:
            resp = await self._client.post(
                relay_info["federation_url"],
                json=body,
                headers=headers,
                timeout=30.0,
            )
            if resp.status_code in (200, 201):
                await log_federation(
                    self._db,
                    message_id,
                    from_relay,
                    target_domain,
                    "outbound",
                    hop_count + 1,
                    "delivered",
                )
                return ForwardResult(delivered=True)
            else:
                error_detail = f"HTTP {resp.status_code}: {resp.text[:200]}"
                await log_federation(
                    self._db,
                    message_id,
                    from_relay,
                    target_domain,
                    "outbound",
                    hop_count + 1,
                    "failed",
                    error=error_detail,
                )
                return ForwardResult(
                    delivered=False, queued=False, error=error_detail
                )
        except httpx.TimeoutException as exc:
            error_detail = f"Timeout: {exc}"
            await log_federation(
                self._db,
                message_id,
                from_relay,
                target_domain,
                "outbound",
                hop_count + 1,
                "failed",
                error=error_detail,
            )
            return ForwardResult(
                delivered=False, queued=False, error=error_detail
            )
        except Exception as exc:
            error_detail = f"Request error: {exc}"
            await log_federation(
                self._db,
                message_id,
                from_relay,
                target_domain,
                "outbound",
                hop_count + 1,
                "failed",
                error=error_detail,
            )
            return ForwardResult(
                delivered=False, queued=False, error=error_detail
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()
