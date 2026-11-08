"""FederationService -- relay discovery and outbound message forwarding.

Discovers remote relay endpoints via DNS SRV lookup with
``.well-known/uam-relay.json`` fallback, caches results in the
``known_relays`` table, and forwards signed envelopes to remote relays.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import dns.exception
import httpx

from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import urlparse

from uam.protocol.types import MAX_ENVELOPE_SIZE, utc_timestamp
from uam.relay.relay_auth import sign_federation_request
from uam.relay.relay_meta import for_federation
from uam.relay.ssrf import (
    SSRFBlockedError,
    build_pinned_url,
    resolve_pinned,
    validate_outbound_target,
)

from uam.db.crud.federation import (
    get_pending_queue,
    enqueue_federation,
    get_known_relay,
    log_federation,
    update_queue_entry,
    upsert_known_relay,
)
from uam.db.session import async_session_factory
from uam.db.engine import get_engine

logger = logging.getLogger(__name__)

# Long enough that the retry loop leaves a forward in progress alone.
FORWARD_GRACE = timedelta(seconds=60)


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
    settings:
        The relay :class:`~uam.relay.config.Settings` instance.
    signing_key:
        The relay's Ed25519 ``SigningKey``.
    verify_key:
        The relay's Ed25519 ``VerifyKey`` (for identity advertisement).
    """

    def __init__(self, settings, signing_key, verify_key):  # noqa: ANN001
        self._settings = settings
        self._signing_key = signing_key
        self._verify_key = verify_key
        # T5.1 (Phase 45): follow_redirects=False — defense-in-depth so an
        # attacker-controlled 30x from a public-IP target cannot bounce the
        # client to a private/loopback IP after validate_outbound_target has
        # passed for the initial URL.
        self._client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
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
        factory = async_session_factory(get_engine())
        async with factory() as session:
            cached = await get_known_relay(session, domain)
        if cached and cached.status == "active":
            last_verified = cached.last_verified
            ttl_hours = cached.ttl_hours or 1
            try:
                if isinstance(last_verified, str):
                    lv_dt = datetime.fromisoformat(last_verified)
                else:
                    lv_dt = last_verified
                if lv_dt.tzinfo is None:
                    lv_dt = lv_dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_hours = (now - lv_dt).total_seconds() / 3600
                if age_hours < ttl_hours:
                    return {
                        "domain": cached.domain,
                        "federation_url": cached.federation_url,
                        "public_key": cached.public_key,
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
                async with factory() as session:
                    await upsert_known_relay(
                        session, domain, federation_url, public_key, "dns-srv", ttl
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
            async with factory() as session:
                await upsert_known_relay(
                    session,
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
        # T5.1 — SSRF guard before outbound HTTP
        try:
            await asyncio.to_thread(
                validate_outbound_target, url, allowed_ports=(443, 8443)
            )
        except SSRFBlockedError as exc:
            logger.warning(
                "T5.1: refusing federation .well-known fetch %s: %s", url, exc
            )
            return None
        # R-46-01 (Phase 46): resolve-once-pin to defeat DNS rebind between
        # validate-time and request-time.  Caller passes IP-literal URL +
        # original Host header + sni_hostname extension to httpx so cert
        # validation chains against the original hostname.
        try:
            original_host, pinned_ip = await asyncio.to_thread(
                resolve_pinned, host, allowed_ports=(443, 8443)
            )
        except SSRFBlockedError as exc:
            logger.warning(
                "R-46-01: refusing federation .well-known fetch %s (pin failed): %s",
                url, exc,
            )
            return None
        pinned_url = build_pinned_url(url, pinned_ip)
        try:
            resp = await self._client.get(
                pinned_url,
                timeout=10.0,
                headers={"Host": original_host},
                extensions={"sni_hostname": original_host},
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("public_key")
        except Exception:
            logger.debug(
                "Failed to fetch .well-known from %s (pinned %s)",
                url, pinned_url, exc_info=True,
            )
            return None

    async def _discover_via_well_known(self, domain: str) -> dict | None:
        """Fetch ``https://{domain}/.well-known/uam-relay.json``.

        Returns ``{"federation_endpoint": ..., "public_key": ...}`` or ``None``.
        """
        url = f"https://{domain}/.well-known/uam-relay.json"
        # T5.1 — SSRF guard before outbound HTTP
        try:
            await asyncio.to_thread(
                validate_outbound_target, url, allowed_ports=(443, 8443)
            )
        except SSRFBlockedError as exc:
            logger.warning(
                "T5.1: refusing federation discovery fetch %s: %s", url, exc
            )
            return None
        # R-46-01 (Phase 46): resolve-once-pin DNS to defeat rebind.
        try:
            original_host, pinned_ip = await asyncio.to_thread(
                resolve_pinned, domain, allowed_ports=(443, 8443)
            )
        except SSRFBlockedError as exc:
            logger.warning(
                "R-46-01: refusing federation discovery fetch %s (pin failed): %s",
                url, exc,
            )
            return None
        pinned_url = build_pinned_url(url, pinned_ip)
        try:
            resp = await self._client.get(
                pinned_url,
                timeout=10.0,
                headers={"Host": original_host},
                extensions={"sni_hostname": original_host},
            )
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
        # T3.2 (Phase 45): include a 128-bit CSPRNG nonce so the receiving
        # relay can dedup replays of this signed body within the
        # federation timestamp freshness window. ``sign_federation_request``
        # below canonicalises and signs the WHOLE body dict — adding this
        # field requires no changes to relay_auth.py because the nonce
        # naturally lands in the canonical signing scope.
        # NOTE: any sibling executor (e.g. 45-04) that adds further fields
        # to this body MUST PRESERVE the ``nonce`` entry — receiving
        # relays reject bodies missing it (Pydantic 422 on
        # FederationDeliverRequest).
        body = {
            "envelope": for_federation(envelope_dict, MAX_ENVELOPE_SIZE),
            "via": (via or []) + [from_relay],
            "hop_count": hop_count + 1,
            "timestamp": utc_timestamp(),
            "from_relay": from_relay,
            "nonce": secrets.token_urlsafe(16),  # T3.2: 128-bit replay defeat
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

        factory = async_session_factory(get_engine())
        # T5.1 — SSRF guard before outbound HTTP. The federation_url came
        # from peer-controlled DNS/.well-known content via discover_relay;
        # we MUST validate it before posting the signed envelope.
        try:
            await asyncio.to_thread(
                validate_outbound_target,
                relay_info["federation_url"],
                allowed_ports=(443, 8443),
            )
        except SSRFBlockedError as exc:
            error_detail = f"SSRF refused: {exc}"
            logger.warning(
                "T5.1: refusing federation forward to %s: %s",
                relay_info["federation_url"],
                exc,
            )
            async with factory() as session:
                await log_federation(
                    session,
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
        # R-46-01 (Phase 46): resolve-once-pin the federation_url's host.
        # The federation_url came from peer-controlled DNS/.well-known, so
        # an attacker can return a public IP at validate-time and a private
        # IP (e.g. 169.254.169.254) at request-time without pinning.  Since
        # the relay's signing key is in-process, an SSRF here could exfil
        # IAM credentials -- this is the highest-stakes outbound site.
        federation_url = relay_info["federation_url"]
        parsed = urlparse(federation_url)
        try:
            original_host, pinned_ip = await asyncio.to_thread(
                resolve_pinned, parsed.hostname, allowed_ports=(443, 8443)
            )
        except SSRFBlockedError as exc:
            error_detail = f"SSRF refused (pin failed): {exc}"
            logger.warning(
                "R-46-01: refusing federation forward to %s (pin failed): %s",
                federation_url, exc,
            )
            async with factory() as session:
                await log_federation(
                    session,
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
        pinned_url = build_pinned_url(federation_url, pinned_ip)
        # Preserve original headers; merge Host so the remote vhost sees the
        # right name and TLS SNI uses the original hostname.
        post_headers = {**headers, "Host": original_host}
        try:
            resp = await self._client.post(
                pinned_url,
                json=body,
                headers=post_headers,
                timeout=30.0,
                extensions={"sni_hostname": original_host},
            )
            if resp.status_code in (200, 201):
                async with factory() as session:
                    await log_federation(
                        session,
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
                async with factory() as session:
                    await log_federation(
                        session,
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
            async with factory() as session:
                await log_federation(
                    session,
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
            async with factory() as session:
                await log_federation(
                    session,
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


async def forward_to_peer(
    state: Any, session: AsyncSession, to_address: str, envelope_dict: dict
) -> str:
    """Forward an envelope to its home relay; the retry loop finishes the job (FED-10).

    Returns ``"federated"`` or ``"federation_queued"``.  Commits the caller's
    transaction first: the queue row must survive a crash, and the forward can
    take 30 seconds and writes its own log rows.
    """
    from_relay = state.settings.relay_domain
    entry = await enqueue_federation(
        session,
        to_address.split("::", 1)[1],
        json.dumps(envelope_dict),
        json.dumps([from_relay]),
        1,
        commit=False,
        next_retry=datetime.now(timezone.utc) + FORWARD_GRACE,
    )
    entry_id = entry.id
    await session.commit()

    try:
        result = await state.federation_service.forward(
            envelope_dict=envelope_dict, from_relay=from_relay
        )
    except Exception:
        logger.exception("Forward to %s failed; the retry loop has it", to_address)
        return "federation_queued"
    if not result.delivered:
        return "federation_queued"
    await update_queue_entry(session, entry_id, "delivered")
    return "federated"


async def retry_pending_federation(factory: Any, service: Any, settings: Any) -> None:
    """Retry the queue rows that are due.  A row that raises is a failed attempt."""
    async with factory() as session:
        pending = await get_pending_queue(session, limit=50)

    for entry in pending:
        try:
            result = await service.forward(
                envelope_dict=json.loads(entry.envelope),
                from_relay=settings.relay_domain,
                via=json.loads(entry.via),
                hop_count=entry.hop_count,
            )
        except Exception as exc:
            logger.exception("Federation retry raised: queue_id=%d", entry.id)
            result = ForwardResult(delivered=False, error=f"{type(exc).__name__}: {exc}")

        async with factory() as session:
            if result.delivered:
                await update_queue_entry(session, entry.id, status="delivered")
                logger.info(
                    "Federation retry delivered: queue_id=%d to %s",
                    entry.id, entry.target_domain,
                )
                continue

            new_attempt = entry.attempt_count + 1
            delays = settings.federation_retry_delays
            if new_attempt >= len(delays):
                await update_queue_entry(
                    session, entry.id, status="failed", error=result.error or "max retries"
                )
                logger.warning(
                    "Federation retry exhausted: queue_id=%d to %s after %d attempts",
                    entry.id, entry.target_domain, new_attempt,
                )
                continue

            await update_queue_entry(
                session,
                entry.id,
                status="pending",
                error=result.error,
                next_retry=datetime.now(timezone.utc) + timedelta(seconds=delays[new_attempt]),
            )
            logger.info(
                "Federation retry scheduled: queue_id=%d to %s, attempt %d, next in %ds",
                entry.id, entry.target_domain, new_attempt, delays[new_attempt],
            )
