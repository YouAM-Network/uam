"""UAM CLI -- Universal Agent Messaging command-line interface.

Thin wrapper around the Python SDK using click.
All commands use sync wrappers (send_sync, inbox_sync, connect_sync, close_sync).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
import httpx

from uam.protocol import UAMError
from uam.protocol.crypto import deserialize_verify_key, public_key_fingerprint
from uam.sdk.agent import Agent
from uam.sdk.config import SDKConfig
from uam.sdk.contact_book import ContactBook
from uam.sdk.key_manager import KeyManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_agent_name(key_dir: Path | None = None) -> str | None:
    """Scan key directory for a .key file and return the agent name.

    If exactly one .key file exists, return the name (filename without .key).
    If multiple exist, return the first alphabetically.
    If none exist, return None.
    """
    if key_dir is None:
        cfg = SDKConfig(name="_probe")
        key_dir = cfg.key_dir
    key_dir = Path(key_dir)
    if not key_dir.exists():
        return None
    key_files = sorted(key_dir.glob("*.key"))
    if not key_files:
        return None
    return key_files[0].stem


def _error(msg: str) -> None:
    """Print an error message to stderr and exit 1."""
    click.echo(msg, err=True)
    raise SystemExit(1)


def _trust_indicator(trust_state: str) -> str:
    """Map a trust_state to a display string with ASCII-safe indicator."""
    indicators = {
        "provisional": "provisional (!)",
        "pinned": "pinned [P]",
        "verified": "verified [V]",
    }
    return indicators.get(trust_state, trust_state)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="uam")
@click.option(
    "--name",
    "-n",
    default=None,
    help="Agent name (auto-detected from ~/.uam/keys/).",
)
@click.pass_context
def cli(ctx: click.Context, name: str | None) -> None:
    """UAM -- Universal Agent Messaging CLI."""
    ctx.ensure_object(dict)
    ctx.obj["name"] = name


# ---------------------------------------------------------------------------
# uam init (CLI-01)
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--name", "-n", default=None, help="Agent name.")
@click.option(
    "--relay", "-r", default=None, help="Relay URL (default: relay.youam.network)."
)
@click.pass_context
def init(ctx: click.Context, name: str | None, relay: str | None) -> None:
    """Initialize a new agent: generate keys and register with relay."""
    agent_name = name or ctx.obj.get("name")
    if not agent_name:
        import socket

        agent_name = socket.gethostname().split(".")[0].lower()

    try:
        # Check if already initialized
        cfg = SDKConfig(name=agent_name, relay_url=relay)
        km = KeyManager(cfg.key_dir)
        key_path = Path(cfg.key_dir) / f"{agent_name}.key"

        if key_path.exists():
            km.load_or_generate(agent_name)
            address = f"{agent_name}::{cfg.relay_domain}"
            fp = public_key_fingerprint(km.verify_key)
            click.echo(f"Agent already initialized: {address}")
            click.echo(f"Fingerprint: {fp}")
            return

        # New agent -- connect to register
        agent = Agent(agent_name, relay=relay)
        agent.connect_sync()
        address = agent.address
        fp = public_key_fingerprint(agent._key_manager.verify_key)
        agent.close_sync()
        click.echo(f"Initialized agent: {address}")
        click.echo(f"Fingerprint: {fp}")
    except UAMError as exc:
        _error(f"Error: {exc}")
    except Exception as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam send (CLI-02)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("address")
@click.argument("message")
@click.pass_context
def send(ctx: click.Context, address: str, message: str) -> None:
    """Send a message to another agent."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        msg_id = agent.send_sync(address, message)
        agent.close_sync()
        click.echo(f"Message sent to {address} (id: {msg_id})")
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam inbox (CLI-03)
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--limit", "-l", default=20, help="Max messages to retrieve.")
@click.pass_context
def inbox(ctx: click.Context, limit: int) -> None:
    """Check your inbox for pending messages."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        messages = agent.inbox_sync(limit=limit)
        agent.close_sync()

        if not messages:
            click.echo("No pending messages.")
            return

        for msg in messages:
            click.echo(f"From: {msg.from_address}")
            click.echo(f"Time: {msg.timestamp}")
            click.echo("---")
            click.echo(msg.content)
            click.echo()
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam whoami (CLI-04)
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """Display your agent address and public key fingerprint (offline)."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    cfg = SDKConfig(name=agent_name)
    key_path = Path(cfg.key_dir) / f"{agent_name}.key"
    if not key_path.exists():
        _error("No agent initialized. Run `uam init` first.")

    km = KeyManager(cfg.key_dir)
    km.load_or_generate(agent_name)
    address = f"{agent_name}::{cfg.relay_domain}"
    fp = public_key_fingerprint(km.verify_key)

    click.echo(f"Address:     {address}")
    click.echo(f"Fingerprint: {fp}")
    click.echo(f"Key file:    {key_path}")


# ---------------------------------------------------------------------------
# uam contacts (CLI-05)
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def contacts(ctx: click.Context) -> None:
    """List known contacts from the local contact book."""
    agent_name = ctx.obj.get("name") or _find_agent_name()

    # Determine data_dir
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        rows = asyncio.run(_list_contacts(book))
    except Exception:
        rows = []

    if not rows:
        click.echo("No contacts yet.")
        return

    # Print table header
    click.echo(f"{'ADDRESS':<30} {'TRUST':<22} {'LAST SEEN'}")
    for row in rows:
        addr = row["address"]
        trust = _trust_indicator(row["trust_state"])
        last = row["last_seen"] or ""
        click.echo(f"{addr:<30} {trust:<22} {last}")


async def _list_contacts(book: ContactBook) -> list[dict]:
    """Open contact book, list contacts, close."""
    await book.open()
    try:
        return await book.list_contacts()
    finally:
        await book.close()


# ---------------------------------------------------------------------------
# uam contact (TOFU-04) -- subcommands: fingerprint, verify, remove
# ---------------------------------------------------------------------------


@cli.group()
def contact():
    """Contact management commands (fingerprint, verify, remove)."""
    pass


@contact.command("fingerprint")
@click.argument("address")
@click.pass_context
def contact_fingerprint(ctx: click.Context, address: str) -> None:
    """Display the fingerprint for a known contact's public key."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        pk_str = asyncio.run(_get_contact_public_key(book, address))
    except Exception:
        pk_str = None

    if pk_str is None:
        _error(f"Contact not found: {address}")

    vk = deserialize_verify_key(pk_str)
    fp = public_key_fingerprint(vk)
    short_fp = fp[:16]

    click.echo(f"Address:     {address}")
    click.echo(f"Fingerprint: {short_fp}")
    click.echo(f"Full:        {fp}")


async def _get_contact_public_key(book: ContactBook, address: str) -> str | None:
    """Open contact book, look up public key, close."""
    await book.open()
    try:
        return await book.get_public_key(address)
    finally:
        await book.close()


@contact.command("verify")
@click.argument("address")
@click.pass_context
def contact_verify(ctx: click.Context, address: str) -> None:
    """Manually verify a contact, upgrading their trust state to verified."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        result = asyncio.run(_verify_contact(book, address))
    except Exception as exc:
        _error(f"Error: {exc}")

    if result is None:
        _error(f"Contact not found: {address}")

    click.echo(f"Contact {address} verified. Trust state: verified")


async def _verify_contact(book: ContactBook, address: str) -> str | None:
    """Upgrade a contact to verified trust state. Returns public_key or None."""
    await book.open()
    try:
        pk = await book.get_public_key(address)
        if pk is None:
            return None
        await book.add_contact(
            address, pk, trust_state="verified", trust_source="manual-verify"
        )
        return pk
    finally:
        await book.close()


@contact.command("remove")
@click.argument("address")
@click.pass_context
def contact_remove(ctx: click.Context, address: str) -> None:
    """Remove a contact from the contact book (escape hatch for key rotation)."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        removed = asyncio.run(_remove_contact(book, address))
    except Exception as exc:
        _error(f"Error: {exc}")

    if not removed:
        _error(f"Contact not found: {address}")

    click.echo(
        f"Contact {address} removed. Future messages will re-resolve the public key."
    )


async def _remove_contact(book: ContactBook, address: str) -> bool:
    """Open contact book, remove contact, close."""
    await book.open()
    try:
        return await book.remove_contact(address)
    finally:
        await book.close()


# ---------------------------------------------------------------------------
# uam card (CLAW-02)
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def card(ctx: click.Context) -> None:
    """Display your signed contact card as JSON."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run 'uam init' first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        card_dict = agent.contact_card()
        agent.close_sync()
        click.echo(json.dumps(card_dict, indent=2))
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam pending (HAND-06)
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def pending(ctx: click.Context) -> None:
    """List pending handshake requests awaiting approval."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        items = agent.pending_sync()
        agent.close_sync()

        if not items:
            click.echo("No pending handshake requests.")
            return

        click.echo(f"{'ADDRESS':<35} {'RECEIVED'}")
        for item in items:
            addr = item["address"]
            received = item.get("received_at", "")
            click.echo(f"{addr:<35} {received}")
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam approve (HAND-06)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("address")
@click.pass_context
def approve(ctx: click.Context, address: str) -> None:
    """Approve a pending handshake request."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        agent.approve_sync(address)
        agent.close_sync()
        click.echo(f"Approved: {address}")
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam deny (HAND-06)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("address")
@click.pass_context
def deny(ctx: click.Context, address: str) -> None:
    """Deny a pending handshake request."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()
        agent.deny_sync(address)
        agent.close_sync()
        click.echo(f"Denied: {address}")
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam block (HAND-06)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("pattern")
@click.pass_context
def block(ctx: click.Context, pattern: str) -> None:
    """Block an address or domain pattern (e.g., spammer::evil.com or *::evil.com)."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        asyncio.run(_do_block(book, pattern))
        click.echo(f"Blocked: {pattern}")
    except Exception as exc:
        _error(f"Error: {exc}")


async def _do_block(book: ContactBook, pattern: str) -> None:
    """Open contact book, add block, close."""
    await book.open()
    try:
        await book.add_block(pattern)
    finally:
        await book.close()


# ---------------------------------------------------------------------------
# uam unblock (HAND-06)
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("pattern")
@click.pass_context
def unblock(ctx: click.Context, pattern: str) -> None:
    """Remove a block on an address or domain pattern."""
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        asyncio.run(_do_unblock(book, pattern))
        click.echo(f"Unblocked: {pattern}")
    except Exception as exc:
        _error(f"Error: {exc}")


async def _do_unblock(book: ContactBook, pattern: str) -> None:
    """Open contact book, remove block, close."""
    await book.open()
    try:
        await book.remove_block(pattern)
    finally:
        await book.close()


# ---------------------------------------------------------------------------
# uam verify-domain (DNS-05)
# ---------------------------------------------------------------------------


@cli.command("verify-domain")
@click.argument("domain")
@click.option("--timeout", "-t", default=300, help="Polling timeout in seconds.")
@click.option("--poll-interval", default=10, help="Polling interval in seconds.")
@click.pass_context
def verify_domain(ctx: click.Context, domain: str, timeout: int, poll_interval: int) -> None:
    """Verify domain ownership for Tier 2 DNS-verified status."""
    from uam.sdk.dns_verifier import generate_txt_record

    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    try:
        agent = Agent(agent_name)
        agent.connect_sync()

        pubkey = agent.public_key
        relay_url = agent._config.relay_url
        txt_value = generate_txt_record(pubkey, relay_url)

        click.echo(f"Add this DNS TXT record to verify {domain}:")
        click.echo()
        click.echo(f"  Host:  _uam.{domain}")
        click.echo(f"  Type:  TXT")
        click.echo(f"  Value: {txt_value}")
        click.echo()
        click.echo(f"Or serve this HTTPS fallback:")
        click.echo()
        click.echo(f"  URL: https://{domain}/.well-known/uam.json")
        click.echo()
        click.echo(f"See documentation for .well-known/uam.json format.")
        click.echo()
        click.echo("Polling for verification...")

        verified = agent.verify_domain_sync(
            domain, timeout=timeout, poll_interval=poll_interval
        )
        agent.close_sync()

        if verified:
            click.echo(
                f"Verified! {agent.address} is now Tier 2 via {domain}."
            )
        else:
            click.echo(
                f"Verification timed out after {timeout}s. "
                f"Check your DNS records and try again."
            )
    except UAMError as exc:
        _error(f"Error: {exc}")
    except RuntimeError as exc:
        _error(f"Error: {exc}")


# ---------------------------------------------------------------------------
# uam bridge (A2A-03)
# ---------------------------------------------------------------------------


@cli.group()
def bridge():
    """Cross-protocol bridge commands."""
    pass


@bridge.group()
def a2a():
    """A2A protocol bridge commands."""
    pass


@a2a.command("import")
@click.argument("url")
@click.pass_context
def a2a_import(ctx: click.Context, url: str) -> None:
    """Import an A2A agent by fetching its Agent Card.

    URL should be the agent's base URL or direct path to agent.json.
    If the URL doesn't end with '/agent.json' or '/.well-known/agent.json',
    appends '/.well-known/agent.json' automatically.
    """
    from uam.bridge.a2a import contact_from_a2a

    # Normalize URL
    normalized = url.rstrip("/")
    if not normalized.endswith("/agent.json"):
        normalized = f"{normalized}/.well-known/agent.json"

    # Fetch A2A Agent Card
    try:
        resp = httpx.get(normalized, timeout=15.0, follow_redirects=True)
        resp.raise_for_status()
        card_data = resp.json()
    except httpx.ConnectError:
        _error(f"Error: Could not connect to {normalized}")
    except httpx.HTTPStatusError as exc:
        _error(f"Error: HTTP {exc.response.status_code} from {normalized}")
    except Exception as exc:
        _error(f"Error: {exc}")

    # Convert A2A -> UAM
    try:
        card, metadata = contact_from_a2a(card_data, source_url=normalized)
    except UAMError as exc:
        _error(f"Error: {exc}")

    # Determine agent name for contact book location
    agent_name = ctx.obj.get("name") or _find_agent_name()
    cfg = SDKConfig(name=agent_name or "_probe")
    book = ContactBook(cfg.data_dir)

    try:
        asyncio.run(_do_a2a_import(book, card))
    except Exception as exc:
        _error(f"Error: {exc}")

    click.echo(f"Imported A2A agent: {card.display_name} ({card.address})")

    # Print bridge metadata summary
    skills = metadata.a2a_fields.get("skills", [])
    caps = metadata.a2a_fields.get("capabilities", {})
    caps_summary = ", ".join(f"{k}={v}" for k, v in caps.items()) if caps else "none"
    click.echo(f"  Skills: {len(skills)} | Capabilities: {caps_summary}")

    for skill in skills:
        click.echo(f"  - {skill.get('name', skill.get('id', 'unnamed'))}")


async def _do_a2a_import(book: ContactBook, card) -> None:
    """Open contact book, add imported A2A contact, close."""
    await book.open()
    try:
        await book.add_contact(
            address=card.address,
            public_key=card.public_key,
            display_name=card.display_name,
            trust_state="bridge",
            trust_source="a2a-import",
            relay=card.relay,
        )
    finally:
        await book.close()


# ---------------------------------------------------------------------------
# uam register (REG-06/07)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# uam db (MIG-05) -- database management subcommands
# ---------------------------------------------------------------------------


def _get_alembic_config(database_url: str) -> "Config":
    """Build an Alembic Config, setting DATABASE_URL in env.

    Searches for alembic.ini in:
      1. Current working directory
      2. Three levels above this file (src/uam/cli -> project root)

    Raises SystemExit via _error() if not found.
    """
    import os
    from pathlib import Path

    from alembic.config import Config

    ini_candidates = [
        Path.cwd() / "alembic.ini",
        Path(__file__).resolve().parents[3] / "alembic.ini",
    ]
    ini_path = None
    for candidate in ini_candidates:
        if candidate.exists():
            ini_path = candidate
            break

    if ini_path is None:
        _error(
            "Could not find alembic.ini. "
            "Run this command from the project root or install the package properly."
        )

    os.environ["DATABASE_URL"] = database_url
    return Config(str(ini_path))


@cli.group()
def db():
    """Database management commands."""
    pass


@db.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    default=None,
    help="Database URL (default: $DATABASE_URL).",
)
@click.option("--revision", default="head", help="Target revision (default: head).")
def upgrade(database_url: str | None, revision: str) -> None:
    """Run database migrations to the target revision."""
    if not database_url:
        _error("DATABASE_URL environment variable is required.")

    from alembic import command

    alembic_cfg = _get_alembic_config(database_url)
    try:
        command.upgrade(alembic_cfg, revision)
        click.echo(f"Database migrated to: {revision}")
    except Exception as exc:
        _error(f"Migration failed: {exc}")


@db.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    default=None,
    help="Database URL (default: $DATABASE_URL).",
)
def current(database_url: str | None) -> None:
    """Show the current migration revision."""
    if not database_url:
        _error("DATABASE_URL environment variable is required.")

    from alembic import command

    alembic_cfg = _get_alembic_config(database_url)
    try:
        command.current(alembic_cfg, verbose=True)
    except Exception as exc:
        _error(f"Error: {exc}")


@db.command()
@click.option(
    "--database-url",
    envvar="DATABASE_URL",
    default=None,
    help="Database URL (default: $DATABASE_URL).",
)
@click.option(
    "--revision", default="-1", help="Target revision (default: -1, one step back)."
)
def downgrade(database_url: str | None, revision: str) -> None:
    """Downgrade database to a previous migration revision."""
    if not database_url:
        _error("DATABASE_URL environment variable is required.")

    from alembic import command

    alembic_cfg = _get_alembic_config(database_url)
    try:
        command.downgrade(alembic_cfg, revision)
        click.echo(f"Database downgraded to: {revision}")
    except Exception as exc:
        _error(f"Downgrade failed: {exc}")


# ---------------------------------------------------------------------------
# uam register (REG-06/07)
# ---------------------------------------------------------------------------


@cli.command("register")
@click.argument("name")
@click.option("--relay", "-r", default=None, help="Relay URL for the namespace.")
@click.option(
    "--registrar-url",
    default=None,
    envvar="UAM_REGISTRAR_URL",
    help="Registrar API URL.",
)
@click.option(
    "--no-browser", is_flag=True, help="Print checkout URL instead of opening browser."
)
@click.pass_context
def register(
    ctx: click.Context,
    name: str,
    relay: str | None,
    registrar_url: str | None,
    no_browser: bool,
) -> None:
    """Register a namespace via the custodial registrar (no wallet required).

    Checks availability, displays pricing, opens Stripe checkout in browser,
    and polls the registrar API until registration is confirmed.
    """
    import base64
    import time
    import webbrowser

    # 1. Detect agent name
    agent_name = ctx.obj.get("name") or _find_agent_name()
    if not agent_name:
        _error("No agent initialized. Run `uam init` first.")

    # 2. Load agent's public key
    cfg = SDKConfig(name=agent_name)
    km = KeyManager(cfg.key_dir)
    key_path = Path(cfg.key_dir) / f"{agent_name}.key"
    if not key_path.exists():
        _error("No agent initialized. Run `uam init` first.")
    km.load_or_generate(agent_name)

    # 3. Encode public key as base64
    public_key_b64 = base64.b64encode(bytes(km.verify_key)).decode()

    # 4. Determine relay URL and registrar URL
    relay_url = relay or cfg.relay_url
    base_url = (registrar_url or cfg.registrar_url or "").rstrip("/")

    # 5. Check availability
    try:
        resp = httpx.get(f"{base_url}/api/v1/names/{name}", timeout=15.0)
        resp.raise_for_status()
        info = resp.json()
    except httpx.HTTPStatusError as exc:
        _error(f"Error checking availability: HTTP {exc.response.status_code}")
    except Exception as exc:
        _error(f"Error checking availability: {exc}")

    if not info.get("available"):
        status = info.get("registration_status")
        if status:
            _error(f"Name '{name}' is not available (status: {status}).")
        else:
            _error(f"Name '{name}' is not available.")

    # 6. Show price
    price_cents = info.get("price_usd_cents", 500)
    price_display = f"${price_cents / 100:.2f}/year"
    click.echo(f"Name:    {name}")
    click.echo(f"Price:   {price_display}")
    click.echo(f"Relay:   {relay_url}")
    click.echo()

    # 7. Confirm
    click.confirm("Proceed to payment?", abort=True)

    # 8. Create registration
    try:
        resp = httpx.post(
            f"{base_url}/api/v1/register",
            json={
                "name": name,
                "public_key": public_key_b64,
                "relay_url": relay_url,
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        reg = resp.json()
    except httpx.HTTPStatusError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", "")
        except Exception:
            pass
        _error(f"Registration failed: {detail or exc.response.status_code}")
    except Exception as exc:
        _error(f"Registration failed: {exc}")

    checkout_url = reg.get("checkout_url", "")
    click.echo(f"\nCheckout URL: {checkout_url}")

    # 9. Open browser
    if not no_browser and checkout_url:
        webbrowser.open(checkout_url)
        click.echo("Opened browser for payment.")
    elif checkout_url:
        click.echo("Open the URL above in your browser to complete payment.")

    # 10. Poll for completion
    click.echo("\nWaiting for payment confirmation...")
    max_polls = 60
    poll_interval = 5  # seconds
    for i in range(max_polls):
        time.sleep(poll_interval)

        try:
            resp = httpx.get(f"{base_url}/api/v1/names/{name}", timeout=15.0)
            resp.raise_for_status()
            poll_info = resp.json()
        except Exception:
            continue  # retry on transient errors

        if not poll_info.get("available"):
            status = poll_info.get("registration_status")
            if status == "completed" or status is None:
                # Registered on-chain (status None means no local record = on-chain only)
                click.echo(f"\nRegistered! Your address: {name}::uam.network")
                return
            if status == "failed":
                _error(f"\nRegistration failed. Check registrar logs for details.")

        # Progress indication every 30 seconds
        elapsed = (i + 1) * poll_interval
        if elapsed % 30 == 0:
            click.echo(f"  Still waiting... ({elapsed}s elapsed)")

    click.echo(
        "\nPayment confirmation timed out after 5 minutes. "
        "Your registration may still complete -- check later with:\n"
        f"  uam register {name}"
    )
