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

from uam.protocol import UAMError
from uam.protocol.crypto import public_key_fingerprint
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
    click.echo(f"{'ADDRESS':<30} {'TRUST':<18} {'LAST SEEN'}")
    for row in rows:
        addr = row["address"]
        trust = row["trust_state"]
        last = row["last_seen"] or ""
        click.echo(f"{addr:<30} {trust:<18} {last}")


async def _list_contacts(book: ContactBook) -> list[dict]:
    """Open contact book, list contacts, close."""
    await book.open()
    try:
        return await book.list_contacts()
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
