#!/usr/bin/env python3
"""Pressure test for the relay: real processes, real sockets, every message counted.

    python tests/pressure/run.py --agents 300 --messages 20 --report out.json

Set DATABASE_URL to run on Postgres (it needs CREATE DATABASE rights); by default
each relay gets its own SQLite file.  Set PRESSURE_OLD_PYTHON to a Python that has
an older ``youam`` installed to include old clients.

Every scenario keeps a ledger of what was sent and what arrived.  Exit code 1 if
any scenario fails.  A live socket gets no acknowledgement from its client, so
mail the relay wrote to a socket that was dying can't be counted either way: such
losses are reported, and only fail a scenario that says they must be zero.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import secrets
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import websockets

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.protocol.register_proof import create_register_proof
from uam.relay.relay_auth import sign_federation_request
from uam.sdk.agent import Agent as SdkAgent

ROOT = Path(__file__).resolve().parents[2]
GATE = asyncio.Semaphore(32)


# -- the relay as a process ---------------------------------------------------


def free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def new_database(base: str | None, folder: Path, name: str) -> str:
    if not base:
        return f"sqlite+aiosqlite:///{folder / f'{name}.db'}"
    import asyncpg

    db = f"pressure_{name}_{secrets.token_hex(4)}"
    conn = await asyncpg.connect(base.replace("postgresql+asyncpg://", "postgresql://"))
    await conn.execute(f'CREATE DATABASE "{db}"')
    await conn.close()
    return f"{base.rsplit('/', 1)[0]}/{db}"


class Relay:
    def __init__(self, domain: str, database_url: str, folder: Path, *, peers: str = "",
                 real_limits: bool = False, port: int | None = None) -> None:
        self.domain = domain
        self.database_url = database_url
        self.folder = folder
        self.peers = peers
        self.real_limits = real_limits
        self.port = port or free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.ws_url = f"ws://127.0.0.1:{self.port}/ws"
        self.process: subprocess.Popen | None = None
        self.peak_rss_kb = 0
        self.log = open(folder / f"{domain}.log", "ab")

    async def start(self, timeout: float = 60.0) -> float:
        env = {
            **os.environ,
            "DATABASE_URL": self.database_url,
            "UAM_DB_PATH": str(self.folder / f"{self.domain}.db"),
            "UAM_RELAY_DOMAIN": self.domain,
            "UAM_RELAY_KEY_PATH": str(self.folder / f"{self.domain}.pem"),
            "UAM_TOKEN_PEPPER": "pressure-test-pepper-1234567890abcdef",
            "UAM_FEDERATION_ENABLED": "true" if self.peers else "false",
            "UAM_DRAIN_SECONDS": "0",
            "UAM_LOG_LEVEL": "WARNING",
            "PRESSURE_PEERS": self.peers,
            "PRESSURE_REAL_LIMITS": "1" if self.real_limits else "0",
            "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
        }
        started = time.monotonic()
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "tests.pressure.relay_app:create", "--factory",
             "--host", "127.0.0.1", "--port", str(self.port), "--ws-max-size", "131072",
             "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=self.log, stderr=self.log,
        )
        async with httpx.AsyncClient() as client:
            while time.monotonic() - started < timeout:
                if self.process.poll() is not None:
                    raise RuntimeError(f"{self.domain} exited with {self.process.returncode}")
                try:
                    if (await client.get(f"{self.url}/health")).status_code == 200:
                        return time.monotonic() - started
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
        raise RuntimeError(f"{self.domain} did not start")

    def rss_kb(self) -> int:
        try:
            for line in Path(f"/proc/{self.process.pid}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                    self.peak_rss_kb = max(self.peak_rss_kb, rss)
                    return rss
        except (OSError, AttributeError):
            pass
        return 0

    def stop(self, sig: int = signal.SIGTERM) -> None:
        if self.process and self.process.poll() is None:
            self.process.send_signal(sig)
            try:
                self.process.wait(30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def errors_logged(self) -> int:
        """Tracebacks from every relay in this run, peers included."""
        return sum(log.read_bytes().count(b"Traceback") for log in self.folder.glob("*.log"))


# -- agents -------------------------------------------------------------------


@dataclass
class Agent:
    name: str
    relay: Relay
    address: str = ""
    token: str = ""
    signing_key: object = None
    verify_key: object = None
    received: Counter = field(default_factory=Counter)
    latency: list = field(default_factory=list)
    ws: object = None
    reader: asyncio.Task | None = None
    acks: dict = field(default_factory=dict)
    errors: Counter = field(default_factory=Counter)

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


async def register(client: httpx.AsyncClient, relay: Relay, name: str) -> Agent:
    signing_key, verify_key = generate_keypair()
    resp = await client.post(
        f"{relay.url}/api/v1/register",
        json={"agent_name": name, "public_key": serialize_verify_key(verify_key)},
    )
    resp.raise_for_status()
    data = resp.json()
    return Agent(name, relay, data["address"], data["token"], signing_key, verify_key)


def envelope(sender: Agent, recipient: Agent, payload: bytes = b"hello") -> dict:
    return to_wire_dict(create_envelope(
        from_address=sender.address,
        to_address=recipient.address,
        message_type=MessageType.MESSAGE,
        payload_plaintext=payload,
        signing_key=sender.signing_key,
        recipient_verify_key=recipient.verify_key,
    ))


async def _read(agent: Agent, ws) -> None:
    try:
        async for frame in ws:
            data = json.loads(frame)
            kind = data.get("type")
            if kind == "ping":
                await ws.send(json.dumps({"type": "pong"}))
            elif kind == "ack":
                waiter = agent.acks.pop(data["message_id"], None)
                if waiter and not waiter.done():
                    waiter.set_result(data)
            elif "uam_version" in data:
                agent.received[data["message_id"]] += 1
            elif "error" in data:
                agent.errors[data["error"]] += 1
                if agent.acks:
                    _, waiter = agent.acks.popitem()
                    if not waiter.done():
                        waiter.set_result(data)
    except (websockets.ConnectionClosed, OSError):
        pass


async def connect(agent: Agent, *, read: bool = True) -> None:
    agent.ws = await websockets.connect(
        agent.relay.ws_url,
        additional_headers=agent.headers,
        max_size=None,
        open_timeout=30,
        ping_interval=None,
    )
    if read:
        agent.reader = asyncio.create_task(_read(agent, agent.ws))


async def disconnect(agent: Agent) -> None:
    if agent.ws is not None:
        await agent.ws.close()
        agent.ws = None
    if agent.reader is not None:
        await agent.reader
        agent.reader = None


async def send_ws(agent: Agent, wire: dict, timeout: float = 30.0) -> dict:
    waiter = asyncio.get_running_loop().create_future()
    agent.acks[wire["message_id"]] = waiter
    await agent.ws.send(json.dumps(wire))
    return await asyncio.wait_for(waiter, timeout)


async def send_rest(client: httpx.AsyncClient, agent: Agent, wire: dict) -> httpx.Response:
    return await client.post(
        f"{agent.relay.url}/api/v1/send", json={"envelope": wire}, headers=agent.headers,
    )


async def collect_inbox(client: httpx.AsyncClient, agent: Agent) -> None:
    while True:
        resp = await client.get(
            f"{agent.relay.url}/api/v1/inbox/{agent.address}",
            params={"limit": 100}, headers=agent.headers,
        )
        resp.raise_for_status()
        messages = resp.json()["messages"]
        if not messages:
            return
        for message in messages:
            agent.received[message["message_id"]] += 1


async def settle(check, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        await asyncio.sleep(0.1)
    return check()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


# -- scenarios ----------------------------------------------------------------


@dataclass
class Ledger:
    """What was accepted for whom."""

    accepted: dict = field(default_factory=dict)  # message_id -> (recipient, stored?)
    refused: Counter = field(default_factory=Counter)
    server_errors: int = 0
    latency: list = field(default_factory=list)

    def tally(self) -> dict:
        lost_stored = lost_live = duplicates = 0
        for message_id, (recipient, delivered_live) in self.accepted.items():
            count = recipient.received[message_id]
            if count == 0:
                if delivered_live:
                    lost_live += 1
                else:
                    lost_stored += 1
            duplicates += max(0, count - 1)
        return {
            "accepted": len(self.accepted),
            "lost_stored": lost_stored,
            "lost_live": lost_live,
            "duplicates": duplicates,
            "refused": dict(self.refused),
            "server_errors": self.server_errors,
            "p50_ms": round(percentile(self.latency, 0.5) * 1000, 1),
            "p99_ms": round(percentile(self.latency, 0.99) * 1000, 1),
        }


async def one_send(client, ledger: Ledger, sender: Agent, recipient: Agent, via_ws: bool) -> None:
    wire = envelope(sender, recipient)
    async with GATE:
        started = time.monotonic()
        try:
            if via_ws and sender.ws is not None:
                reply = await send_ws(sender, wire)
                if reply.get("type") == "ack":
                    ledger.accepted[wire["message_id"]] = (recipient, reply["delivered"])
                else:
                    ledger.refused[reply.get("error", "?")] += 1
            else:
                resp = await send_rest(client, sender, wire)
                if resp.status_code == 200:
                    ledger.accepted[wire["message_id"]] = (recipient, resp.json()["delivered"])
                elif resp.status_code >= 500:
                    ledger.server_errors += 1
                else:
                    ledger.refused[str(resp.status_code)] += 1
        except (asyncio.TimeoutError, websockets.ConnectionClosed, httpx.HTTPError) as exc:
            ledger.refused[type(exc).__name__] += 1
        ledger.latency.append(time.monotonic() - started)


async def steady_load(client, relay: Relay, agents: list[Agent], messages: int) -> dict:
    """Half the agents online, half offline, then everyone collects."""
    online, offline = agents[: len(agents) // 2], agents[len(agents) // 2:]
    await asyncio.gather(*(connect(a) for a in online))
    ledger = Ledger()
    jobs = []
    for sender in agents:
        for i in range(messages):
            jobs.append(one_send(client, ledger, sender, random.choice(agents), i % 2 == 0))
    random.shuffle(jobs)
    started = time.monotonic()
    await asyncio.gather(*jobs)
    elapsed = time.monotonic() - started

    # Offline agents: half reconnect and drain, half read their inbox.
    half = len(offline) // 2
    await asyncio.gather(*(connect(a) for a in offline[:half]))
    await asyncio.gather(*(collect_inbox(client, a) for a in offline[half:]))
    await settle(lambda: ledger.tally()["lost_stored"] == 0 and ledger.tally()["lost_live"] == 0)
    await asyncio.gather(*(collect_inbox(client, a) for a in agents))
    await asyncio.gather(*(disconnect(a) for a in agents))
    report = ledger.tally()
    report["per_second"] = round(len(jobs) / elapsed, 1)
    report["pass"] = (
        report["lost_stored"] == 0 and report["lost_live"] == 0
        and report["server_errors"] == 0 and report["refused"] == {}
    )
    return report


async def reconnect_storm(client, relay: Relay, agents: list[Agent], rounds: int) -> dict:
    """Everyone reconnects at once, repeatedly, while mail flows."""
    await asyncio.gather(*(connect(a) for a in agents))
    ledger = Ledger()
    stop = asyncio.Event()

    async def traffic() -> None:
        while not stop.is_set():
            await one_send(client, ledger, random.choice(agents), random.choice(agents), False)

    workers = [asyncio.create_task(traffic()) for _ in range(8)]
    for _ in range(rounds):
        await asyncio.sleep(1.0)
        await asyncio.gather(*(disconnect(a) for a in agents))
        await asyncio.gather(*(connect(a) for a in agents))
    stop.set()
    await asyncio.gather(*workers)

    # After the storm, live mail must still reach everyone at once.
    probe = Ledger()
    await asyncio.gather(*(
        one_send(client, probe, agents[0], a, False) for a in agents[1:]
    ))
    probe_live = sum(1 for _, live in probe.accepted.values() if live)

    await asyncio.sleep(1.0)
    await asyncio.gather(*(collect_inbox(client, a) for a in agents))
    await asyncio.gather(*(disconnect(a) for a in agents))
    report = ledger.tally()
    report["live_after_storm"] = f"{probe_live}/{len(agents) - 1}"
    report["pass"] = (
        report["lost_stored"] == 0 and report["server_errors"] == 0
        and probe_live == len(agents) - 1
    )
    return report


async def stalled_socket(client, relay: Relay, agents: list[Agent]) -> dict:
    """One client stops reading; everyone else must not notice."""
    stalled, sender, bystander_a, bystander_b = agents[:4]
    await connect(stalled, read=False)
    await connect(bystander_a)
    await connect(bystander_b)
    payload = secrets.token_bytes(40_000)
    fill = Ledger()
    probe = Ledger()
    stop = asyncio.Event()

    async def flood() -> None:
        for _ in range(400):
            if stop.is_set():
                return
            wire = envelope(sender, stalled, payload)
            resp = await send_rest(client, sender, wire)
            if resp.status_code >= 500:
                fill.server_errors += 1
            elif resp.status_code == 200:
                fill.accepted[wire["message_id"]] = (stalled, resp.json()["delivered"])
                if not resp.json()["delivered"]:
                    return  # the relay gave up on the socket

    async def probes() -> None:
        while not stop.is_set():
            await one_send(client, probe, bystander_a, bystander_b, True)
            await asyncio.sleep(0.05)

    prober = asyncio.create_task(probes())
    started = time.monotonic()
    await flood()
    gave_up_after = time.monotonic() - started
    await asyncio.sleep(1.0)
    stop.set()
    await prober

    stored_after_stall = sum(1 for _, live in fill.accepted.values() if not live)
    with_ws = stalled.ws
    stalled.ws = None
    try:
        await with_ws.close()
    except Exception:
        pass
    await collect_inbox(client, stalled)
    await disconnect(bystander_a)
    await disconnect(bystander_b)
    report = probe.tally()
    report.update(
        gave_up_after_s=round(gave_up_after, 1),
        stored_after_stall=stored_after_stall,
        flood_server_errors=fill.server_errors,
    )
    report["pass"] = (
        stored_after_stall >= 1 and report["lost_stored"] == 0
        and report["lost_live"] == 0 and fill.server_errors == 0
        # On SQLite one writer waits for another, and the send to the stalled
        # socket happens inside a write transaction.
        and (report["p99_ms"] < 2000 or "sqlite" in relay.database_url)
    )
    return report


async def close_after_send(client, relay: Relay, agents: list[Agent], folder: Path) -> dict:
    """The real SDK sends over a WebSocket and closes at once, as `uam send` does."""
    recipient = agents[0]
    sent = []
    os.environ["UAM_HOME"] = str(folder / "sdk-home")  # never the real ~/.uam
    for round_number in range(10):
        sdk = SdkAgent(
            f"quick{round_number}",
            relay=relay.url,
            domain=relay.domain,
            transport="websocket",
        )
        await sdk.connect()
        for _ in range(4):
            sent.append(await sdk.send(recipient.address, "hello"))
        await sdk.close()
    await asyncio.sleep(1.0)
    await collect_inbox(client, recipient)
    lost = sum(recipient.received[message_id] == 0 for message_id in sent)
    return {"sent": len(sent), "lost": lost, "pass": lost == 0}


async def hostile(client, relay: Relay, agents: list[Agent]) -> dict:
    """Attackers at full speed while a bystander keeps working."""
    alice, bob, carol, mallory = agents[:4]
    await connect(bob)
    probe = Ledger()
    counts: Counter = Counter()
    stop = asyncio.Event()
    rss_before = relay.rss_kb()

    async def probes() -> None:
        while not stop.is_set():
            await one_send(client, probe, alice, bob, False)
            await asyncio.sleep(0.02)

    async def post(url, **kwargs) -> None:
        resp = await client.post(f"{relay.url}{url}", **kwargs)
        counts[f"{url.split('/')[3] if url.count('/') > 2 else url}:{resp.status_code}"] += 1

    async def junk_frames() -> None:
        frames = ["[1,2]", "7", "null", '"uam_version"', "{}", '{"uam_version":"0.1"}',
                  json.dumps({"uam_version": "0.1", "type": ["x"], "from": carol.address})]
        ws = await websockets.connect(relay.ws_url, additional_headers=mallory.headers, max_size=None)
        for _ in range(30):
            for frame in frames:
                await ws.send(frame)
                await asyncio.wait_for(ws.recv(), 10)
        await ws.close()

    async def oversized() -> None:
        for size in (70_000, 120_000, 500_000):
            ws = await websockets.connect(relay.ws_url, additional_headers=carol.headers, max_size=None)
            wire = envelope(carol, bob)
            wire["payload"] = "A" * size
            try:
                await ws.send(json.dumps(wire))
                counts[f"oversized:{json.loads(await asyncio.wait_for(ws.recv(), 10)).get('error')}"] += 1
            except websockets.ConnectionClosed as exc:
                counts[f"oversized:closed {exc.rcvd.code if exc.rcvd else '?'}"] += 1
            await ws.close()

    async def takeover() -> None:
        for _ in range(50):
            await post("/api/v1/register", json={
                "agent_name": alice.name,
                "public_key": serialize_verify_key(alice.verify_key),
            })
            forged, _ = generate_keypair()
            await post("/api/v1/register", json={
                "agent_name": alice.name,
                "public_key": serialize_verify_key(alice.verify_key),
                "proof": create_register_proof(alice.address, forged),
            })

    async def bad_tokens() -> None:
        for _ in range(200):
            await post("/api/v1/send", json={"envelope": {}},
                       headers={"Authorization": "Bearer nonsense"})

    async def unsigned_federation() -> None:
        sk, _ = generate_keypair()
        for i in range(100):
            body = {"envelope": envelope(carol, bob), "via": [], "hop_count": 0,
                    "timestamp": "2026-01-01T00:00:00Z", "from_relay": "peer.example",
                    "nonce": secrets.token_urlsafe(16)}
            await post("/api/v1/federation/deliver", json=body,
                       headers={"X-UAM-Relay-Signature": sign_federation_request(body, sk)})

    async def duplicates() -> None:
        wire = envelope(carol, bob)
        await asyncio.gather(*(send_rest(client, carol, wire) for _ in range(300)))

    async def nobody() -> None:
        ghost = Agent("ghost", relay, f"ghost::{relay.domain}", verify_key=bob.verify_key)
        for _ in range(100):
            resp = await send_rest(client, carol, envelope(carol, ghost))
            counts[f"nobody:{resp.status_code}"] += 1

    prober = asyncio.create_task(probes())
    try:
        await asyncio.gather(junk_frames(), oversized(), takeover(), bad_tokens(),
                             unsigned_federation(), duplicates(), nobody())
    finally:
        stop.set()
        await prober
    await asyncio.sleep(0.5)
    await collect_inbox(client, bob)
    await disconnect(bob)

    # The victim of the takeover attempts still has its token.
    still_mine = await client.get(
        f"{relay.url}/api/v1/inbox/{alice.address}", headers=alice.headers
    )
    report = probe.tally()
    report["attacks"] = dict(counts)
    report["rss_growth_mb"] = round((relay.rss_kb() - rss_before) / 1024, 1)
    server_errors = sum(n for k, n in counts.items() if k.endswith(":500"))
    report["pass"] = (
        server_errors == 0 and report["server_errors"] == 0
        and report["lost_stored"] == 0 and report["lost_live"] == 0
        and still_mine.status_code == 200
        and not any(k.startswith("register:200") for k in counts)
    )
    return report


async def crash_restart(client, relay: Relay, agents: list[Agent]) -> dict:
    """kill -9 under load: nothing the relay stored may be lost."""
    half = len(agents) // 2
    senders, recipients = agents[:half], agents[half:]
    ledger = Ledger()
    stop = asyncio.Event()

    async def traffic() -> None:
        while not stop.is_set():
            await one_send(client, ledger, random.choice(senders), random.choice(recipients), False)

    workers = [asyncio.create_task(traffic()) for _ in range(8)]
    await asyncio.sleep(3.0)
    relay.stop(signal.SIGKILL)
    stop.set()
    results = await asyncio.gather(*workers, return_exceptions=True)
    assert not any(isinstance(r, BaseException) for r in results), results
    boot = await relay.start()
    await asyncio.gather(*(collect_inbox(client, a) for a in recipients))
    report = ledger.tally()
    report["reboot_s"] = round(boot, 1)
    report["pass"] = report["lost_stored"] == 0 and report["accepted"] > 0
    return report


async def real_limits(client, folder: Path, base: str | None) -> dict:
    """With the real limits, many concurrent sends take exactly the limit."""
    relay = Relay("limits.test", await new_database(base, folder, "limits"), folder, real_limits=True)
    await relay.start()
    try:
        agents = []
        for i in range(3):
            agents.append(await register(client, relay, f"limits{i}"))
        sender, recipient, _ = agents
        wire = envelope(sender, recipient)
        same = await asyncio.gather(*(send_rest(client, sender, wire) for _ in range(40)))
        fresh = await asyncio.gather(*(
            send_rest(client, sender, envelope(sender, recipient)) for _ in range(40)
        ))
        statuses = Counter(r.status_code for r in [*same, *fresh])
        report = {"statuses": dict(statuses)}
        # The default sender limit for a new agent's reputation is 10 a minute.
        report["pass"] = statuses[200] == 10 and statuses[429] == 70 and not any(
            s >= 500 for s in statuses
        )
        return report
    finally:
        relay.stop()


async def federation(client, folder: Path, base: str | None, messages: int) -> dict:
    """Two real relays: delivery, replay refusal, and a peer that goes away."""
    a_port, b_port = free_port(), free_port()
    peers = f"a.test=http://127.0.0.1:{a_port},b.test=http://127.0.0.1:{b_port}"
    a = Relay("a.test", await new_database(base, folder, "a"), folder, peers=peers, port=a_port)
    b = Relay("b.test", await new_database(base, folder, "b"), folder, peers=peers, port=b_port)
    await asyncio.gather(a.start(), b.start())
    try:
        alice = await register(client, a, "alice")
        bob = await register(client, b, "bob")
        ledger = Ledger()
        await connect(alice)
        await asyncio.gather(*(
            one_send(client, ledger, alice, bob, i % 2 == 0) for i in range(messages)
        ))
        await asyncio.sleep(0.5)
        await collect_inbox(client, bob)
        first = ledger.tally()

        b.stop()
        queued = Ledger()
        await asyncio.gather(*(one_send(client, queued, alice, bob, False) for _ in range(5)))
        await b.start()
        deadline = time.monotonic() + 120  # the retry loop waits out FORWARD_GRACE
        while time.monotonic() < deadline and queued.tally()["lost_stored"]:
            await collect_inbox(client, bob)
            await asyncio.sleep(1.0)
        await disconnect(alice)
        second = queued.tally()
        report = {"online": first, "peer_down": second}
        report["pass"] = (
            first["accepted"] == messages and first["lost_stored"] == 0
            and first["lost_live"] == 0 and first["server_errors"] == 0
            and second["accepted"] == 5 and second["lost_stored"] == 0
            and second["lost_live"] == 0
        )
        return report
    finally:
        a.stop()
        b.stop()


OLD_CLIENT = """
import asyncio, os, sys
from uam import Agent, __version__

async def main():
    relay = sys.argv[1]
    a = Agent("oldalice", relay=relay, transport="http")
    b = Agent("oldbob", relay=relay, transport="http")
    await a.connect(); await b.connect()
    await a.send(b.address, "hello from " + __version__)
    await asyncio.sleep(1)
    got = await b.inbox()
    got = got or await b.inbox()
    await a.close(); await b.close()
    print(__version__, len(got))

asyncio.run(main())
"""


async def old_client(relay: Relay, folder: Path) -> dict:
    python = os.environ.get("PRESSURE_OLD_PYTHON")
    if not python:
        return {"skipped": "PRESSURE_OLD_PYTHON not set", "pass": True}
    env = {k: v for k, v in os.environ.items() if not k.startswith("UAM_") and k != "PYTHONPATH"}
    env["UAM_HOME"] = str(folder / "old-client")
    env["UAM_RELAY_DOMAIN"] = relay.domain  # 1.0.0 can't learn it from the relay
    process = await asyncio.create_subprocess_exec(
        python, "-I", "-c", OLD_CLIENT, relay.url, env=env, cwd=folder,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await asyncio.wait_for(process.communicate(), 60)
    text = out.decode().strip()
    return {
        "output": text or err.decode()[-400:],
        "pass": process.returncode == 0 and text.split()[-1:] != ["0"],
    }


# -- the run ------------------------------------------------------------------


async def main(args: argparse.Namespace) -> int:
    folder = Path(tempfile.mkdtemp(prefix="uam-pressure-"))
    base = os.environ.get("DATABASE_URL")
    # A peer that isn't there: it turns federation on for the hostile scenario.
    relay = Relay(
        "pressure.test", await new_database(base, folder, "main"), folder,
        peers="absent.test=http://127.0.0.1:1",
    )
    report: dict = {"database": "postgres" if base else "sqlite", "folder": str(folder)}
    boot = await relay.start()
    report["boot_s"] = round(boot, 1)

    async def sample() -> None:
        while True:
            relay.rss_kb()
            await asyncio.sleep(0.5)

    sampler = asyncio.create_task(sample())
    limits = httpx.Limits(max_connections=64, max_keepalive_connections=32)
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        async def fresh(prefix: str, count: int) -> list[Agent]:
            return list(await asyncio.gather(*(
                register(client, relay, f"{prefix}{i}") for i in range(count)
            )))

        scenarios = [
            ("steady_load", lambda a: steady_load(client, relay, a, args.messages), args.agents),
            ("reconnect_storm", lambda a: reconnect_storm(client, relay, a, 3), args.agents // 2),
            ("stalled_socket", lambda a: stalled_socket(client, relay, a), 4),
            ("close_after_send", lambda a: close_after_send(client, relay, a, folder), 1),
            ("hostile", lambda a: hostile(client, relay, a), 4),
            ("crash_restart", lambda a: crash_restart(client, relay, a), 20),
        ]
        for name, scenario, count in scenarios:
            if args.only and name not in args.only:
                continue
            agents = await fresh(name.replace("_", "")[:12], count)
            started = time.monotonic()
            try:
                result = await asyncio.wait_for(scenario(agents), args.scenario_timeout)
            except Exception as exc:
                result = {"pass": False, "error": f"{type(exc).__name__}: {exc}"}
            result["seconds"] = round(time.monotonic() - started, 1)
            report[name] = result
            print(name, json.dumps(result), flush=True)

        extras = [
            ("old_client", lambda: old_client(relay, folder)),
            ("real_limits", lambda: real_limits(client, folder, base)),
            ("federation", lambda: federation(client, folder, base, args.messages)),
        ]
        for name, scenario in extras:
            if args.only and name not in args.only:
                continue
            try:
                result = await asyncio.wait_for(scenario(), args.scenario_timeout)
            except Exception as exc:
                result = {"pass": False, "error": f"{type(exc).__name__}: {exc}"}
            report[name] = result
            print(name, json.dumps(result), flush=True)

    sampler.cancel()
    report["peak_rss_mb"] = round(relay.peak_rss_kb / 1024, 1)
    report["tracebacks_in_log"] = relay.errors_logged()
    relay.stop()
    scenarios_passed = [v["pass"] for v in report.values() if isinstance(v, dict) and "pass" in v]
    report["passed"] = all(scenarios_passed) and report["tracebacks_in_log"] == 0
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in ("peak_rss_mb", "tracebacks_in_log", "passed", "folder")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--agents", type=int, default=60)
    parser.add_argument("--messages", type=int, default=10)
    parser.add_argument("--scenario-timeout", type=float, default=300)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--report")
    sys.exit(asyncio.run(main(parser.parse_args())))
