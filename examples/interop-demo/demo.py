#!/usr/bin/env python3
"""UAM Interop Demo -- Python Agent

This agent runs on relay-alpha and communicates with a TypeScript agent
on relay-beta. It demonstrates cross-language, cross-relay encrypted
messaging using only the public UAM SDK API.

Usage:
    python3 demo.py --relay http://localhost:9001 --domain alpha.demo \
                    --name py-demo --peer ts-demo::beta.demo
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time

# Only public SDK API -- no internal imports
from uam.sdk.agent import Agent


async def main() -> None:
    parser = argparse.ArgumentParser(description="UAM Interop Demo -- Python Agent")
    parser.add_argument("--relay", default="http://localhost:9001", help="Relay URL (default: http://localhost:9001)")
    parser.add_argument("--name", default="py-agent", help="Agent name (default: py-agent)")
    parser.add_argument("--peer", required=True, help="Peer agent address (e.g., ts-demo::beta.demo)")
    parser.add_argument("--domain", default="alpha.demo", help="Relay domain (default: alpha.demo)")
    args = parser.parse_args()

    print("=" * 60)
    print("  UAM Interop Demo -- Python Agent")
    print("=" * 60)
    print()

    # Create a temp directory for keys (fresh identity each run)
    with tempfile.TemporaryDirectory(prefix="uam-demo-py-") as key_dir:
        # Step 1: Create and connect the agent
        print(f"[1/8] Creating agent '{args.name}' on {args.relay} ({args.domain})...")
        agent = Agent(
            args.name,
            relay=args.relay,
            domain=args.domain,
            transport="http",
            key_dir=key_dir,
        )
        try:
            await agent.connect()
            print(f"       Address: {agent.address}")
            print(f"       Public key: {agent.public_key[:32]}...")
            print()

            # Step 2: Print contact card
            print("[2/8] Contact card:")
            card = agent.contact_card()
            print(f"       {json.dumps(card, indent=2)[:200]}...")
            print()

            # Step 3: Send initial message
            msg1 = "Hello from Python! This message was encrypted with NaCl Box and sent across federated relays."
            print(f"[3/8] Sending message to {args.peer}...")
            msg1_id = await agent.send(args.peer, msg1)
            print(f"       Sent message to {args.peer}: {msg1_id}")
            print()

            # Step 4: Wait for reply
            print("[4/8] Waiting 3 seconds for reply...")
            await asyncio.sleep(3)

            # Step 5: Check inbox
            print("[5/8] Checking inbox...")
            messages = await agent.inbox()
            received_count = 0
            for msg in messages:
                if msg.type == "message":
                    received_count += 1
                    print(f"       From: {msg.from_address}")
                    print(f"       Body: {msg.content}")
                    print(f"       Time: {msg.timestamp}")
                    print(f"       ID:   {msg.message_id}")
                    print()
            if received_count == 0:
                print("       (no messages yet)")
                print()

            # Step 6: Send follow-up message
            msg2 = "This is message 2 from Python. UAM works across languages!"
            print(f"[6/8] Sending follow-up message...")
            msg2_id = await agent.send(args.peer, msg2)
            print(f"       Sent message 2: {msg2_id}")
            print()

            # Step 7: Wait and check inbox again
            print("[7/8] Waiting 2 seconds for more replies...")
            await asyncio.sleep(2)
            messages2 = await agent.inbox()
            new_count = 0
            for msg in messages2:
                if msg.type == "message":
                    new_count += 1
                    print(f"       From: {msg.from_address}")
                    print(f"       Body: {msg.content}")
                    print()
            if new_count == 0:
                print("       (no new messages)")
                print()

            # Step 8: Summary
            total_received = received_count + new_count
            print("[8/8] Summary:")
            print(f"       Messages sent:     2")
            print(f"       Messages received: {total_received}")
            print(f"       Agent address:     {agent.address}")
            print(f"       Peer address:      {args.peer}")
            print()

        except Exception as exc:
            print(f"\n  ERROR: {exc}", file=sys.stderr)
            raise
        finally:
            # Step 9: Close agent
            print("Closing agent...")
            await agent.close()
            print("Python agent finished.")


if __name__ == "__main__":
    asyncio.run(main())
