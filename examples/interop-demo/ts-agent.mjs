#!/usr/bin/env node
/**
 * UAM Interop Demo -- TypeScript Agent
 *
 * This agent runs on relay-beta and communicates with a Python agent
 * on relay-alpha. It demonstrates cross-language, cross-relay encrypted
 * messaging using only the public UAM TypeScript SDK API.
 *
 * Usage:
 *   node ts-agent.mjs --relay http://localhost:9002 --domain beta.demo \
 *                      --name ts-demo --peer py-demo::alpha.demo
 */

import { Agent } from '../../ts-sdk/dist/index.js';
import { parseArgs } from 'node:util';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Parse command-line arguments
const { values: args } = parseArgs({
  options: {
    relay:  { type: 'string', default: 'http://localhost:9002' },
    name:   { type: 'string', default: 'ts-agent' },
    peer:   { type: 'string' },
    domain: { type: 'string', default: 'beta.demo' },
  },
  strict: true,
});

if (!args.peer) {
  console.error('Usage: node ts-agent.mjs --peer <address> [--relay URL] [--name NAME] [--domain DOMAIN]');
  process.exit(1);
}

/** Sleep helper */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  console.log('='.repeat(60));
  console.log('  UAM Interop Demo -- TypeScript Agent');
  console.log('='.repeat(60));
  console.log();

  // Create a temp directory for keys (fresh identity each run)
  const keyDir = mkdtempSync(join(tmpdir(), 'uam-demo-ts-'));

  // Step 1: Create and connect the agent
  console.log(`[1/8] Creating agent '${args.name}' on ${args.relay} (${args.domain})...`);
  const agent = new Agent(args.name, {
    relay: args.relay,
    domain: args.domain,
    transport: 'http',
    keyDir: keyDir,
  });

  try {
    await agent.connect();
    console.log(`       Address: ${agent.address}`);
    console.log(`       Public key: ${agent.publicKey.substring(0, 32)}...`);
    console.log();

    // Step 2: Print contact card
    console.log('[2/8] Contact card:');
    const card = await agent.contactCard();
    console.log(`       ${JSON.stringify(card, null, 2).substring(0, 200)}...`);
    console.log();

    // Step 3: Wait for Python's initial message
    console.log('[3/8] Waiting 2 seconds for Python agent message...');
    await sleep(2000);

    // Step 4: Check inbox
    console.log('[4/8] Checking inbox...');
    const messages = await agent.inbox();
    let receivedCount = 0;
    for (const msg of messages) {
      if (msg.type === 'message') {
        receivedCount++;
        console.log(`       From: ${msg.fromAddress}`);
        console.log(`       Body: ${msg.content}`);
        console.log(`       Time: ${msg.timestamp}`);
        console.log(`       ID:   ${msg.messageId}`);
        console.log();
      }
    }
    if (receivedCount === 0) {
      console.log('       (no messages yet)');
      console.log();
    }

    // Step 5: Reply to each message
    console.log('[5/8] Sending replies...');
    for (const msg of messages) {
      if (msg.type === 'message') {
        const reply = 'Hello from TypeScript! Received your message loud and clear.';
        const replyId = await agent.send(msg.fromAddress, reply);
        console.log(`       Replied to ${msg.fromAddress}: ${replyId}`);
      }
    }
    // Also send a reply to the peer in case no messages were received yet
    if (receivedCount === 0) {
      const initReply = 'Hello from TypeScript! Ready to communicate.';
      const replyId = await agent.send(args.peer, initReply);
      console.log(`       Sent initial message to ${args.peer}: ${replyId}`);
    }
    console.log();

    // Step 6: Wait for more messages
    console.log('[6/8] Waiting 2 seconds for more messages...');
    await sleep(2000);

    // Step 7: Check inbox again
    console.log('[7/8] Checking inbox again...');
    const messages2 = await agent.inbox();
    let newCount = 0;
    for (const msg of messages2) {
      if (msg.type === 'message') {
        newCount++;
        console.log(`       From: ${msg.fromAddress}`);
        console.log(`       Body: ${msg.content}`);
        console.log();

        // Reply to new messages
        const farewell = 'TypeScript agent signing off. Cross-language interop confirmed!';
        const farewellId = await agent.send(msg.fromAddress, farewell);
        console.log(`       Farewell reply: ${farewellId}`);
      }
    }
    if (newCount === 0) {
      console.log('       (no new messages)');
      console.log();
    }

    // Step 8: Summary
    const totalReceived = receivedCount + newCount;
    console.log('[8/8] Summary:');
    console.log(`       Messages received: ${totalReceived}`);
    console.log(`       Replies sent:      ${receivedCount + newCount + (receivedCount === 0 ? 1 : 0)}`);
    console.log(`       Agent address:     ${agent.address}`);
    console.log(`       Peer address:      ${args.peer}`);
    console.log();

  } catch (err) {
    console.error(`\n  ERROR: ${err.message || err}`);
    throw err;
  } finally {
    // Close agent
    console.log('Closing agent...');
    await agent.close();
    console.log('TypeScript agent finished.');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
