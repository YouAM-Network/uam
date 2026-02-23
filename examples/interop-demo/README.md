# UAM Interop Demo: Cross-Language, Cross-Relay Messaging

This demo proves that UAM (Universal Agent Messaging) works across:

- **Different languages** -- Python agent + TypeScript agent
- **Different relays** -- Relay Alpha (alpha.demo) + Relay Beta (beta.demo)
- **Different frameworks** -- PyNaCl (Python) + libsodium-wrappers (TypeScript)
- **Zero custom integration** -- both agents use only the public SDK API

Two agents on completely different stacks exchange encrypted, signed messages
through federated relays with no special configuration.

## Prerequisites

- **Docker** (with Docker Compose) -- for running the two relay instances
- **Python 3.10+** -- for the Python agent
- **Node.js 18+** -- for the TypeScript agent
- **UAM Python SDK** installed: `pip install -e .` (from project root)
- **UAM TypeScript SDK** built: `cd ts-sdk && npm install && npm run build`

## Quick Start

```bash
cd examples/interop-demo
chmod +x run-demo.sh
./run-demo.sh
```

That's it. The script handles everything: building the Docker image, starting
two federated relays, running both agents, and showing the results.

## What Happens Step by Step

### 1. Relay Infrastructure

The orchestrator starts two independent relay instances:

```
Relay Alpha (alpha.demo) -- port 9001
Relay Beta  (beta.demo)  -- port 9002
```

Both relays have federation enabled and can discover each other via Docker
network DNS aliases (simulating `.well-known` discovery in production).

### 2. Python Agent (Relay Alpha)

The Python agent:
1. Creates a fresh identity (Ed25519 keypair)
2. Registers on Relay Alpha as `py-demo::alpha.demo`
3. Sends an encrypted message to `ts-demo::beta.demo`
4. Waits for and reads replies from the TypeScript agent
5. Sends a follow-up message

### 3. TypeScript Agent (Relay Beta)

The TypeScript agent:
1. Creates a fresh identity (Ed25519 keypair via libsodium)
2. Registers on Relay Beta as `ts-demo::beta.demo`
3. Checks inbox for the Python agent's message
4. Sends an encrypted reply back to `py-demo::alpha.demo`
5. Checks for and responds to follow-up messages

### 4. Message Flow

```
                   Federation
Python Agent -----> Relay Alpha ---------> Relay Beta -----> TypeScript Agent
(py-demo)          (alpha.demo)           (beta.demo)       (ts-demo)
                                                              |
TypeScript Agent <-- Relay Beta <--------- Relay Alpha <------+
(ts-demo)          (beta.demo)            (alpha.demo)     (reply)
```

### Expected Output

```
[1/8] Creating agent 'py-demo' on http://localhost:9001 (alpha.demo)...
       Address: py-demo::alpha.demo
       Public key: abc123...

[3/8] Sending message to ts-demo::beta.demo...
       Sent message to ts-demo::beta.demo: msg-uuid-here

[5/8] Checking inbox...
       From: ts-demo::beta.demo
       Body: Hello from TypeScript! Received your message loud and clear.
```

## Architecture Diagram

```
+------------------+           +------------------+
|   Python Agent   |           | TypeScript Agent |
|   (demo.py)      |           | (ts-agent.mjs)   |
|                  |           |                  |
|  from uam.sdk    |           |  import { Agent }|
|  import Agent    |           |  from 'uam'     |
+--------+---------+           +--------+---------+
         |                              |
         | HTTP transport               | HTTP transport
         |                              |
+--------v---------+           +--------v---------+
|   Relay Alpha    |           |   Relay Beta     |
|   alpha.demo     |  <------> |   beta.demo      |
|   port 9001      | federation|   port 9002      |
+------------------+           +------------------+
         |                              |
         +--------- Docker Network -----+
                    (uam-demo)
```

Key points:
- Each agent connects ONLY to its home relay
- Agents do NOT know about federation -- it's transparent
- Messages are encrypted end-to-end (NaCl Box)
- Messages are signed with Ed25519 -- tamper-proof
- Relays forward encrypted payloads -- they cannot read message content

## Manual Mode

For debugging, you can run each component separately:

### 1. Start relays (Docker)

```bash
# Build the relay image
docker build -f ../../docker/Dockerfile -t uam-relay ../..

# Start both relays
docker compose -f docker-compose.demo.yml up -d

# Verify health
curl http://localhost:9001/health
curl http://localhost:9002/health
```

### 2. Run the Python agent

```bash
python3 demo.py \
    --relay http://localhost:9001 \
    --domain alpha.demo \
    --name py-demo \
    --peer ts-demo::beta.demo
```

### 3. Run the TypeScript agent (in another terminal)

```bash
node ts-agent.mjs \
    --relay http://localhost:9002 \
    --domain beta.demo \
    --name ts-demo \
    --peer py-demo::alpha.demo
```

### 4. Stop relays

```bash
docker compose -f docker-compose.demo.yml down
```

## Verifying the Results

Look for these indicators in the output:

1. **Both agents register successfully** -- each prints its UAM address
2. **Messages are sent with unique IDs** -- UUIDs in the "Sent message" lines
3. **Messages are received and decrypted** -- inbox shows plaintext content
4. **Cross-relay delivery works** -- Python on alpha.demo receives from beta.demo
5. **Summaries show send/receive counts** -- both agents report messages exchanged

## Troubleshooting

### Docker is not running

```
ERROR: Cannot connect to the Docker daemon
```

Start Docker Desktop or the Docker service, then retry.

### Ports 9001/9002 already in use

```
ERROR: Bind for 0.0.0.0:9001 failed: port is already allocated
```

Stop any existing relay containers:
```bash
docker compose -f docker-compose.demo.yml down
```

Or use different ports by editing `docker-compose.demo.yml`.

### TypeScript SDK not built

```
Error: Cannot find module '../../ts-sdk/dist/index.js'
```

Build the TypeScript SDK first:
```bash
cd ../../ts-sdk
npm install
npm run build
cd ../examples/interop-demo
```

### Python SDK not installed

```
ModuleNotFoundError: No module named 'uam'
```

Install the Python SDK in development mode:
```bash
cd ../..
pip install -e ".[relay]"
cd examples/interop-demo
```

### Relays not becoming healthy

If the health check times out after 60 seconds:
```bash
# Check relay logs
docker compose -f docker-compose.demo.yml logs relay-alpha
docker compose -f docker-compose.demo.yml logs relay-beta
```

Common causes: Docker build failure, missing dependencies, port conflicts.

### Running without Docker (--no-docker)

If Docker is unavailable, you can start relays manually and use the `--no-docker` flag:

```bash
# Start relays some other way (e.g., directly with uvicorn)
# Then run the demo without Docker:
./run-demo.sh --no-docker
```

This skips Docker image building and container startup, but expects relays to
already be running on ports 9001 and 9002.
