# Expo Phase 6A Report — Real Multi-Computer Connectivity & Integration Validation

## 1. Executive Summary & Verification Baseline

Expo Phase 6A establishes, validates, and hardens the networking foundation required for the storage network to operate across separate physical computers connected over local area networks (LAN) or routed TCP/IP infrastructure.

### Test Regression Baseline & Results
- **Regression Baseline (Phases 1–5C)**: 143 passed, 0 failed.
- **Phase 6A New Test Suite**: 30 passed, 0 failed (`coordinator/tests/test_phase6a.py`).
- **Post-Implementation Full Suite**: **173 passed, 0 failed** in 100.22s.
- **Zero regressions** introduced across replication, erasure coding, catalog, and reconciliation workflows.

---

## 2. Architecture Changes and Actual Network Path

Prior to Phase 6A, components frequently defaulted to loopback addresses (`127.0.0.1` / `localhost`) and assumed all services ran in a shared environment. Phase 6A establishes an end-to-end multi-process and multi-computer architecture:

```
+-------------------------------------------------------------------------------+
|                               NETWORK TOPOLOGY                                |
+-------------------------------------------------------------------------------+

  [ COMPUTER A: Coordinator ] (e.g. 192.168.1.100:9000)
       ^                                    ^
       | Heartbeat / Reg (HTTP)             | Heartbeat / Reg (HTTP)
       |                                    |
  [ COMPUTER B: Storage Node 1 ]       [ COMPUTER C: Storage Node 2 ]
  Bind: 0.0.0.0:8001                   Bind: 0.0.0.0:8001
  Advertised: 192.168.1.101:8001       Advertised: 192.168.1.102:8001
       ^                                    ^
       | Direct Chunk Transfer              | Direct Chunk Transfer
       +------------------+  +--------------+
                          |  |
                 [ Consumer Client ]
                 (Computer A, B, C, or D)
                 1. Queries Coordinator for eligible nodes
                 2. Connects directly to Node Advertised Endpoints
                 3. Uploads / Downloads / Verifies SHA-256
```

### The Actual Network Path
1. **Node Startup & Discovery**:
   - The Storage Node binds to its local network interface (e.g., `0.0.0.0:8001`).
   - The node determines its reachable endpoint from `ADVERTISED_ENDPOINT` (e.g., `http://192.168.1.101:8001`).
   - The node opens a real TCP connection to `COORDINATOR_URL` (e.g., `http://192.168.1.100:9000/nodes/register`) and publishes its persistent `node_id`, capacity, and `advertised_endpoint`.
2. **Heartbeat & Liveness**:
   - The node runs a background `asyncio` loop sending periodic heartbeats to `POST /nodes/{node_id}/heartbeat`.
   - If the Coordinator goes down, the node applies exponential backoff with random jitter (0.5x to 1.5x) to prevent thundering herds on recovery.
3. **Client Direct Storage Placement**:
   - A client calls `upload_logical_file()`.
   - The client contacts the Coordinator to discover eligible nodes and inspects advertised endpoints.
   - The client connects **directly** over TCP/HTTP to each Storage Node's advertised endpoint to store chunks or erasure shards.
   - The client uploads chunk bytes, receives the stored file ID, and registers the catalog manifest on the Coordinator.
4. **Direct Download & Failover**:
   - The client reads the manifest from the Coordinator catalog.
   - The client streams chunks directly from the Storage Nodes' advertised endpoints.
   - If a primary node is unreachable, the client fails over to replica nodes or reconstructs missing shards via Reed-Solomon erasure coding.

---

## 3. Bind Addresses versus Advertised Endpoints

### Conceptual Distinctions
- **`127.0.0.1` and `localhost` (Loopback)**:
  - Accessible ONLY by processes running on the exact same local machine.
  - Packets never leave the operating system network stack.
  - A node advertising `127.0.0.1` is completely unreachable by other computers.
- **`0.0.0.0` (Inaddr Any)**:
  - A bind-only address instructing the socket to accept incoming connections on **all** active network interfaces (loopback, Ethernet, Wi-Fi).
  - Cannot be used as an advertised URL (e.g., `http://0.0.0.0:8000` is invalid for remote callers).
- **Private LAN Address (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`)**:
  - Routable within the local Wi-Fi / Ethernet subnet.
  - Computers on the same home or office network can connect directly.
  - Not reachable from the public Internet without port forwarding or VPN.
- **Public IP / DNS Hostname**:
  - Globally routable across the public Internet (requires open firewall/NAT forwarding).
- **Container / WSL-Specific Address (`172.x.x.x` in Docker / WSL2)**:
  - Only reachable by the host OS or intra-container network unless port proxying is configured.
- **Future Relay Endpoint**:
  - Reserved for Phase 6B/6C NAT traversal and relay proxies.

### Endpoint and Port Syntax Validation
Both the Storage Node configuration and Coordinator Node Registry now strictly validate endpoints:
1. **Port Validation**:
   - Port must be an integer in the valid range `1 <= port <= 65535`. Out-of-range ports (`0`, `-1`, `70000`) are rejected with HTTP 400.
2. **URL Scheme Validation**:
   - Scheme must be `http` or `https`. Unsupported schemes (`ftp://`, `ssh://`, `file://`, `javascript:`) are rejected with HTTP 400.
3. **Netloc & Hostname Validation**:
   - Netloc cannot be empty and must specify a non-empty hostname or IP. URLs like `http://:8000` or malformed strings are rejected with HTTP 400.
4. **Reconciliation Target Correction**:
   - Coordinator reconciliation (`reconciliation.py`) was updated to select `advertised_endpoint` rather than assuming local bind endpoints.

---

## 4. Multi-Computer Registration and Heartbeat Lifecycle

1. **Persistent Node Identity**:
   - Node IDs are generated once (`NODE-<UUID>`) and persisted to SQLite metadata (`node_metadata.db`) in the node's storage sandbox.
   - When a node restarts, it loads the existing `node_id`.
   - The Coordinator's `register_node` updates the existing record idempotently without creating duplicate rows.
2. **Dynamic Liveness Tracking**:
   - Coordinator tracks `last_seen` timestamp.
   - Dynamic timeout rule: If `(now - last_seen) > NODE_HEARTBEAT_TIMEOUT_SECONDS` (default: 30s), the node is automatically marked `offline`.
   - As soon as a heartbeat arrives from an offline node, it transitions immediately back to `online`.
3. **Resilient Retry with Jitter**:
   - Storage Node heartbeat loop implements bounded exponential backoff:
     - Base interval: `HEARTBEAT_INTERVAL_SECONDS` (default: 15s).
     - On failure: Sleep for `min(max_backoff, backoff * random.uniform(0.5, 1.5))`, where `backoff` doubles up to 60s max.
     - On success: Reset backoff to 1.0s and sleep the standard interval.

---

## 5. Network Transport, Timeouts, and Error Handling

1. **Explicit HTTP Client Timeouts**:
   - Replaced unmanaged requests with `httpx` using explicit structured timeouts:
     `httpx.Timeout(timeout=30.0, connect=10.0)`.
2. **Connection Lifecycle & Resource Safety**:
   - All HTTP interactions use context managers (`with httpx.Client(...) as client:`) ensuring TCP sockets and file descriptors are closed immediately.
3. **Error Discrimination**:
   - Distinguishes network transport failures (connection refused, DNS resolution failure, socket reset, connection timeout) from application errors (HTTP 401 Unauthorized, HTTP 404 Not Found, HTTP 507 Insufficient Storage, SHA-256 Checksum Mismatch).
4. **Idempotent Retries**:
   - `download_chunk_bytes` performs bounded retries with small backoff before declaring a node placement unavailable and failing over.
5. **Credential Protection**:
   - Headers and logging sanitize authentication tokens. Tokens and encryption keys are never written to standard logs, exception traces, or CLI outputs.

---

## 6. Authentication and Transport Security

1. **Header Verification**:
   - Support for `X-Auth-Token` and `Authorization: Bearer <token>`.
   - Storage Nodes reject unauthenticated upload, download, list, and storage inspection requests when `AUTH_TOKEN` is configured.
   - Coordinator rejects unauthenticated registration and catalog requests when `COORDINATOR_AUTH_TOKEN` is configured.
2. **TLS Verification**:
   - `CoordinatorClient` and `ExpoClient` support `verify_tls=True` with custom `ca_cert` path.
   - Hostname and certificate verification are strictly enforced when TLS is active.
3. **Development Mode Boundaries**:
   - Plain HTTP is permitted for local and LAN development, but clearly documented as unencrypted in transit.

---

## 7. Level A: Local Multi-Process Automated Validation Results

All 30 automated integration tests in `coordinator/tests/test_phase6a.py` run against real Uvicorn servers listening on OS TCP sockets across distinct ports and directories:

| Test Case | Description | Result |
| :--- | :--- | :--- |
| `test_validate_port_valid` | Valid TCP ports (1–65535) pass validation | **PASSED** |
| `test_validate_port_invalid` | Out-of-range ports (0, -1, 65536, 100000) rejected | **PASSED** |
| `test_validate_endpoint_url_valid` | Valid HTTP/HTTPS URLs pass validation | **PASSED** |
| `test_validate_endpoint_url_invalid_schemes` | Rejects ftp, ssh, file, javascript schemes | **PASSED** |
| `test_validate_endpoint_url_invalid_netloc_and_ports` | Rejects empty hosts, port 0, port 70000 | **PASSED** |
| `test_storage_node_advertised_endpoint_config_validation` | Settings validation & 0.0.0.0 loopback fallback | **PASSED** |
| `test_coordinator_api_rejects_invalid_endpoints` | API returns HTTP 400 for malformed URLs/ports | **PASSED** |
| `test_level_a_real_multiprocess_registration_and_heartbeats` | Real multi-process registration & advertised endpoints | **PASSED** |
| `test_level_a_real_multiprocess_replication_lifecycle` | End-to-end logical upload, catalog, download, SHA-256 match | **PASSED** |
| `test_level_a_real_multiprocess_erasure_coding_lifecycle` | RS EC (k=2, m=1) upload, download, and SHA-256 match | **PASSED** |
| `test_level_a_real_multiprocess_node_outage_and_replica_failover` | Kill primary node process; client downloads from replica | **PASSED** |
| `test_level_a_real_multiprocess_erasure_coding_node_outage_reconstruction` | Kill 1 node (reconstructs); kill 2nd node (fails safely) | **PASSED** |
| `test_level_a_real_multiprocess_node_restart_and_identity_persistence` | Restart node process; verifies zero duplicate records | **PASSED** |
| `test_level_a_real_multiprocess_logical_deletion_and_cleanup` | Durable deletion job cleans physical chunks over real HTTP | **PASSED** |
| `test_level_a_real_multiprocess_auth_enforcement` | Rejects invalid tokens (401), accepts valid token (200) | **PASSED** |

Execution command:
```powershell
$env:PYTHONPATH="."; pytest coordinator/tests/test_phase6a.py -v
# Result: 30 passed in 42.72s
```

Full regression command:
```powershell
$env:PYTHONPATH="."; pytest -q
# Result: 173 passed, 0 failed in 100.22s
```

---

## 8. Level B: Physical Multi-Computer Manual Validation Procedure

This documented procedure enables running Expo across two or more physical computers on the same local network.

### Network Topology Example
- **Computer A (Coordinator)**: LAN IP `192.168.1.100`
- **Computer B (Storage Node 1)**: LAN IP `192.168.1.101`
- **Computer C (Storage Node 2 & Client)**: LAN IP `192.168.1.102`

### Prerequisites
- Python 3.10+ installed on all machines.
- Repository cloned or copied to all machines.
- Dependencies installed: `pip install fastapi uvicorn httpx pydantic zfec`.
- Windows / Linux Firewalls configured to allow inbound TCP on required ports:
  - Computer A: Allow inbound TCP on port `9000`.
  - Computer B: Allow inbound TCP on port `8001`.
  - Computer C: Allow inbound TCP on port `8001`.

### Step 1: Start Coordinator (Computer A)
```bash
# On Computer A (192.168.1.100)
export COORDINATOR_HOST=0.0.0.0
export COORDINATOR_PORT=9000
export COORDINATOR_AUTH_TOKEN=expo-lan-token
export NODE_HEARTBEAT_TIMEOUT_SECONDS=30

python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```
Verify on Computer A:
```bash
curl http://127.0.0.1:9000/health
# {"status":"online"}
```

### Step 2: Start Storage Node 1 (Computer B)
```bash
# On Computer B (192.168.1.101)
export NODE_HOST=0.0.0.0
export NODE_PORT=8001
export ADVERTISED_ENDPOINT="http://192.168.1.101:8001"
export COORDINATOR_ENABLED=true
export COORDINATOR_URL="http://192.168.1.100:9000"
export COORDINATOR_AUTH_TOKEN=expo-lan-token
export STORAGE_ROOT="./storage_node_data"
export HEARTBEAT_INTERVAL_SECONDS=15

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 8001
```

### Step 3: Start Storage Node 2 (Computer C)
```bash
# On Computer C (192.168.1.102)
export NODE_HOST=0.0.0.0
export NODE_PORT=8001
export ADVERTISED_ENDPOINT="http://192.168.1.102:8001"
export COORDINATOR_ENABLED=true
export COORDINATOR_URL="http://192.168.1.100:9000"
export COORDINATOR_AUTH_TOKEN=expo-lan-token
export STORAGE_ROOT="./storage_node_data"
export HEARTBEAT_INTERVAL_SECONDS=15

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 8001
```

### Step 4: Verify Node Discovery (From Any Computer)
```bash
curl -H "X-Auth-Token: expo-lan-token" http://192.168.1.100:9000/nodes
```
Expected output:
```json
{
  "count": 2,
  "nodes": [
    {
      "node_id": "NODE-...",
      "status": "online",
      "advertised_endpoint": "http://192.168.1.101:8001",
      "connectivity_mode": "LAN"
    },
    {
      "node_id": "NODE-...",
      "status": "online",
      "advertised_endpoint": "http://192.168.1.102:8001",
      "connectivity_mode": "LAN"
    }
  ]
}
```

### Step 5: Upload and Download File via Client CLI
```bash
# Create test file
echo "Hello from Expo Multi-Computer Physical Test" > sample.txt

# Upload with replication factor 2 across both computers
python -m client.cli logical-upload sample.txt --coordinator-url http://192.168.1.100:9000 --token expo-lan-token
# Outputs:
# File ID   : <FILE_ID>
# Key (Hex) : <DEK_HEX>
# Status    : available

# Download and verify integrity
python -m client.cli logical-download <FILE_ID> <DEK_HEX> downloaded_sample.txt --coordinator-url http://192.168.1.100:9000 --token expo-lan-token

# Compare SHA-256 hashes
certutil -hashfile sample.txt SHA256
certutil -hashfile downloaded_sample.txt SHA256
```

### Step 6: Simulate Node Outage & Failover
1. Stop the Storage Node process on Computer B (`Ctrl+C`).
2. Run `logical-download` again on Computer C.
3. The client fails over to Computer C's replica and successfully reconstructs the file.
4. Restart the Storage Node on Computer B. Verify it reconnects and reports healthy heartbeats.

### Step 7: Safe Shutdown
- Stop storage nodes on Computer B and Computer C (`Ctrl+C`).
- Stop coordinator on Computer A (`Ctrl+C`).

### Troubleshooting Guide
- **Connection Refused**: Check firewall inbound rules. Ensure the service bound to `0.0.0.0` rather than `127.0.0.1`.
- **401 Unauthorized**: Ensure `COORDINATOR_AUTH_TOKEN` on nodes and client match the Coordinator.
- **Node Advertises 127.0.0.1**: Ensure `ADVERTISED_ENDPOINT` is explicitly set to the machine's LAN IP.
- **Name Resolution Failure**: Use IP addresses directly if local hostnames do not resolve over mDNS/DNS.

---

## 9. Modified and Created Files

| File | Status | Description |
| :--- | :--- | :--- |
| `coordinator/app/node_registry.py` | Modified | Added `validate_port` and `validate_endpoint_url`; rejects invalid schemes, ports, and malformed URLs. |
| `coordinator/app/reconciliation.py` | Modified | Switched orphan and deletion target queries to use `advertised_endpoint`; added `_get_headers` and explicit timeouts. |
| `storage_node/app/config.py` | Modified | Added port range and URL validation to `resolved_advertised_endpoint`. |
| `client/chunker.py` | Modified | Added optional `chunk_id` field to `ChunkPlacement` to track stored file IDs per placement. |
| `client/client.py` | Modified | Added `ChunkPlacement.chunk_id` tracking on upload; added `httpx.Timeout` and bounded retries on download. |
| `client/placement.py` | Modified | Switched reachability probe to `httpx` with connection/read timeouts and granular failure diagnostics. |
| `coordinator/tests/test_phase6a.py` | Created | Comprehensive 30-test suite covering endpoint validation and Level A real multi-process TCP servers. |
| `phase6a_implementation_plan.md` | Created | Implementation plan artifact. |
| `phase6a_report.md` | Created / Updated | Full Phase 6A documentation and validation report. |

---

## 10. Known Limitations and Scope Boundaries (Deferred to 6B/6C)

The following items are outside the scope of Phase 6A and deferred to future phases:
1. **NAT Traversal & Hole Punching (Phase 6B)**: Nodes behind symmetric NAT or CGNAT currently require manual port forwarding or VPNs. STUN/TURN/ICE hole punching is deferred to Phase 6B.
2. **Relay Routing (Phase 6B)**: Relaying traffic through intermediary nodes when direct TCP connections cannot be established.
3. **Automated Public Certificate Management (Phase 6C)**: Automated ACME / Let's Encrypt TLS provisioning for public endpoints.
4. **Bandwidth / Incentive Metering (Phase 6C)**: Accounting for node storage and bandwidth contributions.
