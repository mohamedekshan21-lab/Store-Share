# Expo Coordinator Service (Phase 2B)

> **Internet Connectivity Foundation, Node Registry, Liveness Heartbeat, Smart Node Selection, & Discovery Service** for the Expo Distributed Storage Network.

> ⚠️ **IMPORTANT ARCHITECTURAL RULE**:  
> **THE COORDINATOR DOES NOT STORE USER FILE CONTENTS.**  
> It stores only Storage Node metadata (node identity, host/port endpoints, advertised public URLs, status, connectivity mode, and storage capacity) and manages node discovery and liveness monitoring. Storage Nodes continue to store actual user files.

---

## Architecture Overview

```text
                    EXPO COORDINATOR
                    ┌───────────────┐
                    │ Node Registry │
                    │ Capacity      │
                    │ Heartbeats    │
                    │ Discovery     │
                    │ Selection     │
                    └───────┬───────┘
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
        Storage Node A  Storage Node B  Storage Node C
        (DIRECT / HTTPS) (LAN / HTTP)   (RELAY / STUB)
        ONLINE          ONLINE          OFFLINE
        100 GB          50 GB           200 GB

                    Consumer Client
                          │
                          ▼
                    Node Discovery
```

---

## Phase 2B Key Features

1. **Persistent Node Identity (`NODE-<UUID4>`)**: Node identity remains stable across IP address, host, or network changes.
2. **Internet-Style Registration (`POST /nodes/register`)**: Storage Nodes register over HTTP or secure HTTPS (`COORDINATOR_URL=https://...`), advertising their reachability endpoint (`ADVERTISED_ENDPOINT`) and connectivity capability mode (`LAN`, `DIRECT`, `RELAY`, `UNKNOWN`).
3. **Smart Node Selection (`GET /nodes/select` / `POST /nodes/select`)**: Algorithmic node selection based on requested capacity (`required_bytes`), liveness status, and preferred connectivity mode.
4. **Advanced Node Discovery Filtering (`GET /nodes`)**: Supports query filtering by `status`, `connectivity_mode`, and `min_available_bytes`.
5. **Secure Transport (HTTPS/TLS)**: Configurable TLS certificate verification (`COORDINATOR_VERIFY_TLS`, `COORDINATOR_CA_CERT`).
6. **Auto-Reconnect Heartbeat Keeping**: Storage Nodes automatically re-register with Coordinator if connection is lost or Coordinator resets.
7. **Resilient Local Autonomy**: Storage Nodes function completely independently even if Coordinator is unreachable.

---

## Project Structure

```text
coordinator/
├── app/
│   ├── __init__.py
│   ├── main.py               # FastAPI application & authentication middleware
│   ├── config.py             # Settings (host, port, DB path, auth token, heartbeat timeout)
│   ├── models.py             # Pydantic data models (NodeRegisterRequest, NodeRecord, NodeSelectionRequest)
│   ├── database.py           # SQLite connection & schema migration
│   └── node_registry.py      # Core registry, heartbeat, capacity, offline logic & select_node algorithm
├── coordinator_client/
│   ├── __init__.py
│   ├── client.py             # Python SDK client (`CoordinatorClient` with TLS support)
│   └── transport.py          # Transport abstraction (`DirectTransport`, `RelayTransport` stub)
├── tests/
│   ├── test_coordinator.py   # Phase 2A unit tests
│   └── test_phase2b.py       # Phase 2B automated test suite (18 scenarios)
├── pytest.ini
└── README.md
```

---

## API Reference

| Method | Endpoint | Access | Description | Status / Error Codes |
|---|---|---|---|---|
| `GET` | `/health` | Public | Coordinator liveness check | `200 OK` |
| `POST` | `/nodes/register` | Protected | Register or update Storage Node | `200 OK`, `400 Bad Request`, `401 Unauthorized` |
| `GET` | `/nodes` | Public | List registered nodes (supports `?status=`, `?connectivity_mode=`, `?min_available_bytes=`) | `200 OK` |
| `GET` | `/nodes/select` | Public | Smart node selection query | `200 OK`, `404 Not Found` |
| `POST` | `/nodes/select` | Public | Smart node selection POST body query | `200 OK`, `404 Not Found` |
| `GET` | `/nodes/{node_id}` | Public | Retrieve node record & heartbeat status | `200 OK`, `404 Not Found` |
| `POST` | `/nodes/{node_id}/heartbeat` | Protected | Liveness heartbeat & capacity update | `200 OK`, `400 Bad Request`, `401 Unauthorized`, `404 Not Found` |
| `DELETE` | `/nodes/{node_id}` | Protected | Deregister node from registry | `200 OK`, `401 Unauthorized`, `404 Not Found` |

---

## Environment Configuration

| Environment Variable | Default Value | Description |
|---|---|---|
| `COORDINATOR_HOST` | `0.0.0.0` | Host interface to listen on |
| `COORDINATOR_PORT` | `9000` | Port to listen on |
| `COORDINATOR_DB_PATH` | `./coordinator_metadata.db` | SQLite database file path |
| `COORDINATOR_AUTH_TOKEN` | `None` | Optional development auth token |
| `NODE_HEARTBEAT_TIMEOUT_SECONDS` | `30` | Heartbeat timeout before node is marked `offline` |

---

## How to Run the Coordinator

```powershell
cd d:\expo
uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```

With development authentication token:
```powershell
$env:COORDINATOR_AUTH_TOKEN = "my-coord-token-123"
uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```

---

## Node Drain & Automated Migration Operations (Phase 8C)

The Coordinator provides durable background migration workers that transfer replicas and erasure-coded shards from a draining node to eligible cluster destinations, physically verify destination readability and checksums, and update manifests atomically:

### 1. Initiating a Node Drain
```powershell
# Using curl or Invoke-RestMethod
curl -X POST "http://localhost:9000/provider/nodes/NODE-UUID-1234/drain" `
  -H "X-Auth-Token: <provider-or-admin-token>" `
  -H "X-Provider-Id: <provider-id>" `
  -H "Content-Type: application/json" `
  -d '{"reason": "Hardware maintenance"}'
```
Upon initiation, placement scheduling for the node is disabled immediately (`is_schedulable=False`). Durable migration records are registered in SQLite (`node_drain_migrations`) for each affected replica or shard.

### 2. Migration Worker Execution & Lifecycle
The Coordinator runs the background migration worker (`NodeDrainMigrationWorker`) on startup. It automatically recovers any `transferring` or `verifying` jobs left in-flight after an unexpected shutdown back to `pending`.
To check migration worker status:
```powershell
curl -X GET "http://localhost:9000/provider/drain/worker/status" `
  -H "X-Auth-Token: <token>"
```

### 3. Monitoring Drain Progress & Granular Migrations
Inspect overall drain progress:
```powershell
curl -X GET "http://localhost:9000/provider/nodes/NODE-UUID-1234/drain" `
  -H "X-Auth-Token: <token>"
```
Inspect granular chunk/shard migration records:
```powershell
curl -X GET "http://localhost:9000/provider/nodes/NODE-UUID-1234/drain/migrations" `
  -H "X-Auth-Token: <token>"
```

### 4. Diagnosing a Blocked Drain Job
If destination nodes lack sufficient configured Expo quota, or if distinct-node placement constraints cannot be satisfied, the drain transitions to `drain_blocked` with actionable diagnostic reasons:
```json
{
  "status": "drain_blocked",
  "reason": "1 chunk migration(s) blocked; insufficient eligible cluster destination nodes"
}
```
Query `/provider/nodes/{node_id}/drain/migrations` to view individual blocked jobs, target chunks, and `last_error`.

### 5. Retrying a Blocked Drain
Once cluster capacity, node connectivity, or redundancy conditions improve (e.g., adding a new Storage Node or clearing disk quota), retry the drain:
```powershell
curl -X POST "http://localhost:9000/provider/nodes/NODE-UUID-1234/drain/retry" `
  -H "X-Auth-Token: <token>"
```
Retries reset `retryable_failure` and `blocked` records back to `pending` and trigger worker execution idempotently without duplicate records.

### 6. Completing Drain (Safety Gate)
Attempting to complete a drain before all migrations are verified will fail with `409 Conflict`:
```powershell
curl -X POST "http://localhost:9000/provider/nodes/NODE-UUID-1234/drain/complete" `
  -H "X-Auth-Token: <token>"
```
Source chunks are **never deleted** during migration; decommissioning or disk purging is a separate future operation.

---

## Run Automated Test Suite (372 Passing Tests)

```powershell
cd d:\expo
pytest coordinator/tests/ storage_node/tests/ -q
```

---

## Physical Multi-Machine & Network Boundary Validation (Phase 8D)

For detailed deployment runbooks, firewall configurations, TLS setups, and empirical validation results across physical machines and network boundaries:
- See the physical deployment plan: [`phase8d_validation_plan.md`](file:///d:/expo/phase8d_validation_plan.md)
- See the empirical validation report: [`phase8d_validation_report.md`](file:///d:/expo/phase8d_validation_report.md)


