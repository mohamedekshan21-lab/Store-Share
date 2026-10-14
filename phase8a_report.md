# Expo Phase 8A — Provider Monitoring and Management Report

**Date:** October 11, 2026  
**Status:** Completed & Regression Verified  
**Baseline Test Suite:** 310 Passing Tests  
**Phase 8A Test Suite:** 316 Passing Tests (6 New Acceptance Tests, 0 Regressions)  
**Multi-Machine Physical LAN/WAN Validation:** Outstanding / Not Claimed  

---

## 1. Executive Summary

Phase 8A establishes a secure, provider-facing monitoring and management layer on top of the Expo Coordinator, Storage Nodes, Phase 7A metering engine, and Phase 7B/7B.1 accounting ledger.

Key deliverables completed in Phase 8A:
1. **Capacity Distinction**: Clear separation of **Configured Expo Quota**, **Verified Stored Data** (authoritative active chunk manifests), and **Physical Host Disk Capacity** (underlying disk storage reported via snapshots).
2. **Strict Data Isolation & Ownership**: Implementation of provider tenancy (`provider_id`) on all storage node registrations, preventing cross-provider snooping, diagnostics leakage, or unauthorized node mutation.
3. **Node Lifecycle & Scheduling Controls**: Ability to disable placement scheduling without breaking read access, and initiate graceful node drain/shutdown transitions.
4. **Responsive Modern Dashboard**: Pure Vanilla HTML5, CSS3, and JavaScript Single-Page Application (SPA) with a dark glassmorphic design system, responsive overview cards, live SVG charts, interactive diagnostics modal, and stale/error state handling.
5. **Coordinator Client SDK & CLI**: Full Python SDK methods and CLI commands (`provider-overview`, `provider-nodes`, `provider-node`, `provider-scheduling`, `provider-shutdown`).
6. **Full Regression Verification**: Complete 316-test suite passing across Coordinator and Storage Node engines.

---

## 2. Architecture Inspection & Frontend Selection

### Prior Repository State Inspection
Before introducing UI assets, the repository was audited for existing web frontend frameworks:
- No Node.js project (`package.json`), React, Vue, Svelte, or Next.js build setup existed in the repository.
- The Coordinator is a high-performance Python FastAPI service with SQLite persistence and Starlette routing.
- Introducing a Node.js compilation pipeline or external frontend framework dependencies would complicate deployment and runtimes across distributed storage node providers.

### Chosen Frontend Implementation
A zero-build, dependency-free Vanilla HTML5 + CSS3 + modern JavaScript architecture was chosen:
- **Location**: [`coordinator/app/static/`](file:///d:/expo/coordinator/app/static/)
  - [`index.html`](file:///d:/expo/coordinator/app/static/index.html): Semantic, accessible HTML5 layout with aria attributes.
  - [`dashboard.css`](file:///d:/expo/coordinator/app/static/dashboard.css): Bespoke dark glassmorphism design system utilizing CSS custom properties, responsive media queries, and subtle animations.
  - [`dashboard.js`](file:///d:/expo/coordinator/app/static/dashboard.js): Modular vanilla JS application implementing non-aggressive polling, dynamic SVG bar/area chart generation, real-time search filtering, scheduling toggle switches, and diagnostic drilldown modals.
- **Delivery**: Mounted cleanly into FastAPI via `StaticFiles(directory=..., name="static")` and served at both `/dashboard` and `/provider/dashboard`.

---

## 3. Data Model & Architecture Enhancements

### 3.1 Database Schema Migrations
In [`coordinator/app/database.py`](file:///d:/expo/coordinator/app/database.py), the `nodes` table was extended with automatic PRAGMA schema migrations:
- `provider_id TEXT DEFAULT 'default_provider'`
- `is_schedulable INTEGER DEFAULT 1`
- `CREATE INDEX IF NOT EXISTS idx_nodes_provider ON nodes(provider_id)`

### 3.2 Capacity Classification
Phase 8A strictly separates the three critical capacity domains required by storage providers:
1. **Configured Expo Storage Quota**: The storage limit agreed upon and allocated to the Expo cluster (from `total_capacity_bytes`).
2. **Verified Stored Data**: Authoritative physical bytes occupied by active chunk files registered in chunk manifests, calculated via `MeteringService.calculate_authoritative_stored_bytes(node_id)`.
3. **Physical Host Disk Capacity**: The underlying operating system disk drive capacity (total and free bytes) measured from host drive snapshots.
4. **Remaining Expo Quota**: Evaluated deterministically as `max(0, configured_quota - verified_stored)`.

### 3.3 Node Placement Scheduling Controls
In [`coordinator/app/node_registry.py`](file:///d:/expo/coordinator/app/node_registry.py):
- `NodeRegistry.set_node_scheduling(node_id, enabled)`: Updates `is_schedulable` state.
- `NodeRegistry.select_node(...)`: Enhanced to strictly enforce `node.is_schedulable and node.status == "online"`. When a node is disabled, it is immediately excluded from chunk placement allocations while remaining online and accessible for chunk retrieval and repair operations.
- `NodeRegistry.set_node_status(node_id, new_status)`: Supports transitioning nodes to `"draining"` or `"disabled"`.

---

## 4. API & Authorization Safeguards

All provider monitoring and management endpoints are consolidated in [`coordinator/app/provider_router.py`](file:///d:/expo/coordinator/app/provider_router.py):

| Endpoint | Method | Security / Dependencies | Description |
|---|---|---|---|
| `/provider/overview` | `GET` | `verify_coordinator_auth`, `resolve_provider_identity` | Aggregates quota, verified usage, physical disk, bandwidth ingress/egress, ECC balance, reputation score, and repair stats. |
| `/provider/nodes` | `GET` | `verify_coordinator_auth`, `resolve_provider_identity` | Lists all registered nodes owned by the calling provider. |
| `/provider/nodes/{node_id}/detail` | `GET` | `verify_coordinator_auth`, `verify_node_ownership` | Detailed point-in-time diagnostics, transfer stats, capacity snapshots, and recent audit activity. |
| `/provider/nodes/{node_id}/scheduling` | `POST` | `verify_coordinator_auth`, `verify_node_ownership` | Enables or disables future chunk placement scheduling. |
| `/provider/nodes/{node_id}/shutdown` | `POST` | `verify_coordinator_auth`, `verify_node_ownership` | Safely marks node as `draining` and disables scheduling. |
| `/dashboard` | `GET` | Open Web UI (authenticated queries via API headers) | Serves the Provider Dashboard Single-Page Application. |
| `/provider/dashboard` | `GET` | Open Web UI alias | Serves the Provider Dashboard Single-Page Application. |

### Data Isolation Safeguards
- **Tenant Resolution**: Identity is determined via `resolve_provider_identity` (checking `X-Provider-Id` or authentication context).
- **Ownership Verification**: `verify_node_ownership(node_id, provider_id, registry)` verifies that `node.provider_id == provider_id`. If Provider A attempts to query, schedule, or shut down a node owned by Provider B, a `403 Forbidden` (`Access denied`) exception is immediately raised.
- **Zero-Knowledge Security**: Endpoints strictly return metadata and metrics. No secret keys, data encryption keys (DEKs), file names, or chunk contents are exposed.

---

## 5. Client SDK & CLI Enhancements

### 5.1 Python CoordinatorClient SDK
[`coordinator/coordinator_client/client.py`](file:///d:/expo/coordinator/coordinator_client/client.py) includes:
- `get_provider_overview(window_hours=24.0, provider_id=None)`
- `get_provider_nodes(provider_id=None)`
- `get_provider_node_detail(node_id, window_hours=24.0, provider_id=None)`
- `set_node_scheduling(node_id, is_schedulable=True, reason=None, provider_id=None)`
- `initiate_node_shutdown(node_id, reason=None, provider_id=None)`

### 5.2 Command-Line Interface (CLI)
[`client/cli.py`](file:///d:/expo/client/cli.py) provides 5 subcommands:
```bash
# 1. View provider overview summary
python -m client.cli --token <TOKEN> provider-overview [--provider-id <ID>] [--window-hours 24.0]

# 2. List registered provider nodes
python -m client.cli --token <TOKEN> provider-nodes [--provider-id <ID>]

# 3. Inspect detailed node diagnostics
python -m client.cli --token <TOKEN> provider-node <NODE_ID> [--provider-id <ID>]

# 4. Enable or disable placement scheduling
python -m client.cli --token <TOKEN> provider-scheduling <NODE_ID> [--disable] [--reason "Maintenance"]

# 5. Initiate graceful shutdown / drain
python -m client.cli --token <TOKEN> provider-shutdown <NODE_ID> [--reason "OS upgrade"]
```

---

## 6. Verification and Test Results

### 6.1 Phase 8A Acceptance Test Suite
A dedicated test suite [`coordinator/tests/test_phase8a.py`](file:///d:/expo/coordinator/tests/test_phase8a.py) was implemented covering all required invariants:
- `test_provider_overview_aggregation_distinguishes_capacities`: Verifies that configured quota, verified stored data, physical host disk, remaining quota, and traffic ingress/egress are correctly calculated and segregated.
- `test_cross_provider_isolation_prevents_unauthorized_access`: Verifies that Provider Alice cannot view, inspect, schedule, or shut down Provider Bob's nodes (403 Forbidden).
- `test_node_scheduling_controls_placement_eligibility`: Verifies that disabling scheduling on a node excludes it from placement allocation (`select_node`), and re-enabling restores its placement eligibility.
- `test_graceful_node_shutdown_transitions_to_draining`: Verifies graceful shutdown sets status to `draining` and `is_schedulable` to False.
- `test_dashboard_routes_and_static_assets`: Verifies `/dashboard`, `/provider/dashboard`, and static CSS/JS files return valid HTML5 and asset contents.
- `test_coordinator_client_sdk_and_cli_phase8a`: Verifies end-to-end SDK methods and CLI commands against the coordinator.

```
coordinator/tests/test_phase8a.py::test_provider_overview_aggregation_distinguishes_capacities PASSED [ 16%]
coordinator/tests/test_phase8a.py::test_cross_provider_isolation_prevents_unauthorized_access PASSED [ 33%]
coordinator/tests/test_phase8a.py::test_node_scheduling_controls_placement_eligibility PASSED [ 50%]
coordinator/tests/test_phase8a.py::test_graceful_node_shutdown_transitions_to_draining PASSED [ 66%]
coordinator/tests/test_phase8a.py::test_dashboard_routes_and_static_assets PASSED [ 83%]
coordinator/tests/test_phase8a.py::test_coordinator_client_sdk_and_cli_phase8a PASSED [100%]
======================== 6 passed, 1 warning in 1.46s =========================
```

### 6.2 Full System Regression Suite
The complete regression test suite covering all Coordinator and Storage Node modules was executed:
```
Command: python -m pytest coordinator/tests/ storage_node/tests/ -q
Result:  316 passed, 1 warning in 198.20s (03:18)
Exit Code: 0
```
**Zero regressions detected across all 316 tests.**

---

## 7. Startup Instructions

### 7.1 Running the Coordinator Service
```bash
# Start Coordinator daemon on default port 9000
python -m coordinator.app.main
```
The Provider Portal dashboard is immediately available in any browser at:
`http://127.0.0.1:9000/dashboard` or `http://127.0.0.1:9000/provider/dashboard`

### 7.2 Registering Storage Nodes with Provider Identity
Storage nodes register with their designated `provider_id`:
```bash
# Register a node under provider 'provider_acme'
python -m coordinator.coordinator_client.client register-node \
    --node-id NODE-ACME-1 \
    --host 192.168.1.100 \
    --port 8000 \
    --total-capacity 500000000000 \
    --provider-id provider_acme
```

---

## 8. Known Limitations & Outstanding Validation

1. **Physical LAN/WAN Network Boundary Testing**:
   All 316 automated tests validate local network configurations, mocks, and single-host subprocess transports. Real-world validation across distinct physical machines, separate routers, and WAN NAT traversal remains outstanding. **Production readiness is not claimed based solely on passing automated tests.**
2. **WebSocket Relay State Persistence**:
   Active WebSocket relay tunnels are kept in-memory; upon Coordinator reboot, connected nodes re-establish tunnels via their backoff retry loops.
3. **Absence of Monetary Trading / Payments**:
   In strict adherence to task requirements, no fiat/crypto payments, marketplace trading, or new economic incentives were implemented. Expo Contribution Credits (ECC) remain an auditable, non-monetary accounting measure of node capacity and transfer contributions.
