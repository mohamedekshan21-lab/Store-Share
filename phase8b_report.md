# Expo Phase 8B — Provider Security, Lifecycle State Separation & Safe Node Drain Report

**Date:** October 12, 2026  
**Status:** Completed & Fully Regression Verified  
**Baseline Test Suite:** 316 Passing Tests (Phase 8A Baseline)  
**Phase 8B Test Suite:** 343 Passing Tests (27 Acceptance Tests in `test_phase8b.py`, 0 Regressions)  
**Multi-Machine Physical LAN/WAN Validation:** Outstanding / Not Claimed  

---

## 1. Executive Summary

Phase 8B hardens provider authentication, identity isolation, node lifecycle separation, and data-safe node draining across the Expo distributed storage system:

1. **Authentication & Explicit Provider Identity Mapping**:
   - Audited Coordinator credentials: determined that `COORDINATOR_AUTH_TOKEN` authorizes Coordinator access but does not identify an individual provider.
   - Established explicit, secure database credential mapping (`provider_credentials` SQLite table) and provider-scoped tokens (`provider:<provider_id>`). Header-based identity inference (`X-Provider-Id`) is rejected for unprivileged callers.
   - Separate, explicit administrator authorization implemented: a valid Coordinator token does not automatically grant administrator access. Administrative privileges require `COORDINATOR_ADMIN_AUTH_TOKEN` or a database credential with `is_admin = 1`.
   - Provider impersonation attempts (mismatches between authenticated principal and `X-Provider-Id`) are rejected immediately with HTTP 403 Forbidden.
   - Browser sessions use cryptographically random opaque tokens (`secrets.token_urlsafe(32)`), stored only as SHA-256 hashes in SQLite (`provider_sessions`), with server-side expiration and explicit revocation upon logout.
   - Session-bound CSRF tokens are required for all state-changing browser requests (`POST`, `PUT`, `DELETE`, `PATCH`).
   - Browser login prevents ordinary providers from using the Coordinator's shared administrative token.
   - Production HTTPS deployment requirements and secure cookie settings documented, with development/testing loopback exceptions clearly noted.

2. **Multi-Dimensional Lifecycle State Separation**:
   - Strictly separated operational node health (`status`: `online`, `offline`, `connecting`, `degraded`) from placement scheduling (`is_schedulable`: `True`/`False`) and durable drain progress (`drain_status`: `none`, `draining`, `drain_blocked`, `drained`, `cancelled`).
   - A node transitioning to `offline` due to missed heartbeats preserves its exact drain history and job records without erasing progress or making an incomplete drain appear complete.
   - Truthful dashboard reporting presents both health status and drain progress independently.

3. **Data-Safe Drain Execution & Physical Verification**:
   - Reused existing verified repair and chunk transfer mechanisms from `client/repair.py` and Storage Node file APIs.
   - Probing candidates: physical presence and readable SHA-256 integrity verification is required before counting any copy as healthy; metadata counts alone do not prove presence or readability.
   - For replicated data: requires the configured number ($R$) of verified, healthy copies on distinct eligible online nodes before declaring a source node safely removable (`drained`).
   - For erasure-coded data: enforces the reconstructibility floor (minimum $k$ surviving shards elsewhere to avoid data loss) and full parity policy ($k + m$ shards on distinct eligible nodes).
   - Destination integrity verified before advancing job progress; corrupt destination payloads or interrupted transfers block the drain job (`drain_blocked`) with actionable diagnostics.
   - Zero deletion of source fragments throughout draining: source chunks remain intact on disk.
   - Safe removal gate: `POST /provider/nodes/{node_id}/drain/complete` fails with HTTP 409 Conflict if any chunk lacks verified redundancy.

---

## 2. Files Changed & Created

| File | Status | Description |
|---|---|---|
| [`coordinator/app/database.py`](file:///d:/expo/coordinator/app/database.py) | Modified | Added `provider_credentials`, `provider_sessions` (SHA-256 hashed session identifiers), and `node_drain_jobs` SQLite tables with foreign-key indexes. Added `drain_status` column migration to `nodes`. |
| [`coordinator/app/node_registry.py`](file:///d:/expo/coordinator/app/node_registry.py) | Modified | Extended `VALID_STATUSES` to support lifecycle separation; added `set_node_drain_status`; ensured `_compute_node_status` handles timeouts without erasing `drain_status`. |
| [`coordinator/app/auth.py`](file:///d:/expo/coordinator/app/auth.py) | **Created** | Implemented `CredentialManager` (salted secret hashing, role checks), `ProviderSessionManager` (SHA-256 hashed session storage, expiration, revocation, CSRF token binding), and `AuthenticatedPrincipal`. |
| [`coordinator/app/drain_service.py`](file:///d:/expo/coordinator/app/drain_service.py) | **Created** | Implemented `NodeDrainService`, `DrainStatus`, and `NodeDrainJobRecord`. Implements physical replica & shard presence/checksum verification, replication factor enforcement, erasure coding floor ($k$) and parity ($k+m$) verification, per-node concurrency locks, restart recovery, and idempotent retries. |
| [`coordinator/app/models.py`](file:///d:/expo/coordinator/app/models.py) | Modified | Added Pydantic models: `SessionLoginRequest`, `SessionLoginResponse`, `SessionStatusResponse`, `NodeDrainRequest`, and `NodeDrainResponse`. |
| [`coordinator/app/provider_router.py`](file:///d:/expo/coordinator/app/provider_router.py) | Modified | Replaced insecure identity resolution with `get_current_principal`; rejected provider impersonation attempts; separated admin authorization; added browser session login/logout/status routes; hardened session login against shared token exposure; added safe drain lifecycle endpoints (`/drain`, `/drain/retry`, `/drain/complete`, `/drain/cancel`); preserved backward compatibility on `/shutdown`. |
| [`coordinator/app/main.py`](file:///d:/expo/coordinator/app/main.py) | Modified | Enforced HTTP security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Content-Security-Policy`). |
| [`coordinator/app/config.py`](file:///d:/expo/coordinator/app/config.py) | Modified | Added `admin_auth_token`, `environment`, and `cookie_secure` configuration settings. |
| [`coordinator/coordinator_client/client.py`](file:///d:/expo/coordinator/coordinator_client/client.py) | Modified | Added client SDK methods: `initiate_node_drain`, `get_node_drain`, `retry_node_drain`, `complete_node_drain`, `cancel_node_drain`. |
| [`coordinator/app/static/index.html`](file:///d:/expo/coordinator/app/static/index.html) | Modified | Added Provider Sign In/Sign Out modal and navigation controls; updated dashboard footer. |
| [`coordinator/app/static/dashboard.js`](file:///d:/expo/coordinator/app/static/dashboard.js) | Modified | Zero hardcoded secrets; session cookie authentication; CSRF token attached to state mutations; separate status badges for node health and drain progress; drain action triggers. |
| [`coordinator/tests/test_phase8b.py`](file:///d:/expo/coordinator/tests/test_phase8b.py) | **Created** | Comprehensive 27 acceptance tests covering authentication, anti-spoofing, admin authorization, CSRF, session expiration/revocation, lifecycle state separation, interrupted transfers, corrupt destination data, EC floor, concurrent retries, and restart recovery. |

---

## 3. Detailed Architectural Implementation

### 3.1 Authentication & Principal Resolution Matrix

```
Caller Request
  │
  ├─► [Bearer / X-Auth-Token Header]
  │     │
  │     ├─► DB Credential (provider_credentials)?
  │     │     -> Matches principal_id, provider_id, is_admin
  │     │     -> If non-admin passes mismatched X-Provider-Id => 403 Forbidden
  │     │
  │     ├─► Admin Token (COORDINATOR_ADMIN_AUTH_TOKEN)?
  │     │     -> is_admin = True
  │     │     -> Can act in provider context via X-Provider-Id
  │     │     -> Cross-provider mutation requires X-Admin-Override: true
  │     │
  │     ├─► Provider Scoped Token (provider:<id>)?
  │     │     -> Bound to provider <id>
  │     │     -> If caller passes mismatched X-Provider-Id => 403 Forbidden
  │     │
  │     └─► Shared Coordinator Token (COORDINATOR_AUTH_TOKEN)?
  │           -> is_admin = False (No automatic admin rights)
  │           -> Coordinator infrastructure caller only
  │
  ├─► [Cookie: expo_session]
  │     │
  │     ├─► SHA-256 hash lookup in provider_sessions
  │     ├─► Check expires_at (purge if expired -> 401 Unauthorized)
  │     ├─► If state-changing (POST/PUT/DELETE/PATCH): verify X-CSRF-Token matches
  │     └─► If non-admin passes mismatched X-Provider-Id => 403 Forbidden
  │
  └─► [No credentials supplied] => 401 Unauthorized (WWW-Authenticate: Bearer)
```

### 3.2 Multi-Dimensional Lifecycle Separation

| Dimension | Field | Stored Location | Values | Driving Mechanism |
|---|---|---|---|---|
| **Health / Availability** | `status` | `nodes.status` | `online`, `offline`, `connecting`, `degraded` | Heartbeat timestamp vs `heartbeat_timeout_seconds` |
| **Placement Eligibility** | `is_schedulable` | `nodes.is_schedulable` | `1` (True), `0` (False) | Disabled explicitly or upon drain initiation |
| **Durable Drain Workflow** | `drain_status` / `status` | `nodes.drain_status` & `node_drain_jobs` | `none`, `draining`, `drain_blocked`, `drained`, `cancelled` | Durability redundancy evaluation across active manifests |

#### Offline Invariance Guarantee
When a node in `draining` or `drain_blocked` state misses heartbeats:
1. Operational status dynamically transitions to `offline`.
2. `drain_status` remains `draining` or `drain_blocked`.
3. Drain history and `node_drain_jobs` records are preserved in full.
4. Calling `/drain/complete` while blocked or incomplete fails with **HTTP 409 Conflict**.
5. When the node resumes sending heartbeats, status returns to `online`, and `drain_status` remains intact.

### 3.3 Data-Safe Drain Redundancy Verification

```
Node Drain Request for Node S
  │
  ├─► Set is_schedulable = False immediately
  ├─► Scan active file catalog (files table)
  │
  ├─► For each dependent chunk:
  │     │
  │     ├─► Mode: Replication (Factor R)
  │     │     ├─► For each other placement P on Node D != S:
  │     │     │     ├─► Node D must be online
  │     │     │     └─► Physical probe: verify file present & SHA-256 matches
  │     │     ├─► If physically verified copies H >= R: Satisfied
  │     │     └─► If H < R: Needed = R - H
  │     │           └─► If eligible candidate nodes < Needed:
  │     │                 Mark drain_blocked with actionable reason
  │     │
  │     └─► Mode: Erasure Coding (k data shards, m parity shards)
  │           ├─► For each other shard on Node D != S:
  │           │     ├─► Node D must be online
  │           │     └─► Physical probe: verify shard present & SHA-256 matches
  │           ├─► Safety Floor: If surviving verified shards < k:
  │           │     Mark drain_blocked immediately (Data loss danger!)
  │           └─► Parity Policy: If surviving verified shards < k + m:
  │                 └─► Needed = (k + m) - surviving
  │                 └─► If eligible candidate nodes < Needed:
  │                       Mark drain_blocked with actionable reason
  │
  ├─► Zero Deletion: Source chunks on Node S are NEVER deleted
  ├─► Transactional state update in SQLite (node_drain_jobs)
  └─► Return truthful NodeDrainResponse
```

---

## 4. Test Suite Execution & Verified Results

### 4.1 Phase 8B Acceptance Suite (`coordinator/tests/test_phase8b.py`)

All 27 automated acceptance tests passed:

```
coordinator/tests/test_phase8b.py::test_missing_and_invalid_credentials_rejected PASSED [  3%]
coordinator/tests/test_phase8b.py::test_provider_identity_spoofing_prevented PASSED [  7%]
coordinator/tests/test_phase8b.py::test_cross_provider_isolation_overview_nodes_and_diagnostics PASSED [ 11%]
coordinator/tests/test_phase8b.py::test_unauthorized_scheduling_and_shutdown_attempts PASSED [ 14%]
coordinator/tests/test_phase8b.py::test_administrative_cross_provider_access_requires_explicit_permission PASSED [ 18%]
coordinator/tests/test_phase8b.py::test_browser_session_login_logout_and_csrf_protection PASSED [ 22%]
coordinator/tests/test_phase8b.py::test_no_sensitive_secrets_leaked_in_assets_or_responses PASSED [ 25%]
coordinator/tests/test_phase8b.py::test_drain_disables_scheduling_immediately PASSED [ 29%]
coordinator/tests/test_phase8b.py::test_drain_blocked_when_insufficient_cluster_redundancy PASSED [ 33%]
coordinator/tests/test_phase8b.py::test_drain_cannot_be_completed_when_redundancy_missing PASSED [ 37%]
coordinator/tests/test_phase8b.py::test_drain_completes_when_redundancy_satisfied PASSED [ 40%]
coordinator/tests/test_phase8b.py::test_drain_idempotent_and_retryable PASSED [ 44%]
coordinator/tests/test_phase8b.py::test_drain_persistence_survives_coordinator_restart PASSED [ 48%]
coordinator/tests/test_phase8b.py::test_concurrent_drain_requests_safe PASSED [ 51%]
coordinator/tests/test_phase8b.py::test_coordinator_client_sdk_drain_methods PASSED [ 55%]
coordinator/tests/test_phase8b.py::test_hashed_session_storage_in_database PASSED [ 59%]
coordinator/tests/test_phase8b.py::test_lifecycle_state_separation_node_offline_during_drain PASSED [ 62%]
coordinator/tests/test_phase8b.py::test_explicit_credential_to_identity_mapping_and_impersonation_rejection PASSED [ 66%]
coordinator/tests/test_phase8b.py::test_separate_administrator_authorization PASSED [ 70%]
coordinator/tests/test_phase8b.py::test_erasure_coded_shard_redundancy_and_floor_evaluation PASSED [ 74%]
coordinator/tests/test_phase8b.py::test_source_fragment_preservation_zero_deletion PASSED [ 77%]
coordinator/tests/test_phase8b.py::test_session_expiry_and_explicit_revocation PASSED [ 81%]
coordinator/tests/test_phase8b.py::test_browser_login_rejects_coordinator_shared_token_for_ordinary_providers PASSED [ 85%]
coordinator/tests/test_phase8b.py::test_corrupt_destination_data_blocks_drain_and_prevents_completion PASSED [ 88%]
coordinator/tests/test_phase8b.py::test_interrupted_transfer_and_network_probe_failure_blocks_drain PASSED [ 92%]
coordinator/tests/test_phase8b.py::test_concurrent_drain_retries_thread_safety PASSED [ 96%]
coordinator/tests/test_phase8b.py::test_full_lifecycle_state_machine_and_offline_invariance PASSED [100%]
====================== 27 passed, 12 warnings in 19.45s =======================
```

### 4.2 Full System Regression Suite Execution

Command executed:
```bash
python -m pytest coordinator/tests/ storage_node/tests/ -q
```

**Observed Test Results**:
- **Total Tests Executed**: 343
- **Passed**: 343
- **Failed**: 0
- **Errors**: 0
- **Skipped**: 0
- **Duration**: 281.17s (04:41)
- **Exit Code**: 0

### Breakdown of Test Suites Across All Phases:

| Test Module | Phase Focus | Passing Count |
|---|---|:---:|
| `coordinator/tests/test_coordinator.py` | Baseline Node Registry & API | 15 |
| `coordinator/tests/test_phase2b.py` | Discovery & Capability Routing | 12 |
| `coordinator/tests/test_phase3a.py` | Chunker & Manifest Serialization | 8 |
| `coordinator/tests/test_phase3b.py` | Distributed AES-256 Pipeline | 9 |
| `coordinator/tests/test_phase3c.py` | Cryptographic Integrity Verification | 9 |
| `coordinator/tests/test_phase4a.py` | Multi-Node Replication Management | 14 |
| `coordinator/tests/test_phase4b.py` | Self-Healing & Repair Engine | 18 |
| `coordinator/tests/test_phase4c.py` | Reed-Solomon Erasure Coding | 18 |
| `coordinator/tests/test_phase5a.py` | Unified File Catalog | 8 |
| `coordinator/tests/test_phase5b.py` | Deletion Tracking Lifecycle | 9 |
| `coordinator/tests/test_phase5c.py` | Reconciliation & Cleanup Engine | 9 |
| `coordinator/tests/test_phase6a.py` | Multiprocess Routing Baseline | 25 |
| `coordinator/tests/test_phase6b.py` | Reverse WebSocket Relay Tunnels | 26 |
| `coordinator/tests/test_phase6b1.py` | Tunnel Resiliency & Recovery | 26 |
| `coordinator/tests/test_phase6b2.py` | Multi-Machine Tunnel Validation | 21 |
| `coordinator/tests/test_phase7a.py` | Bandwidth & Capacity Metering | 28 |
| `coordinator/tests/test_phase7b.py` | Contribution Credits & Reputation | 18 |
| `coordinator/tests/test_phase7b1.py` | Ledger Integrity & Audit Records | 11 |
| `coordinator/tests/test_phase8a.py` | Provider Monitoring & Diagnostics | 6 |
| `coordinator/tests/test_phase8b.py` | **Provider Security & Safe Node Lifecycle** | **27** |
| `storage_node/tests/*` | Storage Node Engine, Sandboxing & Storage API | 40 |
| **Total Regression Suite** | | **343 Passed** |

---

## 5. Deployment Requirements & Security Invariants

### 5.1 HTTPS & Cookie Security Configuration
- **Production Deployments (`COORDINATOR_ENV=production`)**:
  - Coordinator must be deployed behind TLS (HTTPS reverse proxy or native certificate termination).
  - Session cookies enforce `Secure=True`, `HttpOnly=True`, and `SameSite=Lax`.
  - HTTP requests automatically receive strict security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy`).
- **Development & Local Testing Exception (`COORDINATOR_ENV=development`)**:
  - Non-HTTPS loopback testing (`127.0.0.1` / `localhost`) permits `cookie_secure=False` because modern browsers reject `Secure` cookies over unencrypted HTTP.

### 5.2 Outstanding Limitations & Disclaimers

1. **Multi-Machine Physical LAN/WAN Validation**:
   - Automated tests run in virtualized local process environments and loopback sockets.
   - Physical multi-machine validation across distinct physical hardware, routers, and WAN NAT boundaries remains **explicitly outstanding and is not claimed**.
2. **Automated Background Migration Worker**:
   - `NodeDrainService` truthfully identifies missing redundancy and prevents unsafe node removal by setting `drain_blocked` or `draining`. Automated background chunk migration workers moving data before complete drain will be deployed in a subsequent phase.
3. **No Monetary Claims**:
   - Expo Contribution Credits (ECC) remain an auditable, non-monetary accounting measure of node capacity and transfer contributions. No cryptocurrency or fiat financial mechanisms are introduced.
