# Expo Phase 8C — Automated, Verified Node Drain Migration Report

**Date:** October 12, 2026  
**Status:** Completed & Fully Regression Verified  
**Baseline Test Suite:** 343 Passing Tests (Phase 8B Baseline)  
**Phase 8C Test Suite:** 360 Passing Tests (17 New Acceptance Tests in `test_phase8c.py`, 0 Failures, 0 Errors, 12 Warnings)  
**Physical Multi-Machine LAN/WAN Validation:** Outstanding / Not Claimed  

---

## 1. Executive Summary

Phase 8C establishes a reliable, durable background node-drain migration subsystem in the Expo distributed storage coordinator. Prior to Phase 8C, node draining recorded intent and evaluated whether surviving nodes already held sufficient redundant copies, but did not automatically transfer replicas or erasure-coded shards to restore cluster redundancy.

Phase 8C implements an autonomous, data-safe background migration worker that:
1. **Granularly tracks durable migrations in SQLite** (`node_drain_migrations` table) with validated state transitions (`pending`, `transferring`, `verifying`, `completed`, `retryable_failure`, `blocked`).
2. **Survives Coordinator restarts** by recovering in-flight transfers and verification attempts back to `pending` during startup.
3. **Selects safe replacement destinations** enforcing strict capacity checks, schedulability, online health, and distinct-node placement constraints across both replicated chunks and Reed-Solomon erasure-coded shards.
4. **Verifies destination data readability and SHA-256 checksums** over network APIs before committing manifest updates or advancing drain progress. A node is never declared safely drained merely because migration was requested or metadata was updated.
5. **Enforces atomic manifest commits** using isolated SQLite transactions without holding long-lived database write locks during large file transfers.
6. **Strictly preserves source data**: source chunks and shards are **never deleted** during migration. Decommissioning and disk purging remain an explicit, separate future operational phase.
7. **Maintains the safety gate** on `POST /provider/nodes/{node_id}/drain/complete`, returning HTTP 409 Conflict if any required migration remains pending, failed, or unverified.
8. **Preserves Phase 8B provider authentication and identity isolation**, preventing cross-provider snooping or unauthorized drain tampering.

---

## 2. Files Changed & Created

| File | Status | Description |
|---|---|---|
| [`coordinator/app/database.py`](file:///d:/expo/coordinator/app/database.py) | Modified | Created durable `node_drain_migrations` table schema with foreign-key relations to `node_drain_jobs`, status constraints, retry counters, and performant indexes (`idx_mig_drain`, `idx_mig_status`, `idx_mig_source`, `idx_mig_dest`, `idx_mig_chunk`). |
| [`coordinator/app/models.py`](file:///d:/expo/coordinator/app/models.py) | Modified | Added Pydantic schema models: `NodeDrainMigrationRecord`, `NodeDrainMigrationListResponse`, and `DrainWorkerStatusResponse`. |
| [`coordinator/app/drain_service.py`](file:///d:/expo/coordinator/app/drain_service.py) | Modified | Implemented `NodeDrainMigrationWorker`, `MigrationStatus`, durable job registration (`register_migrations_for_node`), destination selector (`select_destination_node`), in-flight recovery on startup (`recover_in_flight_migrations`), atomic manifest commit logic, and progress synchronization. |
| [`coordinator/app/provider_router.py`](file:///d:/expo/coordinator/app/provider_router.py) | Modified | Added `GET /provider/nodes/{node_id}/drain/migrations` (listing granular migration jobs with ownership verification) and `GET /provider/drain/worker/status` (reporting worker metrics). Integrated worker bootstrap into drain service dependency. |
| [`coordinator/coordinator_client/client.py`](file:///d:/expo/coordinator/coordinator_client/client.py) | Modified | Added Python SDK methods `list_drain_migrations(node_id, provider_id)` and `get_drain_worker_status()`. |
| [`coordinator/README.md`](file:///d:/expo/coordinator/README.md) | Modified | Documented operational procedures for starting the worker, initiating a drain, monitoring progress, diagnosing blocked jobs, and triggering idempotent retries. |
| [`coordinator/tests/test_phase8c.py`](file:///d:/expo/coordinator/tests/test_phase8c.py) | **Created** | Comprehensive 17-scenario automated acceptance test suite covering replicated chunk migration, erasure shard reconstruction, checksum mismatch detection, interrupted network timeouts, destination capacity exhaustion, source offline transitions, startup recovery, idempotent retries, concurrent workers, placement constraints, provider isolation, and SDK operations. |

---

## 3. Architecture & Worker Lifecycle

### 3.1 Worker Concurrency & Thread Isolation

The `NodeDrainMigrationWorker` operates as a thread-safe daemon component managed by `NodeDrainService`:

```
                      NodeDrainMigrationWorker
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
   Worker Thread Pool                           In-Flight Guard
(max_concurrent_workers = 4)             (_in_flight_migrations set & lock)
           │                                           │
  ┌────────┴────────┐                                  ▼
  │ process_batch() │                    Prevents duplicate concurrent
  └────────┬────────┘                    execution on same migration_id
           │
           ▼
1. Fetch 'pending' / 'retryable_failure' from SQLite (ORDER BY created_at)
2. Filter through _in_flight_migrations
3. Mark status -> 'transferring' in SQLite
4. Read source (or reconstruct from surviving shards)
5. Transfer to selected destination
6. Mark status -> 'verifying'
7. Physical SHA-256 verification via HTTP probe
8. Atomic SQLite commit -> 'completed' + update file manifest
9. Release from _in_flight_migrations
10. Recalculate parent drain progress
```

### 3.2 Startup Recovery Sequence (`recover_in_flight_migrations`)

When the Coordinator restarts (or in the event of an ungraceful crash / power outage during transfer or verification):
1. Upon initialization of `NodeDrainService`, `recover_in_flight_migrations()` executes immediately.
2. It executes an atomic SQL query:
   ```sql
   UPDATE node_drain_migrations
   SET status = 'pending',
       destination_node_id = NULL,
       updated_at = ?
   WHERE status IN ('transferring', 'verifying')
   ```
3. Any partially uploaded or unverified chunks on destinations are discarded or overwritten on the subsequent attempt; the migration safely restarts from `pending` without corrupted metadata or duplicate placement counts.

---

## 4. Migration State Machine & Data Model

### 4.1 Schema Definition (`node_drain_migrations`)

```sql
CREATE TABLE IF NOT EXISTS node_drain_migrations (
    migration_id TEXT PRIMARY KEY,
    drain_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    chunk_id TEXT NOT NULL,
    shard_index INTEGER,
    source_node_id TEXT NOT NULL,
    destination_node_id TEXT,
    status TEXT NOT NULL CHECK(status IN (
        'pending', 'transferring', 'verifying', 'completed', 'retryable_failure', 'blocked'
    )),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    last_error TEXT,
    payload_bytes INTEGER DEFAULT 0,
    sha256_checksum TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY(drain_id) REFERENCES node_drain_jobs(drain_id) ON DELETE CASCADE,
    FOREIGN KEY(source_node_id) REFERENCES nodes(node_id)
);
```

### 4.2 State Machine Transitions

```
                    ┌──────────────┐
                    │   pending    │ ◄──────────────────────┐
                    └──────┬───────┘                        │
                           │ Destination selected           │ Retry / Restart
                           ▼                                │
                    ┌──────────────┐                        │
                    │ transferring │                        │
                    └──────┬───────┘                        │
                           │ Upload complete                │
                           ▼                                │
                    ┌──────────────┐                        │
                    │  verifying   │                        │
                    └──────┬───────┘                        │
             Checksum OK   │   Checksum mismatch /          │
        & readability OK   │   Read failure                 │
                           │                                │
            ┌──────────────┴──────────────┐                 │
            ▼                             ▼                 │
     ┌─────────────┐             ┌───────────────────┐      │
     │  completed  │             │ retryable_failure ├──────┘
     └─────────────┘             └────────┬──────────┘
                                          │
                                          │ retries >= max_retries
                                          │ OR no eligible destination
                                          ▼
                                   ┌─────────────┐
                                   │   blocked   │
                                   └─────────────┘
```

- **`pending`**: Registered migration waiting for worker execution and destination selection.
- **`transferring`**: Source data is being read (or reconstructed) and uploaded to the candidate destination.
- **`verifying`**: Destination data has been written; worker is validating physical readability and SHA-256 integrity.
- **`completed`**: Destination has verified valid data; file manifest is committed in SQLite; source chunk remains untouched.
- **`retryable_failure`**: Network timeout, transient connection error, or destination checksum mismatch. Will be retried up to `max_retries` (default: 3).
- **`blocked`**: Exhausted retries or no eligible online destination satisfying quota and distinct-node placement rules. Blocks parent drain with descriptive diagnostics.

---

## 5. Safe Destination Selection Algorithm

Before initiating any transfer, `select_destination_node` evaluates cluster topology against five strict constraints:

1. **Online Health**: The destination must report status `online` and have sent a heartbeat within `heartbeat_timeout_seconds`.
2. **Source Exclusion**: The destination must never be the source draining node.
3. **Schedulability & Drain Status**: The destination must be schedulable (`is_schedulable=True`) and not undergoing draining itself (`drain_status='none'`).
4. **Distinct-Node Placement**:
   - *Replication Mode*: The destination must not already hold a primary or secondary replica of the target chunk.
   - *Erasure-Coding Mode*: The destination must not already hold any shard ($0 \le i < k+m$) of the target chunk.
5. **Configured Quota Enforcement**: The destination's `available_capacity_bytes` must be greater than or equal to the required chunk or shard size.
6. **Load Balancing**: Eligible candidate nodes are ordered by available capacity descending, placing data on the least utilized nodes.

If no candidate satisfies all six conditions, the migration transitions to `blocked` with the reason:
`"No eligible replacement node available with sufficient capacity and distinct placement."`

The parent drain transitions to `drain_blocked`. Redundancy requirements are never silently relaxed.

---

## 6. Transfer Verification & Metadata Commit Sequence

To prevent database locks during large network transfers, the worker follows an isolated staged commit protocol:

```
[Phase 1: Transfer Preparation]
  │
  ├─► Select destination node
  └─► Acquire migration in _in_flight_migrations
      Short SQLite Tx: UPDATE status='transferring', destination_node_id=?

[Phase 2: Data Transfer (NO DATABASE LOCK HELD)]
  │
  ├─► Download source payload from authorized source node storage API
  │   (Or reconstruct missing shard from surviving k shards if source is degraded)
  └─► Upload opaque encrypted ciphertext to destination endpoint

[Phase 3: Physical Verification (NO DATABASE LOCK HELD)]
  │
  ├─► Verify destination returns 200 OK
  └─► Verify destination SHA-256 header matches expected chunk/shard checksum

[Phase 4: Atomic SQLite Commit]
  │
  └─► BEGIN IMMEDIATE TRANSACTION
        ├─ Update file manifest_json: replace source placement with destination
        ├─ Increment file manifest_version
        ├─ Update node_drain_migrations: status='completed', completed_at=now()
        ├─ Re-evaluate parent node_drain_jobs:
        │    migrated_chunks += 1, remaining_chunks -= 1
        │    If remaining_chunks == 0 => status='drained'
        └─ COMMIT TRANSACTION
```

---

## 7. Redundancy Safety Guarantees

### 7.1 Replicated Chunks
- Target replication factor ($R$) is strictly maintained.
- If $R=2$ and the source holds one copy, migration ensures another online node holds a verified copy before completing.
- If a chunk already had sufficient verified copies on surviving nodes (e.g., $R=3$ with 2 other verified nodes online), migration verifies those copies without redundant re-transfer.

### 7.2 Erasure-Coded Shards
- Supported schemes ($k+m$, e.g., $4+2=6$) distribute shards across $N \ge k+m$ distinct nodes.
- When an EC node drains, the worker selects an eligible $(k+m+1)$-th node that does not hold any shard of the chunk.
- If the draining node's shard cannot be read directly from the source, the worker downloads $k$ surviving shards from other online nodes, reconstructs the missing shard via Reed-Solomon polynomial interpolation, uploads the reconstructed shard to the destination, and verifies its checksum.

---

## 8. Source Data Preservation & Drain Safety Gate

During Phase 8C:
- **Zero Deletion**: Source chunks and shards are never deleted, removed, or trimmed by the migration worker.
- **Source Readability**: Draining nodes remain readable and available for client downloads as long as they are online.
- **Offline Resilience**: If a source node becomes offline during drain, its drain job status and registered migrations remain intact in SQLite; progress is not reset or assumed complete.
- **Safe Completion Gate**:
  Calling `POST /provider/nodes/{node_id}/drain/complete` queries both file manifests and `node_drain_migrations`:
  ```json
  HTTP 409 Conflict
  {
    "detail": "Cannot complete drain: 1 chunk(s) still lack verified redundancy across online nodes."
  }
  ```
  Only when all migrations report `completed` and cluster-wide redundancy checks confirm every chunk is protected will the endpoint return HTTP 200 with status `drained`.

---

## 9. Test Execution & Verified Results

The complete test suite was executed against the repository:

```powershell
python -m pytest coordinator/tests/ storage_node/tests/ -q
```

### 9.1 Summary of Observed Results

```text
........................................................................ [ 20%]
........................................................................ [ 40%]
........................................................................ [ 60%]
........................................................................ [ 80%]
........................................................................ [100%]
============================== warnings summary ===============================
360 passed, 12 warnings in 531.33s (0:08:51)
```

- **Total Tests Passed:** 360
- **Total Tests Failed:** 0
- **Total Tests Errored:** 0
- **Total Warnings:** 12 (1 `multipart` deprecation warning, 11 Starlette cookie deprecation warnings from Phase 8B test client)
- **Net New Tests in Phase 8C:** 17

### 9.2 Phase 8C Test Matrix (`coordinator/tests/test_phase8c.py`)

| Test Name | Verifications | Result |
|---|---|---|
| `test_successful_replica_migration` | End-to-end migration of replicated chunk; distinct node selection; SHA-256 verification; manifest update; source preservation. | **PASSED** |
| `test_successful_erasure_coded_shard_migration` | 4+2 EC shard migration to distinct replacement node; integrity verification; manifest placement update; drain completion. | **PASSED** |
| `test_destination_checksum_mismatch_detected_and_rejected` | Corrupted destination payload detected during verification; job transitions to `retryable_failure`; manifest remains uncommitted. | **PASSED** |
| `test_interrupted_transfer_and_network_timeout_retryable` | Simulated network timeout during transfer; bounded retry count increments; retryable error logged without exposing secrets. | **PASSED** |
| `test_destination_capacity_exhaustion_blocks_drain` | Candidate nodes lack sufficient available quota; migration transitions to `blocked`; parent drain sets `drain_blocked` with actionable reason. | **PASSED** |
| `test_source_becoming_offline_during_migration_preserves_drain_state` | Source node misses heartbeats and transitions to `offline`; drain job and migration records remain intact in SQLite without data loss. | **PASSED** |
| `test_coordinator_restart_recovers_in_flight_migrations` | Simulated Coordinator restart during transfer; recovery query resets in-flight migrations to `pending`; subsequent batch processes successfully. | **PASSED** |
| `test_repeated_jobs_and_retries_idempotent` | Repeated drain requests and worker retries do not create duplicate migrations or corrupt placement manifests. | **PASSED** |
| `test_concurrent_workers_prevent_duplicate_execution` | Concurrent worker threads processing the same migration queue respect `_in_flight_migrations` lock; zero duplicate transfers. | **PASSED** |
| `test_replica_and_shard_placement_constraints_enforced` | Replacement node selection strictly excludes existing primary/secondary nodes (replication) and existing shard nodes (EC). | **PASSED** |
| `test_failure_to_migrate_when_no_eligible_destination_exists` | Draining solo node in 1-node cluster; worker detects zero destinations; sets `blocked` state with diagnostic details; zero crashes. | **PASSED** |
| `test_redundancy_verification_safety_gate_before_completion` | `POST /drain/complete` returns 409 Conflict while migration is incomplete; succeeds only after verified completion. | **PASSED** |
| `test_source_data_preserved_after_migration` | Verifies source node chunk storage is byte-for-byte identical before and after migration; confirms ZERO source deletion. | **PASSED** |
| `test_provider_isolation_and_authorization_on_drain_operations` | Provider B cannot inspect or retry Provider A's drain migrations; unauthenticated requests rejected with 401; admin override validated. | **PASSED** |
| `test_accurate_dashboard_and_api_progress_reporting` | Verifies metrics on `GET /provider/drain/worker/status` and progress counters on `GET /provider/nodes/{node_id}/drain`. | **PASSED** |
| `test_erasure_shard_migration_reconstruction_from_surviving_shards` | Source EC node shard unreadable; worker reconstructs missing shard from surviving $k$ shards using Reed-Solomon interpolation; restores full parity. | **PASSED** |
| `test_coordinator_client_sdk_drain_migrations_and_worker_status` | SDK methods `list_drain_migrations` and `get_drain_worker_status` interface correctly with API. | **PASSED** |

---

## 10. Operational Guide

### 10.1 Starting the Worker
The migration worker initializes automatically with the Coordinator application:
```powershell
$env:COORDINATOR_AUTH_TOKEN = "coordinator-secret-token"
uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```
On startup, `recover_in_flight_migrations()` executes automatically to recover any migrations left in progress by a previous instance.

### 10.2 Initiating a Node Drain
```powershell
curl -X POST "http://localhost:9000/provider/nodes/NODE-123/drain" `
  -H "X-Auth-Token: coordinator-secret-token" `
  -H "X-Provider-Id: my_provider" `
  -H "Content-Type: application/json" `
  -d '{"reason": "Decommissioning old hardware"}'
```

### 10.3 Monitoring Drain Progress & Migration Records
Check high-level drain status:
```powershell
curl -X GET "http://localhost:9000/provider/nodes/NODE-123/drain" `
  -H "X-Auth-Token: coordinator-secret-token"
```

Check granular chunk/shard migrations:
```powershell
curl -X GET "http://localhost:9000/provider/nodes/NODE-123/drain/migrations" `
  -H "X-Auth-Token: coordinator-secret-token"
```

### 10.4 Diagnosing a Blocked Job
When a drain returns `"status": "drain_blocked"`, inspect the `last_error` field on individual migrations:
- **`insufficient quota`**: Register additional Storage Nodes or increase quota on existing nodes.
- **`placement constraint`**: Add storage nodes in distinct availability zones or failure domains.
- **`corrupt destination payload`**: Check network stability or storage device health on the candidate node.

### 10.5 Retrying a Blocked Drain
Once cluster conditions are resolved:
```powershell
curl -X POST "http://localhost:9000/provider/nodes/NODE-123/drain/retry" `
  -H "X-Auth-Token: coordinator-secret-token"
```
Blocked and failed migrations are reset to `pending` and processed immediately.

---

## 11. Known Limitations & Outstanding Work

1. **Source Decommissioning & Disk Purging**:
   Source chunks are preserved indefinitely during Phase 8C to prevent catastrophic data loss. An explicit, policy-driven decommissioning phase (requiring operator confirmation and cryptographic attestation) is planned for a subsequent release.
2. **Physical Multi-Machine LAN/WAN Validation**:
   All 360 regression tests execute in automated virtualized test environments using loopback and in-memory mock transports. Multi-machine physical LAN/WAN validation across heterogeneous physical hardware and routed networks remains outstanding.
3. **Production Readiness Disclaimer**:
   Passing automated regression tests confirms code correctness against test assertions, but does not guarantee production readiness without physical stress testing, cross-datacenter WAN latency validation, and operational hardening.
