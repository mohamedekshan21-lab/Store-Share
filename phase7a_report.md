# Phase 7A Report — Bandwidth and Capacity Metering

## 1. Executive Summary

Phase 7A implements an auditable, persistent, zero-knowledge bandwidth and capacity metering engine for the Expo distributed storage network. The system measures:
1. **Contributed storage quota** per storage node, strictly isolated from host physical disk capacity.
2. **Authoritative Expo storage occupied** across replicas and erasure-coded shards without double counting.
3. **Payload bandwidth transfers** (ingress and egress) with strict idempotency and failure exclusion.
4. **Node availability and uptime** calculated over rolling time windows using heartbeat observation intervals.
5. **Successful recovery operations** (replications and self-healing repairs) credited only upon verified completion.
6. **Aggregated historical contribution summaries** accessible via REST API and Python SDK for future accounting.

All 28 new Phase 7A acceptance tests passed (`coordinator/tests/test_phase7a.py`). The full regression suite achieved **281 passing tests** (241 Coordinator + 40 Storage Node) with 0 failures.

---

## 2. Architectural Authority Mapping

| Metric | Authoritative Component | Mechanism |
|---|---|---|
| **Contributed Storage Quota** | Storage Node / `NodeRegistry` | Reported during registration and liveness heartbeat (`total_capacity_bytes`). |
| **Host Physical Disk Capacity & Free** | Storage Node Host OS | Captured as metadata in capacity snapshots, kept strictly separate from Expo quota. |
| **Node Stored Bytes (Authoritative)** | Coordinator `FileCatalog` | Distinct chunk and shard placement sums from active manifests in `files` table. |
| **Node Stored Bytes (Physical Observed)** | Storage Node `StorageManager` | Filesystem sandbox byte usage (`get_used_bytes()`) reported in heartbeats. |
| **Ingress & Egress Transferred Bytes** | Coordinator Relay (`RelayService`) & Storage Node API | Actual completed HTTP/WebSocket payload bytes logged to `metering_transfer_events`. |
| **Node Uptime & Availability Percentage** | Coordinator `NodeRegistry` | Continuous heartbeat observations (`node_heartbeat_observations`) evaluated over rolling windows. |
| **Replication & Repair Contributions** | Coordinator Repair / Reconciliation | Verified completion events logged to `metering_operation_events`. |

---

## 3. Persistent SQLite Metering Data Model

The database schema in `coordinator/app/database.py` was extended with four dedicated tables and indexed queries:

### 3.1 `node_capacity_snapshots`
Records point-in-time capacity states:
- `snapshot_id`: Unique snapshot UUID.
- `node_id`: Target storage node ID.
- `total_quota_bytes`: Configured Expo quota contributed by the node provider.
- `used_bytes`: Current Expo data bytes stored on the node.
- `remaining_quota_bytes`: Available remaining Expo quota (`total_quota_bytes - used_bytes`).
- `physical_total_bytes`: Total host disk size (optional metadata).
- `physical_free_bytes`: Total host disk free space (optional metadata).
- `measured_at`: ISO 8601 UTC timestamp.
- `source`: Source of observation (`'heartbeat'`, `'registration'`, `'audit'`).
- `is_valid`: Boolean flag (1 for valid, 0 for corrupt/suspect measurements).
- Index: `idx_cap_node_measured (node_id, measured_at)`.

### 3.2 `metering_transfer_events`
Records completed bandwidth transfers:
- `event_id`: Unique event UUID.
- `node_id`: Target storage node ID.
- `direction`: Transfer direction (`'upload'` for ingress, `'download'` for egress).
- `operation_type`: `'client_upload'`, `'client_download'`, `'replication'`, `'repair'`, or `'relay'`.
- `payload_bytes`: Exact payload bytes successfully transferred.
- `chunk_id` / `file_id`: Chunk or file identifier if applicable.
- `status`: Completion status (`'success'`, `'failed'`, `'cancelled'`).
- `timestamp`: ISO 8601 UTC timestamp.
- `idempotency_key`: Client- or Coordinator-supplied unique key preventing duplicate accounting.
- Indexes: `idx_transfer_node_ts (node_id, timestamp)`, `idx_transfer_idem (idempotency_key)`.

### 3.3 `node_heartbeat_observations`
Records liveness observations for uptime calculation:
- `observation_id`: Unique observation UUID.
- `node_id`: Target storage node ID.
- `observed_at`: ISO 8601 UTC timestamp of heartbeat reception.
- `reported_status`: Liveness status (`'online'`, `'offline'`, `'degraded'`).
- `response_time_ms`: Round-trip response latency in milliseconds if measured.
- Index: `idx_hb_node_observed (node_id, observed_at)`.

### 3.4 `metering_operation_events`
Records self-healing and replication operations:
- `operation_id`: Unique operation UUID.
- `operation_type`: `'replication'`, `'repair'`, or `'rebalance'`.
- `source_node_id`: Source node providing the chunk data.
- `target_node_id`: Destination node receiving and storing the recovered chunk.
- `chunk_id`: Chunk or shard UUID.
- `payload_bytes`: Verified transferred payload bytes.
- `status`: `'completed'` or `'failed'`.
- `completed_at`: ISO 8601 UTC completion timestamp.
- `duration_seconds`: Operation execution duration.
- `idempotency_key`: Unique key preventing duplicate accounting on job retries.
- Indexes: `idx_op_target_node (target_node_id, completed_at)`, `idx_op_idem (idempotency_key)`.

---

## 4. Accurate Accounting Policy Rules Implemented

1. **Payload Bytes vs. Requested Sizes**: Metering strictly counts verified transferred bytes from completed HTTP/tunnel payloads, never header overhead or unverified requested sizes.
2. **Independent Node Accounting**: Replicated copies and erasure-coded shards reside on distinct storage nodes and consume independent physical storage quotas.
3. **Distinct Chunk Aggregation**: Authoritative node storage calculation aggregates distinct chunk/shard IDs per node, preventing double counting even if a manifest contains duplicate placement references.
4. **Immediate Deletion Reflection**: When a file is marked deleted or purged in catalog reconciliation, authoritative usage immediately deducts the reclaimed storage.
5. **Separation of Cumulative Transfers from Current Storage**: Lifetime upload/download bandwidth totals are maintained completely separate from point-in-time stored bytes.
6. **Strict Idempotency Protection**: All transfer and operation events require an `idempotency_key`. Duplicate submissions return the existing record without inserting duplicate rows or inflating totals.
7. **Failure Exclusion**: Failed transfers and unsuccessful repair attempts are recorded with status `'failed'` and strictly excluded from successful contribution aggregates.
8. **Configured Quota vs. Physical Disk Separation**: Configured Expo quota is strictly separated from physical host disk capacity, ensuring providers are never credited for unallocated host storage.

---

## 5. API Endpoints & Client SDK Extension

### REST API Endpoints (`/metering` Router)
- `POST /metering/transfers`: Record a bandwidth transfer event (idempotent).
- `GET /metering/transfers`: Query transfer events with filtering (`node_id`, `direction`, `status`, `start_time`, `end_time`).
- `GET /metering/snapshots`: Query historical node capacity snapshots.
- `POST /metering/operations`: Record a completed replication or repair operation (idempotent).
- `GET /metering/operations`: Query operation history (`node_id`, `operation_type`, `status`).
- `GET /metering/nodes/{node_id}/summary`: Aggregated contribution summary (quota, used, ingress, egress, uptime, repairs).
- `GET /metering/nodes/{node_id}/uptime`: Rolling window uptime, offline duration, and availability percentage.
- `GET /metering/cluster/summary`: Cluster-wide totals (total quota, total used, total transfers, active nodes).

### Automatic Instrumentation Hooks
- **`NodeRegistry.register_node`**: Automatically logs initial heartbeat observation and baseline capacity snapshot.
- **`NodeRegistry.heartbeat`**: Automatically logs heartbeat observation and capacity updates.
- **`coordinator/app/relay.py`**: Automatically records verified ingress/egress bytes for all relayed transfers.
- **`coordinator/app/main.py` (`create_repair_job`)**: Automatically records successful repair operations upon completion.

### CoordinatorClient Python SDK (`coordinator/coordinator_client/client.py`)
- `get_metering_node_summary(node_id, window_hours=24.0)`
- `get_metering_node_uptime(node_id, window_start=None, window_end=None)`
- `get_metering_cluster_summary(window_hours=24.0)`
- `record_metering_transfer(node_id, direction, operation_type, payload_bytes, ...)`

---

## 6. Acceptance Test Suite (`coordinator/tests/test_phase7a.py`)

A comprehensive 28-test suite was implemented to validate all aspects of Phase 7A:

| Test Group | Test Count | Description | Result |
|---|---|---|---|
| **Database Schema** | 1 | Schema creation, migrations, and index validation | PASSED |
| **Capacity Snapshots** | 3 | Recording snapshots, physical vs quota separation, historical ordering | PASSED |
| **Transfer Events** | 3 | Direction tracking, strict idempotency, status filtering | PASSED |
| **Uptime & Availability** | 4 | Continuous heartbeats (~100%), gap detection, unknown node handling, window clipping | PASSED |
| **Replication & Repair Operations** | 2 | Operation recording, idempotency, failure exclusion from totals | PASSED |
| **Authoritative Storage & Deduplication** | 3 | Distinct chunk aggregation, deletion reduction, transfer/storage separation | PASSED |
| **Contribution & Cluster Summaries** | 2 | Comprehensive node summary and cluster-wide aggregation | PASSED |
| **REST API Endpoints** | 6 | `/metering/transfers`, `/metering/snapshots`, `/metering/operations`, `/metering/nodes/{id}/summary`, `/metering/nodes/{id}/uptime`, `/metering/cluster/summary` | PASSED |
| **Automatic Instrumentation Hooks** | 3 | Automatic capture on node registration, heartbeat, and repair completion | PASSED |
| **CoordinatorClient SDK** | 1 | SDK wrapper verification against metering endpoints | PASSED |

**Phase 7A Test Result: 28 passed in 2.05s**

---

## 7. Full Repository Regression Test Results

```text
coordinator/tests/test_phase7a.py:  28 passed in 2.05s
coordinator/tests/ (Full Suite):   241 passed in 358.41s
storage_node/tests/ (Full Suite):   40 passed in 1.15s
======================================================
Total Passing Tests:               281 passed, 0 failed (100% pass rate)
```

---

## 8. Deployment Readiness and Next Steps

- **Production Readiness**: The Phase 7A metering engine is lightweight, backward-compatible, transactional, and fully tested.
- **Non-Invasive Architecture**: Existing storage node and client APIs remain untouched; instrumentation runs unobtrusively inside Coordinator event handlers.
- **Foundation for Phase 7B**: Clean, auditable metrics are now available for Phase 7B (Marketplace, Contribution Credits, and Node Scoring), requiring no structural changes to Phase 7A tables.
