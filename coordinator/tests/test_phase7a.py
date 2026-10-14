"""
Phase 7A Acceptance Test Suite: Bandwidth and Capacity Metering.
Tests the persistent SQLite data model, accurate accounting rules,
uptime calculation, transfer idempotency, deduplication, and REST API endpoints.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator

import pytest
from starlette.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.main import app
from coordinator.app.metering import MeteringService
from coordinator.app.models import (
    NodeRegisterRequest,
    NodeHeartbeatRequest,
    CapacitySnapshotRecord,
    TransferEventCreateRequest,
    OperationEventCreateRequest,
    RepairJobRecord,
)
from coordinator.app.node_registry import NodeRegistry
from coordinator.coordinator_client import CoordinatorClient


@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated test settings with temporary SQLite database."""
    db_file = tmp_path / "coordinator_phase7a.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase7a-secret-token",
        heartbeat_timeout_seconds=5,  # Short timeout for fast uptime testing
    )


@pytest.fixture
def metering_service(test_settings: CoordinatorSettings) -> MeteringService:
    """Fixture providing MeteringService instance."""
    return MeteringService(test_settings)


@pytest.fixture
def node_registry(test_settings: CoordinatorSettings) -> NodeRegistry:
    """Fixture providing NodeRegistry instance."""
    return NodeRegistry(test_settings)


@pytest.fixture
def test_client(test_settings: CoordinatorSettings) -> Generator[TestClient, None, None]:
    """TestClient configured with isolated test settings."""
    app.state.settings = test_settings
    app.state.registry = NodeRegistry(test_settings)
    app.state.metering_service = MeteringService(test_settings)
    with TestClient(app) as client:
        yield client


# =============================================================================
# 1. Database Schema and Migrations
# =============================================================================

def test_metering_schema_tables_and_indices_created(test_settings: CoordinatorSettings):
    """Verifies that all 4 metering tables and their indexes exist after database initialization."""
    init_db(test_settings.db_path)
    with get_db_connection(test_settings.db_path) as conn:
        tables = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        assert "node_capacity_snapshots" in tables
        assert "metering_transfer_events" in tables
        assert "node_heartbeat_observations" in tables
        assert "metering_operation_events" in tables

        indices = [
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        ]
        assert "idx_cap_node_measured" in indices
        assert "idx_transfer_node_ts" in indices
        assert "idx_transfer_idem" in indices
        assert "idx_hb_node_observed" in indices
        assert "idx_op_target_node" in indices
        assert "idx_op_idem" in indices


# =============================================================================
# 2. Node Capacity Snapshots
# =============================================================================

def test_record_capacity_snapshot_basic(metering_service: MeteringService):
    """Verifies recording and retrieving a basic node capacity snapshot."""
    node_id = "NODE-SNAP-01"
    snap = metering_service.record_capacity_snapshot(
        node_id=node_id,
        total_quota_bytes=10_000_000,
        used_bytes=2_500_000,
        source="heartbeat",
    )
    assert snap.node_id == node_id
    assert snap.total_quota_bytes == 10_000_000
    assert snap.used_bytes == 2_500_000
    assert snap.remaining_quota_bytes == 7_500_000
    assert snap.is_valid is True

    history = metering_service.get_capacity_snapshots(node_id)
    assert len(history) == 1
    assert history[0].snapshot_id == snap.snapshot_id


def test_capacity_snapshot_separates_quota_from_physical_disk(metering_service: MeteringService):
    """
    Confirms configured Expo quota is strictly separated from physical host disk.
    Never implies the entire host disk is contributed to Expo.
    """
    node_id = "NODE-SNAP-02"
    snap = metering_service.record_capacity_snapshot(
        node_id=node_id,
        total_quota_bytes=50_000_000_000,      # 50 GB contributed to Expo
        used_bytes=10_000_000_000,             # 10 GB Expo data
        physical_total_bytes=1_000_000_000_000, # 1 TB host physical disk
        physical_free_bytes=400_000_000_000,    # 400 GB host free space
        source="heartbeat",
    )
    assert snap.total_quota_bytes == 50_000_000_000
    assert snap.physical_total_bytes == 1_000_000_000_000
    assert snap.remaining_quota_bytes == 40_000_000_000
    # Configured quota is 5% of host disk, properly separated
    assert snap.total_quota_bytes < snap.physical_total_bytes


def test_capacity_snapshots_query_and_ordering(metering_service: MeteringService):
    """Verifies chronological ordering and filtering of capacity snapshots."""
    node_id = "NODE-SNAP-03"
    t1 = "2026-10-11T10:00:00+00:00"
    t2 = "2026-10-11T11:00:00+00:00"
    t3 = "2026-10-11T12:00:00+00:00"

    metering_service.record_capacity_snapshot(node_id, 1000, 100, timestamp=t1)
    metering_service.record_capacity_snapshot(node_id, 1000, 200, timestamp=t2)
    metering_service.record_capacity_snapshot(node_id, 1000, 300, timestamp=t3)

    snaps = metering_service.get_capacity_snapshots(node_id)
    assert len(snaps) == 3
    # Most recent first
    assert snaps[0].measured_at == t3
    assert snaps[0].used_bytes == 300
    assert snaps[2].measured_at == t1


# =============================================================================
# 3. Transfer Events & Strict Idempotency
# =============================================================================

def test_record_transfer_event_success(metering_service: MeteringService):
    """Verifies recording ingress and egress transfer events."""
    node_id = "NODE-TX-01"
    evt1 = metering_service.record_transfer_event(
        node_id=node_id,
        direction="upload",
        operation_type="client_upload",
        payload_bytes=1_048_576,  # 1 MB
        chunk_id="chunk-abc",
        status="success",
    )
    assert evt1.direction == "upload"
    assert evt1.payload_bytes == 1_048_576
    assert evt1.status == "success"

    evt2 = metering_service.record_transfer_event(
        node_id=node_id,
        direction="download",
        operation_type="client_download",
        payload_bytes=524_288,  # 512 KB
        chunk_id="chunk-abc",
        status="success",
    )
    assert evt2.direction == "download"
    assert evt2.payload_bytes == 524_288

    events = metering_service.get_transfer_events(node_id=node_id)
    assert len(events) == 2


def test_transfer_event_idempotency_prevents_double_counting(metering_service: MeteringService):
    """
    Duplicate submissions with identical idempotency keys must return the existing
    record and NEVER insert duplicate records or inflate totals.
    """
    node_id = "NODE-TX-IDEM"
    idem_key = "client-tx-uuid-12345"

    evt_a = metering_service.record_transfer_event(
        node_id=node_id,
        direction="upload",
        operation_type="client_upload",
        payload_bytes=1000,
        idempotency_key=idem_key,
    )
    # Repeated attempt (e.g. client network retry)
    evt_b = metering_service.record_transfer_event(
        node_id=node_id,
        direction="upload",
        operation_type="client_upload",
        payload_bytes=1000,
        idempotency_key=idem_key,
    )
    assert evt_a.event_id == evt_b.event_id
    assert evt_a.idempotency_key == evt_b.idempotency_key

    # Query database directly to confirm exactly one record exists
    with get_db_connection(metering_service.db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM metering_transfer_events WHERE idempotency_key = ?",
            (idem_key,),
        ).fetchone()[0]
        assert count == 1


def test_transfer_events_status_filtering(metering_service: MeteringService):
    """Failed or cancelled transfers must be distinguishable and excluded from successful totals."""
    node_id = "NODE-TX-STATUS"
    metering_service.record_transfer_event(
        node_id=node_id, direction="upload", operation_type="client_upload",
        payload_bytes=1000, status="success"
    )
    metering_service.record_transfer_event(
        node_id=node_id, direction="upload", operation_type="client_upload",
        payload_bytes=5000, status="failed"
    )

    success_events = metering_service.get_transfer_events(node_id=node_id, status="success")
    assert len(success_events) == 1
    assert success_events[0].payload_bytes == 1000

    failed_events = metering_service.get_transfer_events(node_id=node_id, status="failed")
    assert len(failed_events) == 1
    assert failed_events[0].payload_bytes == 5000


# =============================================================================
# 4. Node Uptime and Availability Calculation
# =============================================================================

def test_record_heartbeat_observation(metering_service: MeteringService):
    """Verifies recording heartbeat observations."""
    obs = metering_service.record_heartbeat_observation(
        node_id="NODE-HB-01",
        reported_status="online",
        response_time_ms=12.5,
    )
    assert obs.node_id == "NODE-HB-01"
    assert obs.reported_status == "online"
    assert obs.response_time_ms == 12.5


def test_node_uptime_continuous_heartbeats(node_registry: NodeRegistry, metering_service: MeteringService):
    """A node heartbeating within timeout has 100% availability."""
    node_id = "NODE-UPTIME-100"
    t_base = datetime.now(timezone.utc) - timedelta(minutes=10)

    # Register node
    node_registry.register_node(
        node_id=node_id, host="127.0.0.1", port=9001,
        total_capacity_bytes=10_000_000,
    )

    # Simulate 5 heartbeats spaced 2 seconds apart (well within 5s timeout)
    for i in range(5):
        t = t_base + timedelta(seconds=i * 2)
        metering_service.record_heartbeat_observation(
            node_id=node_id, reported_status="online", observed_at=t.isoformat()
        )

    w_start = t_base.isoformat()
    w_end = (t_base + timedelta(seconds=8)).isoformat()
    uptime = metering_service.calculate_node_uptime(node_id, window_start=w_start, window_end=w_end)

    assert uptime.availability_percentage >= 99.0
    assert uptime.observed_online_seconds > 0.0
    assert uptime.total_heartbeats_count >= 5


def test_node_uptime_with_offline_gap(node_registry: NodeRegistry, metering_service: MeteringService):
    """A node with an extended heartbeat gap exceeding timeout yields reduced availability."""
    node_id = "NODE-UPTIME-GAP"
    t_start = datetime.now(timezone.utc) - timedelta(minutes=30)

    node_registry.register_node(
        node_id=node_id, host="127.0.0.1", port=9002, total_capacity_bytes=10_000_000
    )

    # Observation 1 at start
    metering_service.record_heartbeat_observation(node_id, "online", observed_at=t_start.isoformat())
    # 20 minutes offline gap (well above 5s timeout)
    t_after_gap = t_start + timedelta(minutes=20)
    metering_service.record_heartbeat_observation(node_id, "online", observed_at=t_after_gap.isoformat())

    uptime = metering_service.calculate_node_uptime(
        node_id,
        window_start=t_start.isoformat(),
        window_end=t_after_gap.isoformat(),
    )
    # The node was online for at most 5 seconds after t_start, then offline for ~19m55s
    assert uptime.availability_percentage < 5.0
    assert uptime.observed_offline_seconds > 1000.0


def test_node_uptime_unknown_node(metering_service: MeteringService):
    """Querying uptime for an unregistered node returns 0% availability safely."""
    uptime = metering_service.calculate_node_uptime("NON-EXISTENT-NODE")
    assert uptime.availability_percentage == 0.0
    assert uptime.total_heartbeats_count == 0


# =============================================================================
# 5. Replication and Repair Operations
# =============================================================================

def test_record_operation_event_success_and_idempotency(metering_service: MeteringService):
    """Verifies operation event recording and strict deduplication via idempotency key."""
    idem_key = "op-repair-chunk-001"
    op1 = metering_service.record_operation_event(
        operation_type="repair",
        source_node_id="NODE-SRC",
        target_node_id="NODE-DST",
        chunk_id="chunk-xyz",
        payload_bytes=65536,
        status="completed",
        duration_seconds=1.2,
        idempotency_key=idem_key,
    )
    assert op1.operation_type == "repair"
    assert op1.payload_bytes == 65536
    assert op1.status == "completed"

    # Duplicate call with same idempotency key
    op2 = metering_service.record_operation_event(
        operation_type="repair",
        source_node_id="NODE-SRC",
        target_node_id="NODE-DST",
        chunk_id="chunk-xyz",
        payload_bytes=65536,
        status="completed",
        idempotency_key=idem_key,
    )
    assert op1.operation_id == op2.operation_id

    # Confirm only 1 row in DB
    with get_db_connection(metering_service.db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM metering_operation_events WHERE idempotency_key = ?",
            (idem_key,),
        ).fetchone()[0]
        assert count == 1


def test_failed_operations_excluded_from_success_totals(metering_service: MeteringService):
    """Failed operations must not count toward successful contribution totals."""
    node_id = "NODE-OP-STATS"
    # 1 completed repair
    metering_service.record_operation_event(
        operation_type="repair", target_node_id=node_id, payload_bytes=1000, status="completed"
    )
    # 2 failed repairs
    metering_service.record_operation_event(
        operation_type="repair", target_node_id=node_id, payload_bytes=2000, status="failed"
    )

    ops = metering_service.get_operation_events(node_id=node_id, status="completed")
    assert len(ops) == 1
    assert ops[0].payload_bytes == 1000


# =============================================================================
# 6. Authoritative Storage Accounting & Deduplication
# =============================================================================

def test_authoritative_stored_bytes_distinct_chunks(metering_service: MeteringService):
    """
    Verifies that authoritative storage aggregates distinct chunks per node,
    counting separate replicas on distinct nodes independently.
    """
    node_a = "NODE-DISTINCT-A"
    node_b = "NODE-DISTINCT-B"

    # Insert test file with 2 chunks into catalog
    # Chunk 1 placed on Node A and Node B (replication factor 2)
    # Chunk 2 placed on Node A only
    manifest = {
        "chunks": [
            {
                "chunk_id": "c1",
                "size_bytes": 100_000,
                "placements": [
                    {"node_id": node_a, "chunk_id": "c1"},
                    {"node_id": node_b, "chunk_id": "c1"},
                ],
            },
            {
                "chunk_id": "c2",
                "size_bytes": 200_000,
                "placements": [
                    {"node_id": node_a, "chunk_id": "c2"},
                ],
            },
        ]
    }

    with get_db_connection(metering_service.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (
                file_id, owner_id, original_filename, original_size,
                status, redundancy_mode, manifest_version, manifest_json,
                created_at, updated_at
            ) VALUES ('f1', 'user1', 'test.bin', 300000, 'active', 'replication', 2, ?, ?, ?)
            """,
            (json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    used_a = metering_service.calculate_authoritative_stored_bytes(node_a)
    used_b = metering_service.calculate_authoritative_stored_bytes(node_b)

    # Node A holds c1 (100k) + c2 (200k) = 300,000 bytes
    assert used_a == 300_000
    # Node B holds c1 (100k) = 100,000 bytes
    assert used_b == 100_000


def test_authoritative_stored_bytes_decreases_on_deletion(metering_service: MeteringService):
    """When a file is marked 'deleted', its chunks are immediately excluded from authoritative usage."""
    node_a = "NODE-DEL-TEST"
    manifest = {
        "chunks": [
            {
                "chunk_id": "cdel-1",
                "size_bytes": 500_000,
                "placements": [{"node_id": node_a, "chunk_id": "cdel-1"}],
            }
        ]
    }

    with get_db_connection(metering_service.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (
                file_id, owner_id, original_filename, original_size,
                status, redundancy_mode, manifest_version, manifest_json,
                created_at, updated_at
            ) VALUES ('f-del', 'user1', 'del.bin', 500000, 'active', 'replication', 2, ?, ?, ?)
            """,
            (json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    assert metering_service.calculate_authoritative_stored_bytes(node_a) == 500_000

    # Mark file deleted
    with get_db_connection(metering_service.db_path) as conn:
        conn.execute("UPDATE files SET status = 'deleted' WHERE file_id = 'f-del'")
        conn.commit()

    assert metering_service.calculate_authoritative_stored_bytes(node_a) == 0


def test_cumulative_transfers_separate_from_current_storage(metering_service: MeteringService, node_registry: NodeRegistry):
    """
    Lifetime ingress/egress transfer totals are kept strictly separate from
    point-in-time stored bytes.
    """
    node_id = "NODE-TRANSFER-SEPARATE"
    node_registry.register_node(
        node_id=node_id, host="127.0.0.1", port=9003,
        total_capacity_bytes=100_000_000, used_capacity_bytes=5_000,
    )

    # 10 uploads of 1,000 bytes = 10,000 bytes ingress
    for i in range(10):
        metering_service.record_transfer_event(
            node_id=node_id, direction="upload", operation_type="client_upload",
            payload_bytes=1_000, status="success"
        )
    # 5 downloads of 2,000 bytes = 10,000 bytes egress
    for i in range(5):
        metering_service.record_transfer_event(
            node_id=node_id, direction="download", operation_type="client_download",
            payload_bytes=2_000, status="success"
        )

    summary = metering_service.get_node_summary(node_id)
    assert summary.lifetime_ingress_bytes == 10_000
    assert summary.lifetime_egress_bytes == 10_000
    assert summary.lifetime_transfer_bytes == 20_000
    # Current stored bytes is 5,000, independent of 20,000 lifetime transfer volume
    assert summary.current_used_bytes == 5_000


# =============================================================================
# 7. Aggregated Summaries (Node and Cluster)
# =============================================================================

def test_get_node_summary_complete(node_registry: NodeRegistry, metering_service: MeteringService):
    """Tests comprehensive node contribution summary calculation."""
    node_id = "NODE-SUMMARY-TEST"
    node_registry.register_node(
        node_id=node_id, host="127.0.0.1", port=9004,
        total_capacity_bytes=50_000_000, used_capacity_bytes=10_000_000,
    )

    metering_service.record_capacity_snapshot(
        node_id=node_id, total_quota_bytes=50_000_000, used_bytes=10_000_000,
        physical_total_bytes=500_000_000, physical_free_bytes=200_000_000,
    )
    metering_service.record_transfer_event(
        node_id=node_id, direction="upload", operation_type="client_upload",
        payload_bytes=15_000, status="success"
    )
    metering_service.record_operation_event(
        operation_type="repair", target_node_id=node_id, payload_bytes=5000, status="completed"
    )

    summary = metering_service.get_node_summary(node_id)
    assert summary.node_id == node_id
    assert summary.configured_quota_bytes == 50_000_000
    assert summary.physical_disk_total_bytes == 500_000_000
    assert summary.physical_disk_free_bytes == 200_000_000
    assert summary.lifetime_ingress_bytes == 15_000
    assert summary.successful_operations_count == 1
    assert summary.successful_operations_bytes == 5000


def test_get_cluster_summary(node_registry: NodeRegistry, metering_service: MeteringService):
    """Tests cluster-wide capacity, bandwidth, and contribution summary."""
    node_registry.register_node("N-1", "127.0.0.1", 9011, total_capacity_bytes=100_000)
    node_registry.register_node("N-2", "127.0.0.1", 9012, total_capacity_bytes=200_000)

    metering_service.record_transfer_event("N-1", "upload", "client_upload", 20_000, status="success")
    metering_service.record_transfer_event("N-2", "download", "client_download", 30_000, status="success")
    metering_service.record_operation_event("replication", "N-2", 15_000, status="completed")

    cluster = metering_service.get_cluster_summary()
    assert cluster.total_nodes_count >= 2
    assert cluster.total_contributed_quota_bytes >= 300_000
    assert cluster.total_ingress_bytes >= 20_000
    assert cluster.total_egress_bytes >= 30_000
    assert cluster.total_transfer_bytes >= 50_000
    assert cluster.total_replications_completed >= 1


# =============================================================================
# 8. REST API Endpoints
# =============================================================================

def test_api_record_and_list_transfers(test_client: TestClient):
    """Tests /metering/transfers POST and GET endpoints."""
    post_res = test_client.post(
        "/metering/transfers",
        json={
            "node_id": "API-NODE-1",
            "direction": "upload",
            "operation_type": "client_upload",
            "payload_bytes": 4096,
            "status": "success",
            "idempotency_key": "api-idem-1",
        },
    )
    assert post_res.status_code == 201
    data = post_res.json()
    assert data["node_id"] == "API-NODE-1"
    assert data["payload_bytes"] == 4096

    # Repeated POST with same idempotency key returns existing event
    post_dup = test_client.post(
        "/metering/transfers",
        json={
            "node_id": "API-NODE-1",
            "direction": "upload",
            "operation_type": "client_upload",
            "payload_bytes": 4096,
            "status": "success",
            "idempotency_key": "api-idem-1",
        },
    )
    assert post_dup.status_code == 201
    assert post_dup.json()["event_id"] == data["event_id"]

    # Query GET
    get_res = test_client.get("/metering/transfers?node_id=API-NODE-1")
    assert get_res.status_code == 200
    list_data = get_res.json()
    assert list_data["count"] == 1
    assert list_data["total_bytes"] == 4096


def test_api_snapshots_list(test_client: TestClient, metering_service: MeteringService):
    """Tests /metering/snapshots GET endpoint."""
    metering_service.record_capacity_snapshot("API-NODE-SNAP", 50000, 10000)

    res = test_client.get("/metering/snapshots?node_id=API-NODE-SNAP")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 1
    assert data["snapshots"][0]["total_quota_bytes"] == 50000


def test_api_operations_post_and_get(test_client: TestClient):
    """Tests /metering/operations POST and GET endpoints."""
    post_res = test_client.post(
        "/metering/operations",
        json={
            "operation_type": "repair",
            "target_node_id": "API-NODE-OP",
            "payload_bytes": 8192,
            "status": "completed",
            "idempotency_key": "api-op-idem-1",
        },
    )
    assert post_res.status_code == 201
    assert post_res.json()["payload_bytes"] == 8192

    get_res = test_client.get("/metering/operations?node_id=API-NODE-OP")
    assert get_res.status_code == 200
    assert get_res.json()["count"] == 1


def test_api_node_summary_endpoint(test_client: TestClient, node_registry: NodeRegistry):
    """Tests /metering/nodes/{node_id}/summary GET endpoint."""
    node_registry.register_node("API-SUMM-NODE", "127.0.0.1", 9020, total_capacity_bytes=1_000_000)

    res = test_client.get("/metering/nodes/API-SUMM-NODE/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["node_id"] == "API-SUMM-NODE"
    assert data["configured_quota_bytes"] == 1_000_000

    # 404 for unknown node
    res_404 = test_client.get("/metering/nodes/NON-EXISTENT/summary")
    assert res_404.status_code == 404


def test_api_node_uptime_endpoint(test_client: TestClient, node_registry: NodeRegistry):
    """Tests /metering/nodes/{node_id}/uptime GET endpoint."""
    node_registry.register_node("API-UPTIME-NODE", "127.0.0.1", 9021, total_capacity_bytes=1_000_000)

    res = test_client.get("/metering/nodes/API-UPTIME-NODE/uptime")
    assert res.status_code == 200
    data = res.json()
    assert data["node_id"] == "API-UPTIME-NODE"
    assert "availability_percentage" in data


def test_api_cluster_summary_endpoint(test_client: TestClient, node_registry: NodeRegistry):
    """Tests /metering/cluster/summary GET endpoint."""
    node_registry.register_node("API-CLUS-1", "127.0.0.1", 9031, total_capacity_bytes=500_000)

    res = test_client.get("/metering/cluster/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_nodes_count"] >= 1
    assert data["total_contributed_quota_bytes"] >= 500_000


# =============================================================================
# 9. Automatic Metering Hooks
# =============================================================================

def test_automatic_metering_on_node_registration(node_registry: NodeRegistry, metering_service: MeteringService):
    """Registering a node automatically creates a heartbeat observation and initial capacity snapshot."""
    node_id = "AUTO-REG-NODE"
    node_registry.register_node(
        node_id=node_id, host="127.0.0.1", port=9040,
        total_capacity_bytes=2_000_000, used_capacity_bytes=100_000,
    )

    # Verify capacity snapshot created automatically
    snaps = metering_service.get_capacity_snapshots(node_id)
    assert len(snaps) == 1
    assert snaps[0].total_quota_bytes == 2_000_000
    assert snaps[0].source == "registration"

    # Verify heartbeat observation created automatically
    with get_db_connection(metering_service.db_path) as conn:
        obs = conn.execute(
            "SELECT * FROM node_heartbeat_observations WHERE node_id = ?",
            (node_id,),
        ).fetchall()
        assert len(obs) >= 1


def test_automatic_metering_on_node_heartbeat(node_registry: NodeRegistry, metering_service: MeteringService):
    """Sending a heartbeat automatically records an observation and updates capacity snapshots."""
    node_id = "AUTO-HB-NODE"
    node_registry.register_node(node_id=node_id, host="127.0.0.1", port=9041, total_capacity_bytes=3_000_000)

    # Send heartbeat with updated usage
    hb_req = NodeHeartbeatRequest(
        node_id=node_id, status="online", used_capacity_bytes=500_000
    )
    node_registry.heartbeat(node_id, hb_req)

    snaps = metering_service.get_capacity_snapshots(node_id)
    assert len(snaps) >= 2
    latest = snaps[0]
    assert latest.used_bytes == 500_000
    assert latest.source == "heartbeat"


def test_automatic_metering_on_repair_job_creation(test_client: TestClient, metering_service: MeteringService):
    """Creating or completing a repair job with state 'SUCCEEDED' automatically records an operation event."""
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    res = test_client.post(
        "/repair/jobs",
        json={
            "job_id": job_id,
            "file_id": "file-123",
            "chunk_id": "chunk-123",
            "source_node_id": "SRC-NODE",
            "destination_node_id": "DST-NODE",
            "state": "SUCCEEDED",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    assert res.status_code == 201

    ops = metering_service.get_operation_events(node_id="DST-NODE")
    assert len(ops) >= 1
    assert ops[0].operation_type == "repair"
    assert ops[0].status == "completed"


# =============================================================================
# 10. CoordinatorClient SDK Integration
# =============================================================================

def test_coordinator_client_metering_sdk(test_client: TestClient, node_registry: NodeRegistry):
    """Verifies that CoordinatorClient SDK methods interface properly with the metering endpoints."""
    node_id = "SDK-METER-NODE"
    node_registry.register_node(node_id, "127.0.0.1", 9050, total_capacity_bytes=800_000)

    # Use CoordinatorClient pointing to in-memory Starlette TestClient transport
    client = CoordinatorClient(coordinator_url="http://testserver", auth_token="phase7a-secret-token")
    # Patch internal _request to use test_client
    original_request = client._request
    client._request = lambda method, path, **kwargs: getattr(test_client, method.lower())(path, **kwargs)

    summary = client.get_metering_node_summary(node_id)
    assert summary["node_id"] == node_id
    assert summary["configured_quota_bytes"] == 800_000

    cluster = client.get_metering_cluster_summary()
    assert cluster["total_nodes_count"] >= 1

    tx_res = client.record_metering_transfer(
        node_id=node_id,
        direction="download",
        operation_type="client_download",
        payload_bytes=2048,
        idempotency_key="sdk-tx-1",
    )
    assert tx_res["payload_bytes"] == 2048
