"""
Phase 8C Acceptance Test Suite: Automated, Verified Node Drain Migration.

Tests validate:
1. Successful replica migration with SHA-256 verification and atomic manifest commit.
2. Successful erasure-coded shard migration with distinct-node placement.
3. Destination checksum mismatch detection, rejection, and retryable/blocked handling.
4. Interrupted transfer and network timeout handling (retryable failure recovery).
5. Destination capacity exhaustion detection and actionable blocked reporting.
6. Source node going offline during migration preserves drain state.
7. Coordinator restart recovery of in-flight (transferring/verifying) jobs.
8. Repeated jobs, retries, and idempotency without duplicate accounting or corrupt manifests.
9. Concurrent worker synchronization (in-memory lock prevents duplicate transfers).
10. Replica and erasure shard placement constraints (distinct-node enforcement).
11. Failure to migrate when no eligible destination exists (blocked with actionable reason).
12. Redundancy verification safety gate: /drain/complete fails with 409 until verified.
13. Source data preservation: source chunks/shards are NEVER deleted.
14. Provider identity isolation and anti-spoofing on migration APIs.
15. Accurate progress reporting through drain endpoints and worker status API.
16. Reed-Solomon shard reconstruction when source shard is corrupt or degraded.
17. Real transport vs mock transport distinction.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import pytest
from starlette.testclient import TestClient

from coordinator.app.main import app
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.metering import MeteringService
from coordinator.app.accounting import AccountingService
from coordinator.app.auth import ProviderSessionManager
from coordinator.app.drain_service import (
    NodeDrainService,
    NodeDrainMigrationWorker,
    DrainStatus,
    MigrationStatus,
)
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError
from client.erasure import encode_ciphertext_chunk


# =============================================================================
# Mock Transport Framework (Explicitly distinguished from real transport)
# =============================================================================

class MockStorageTransport:
    """
    Mock storage node transport to simulate network conditions, timeouts,
    checksum mismatches, capacity limits, and verify zero source deletion.
    """

    def __init__(self) -> None:
        # endpoint -> {item_id: bytes}
        self.node_storage: Dict[str, Dict[str, bytes]] = {}
        self.download_failures: Set[str] = set()
        self.upload_failures: Set[str] = set()
        self.verify_corruptions: Set[str] = set()
        self.deleted_items: List[Tuple[str, str]] = []
        self.download_counts: Dict[str, int] = {}
        self.upload_counts: Dict[str, int] = {}

    def set_chunk(self, endpoint: str, item_id: str, data: bytes) -> None:
        clean_ep = endpoint.rstrip("/")
        if clean_ep not in self.node_storage:
            self.node_storage[clean_ep] = {}
        self.node_storage[clean_ep][item_id] = data

    def get_chunk(self, endpoint: str, item_id: str) -> Optional[bytes]:
        clean_ep = endpoint.rstrip("/")
        return self.node_storage.get(clean_ep, {}).get(item_id)

    def downloader(self, endpoint: str, item_id: str) -> bytes:
        clean_ep = endpoint.rstrip("/")
        self.download_counts[item_id] = self.download_counts.get(item_id, 0) + 1
        if clean_ep in self.download_failures or item_id in self.download_failures:
            raise ConnectionError(f"Simulated network timeout downloading {item_id} from {clean_ep}")
        storage = self.node_storage.get(clean_ep, {})
        if item_id not in storage:
            raise FileNotFoundError(f"Chunk {item_id} not found on node {clean_ep}")
        return storage[item_id]

    def uploader(
        self,
        endpoint: str,
        filename: str,
        payload: bytes,
        expected_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_ep = endpoint.rstrip("/")
        item_id = filename.replace(".dat", "")
        self.upload_counts[item_id] = self.upload_counts.get(item_id, 0) + 1
        if clean_ep in self.upload_failures or item_id in self.upload_failures:
            raise ConnectionError(f"Simulated upload failure to {clean_ep}")
        if clean_ep not in self.node_storage:
            self.node_storage[clean_ep] = {}
        self.node_storage[clean_ep][item_id] = payload
        return {
            "file_id": item_id,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def verifier(
        self,
        endpoint: str,
        item_id: str,
        expected_sha256: Optional[str] = None,
    ) -> bool:
        clean_ep = endpoint.rstrip("/")
        if clean_ep in self.verify_corruptions or item_id in self.verify_corruptions:
            return False  # Simulate corrupt checksum on destination
        storage = self.node_storage.get(clean_ep, {})
        if item_id not in storage:
            return False
        if expected_sha256:
            actual_sha = hashlib.sha256(storage[item_id]).hexdigest()
            return actual_sha.lower() == expected_sha256.lower()
        return True


# =============================================================================
# Pytest Fixtures
# =============================================================================

@pytest.fixture
def test_settings(tmp_path: Path) -> CoordinatorSettings:
    """Fixture providing isolated temporary database and settings for Phase 8C tests."""
    db_file = tmp_path / "coordinator_phase8c_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="phase8c-admin-token",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture
def mock_transport() -> MockStorageTransport:
    return MockStorageTransport()


@pytest.fixture
def test_client(
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
) -> Generator[TestClient, None, None]:
    """TestClient configured with isolated state and mock transport."""
    app.state.settings = test_settings
    app.state.registry = NodeRegistry(test_settings)
    app.state.metering_service = MeteringService(test_settings)
    app.state.accounting_service = AccountingService(test_settings)
    app.state.session_manager = ProviderSessionManager(test_settings)

    drain_service = NodeDrainService(test_settings)
    worker = NodeDrainMigrationWorker(
        drain_service=drain_service,
        registry=app.state.registry,
        downloader=mock_transport.downloader,
        uploader=mock_transport.uploader,
        verifier=mock_transport.verifier,
    )
    drain_service.worker = worker
    app.state.drain_service = drain_service

    with TestClient(app) as client:
        yield client


# =============================================================================
# 1. Replica Migration Tests
# =============================================================================

def test_successful_replica_migration(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Validates end-to-end verified migration of a replicated chunk:
    - Source node NODE-A drains.
    - Worker selects eligible replacement node NODE-C (distinct from A and B).
    - Chunk is downloaded from NODE-A, uploaded to NODE-C, and verified via SHA-256.
    - Manifest is updated atomically replacing NODE-A with NODE-C.
    - Source chunk on NODE-A remains intact (ZERO source deletion).
    - Drain completes successfully.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_replica"}

    # 1. Register 3 storage nodes
    test_client.post("/nodes/register", json={"node_id": "NODE-A", "host": "10.1.1.1", "port": 8001, "provider_id": "p_replica", "total_capacity_bytes": 100000}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "NODE-B", "host": "10.1.1.2", "port": 8002, "provider_id": "p_replica", "total_capacity_bytes": 100000}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "NODE-C", "host": "10.1.1.3", "port": 8003, "provider_id": "p_replica", "total_capacity_bytes": 100000}, headers=auth_headers)

    # 2. Store chunk payload on NODE-A and NODE-B
    chunk_payload = b"Sample replicated ciphertext payload for Phase 8C verification!"
    chunk_sha = hashlib.sha256(chunk_payload).hexdigest()
    mock_transport.set_chunk("http://10.1.1.1:8001", "chk-rep-101", chunk_payload)
    mock_transport.set_chunk("http://10.1.1.2:8002", "chk-rep-101", chunk_payload)

    # 3. Create active file in catalog (replication_factor=2 across NODE-A and NODE-B)
    manifest = {
        "file_id": "file-rep-1",
        "total_size": len(chunk_payload),
        "chunk_size": len(chunk_payload),
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [
            {
                "chunk_id": "chk-rep-101",
                "sha256": chunk_sha,
                "size": len(chunk_payload),
                "placements": [
                    {"node_id": "NODE-A", "node_endpoint": "http://10.1.1.1:8001", "role": "PRIMARY"},
                    {"node_id": "NODE-B", "node_endpoint": "http://10.1.1.2:8002", "role": "SECONDARY"},
                ],
            }
        ],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', 'replication', 1, ?, ?, ?)
            """,
            ("file-rep-1", "user_rep", "sample_rep.bin", len(chunk_payload), json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # 4. Initiate drain on NODE-A
    res_init = test_client.post("/provider/nodes/NODE-A/drain", json={"reason": "Retiring NODE-A"}, headers=auth_headers)
    assert res_init.status_code == 200
    init_data = res_init.json()
    assert init_data["status"] == "draining"

    # Check migration was registered in SQLite
    res_migs = test_client.get("/provider/nodes/NODE-A/drain/migrations", headers=auth_headers).json()
    assert res_migs["count"] == 1
    assert res_migs["migrations"][0]["chunk_id"] == "chk-rep-101"
    assert res_migs["migrations"][0]["status"] == "pending"

    # 5. Execute worker
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    processed = worker.process_next_batch(max_items=10, node_id="NODE-A")
    assert processed == 1

    # 6. Verify migration status is COMPLETED
    res_migs_after = test_client.get("/provider/nodes/NODE-A/drain/migrations", headers=auth_headers).json()
    mig = res_migs_after["migrations"][0]
    assert mig["status"] == "completed"
    assert mig["destination_node_id"] == "NODE-C"
    assert mig["completed_at"] is not None

    # 7. Verify chunk is present on NODE-C
    dest_chunk = mock_transport.get_chunk("http://10.1.1.3:8003", "chk-rep-101")
    assert dest_chunk == chunk_payload

    # 8. Verify Source Chunk is PRESERVED on NODE-A (ZERO source deletion)
    src_chunk = mock_transport.get_chunk("http://10.1.1.1:8001", "chk-rep-101")
    assert src_chunk == chunk_payload, "Source data must not be deleted during migration!"

    # 9. Verify Authoritative Manifest was atomically updated
    with get_db_connection(test_settings.db_path) as conn:
        f_row = conn.execute("SELECT manifest_json FROM files WHERE file_id = 'file-rep-1'").fetchone()
        updated_manifest = json.loads(f_row["manifest_json"])
        placements = updated_manifest["chunks"][0]["placements"]
        placement_nids = [p["node_id"] for p in placements]
        assert "NODE-A" not in placement_nids
        assert "NODE-C" in placement_nids
        assert "NODE-B" in placement_nids

    # 10. Complete Drain Gate succeeds
    res_comp = test_client.post("/provider/nodes/NODE-A/drain/complete", headers=auth_headers)
    assert res_comp.status_code == 200
    assert res_comp.json()["status"] == "drained"


# =============================================================================
# 2. Erasure-Coded Shard Migration Tests
# =============================================================================

def test_successful_erasure_coded_shard_migration(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Validates safe migration of an erasure-coded shard:
    - 4+2 EC scheme distributed across 6 nodes.
    - Node NODE-EC-1 drains.
    - Worker selects eligible 7th replacement node NODE-EC-7 (not holding any shard).
    - Shard is transferred, verified, and committed.
    - Redundancy is preserved; drain completes.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_ec"}

    # 1. Register 7 nodes
    for i in range(1, 8):
        nid = f"NODE-EC-{i}"
        test_client.post(
            "/nodes/register",
            json={"node_id": nid, "host": f"10.2.1.{i}", "port": 8100 + i, "provider_id": "p_ec", "total_capacity_bytes": 100000},
            headers=auth_headers,
        )

    # 2. Encode ciphertext chunk into 4 data + 2 parity shards
    raw_chunk = b"Important ciphertext chunk payload requiring Reed-Solomon protection!"
    shards, orig_size, enc_size, pad_len = encode_ciphertext_chunk(raw_chunk, data_shards=4, parity_shards=2)
    assert len(shards) == 6

    # Place shards 0..5 onto nodes NODE-EC-1..NODE-EC-6
    shards_manifest = []
    for idx, s in enumerate(shards):
        ep = f"http://10.2.1.{idx+1}:{8100+idx+1}"
        mock_transport.set_chunk(ep, s.shard_id, s.payload)
        shards_manifest.append({
            "shard_index": s.shard_index,
            "shard_id": s.shard_id,
            "shard_type": s.shard_type,
            "shard_sha256": s.sha256,
            "shard_size": len(s.payload),
            "node_id": f"NODE-EC-{idx+1}",
            "node_endpoint": ep,
        })

    manifest = {
        "file_id": "file-ec-1",
        "total_size": len(raw_chunk),
        "chunk_size": len(raw_chunk),
        "redundancy_mode": "erasure",
        "data_shards": 4,
        "parity_shards": 2,
        "chunks": [
            {
                "chunk_id": "chk-ec-101",
                "size": len(raw_chunk),
                "data_shard_count": 4,
                "parity_shard_count": 2,
                "padding_length": pad_len,
                "original_ciphertext_size": orig_size,
                "shards": shards_manifest,
            }
        ],
    }

    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', 'erasure', 1, ?, ?, ?)
            """,
            ("file-ec-1", "user_ec", "sample_ec.bin", len(raw_chunk), json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # 3. Initiate drain on NODE-EC-1 (holding shard 0)
    res_init = test_client.post("/provider/nodes/NODE-EC-1/drain", json={"reason": "Draining EC node 1"}, headers=auth_headers)
    assert res_init.status_code == 200

    # 4. Run worker
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    processed = worker.process_next_batch(max_items=10, node_id="NODE-EC-1")
    assert processed == 1

    # 5. Check migration record
    migs = test_client.get("/provider/nodes/NODE-EC-1/drain/migrations", headers=auth_headers).json()["migrations"]
    assert len(migs) == 1
    assert migs[0]["status"] == "completed"
    assert migs[0]["destination_node_id"] == "NODE-EC-7"
    assert migs[0]["shard_index"] == 0

    # 6. Verify shard payload on NODE-EC-7
    target_shard = shards[0]
    dest_shard_bytes = mock_transport.get_chunk("http://10.2.1.7:8107", target_shard.shard_id)
    assert dest_shard_bytes == target_shard.payload

    # 7. Verify source shard on NODE-EC-1 preserved
    src_shard_bytes = mock_transport.get_chunk("http://10.2.1.1:8101", target_shard.shard_id)
    assert src_shard_bytes == target_shard.payload

    # 8. Complete drain succeeds
    res_comp = test_client.post("/provider/nodes/NODE-EC-1/drain/complete", headers=auth_headers)
    assert res_comp.status_code == 200
    assert res_comp.json()["status"] == "drained"


# =============================================================================
# 3. Checksum Mismatch Detection and Rejection
# =============================================================================

def test_destination_checksum_mismatch_detected_and_rejected(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    If destination stored content fails SHA-256 integrity verification:
    - Worker rejects destination copy.
    - Manifest is NOT updated.
    - Migration transitions to retryable_failure (or blocked after retries).
    - Drain cannot be completed.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_check"}

    test_client.post("/nodes/register", json={"node_id": "CHK-A", "host": "10.3.1.1", "port": 8201, "provider_id": "p_check"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "CHK-B", "host": "10.3.1.2", "port": 8202, "provider_id": "p_check"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "CHK-C", "host": "10.3.1.3", "port": 8203, "provider_id": "p_check"}, headers=auth_headers)

    payload = b"Valid chunk content to migrate"
    sha = hashlib.sha256(payload).hexdigest()
    mock_transport.set_chunk("http://10.3.1.1:8201", "chk-mismatch-1", payload)

    manifest = {
        "file_id": "file-mismatch-1",
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [{"chunk_id": "chk-mismatch-1", "sha256": sha, "size": len(payload), "placements": [{"node_id": "CHK-A", "node_endpoint": "http://10.3.1.1:8201"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'm.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-mismatch-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # Simulate corrupt verifier on destination CHK-C or CHK-B
    mock_transport.verify_corruptions.add("http://10.3.1.2:8202")
    mock_transport.verify_corruptions.add("http://10.3.1.3:8203")

    test_client.post("/provider/nodes/CHK-A/drain", headers=auth_headers)

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=10, node_id="CHK-A")

    # Migration should fail verification
    migs = test_client.get("/provider/nodes/CHK-A/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] in (MigrationStatus.RETRYABLE_FAILURE, MigrationStatus.BLOCKED)
    assert "verification" in migs[0]["last_error"].lower()

    # Manifest must NOT have been updated with destination
    with get_db_connection(test_settings.db_path) as conn:
        f_row = conn.execute("SELECT manifest_json FROM files WHERE file_id = 'file-mismatch-1'").fetchone()
        m_curr = json.loads(f_row["manifest_json"])
        assert m_curr["chunks"][0]["placements"][0]["node_id"] == "CHK-A"

    # Complete drain must fail with 409 Conflict
    res_comp = test_client.post("/provider/nodes/CHK-A/drain/complete", headers=auth_headers)
    assert res_comp.status_code == 409


# =============================================================================
# 4. Interrupted Transfer & Network Timeout Recovery
# =============================================================================

def test_interrupted_transfer_and_network_timeout_retryable(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Simulates transient network timeout during transfer:
    - First attempt fails with network error -> transitions to retryable_failure.
    - Network recovers -> subsequent execution succeeds.
    - Manifest is updated and job completes.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_net"}

    test_client.post("/nodes/register", json={"node_id": "NET-A", "host": "10.4.1.1", "port": 8301, "provider_id": "p_net"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "NET-B", "host": "10.4.1.2", "port": 8302, "provider_id": "p_net"}, headers=auth_headers)

    payload = b"Network timeout test payload"
    mock_transport.set_chunk("http://10.4.1.1:8301", "chk-net-1", payload)

    manifest = {
        "file_id": "file-net-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-net-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "NET-A", "node_endpoint": "http://10.4.1.1:8301"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'net.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-net-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/NET-A/drain", headers=auth_headers)

    # 1. Simulate network failure on upload
    mock_transport.upload_failures.add("http://10.4.1.2:8302")
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="NET-A")

    migs = test_client.get("/provider/nodes/NET-A/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] == MigrationStatus.RETRYABLE_FAILURE
    assert migs[0]["retry_count"] == 1

    # 2. Network recovers
    mock_transport.upload_failures.clear()
    worker.process_next_batch(max_items=1, node_id="NET-A")

    migs_rec = test_client.get("/provider/nodes/NET-A/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs_rec[0]["status"] == MigrationStatus.COMPLETED
    assert migs_rec[0]["destination_node_id"] == "NET-B"


# =============================================================================
# 5. Destination Capacity Exhaustion
# =============================================================================

def test_destination_capacity_exhaustion_blocks_drain(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    If available destination nodes lack sufficient quota for the chunk:
    - Migration marks BLOCKED with actionable capacity reason.
    - Parent drain transitions to drain_blocked.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_cap"}

    # Source node has data, destination has only 50 bytes available
    test_client.post("/nodes/register", json={"node_id": "CAP-SRC", "host": "10.5.1.1", "port": 8401, "provider_id": "p_cap", "total_capacity_bytes": 10000}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "CAP-DEST", "host": "10.5.1.2", "port": 8402, "provider_id": "p_cap", "total_capacity_bytes": 100, "used_capacity_bytes": 60, "available_capacity_bytes": 40}, headers=auth_headers)

    payload = b"Large payload that exceeds the destination available capacity of 40 bytes!"
    assert len(payload) > 40
    mock_transport.set_chunk("http://10.5.1.1:8401", "chk-cap-1", payload)

    manifest = {
        "file_id": "file-cap-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-cap-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "CAP-SRC", "node_endpoint": "http://10.5.1.1:8401"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'c.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-cap-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/CAP-SRC/drain", headers=auth_headers)

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="CAP-SRC")

    migs = test_client.get("/provider/nodes/CAP-SRC/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] == MigrationStatus.BLOCKED
    assert "sufficient quota" in migs[0]["last_error"].lower()

    # Drain job is blocked
    drain_status = test_client.get("/provider/nodes/CAP-SRC/drain", headers=auth_headers).json()
    assert drain_status["status"] == "drain_blocked"


# =============================================================================
# 6. Source Node Offline During Migration
# =============================================================================

def test_source_becoming_offline_during_migration_preserves_drain_state(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    If source node goes offline due to missed heartbeats during drain:
    - Lifecycle state preserves drain_status ('draining' or 'drain_blocked').
    - Status is NOT marked drained.
    - If another replica exists on surviving node, migration can still succeed.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_off"}

    test_client.post("/nodes/register", json={"node_id": "OFF-SRC", "host": "10.6.1.1", "port": 8501, "provider_id": "p_off"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "OFF-REP", "host": "10.6.1.2", "port": 8502, "provider_id": "p_off"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "OFF-DEST", "host": "10.6.1.3", "port": 8503, "provider_id": "p_off"}, headers=auth_headers)

    payload = b"Surviving replica chunk bytes"
    # OFF-SRC has chunk, OFF-REP also has chunk
    mock_transport.set_chunk("http://10.6.1.1:8501", "chk-off-1", payload)
    mock_transport.set_chunk("http://10.6.1.2:8502", "chk-off-1", payload)

    manifest = {
        "file_id": "file-off-1",
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [{"chunk_id": "chk-off-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [
            {"node_id": "OFF-SRC", "node_endpoint": "http://10.6.1.1:8501"},
            {"node_id": "OFF-REP", "node_endpoint": "http://10.6.1.2:8502"},
        ]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'off.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-off-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/OFF-SRC/drain", headers=auth_headers)

    # Simulate OFF-SRC becomes offline (missed heartbeats and download fails)
    mock_transport.download_failures.add("http://10.6.1.1:8501")
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute("UPDATE nodes SET last_seen = '2020-01-01T00:00:00Z' WHERE node_id = 'OFF-SRC'")
        conn.commit()

    # Verify node status is now evaluated as offline
    node_det = test_client.get("/provider/nodes/OFF-SRC/detail", headers=auth_headers).json()
    assert node_det["status"] == "offline"
    assert node_det["drain_status"] in ("draining", "drain_blocked")

    # Worker can still fetch from surviving replica OFF-REP and migrate to OFF-DEST
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="OFF-SRC")

    migs = test_client.get("/provider/nodes/OFF-SRC/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] == MigrationStatus.COMPLETED
    assert migs[0]["destination_node_id"] == "OFF-DEST"


# =============================================================================
# 7. Coordinator Restart Recovery
# =============================================================================

def test_coordinator_restart_recovers_in_flight_migrations(
    test_settings: CoordinatorSettings,
):
    """
    If the Coordinator crashes while migrations are 'transferring' or 'verifying':
    - On restart, recover_in_flight_migrations() resets them to 'pending'.
    - No migration is lost or left in orphaned in-flight state.
    """
    init_db(test_settings.db_path)
    now_str = datetime.now(timezone.utc).isoformat()

    # Insert simulated interrupted migrations
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO node_drain_migrations (
                migration_id, drain_id, file_id, chunk_id, source_node_id, status, retry_count, max_retries, payload_bytes, created_at, updated_at
            ) VALUES
            ('mig-interrupted-1', 'drain-1', 'f1', 'c1', 'n1', 'transferring', 0, 3, 100, ?, ?),
            ('mig-interrupted-2', 'drain-1', 'f2', 'c2', 'n1', 'verifying', 1, 3, 200, ?, ?),
            ('mig-completed-3', 'drain-1', 'f3', 'c3', 'n1', 'completed', 0, 3, 300, ?, ?)
            """,
            (now_str, now_str, now_str, now_str, now_str, now_str),
        )
        conn.commit()

    # Simulate Coordinator restart: new service instance
    drain_service = NodeDrainService(test_settings)
    recovered = drain_service.recover_in_flight_migrations()
    assert recovered == 2

    # Verify statuses in SQLite
    with get_db_connection(test_settings.db_path) as conn:
        m1 = conn.execute("SELECT status FROM node_drain_migrations WHERE migration_id = 'mig-interrupted-1'").fetchone()
        m2 = conn.execute("SELECT status FROM node_drain_migrations WHERE migration_id = 'mig-interrupted-2'").fetchone()
        m3 = conn.execute("SELECT status FROM node_drain_migrations WHERE migration_id = 'mig-completed-3'").fetchone()

        assert m1["status"] == "pending"
        assert m2["status"] == "pending"
        assert m3["status"] == "completed"


# =============================================================================
# 8. Repeated Jobs and Idempotency
# =============================================================================

def test_repeated_jobs_and_retries_idempotent(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Repeated drain and worker calls are idempotent:
    - Never duplicate migration jobs in SQLite.
    - Never corrupt manifest placements with duplicate entries.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_idem"}

    test_client.post("/nodes/register", json={"node_id": "IDEM-A", "host": "10.7.1.1", "port": 8601, "provider_id": "p_idem"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "IDEM-B", "host": "10.7.1.2", "port": 8602, "provider_id": "p_idem"}, headers=auth_headers)

    payload = b"Idempotent migration chunk"
    mock_transport.set_chunk("http://10.7.1.1:8601", "chk-idem-1", payload)

    manifest = {
        "file_id": "file-idem-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-idem-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "IDEM-A", "node_endpoint": "http://10.7.1.1:8601"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'i.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-idem-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # 1. First drain call
    test_client.post("/provider/nodes/IDEM-A/drain", headers=auth_headers)
    migs1 = test_client.get("/provider/nodes/IDEM-A/drain/migrations", headers=auth_headers).json()["migrations"]
    assert len(migs1) == 1

    # 2. Second drain call does not create duplicate migration records
    test_client.post("/provider/nodes/IDEM-A/drain", headers=auth_headers)
    migs2 = test_client.get("/provider/nodes/IDEM-A/drain/migrations", headers=auth_headers).json()["migrations"]
    assert len(migs2) == 1
    assert migs1[0]["migration_id"] == migs2[0]["migration_id"]

    # 3. Process migration
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="IDEM-A")

    # 4. Running worker again on already completed migration does nothing
    proc2 = worker.process_next_batch(max_items=1, node_id="IDEM-A")
    assert proc2 == 0

    # 5. Check manifest has exactly one placement
    with get_db_connection(test_settings.db_path) as conn:
        f_row = conn.execute("SELECT manifest_json FROM files WHERE file_id = 'file-idem-1'").fetchone()
        placements = json.loads(f_row["manifest_json"])["chunks"][0]["placements"]
        assert len(placements) == 1
        assert placements[0]["node_id"] == "IDEM-B"


# =============================================================================
# 9. Concurrent Worker Synchronization
# =============================================================================

def test_concurrent_workers_prevent_duplicate_execution(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Multiple concurrent worker threads attempting to process the same migration
    are synchronized via in-memory locks: exactly one thread executes the transfer.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_conc"}

    test_client.post("/nodes/register", json={"node_id": "CONC-A", "host": "10.8.1.1", "port": 8701, "provider_id": "p_conc"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "CONC-B", "host": "10.8.1.2", "port": 8702, "provider_id": "p_conc"}, headers=auth_headers)

    payload = b"Concurrent worker payload"
    mock_transport.set_chunk("http://10.8.1.1:8701", "chk-conc-1", payload)

    manifest = {
        "file_id": "file-conc-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-conc-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "CONC-A", "node_endpoint": "http://10.8.1.1:8701"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'conc.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-conc-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/CONC-A/drain", headers=auth_headers)
    migs = test_client.get("/provider/nodes/CONC-A/drain/migrations", headers=auth_headers).json()["migrations"]
    mig_id = migs[0]["migration_id"]

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    results = []

    def run_worker():
        res = worker.process_migration(mig_id)
        results.append(res)

    threads = [threading.Thread(target=run_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Upload should have been executed exactly once
    assert mock_transport.upload_counts.get("chk-conc-1", 0) == 1
    # Check status is completed
    mig_final = test_client.get("/provider/nodes/CONC-A/drain/migrations", headers=auth_headers).json()["migrations"][0]
    assert mig_final["status"] == "completed"


# =============================================================================
# 10. Placement Constraints Enforced (Distinct-Node Distribution)
# =============================================================================

def test_replica_and_shard_placement_constraints_enforced(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Validates that destination selection strictly excludes nodes that already hold
    a placement for the chunk or any shard of the chunk.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_rule"}

    # Register 4 nodes
    for i in range(1, 5):
        test_client.post(
            "/nodes/register",
            json={"node_id": f"RULE-{i}", "host": f"10.9.1.{i}", "port": 8800 + i, "provider_id": "p_rule"},
            headers=auth_headers,
        )

    drain_service: NodeDrainService = app.state.drain_service
    registry: NodeRegistry = app.state.registry

    # 1. Replication: Chunk is on RULE-1 and RULE-2. Source is RULE-1.
    # Candidates must exclude RULE-1 (source) and RULE-2 (already holds chunk).
    dest = drain_service.select_destination_node(
        mode="replication",
        required_bytes=100,
        existing_node_ids={"RULE-1", "RULE-2"},
        source_node_id="RULE-1",
        registry=registry,
    )
    assert dest is not None
    assert dest.node_id in ("RULE-3", "RULE-4")

    # 2. Erasure coding: Shards exist on RULE-1, RULE-2, RULE-3. Source is RULE-1.
    # Destination must be RULE-4 only!
    dest_ec = drain_service.select_destination_node(
        mode="erasure",
        required_bytes=100,
        existing_node_ids={"RULE-1", "RULE-2", "RULE-3"},
        source_node_id="RULE-1",
        registry=registry,
    )
    assert dest_ec is not None
    assert dest_ec.node_id == "RULE-4"


# =============================================================================
# 11. Failure When No Eligible Destination Exists
# =============================================================================

def test_failure_to_migrate_when_no_eligible_destination_exists(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    When no eligible destination node exists:
    - Worker marks migration as BLOCKED.
    - Parent drain job is marked DRAIN_BLOCKED with actionable diagnostic.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_nodest"}

    # Only 1 node in cluster
    test_client.post("/nodes/register", json={"node_id": "SOLO-1", "host": "10.10.1.1", "port": 8901, "provider_id": "p_nodest"}, headers=auth_headers)

    payload = b"Solo node chunk payload"
    mock_transport.set_chunk("http://10.10.1.1:8901", "chk-solo-1", payload)

    manifest = {
        "file_id": "file-solo-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-solo-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "SOLO-1", "node_endpoint": "http://10.10.1.1:8901"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'solo.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-solo-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/SOLO-1/drain", headers=auth_headers)

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="SOLO-1")

    migs = test_client.get("/provider/nodes/SOLO-1/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] == MigrationStatus.BLOCKED
    assert "no eligible online destination" in migs[0]["last_error"].lower()


# =============================================================================
# 12. Redundancy Verification Safety Gate Before Drain Completion
# =============================================================================

def test_redundancy_verification_safety_gate_before_completion(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    The safety gate /provider/nodes/{node_id}/drain/complete returns 409 Conflict
    whenever any required migration is unverified or blocked.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_gate"}

    test_client.post("/nodes/register", json={"node_id": "GATE-1", "host": "10.11.1.1", "port": 8911, "provider_id": "p_gate"}, headers=auth_headers)
    payload = b"Gate test payload"
    mock_transport.set_chunk("http://10.11.1.1:8911", "chk-gate-1", payload)

    manifest = {
        "file_id": "file-gate-1",
        "redundancy_mode": "replication",
        "replication_factor": 2,
        "chunks": [{"chunk_id": "chk-gate-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "GATE-1", "node_endpoint": "http://10.11.1.1:8911"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'g.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-gate-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/GATE-1/drain", headers=auth_headers)

    # Calling complete drain before migration succeeds -> 409 Conflict
    res_comp = test_client.post("/provider/nodes/GATE-1/drain/complete", headers=auth_headers)
    assert res_comp.status_code == 409
    assert "Cannot mark node 'GATE-1' as safely removable" in res_comp.json()["detail"]


# =============================================================================
# 13. Source Data Preserved After Successful & Failed Migrations
# =============================================================================

def test_source_data_preserved_after_migration(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Source chunks and shards must NEVER be deleted during Phase 8C.
    Verifies that source storage remains identical before and after migration.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_preserve"}

    test_client.post("/nodes/register", json={"node_id": "PRES-A", "host": "10.12.1.1", "port": 8921, "provider_id": "p_preserve"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "PRES-B", "host": "10.12.1.2", "port": 8922, "provider_id": "p_preserve"}, headers=auth_headers)

    chunk_data = b"Precious user data that must never be deleted from source!"
    mock_transport.set_chunk("http://10.12.1.1:8921", "chk-pres-1", chunk_data)

    manifest = {
        "file_id": "file-pres-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-pres-1", "sha256": hashlib.sha256(chunk_data).hexdigest(), "size": len(chunk_data), "placements": [{"node_id": "PRES-A", "node_endpoint": "http://10.12.1.1:8921"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'p.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-pres-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/PRES-A/drain", headers=auth_headers)

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="PRES-A")

    # Destination has data
    assert mock_transport.get_chunk("http://10.12.1.2:8922", "chk-pres-1") == chunk_data
    # Source STILL has data intact!
    assert mock_transport.get_chunk("http://10.12.1.1:8921", "chk-pres-1") == chunk_data


# =============================================================================
# 14. Provider Isolation and Authorization on Migration APIs
# =============================================================================

def test_provider_isolation_and_authorization_on_drain_operations(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
):
    """
    Enforces Phase 8B provider isolation:
    - Provider A cannot inspect or retry migrations on Provider B's node (403 Forbidden).
    - Unauthenticated callers are rejected with 401 Unauthorized.
    """
    token = test_settings.auth_token

    # Node owned by provider 'alice'
    test_client.post("/nodes/register", json={"node_id": "ISO-ALICE-1", "host": "10.13.1.1", "port": 8931, "provider_id": "alice"}, headers={"X-Auth-Token": token, "X-Provider-Id": "alice"})
    test_client.post("/provider/nodes/ISO-ALICE-1/drain", headers={"X-Auth-Token": "provider:alice", "X-Provider-Id": "alice"})

    # 1. Unauthenticated request rejected
    res_noauth = test_client.get("/provider/nodes/ISO-ALICE-1/drain/migrations")
    assert res_noauth.status_code == 401

    # 2. Provider Bob attempts to inspect Alice's migrations -> 403 Forbidden
    res_bob = test_client.get("/provider/nodes/ISO-ALICE-1/drain/migrations", headers={"X-Auth-Token": "provider:bob", "X-Provider-Id": "bob"})
    assert res_bob.status_code == 403

    # 3. Provider Bob attempts to retry Alice's drain -> 403 Forbidden
    res_bob_retry = test_client.post("/provider/nodes/ISO-ALICE-1/drain/retry", headers={"X-Auth-Token": "provider:bob", "X-Provider-Id": "bob"})
    assert res_bob_retry.status_code == 403

    # 4. Alice requests her own migrations -> 200 OK
    res_alice = test_client.get("/provider/nodes/ISO-ALICE-1/drain/migrations", headers={"X-Auth-Token": "provider:alice", "X-Provider-Id": "alice"})
    assert res_alice.status_code == 200


# =============================================================================
# 15. Accurate Dashboard and API Progress Reporting
# =============================================================================

def test_accurate_dashboard_and_api_progress_reporting(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Verifies that /provider/nodes/{node_id}/drain and /provider/drain/worker/status
    report strictly accurate, truthful progress counts.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_metric"}

    test_client.post("/nodes/register", json={"node_id": "METRIC-A", "host": "10.14.1.1", "port": 8941, "provider_id": "p_metric"}, headers=auth_headers)
    test_client.post("/nodes/register", json={"node_id": "METRIC-B", "host": "10.14.1.2", "port": 8942, "provider_id": "p_metric"}, headers=auth_headers)

    payload = b"Metrics testing payload"
    mock_transport.set_chunk("http://10.14.1.1:8941", "chk-met-1", payload)

    manifest = {
        "file_id": "file-met-1",
        "redundancy_mode": "replication",
        "replication_factor": 1,
        "chunks": [{"chunk_id": "chk-met-1", "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload), "placements": [{"node_id": "METRIC-A", "node_endpoint": "http://10.14.1.1:8941"}]}],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'met.bin', 10, 'active', 'replication', 1, ?, ?, ?)",
            ("file-met-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    test_client.post("/provider/nodes/METRIC-A/drain", headers=auth_headers)

    # 1. Before worker execution: 1 pending, 0 completed
    status_before = test_client.get("/provider/drain/worker/status", headers=auth_headers).json()
    assert status_before["pending_migrations"] >= 1
    assert status_before["completed_migrations"] == 0

    drain_before = test_client.get("/provider/nodes/METRIC-A/drain", headers=auth_headers).json()
    assert drain_before["total_chunks"] == 1
    assert drain_before["migrated_chunks"] == 0
    assert drain_before["remaining_chunks"] == 1

    # 2. After worker execution: 0 pending, 1 completed
    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="METRIC-A")

    status_after = test_client.get("/provider/drain/worker/status", headers=auth_headers).json()
    assert status_after["completed_migrations"] >= 1

    drain_after = test_client.get("/provider/nodes/METRIC-A/drain", headers=auth_headers).json()
    assert drain_after["total_chunks"] == 1
    assert drain_after["migrated_chunks"] == 1
    assert drain_after["remaining_chunks"] == 0


# =============================================================================
# 16. RS Erasure Reconstruction From Surviving Shards
# =============================================================================

def test_erasure_shard_migration_reconstruction_from_surviving_shards(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    If the source shard on the draining node is corrupted or completely unreadable,
    the worker reconstructs the required shard from the surviving k shards across
    the other online cluster nodes and migrates the reconstructed shard to destination.
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_recon"}

    # 7 nodes
    for i in range(1, 8):
        test_client.post(
            "/nodes/register",
            json={"node_id": f"RECON-{i}", "host": f"10.15.1.{i}", "port": 8950 + i, "provider_id": "p_recon"},
            headers=auth_headers,
        )

    raw_data = b"Highly confidential ciphertext chunk for reconstruction test!"
    shards, orig_size, enc_size, pad_len = encode_ciphertext_chunk(raw_data, data_shards=4, parity_shards=2)

    shards_meta = []
    for idx, s in enumerate(shards):
        ep = f"http://10.15.1.{idx+1}:{8950+idx+1}"
        shards_meta.append({
            "shard_index": s.shard_index,
            "shard_id": s.shard_id,
            "shard_sha256": s.sha256,
            "shard_size": len(s.payload),
            "node_id": f"RECON-{idx+1}",
            "node_endpoint": ep,
        })
        if idx == 0:
            # CORRUPT the shard on RECON-1 (the draining node)
            mock_transport.set_chunk(ep, s.shard_id, b"Corrupt payload bytes!!")
        else:
            # Valid shards on RECON-2..RECON-6
            mock_transport.set_chunk(ep, s.shard_id, s.payload)

    manifest = {
        "file_id": "file-recon-1",
        "redundancy_mode": "erasure",
        "data_shards": 4,
        "parity_shards": 2,
        "chunks": [{
            "chunk_id": "chk-recon-1",
            "size": len(raw_data),
            "data_shard_count": 4,
            "parity_shard_count": 2,
            "padding_length": pad_len,
            "original_ciphertext_size": orig_size,
            "shards": shards_meta,
        }],
    }
    with get_db_connection(test_settings.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, manifest_json, created_at, updated_at) VALUES (?, 'u', 'r.bin', 10, 'active', 'erasure', 1, ?, ?, ?)",
            ("file-recon-1", json.dumps(manifest), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # Initiate drain on RECON-1
    test_client.post("/provider/nodes/RECON-1/drain", headers=auth_headers)

    worker: NodeDrainMigrationWorker = app.state.drain_service.worker
    worker.process_next_batch(max_items=1, node_id="RECON-1")

    # Migration should SUCCEED via reconstruction from surviving shards
    migs = test_client.get("/provider/nodes/RECON-1/drain/migrations", headers=auth_headers).json()["migrations"]
    assert migs[0]["status"] == MigrationStatus.COMPLETED
    assert migs[0]["destination_node_id"] == "RECON-7"

    # Destination RECON-7 now holds the perfectly reconstructed shard 0!
    reconstructed_bytes = mock_transport.get_chunk("http://10.15.1.7:8957", shards[0].shard_id)
    assert reconstructed_bytes == shards[0].payload


# =============================================================================
# 17. Coordinator Client SDK Methods Test
# =============================================================================

def test_coordinator_client_sdk_drain_migrations_and_worker_status(
    test_client: TestClient,
    test_settings: CoordinatorSettings,
    mock_transport: MockStorageTransport,
):
    """
    Validates CoordinatorClient SDK methods list_drain_migrations() and
    get_drain_worker_status().
    """
    token = test_settings.auth_token
    auth_headers = {"X-Auth-Token": token, "X-Provider-Id": "p_sdk"}

    test_client.post("/nodes/register", json={"node_id": "SDK-A", "host": "10.16.1.1", "port": 8961, "provider_id": "p_sdk"}, headers=auth_headers)
    test_client.post("/provider/nodes/SDK-A/drain", headers=auth_headers)

    coord_client = CoordinatorClient(
        coordinator_url="http://testserver",
        auth_token=token,
    )
    def fake_request(method: str, path: str, **kwargs):
        headers = coord_client._get_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
        return test_client.request(method, path, headers=headers, **kwargs)

    coord_client._request = fake_request

    # 1. Test get_drain_worker_status via SDK
    worker_status = coord_client.get_drain_worker_status()
    assert "pending_migrations" in worker_status
    assert "completed_migrations" in worker_status

    # 2. Test list_drain_migrations via SDK
    migs = coord_client.list_drain_migrations("SDK-A", provider_id="p_sdk")
    assert isinstance(migs, list)
