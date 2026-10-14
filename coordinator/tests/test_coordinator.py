"""
Automated unit & integration test suite for Expo Coordinator Service (Phase 2A).
Validates health, node registration, duplicate registration idempotency, node discovery,
individual node queries, heartbeats, capacity tracking & validation, last_seen updates,
offline detection, node returning online, invalid node IDs, authentication,
coordinator unavailable behavior, and independent storage node operation.
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app, get_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.coordinator_integration import CoordinatorNotifier


@pytest.fixture
def tmp_coordinator_db(tmp_path):
    """Provides a temporary SQLite database path for Coordinator tests."""
    db_file = tmp_path / "coordinator_test.db"
    return db_file


@pytest.fixture
def test_coordinator_settings(tmp_coordinator_db):
    """Provides test settings for Coordinator."""
    return CoordinatorSettings(
        db_path=tmp_coordinator_db,
        host="127.0.0.1",
        port=9000,
        auth_token=None,
        heartbeat_timeout_seconds=2,  # Short timeout for fast offline testing
    )


@pytest.fixture
def client(test_coordinator_settings):
    """Provides FastAPI TestClient with overridden Coordinator settings."""
    app.state.settings = test_coordinator_settings
    app.state.registry = NodeRegistry(test_coordinator_settings)
    
    def override_get_settings():
        return test_coordinator_settings

    app.dependency_overrides[get_settings] = override_get_settings
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# 1. Coordinator Health Test
def test_1_coordinator_health(client):
    """Verify GET /health returns 200 OK and status 'online'."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"


# 2. Node Registration Test
def test_2_node_registration(client):
    """Verify POST /nodes/register registers a new Storage Node."""
    payload = {
        "node_id": "NODE-test-node-001",
        "host": "192.168.1.50",
        "port": 8000,
        "total_capacity_bytes": 10737418240,
        "used_capacity_bytes": 1073741824,
        "available_capacity_bytes": 9663676416,
    }
    res = client.post("/nodes/register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["node_id"] == "NODE-test-node-001"
    assert data["host"] == "192.168.1.50"
    assert data["port"] == 8000
    assert data["status"] == "online"
    assert data["total_capacity_bytes"] == 10737418240
    assert data["used_capacity_bytes"] == 1073741824
    assert data["available_capacity_bytes"] == 9663676416
    assert "last_seen" in data
    assert "registered_at" in data


# 3. Duplicate Registration Test (Idempotency)
def test_3_duplicate_registration(client):
    """Verify registering the same node_id twice updates record without duplicate entries."""
    payload1 = {
        "node_id": "NODE-idempotent-001",
        "host": "10.0.0.1",
        "port": 8001,
        "total_capacity_bytes": 5000000,
        "used_capacity_bytes": 1000000,
    }
    res1 = client.post("/nodes/register", json=payload1)
    assert res1.status_code == 200
    reg_time_1 = res1.json()["registered_at"]

    # Re-register same node with updated port & used capacity
    payload2 = {
        "node_id": "NODE-idempotent-001",
        "host": "10.0.0.1",
        "port": 8002,
        "total_capacity_bytes": 5000000,
        "used_capacity_bytes": 2000000,
    }
    res2 = client.post("/nodes/register", json=payload2)
    assert res2.status_code == 200
    data2 = res2.json()

    assert data2["node_id"] == "NODE-idempotent-001"
    assert data2["port"] == 8002
    assert data2["used_capacity_bytes"] == 2000000
    assert data2["available_capacity_bytes"] == 3000000
    assert data2["registered_at"] == reg_time_1  # Initial registration timestamp preserved

    # Verify single node in listing
    res_list = client.get("/nodes")
    assert res_list.status_code == 200
    nodes = res_list.json()["nodes"]
    idempotent_nodes = [n for n in nodes if n["node_id"] == "NODE-idempotent-001"]
    assert len(idempotent_nodes) == 1


# 4. Node Discovery Test
def test_4_node_discovery(client):
    """Verify GET /nodes lists all registered Storage Nodes and supports status filtering."""
    client.post("/nodes/register", json={"node_id": "NODE-disc-A", "host": "1.1.1.1", "port": 8001})
    client.post("/nodes/register", json={"node_id": "NODE-disc-B", "host": "1.1.1.2", "port": 8002})

    res = client.get("/nodes")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 2

    # Filter by status=online
    res_online = client.get("/nodes?status=online")
    assert res_online.status_code == 200
    online_nodes = res_online.json()["nodes"]
    for n in online_nodes:
        assert n["status"] == "online"


# 5. Get Individual Node Test
def test_5_get_individual_node(client):
    """Verify GET /nodes/{node_id} returns node info or 404 if not found."""
    client.post("/nodes/register", json={"node_id": "NODE-single-1", "host": "127.0.0.1", "port": 8080})

    res = client.get("/nodes/NODE-single-1")
    assert res.status_code == 200
    assert res.json()["node_id"] == "NODE-single-1"

    # Non-existent node
    res_404 = client.get("/nodes/NODE-NONEXISTENT")
    assert res_404.status_code == 404


# 6. Heartbeat Test
def test_6_heartbeat(client):
    """Verify POST /nodes/{node_id}/heartbeat updates node liveness."""
    client.post("/nodes/register", json={"node_id": "NODE-hb-1", "host": "127.0.0.1", "port": 8080})

    hb_payload = {"status": "online"}
    res = client.post("/nodes/NODE-hb-1/heartbeat", json=hb_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["node_id"] == "NODE-hb-1"
    assert data["status"] == "online"


# 7. Capacity Update & Validation Test
def test_7_capacity_update_and_validation(client):
    """Verify heartbeat updates capacity stats and enforces non-negative capacity rules."""
    client.post(
        "/nodes/register",
        json={
            "node_id": "NODE-cap-1",
            "host": "127.0.0.1",
            "port": 8080,
            "total_capacity_bytes": 10000,
            "used_capacity_bytes": 1000,
        },
    )

    # Update capacity via heartbeat
    hb_payload = {
        "used_capacity_bytes": 4000,
    }
    res = client.post("/nodes/NODE-cap-1/heartbeat", json=hb_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["used_capacity_bytes"] == 4000
    assert data["available_capacity_bytes"] == 6000

    # Test invalid capacity (used > total)
    invalid_hb = {"used_capacity_bytes": 15000}
    res_err = client.post("/nodes/NODE-cap-1/heartbeat", json=invalid_hb)
    assert res_err.status_code == 400

    # Test invalid registration (negative capacity)
    invalid_reg = {
        "node_id": "NODE-neg-cap",
        "host": "127.0.0.1",
        "port": 8080,
        "total_capacity_bytes": -100,
    }
    res_reg_err = client.post("/nodes/register", json=invalid_reg)
    assert res_reg_err.status_code == 400


# 8. Last-seen Update Test
def test_8_last_seen_update(client):
    """Verify heartbeat updates last_seen timestamp."""
    reg_res = client.post("/nodes/register", json={"node_id": "NODE-time-1", "host": "127.0.0.1", "port": 8080})
    first_last_seen = reg_res.json()["last_seen"]

    time.sleep(0.01)

    hb_res = client.post("/nodes/NODE-time-1/heartbeat", json={"status": "online"})
    second_last_seen = hb_res.json()["last_seen"]

    assert second_last_seen >= first_last_seen


# 9. Offline Detection Test
def test_9_offline_detection(test_coordinator_settings):
    """Verify Coordinator detects nodes that miss heartbeats and marks them offline."""
    registry = NodeRegistry(test_coordinator_settings)
    
    # Register node with last_seen set 10 seconds in the past (timeout is 2s)
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    
    # Directly set or register and update
    node_rec = registry.register_node(
        {
            "node_id": "NODE-offline-1",
            "host": "127.0.0.1",
            "port": 8080,
        }
        if False
        else None  # use Pydantic object
    ) if False else None

    from coordinator.app.models import NodeRegisterRequest
    registry.register_node(
        NodeRegisterRequest(node_id="NODE-offline-1", host="127.0.0.1", port=8080)
    )

    # Manually set last_seen to old_time
    p = registry.db_path
    from coordinator.app.database import get_db_connection
    with get_db_connection(p) as conn:
        conn.execute(
            "UPDATE nodes SET last_seen = ? WHERE node_id = ?",
            (old_time, "NODE-offline-1"),
        )
        conn.commit()


    # Query node info
    node = registry.get_node("NODE-offline-1")
    assert node is not None
    assert node.status == "offline"


# 10. Node Returning Online Test
def test_10_node_returning_online(test_coordinator_settings):
    """Verify an offline node returns to online status upon registration or heartbeat."""
    registry = NodeRegistry(test_coordinator_settings)
    from coordinator.app.models import NodeRegisterRequest, NodeHeartbeatRequest

    # Register node
    registry.register_node(
        NodeRegisterRequest(node_id="NODE-recover-1", host="127.0.0.1", port=8080)
    )

    # Force offline
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    from coordinator.app.database import get_db_connection
    with get_db_connection(registry.db_path) as conn:
        conn.execute(
            "UPDATE nodes SET status = 'offline', last_seen = ? WHERE node_id = ?",
            (old_time, "NODE-recover-1"),
        )
        conn.commit()

    assert registry.get_node("NODE-recover-1").status == "offline"

    # Send heartbeat
    registry.heartbeat("NODE-recover-1", NodeHeartbeatRequest(status="online"))

    # Assert node is online again
    rec = registry.get_node("NODE-recover-1")
    assert rec.status == "online"


# 11. Invalid Node ID Test
def test_11_invalid_node_id(client):
    """Verify operations with non-existent or invalid node IDs return appropriate errors."""
    res_get = client.get("/nodes/NON-EXISTENT-ID")
    assert res_get.status_code == 404

    res_hb = client.post("/nodes/NON-EXISTENT-ID/heartbeat", json={"status": "online"})
    assert res_hb.status_code == 404

    res_del = client.delete("/nodes/NON-EXISTENT-ID")
    assert res_del.status_code == 404


# 12. Authentication Failure Test
def test_12_authentication_failure(test_coordinator_settings):
    """Verify missing or invalid token requests are rejected with 401 Unauthorized."""
    auth_settings = CoordinatorSettings(
        db_path=test_coordinator_settings.db_path,
        host="127.0.0.1",
        port=9000,
        auth_token="coord-secret-token-123",
    )
    app.state.settings = auth_settings
    app.state.registry = NodeRegistry(auth_settings)

    def override_settings():
        return auth_settings

    app.dependency_overrides[get_settings] = override_settings
    try:
        with TestClient(app) as auth_client:
            payload = {"node_id": "NODE-auth-fail", "host": "127.0.0.1", "port": 8080}
            res_unauth = auth_client.post("/nodes/register", json=payload)
            assert res_unauth.status_code == 401

            res_wrong = auth_client.post(
                "/nodes/register",
                json=payload,
                headers={"X-Auth-Token": "wrong-token"},
            )
            assert res_wrong.status_code == 401
    finally:
        app.dependency_overrides.clear()


# 13. Authentication Success Test
def test_13_authentication_success(test_coordinator_settings):
    """Verify requests with valid auth tokens (X-Auth-Token or Bearer) succeed."""
    auth_settings = CoordinatorSettings(
        db_path=test_coordinator_settings.db_path,
        host="127.0.0.1",
        port=9000,
        auth_token="coord-secret-token-123",
    )
    app.state.settings = auth_settings
    app.state.registry = NodeRegistry(auth_settings)

    def override_settings():
        return auth_settings

    app.dependency_overrides[get_settings] = override_settings
    try:
        with TestClient(app) as auth_client:
            payload = {"node_id": "NODE-auth-success", "host": "127.0.0.1", "port": 8080}
            res_auth_x = auth_client.post(
                "/nodes/register",
                json=payload,
                headers={"X-Auth-Token": "coord-secret-token-123"},
            )
            assert res_auth_x.status_code == 200

            res_auth_bearer = auth_client.post(
                "/nodes/NODE-auth-success/heartbeat",
                json={"status": "online"},
                headers={"Authorization": "Bearer coord-secret-token-123"},
            )
            assert res_auth_bearer.status_code == 200
    finally:
        app.dependency_overrides.clear()



# 14. Coordinator Unavailable Behavior Test
def test_14_coordinator_unavailable_behavior(tmp_path):
    """Verify Storage Node handle Coordinator unavailability gracefully without throwing exceptions."""
    storage_root = tmp_path / "storage"
    storage_settings = StorageSettings(
        storage_root=storage_root,
        coordinator_enabled=True,
        coordinator_url="http://127.0.0.1:59999",  # Unreachable port
    )

    manager = StorageManager(storage_settings)
    notifier = CoordinatorNotifier(storage_settings, manager)

    # Calling register and heartbeat should log warnings and return None gracefully
    reg_result = notifier.register()
    assert reg_result is None

    hb_result = notifier.heartbeat()
    assert hb_result is None


# 15. Storage Node Still Functioning Without Coordinator Test
def test_15_storage_node_functioning_without_coordinator(tmp_path):
    """Verify local Storage Node file operations work seamlessly even if Coordinator is disabled/down."""
    storage_root = tmp_path / "storage"
    storage_settings = StorageSettings(
        storage_root=storage_root,
        coordinator_enabled=False,
    )

    manager = StorageManager(storage_settings)
    
    # 1. Store file
    sample_bytes = b"Hello distributed world! Independent storage test."
    import io
    meta = manager.save_file(
        file_obj=io.BytesIO(sample_bytes),
        original_filename="independent.txt",
    )
    assert meta.file_id is not None

    # 2. Retrieve storage info
    info = manager.get_storage_info()
    assert info.used_bytes == len(sample_bytes)

    # 3. Read file back
    retrieved_meta, file_path = manager.get_file(meta.file_id)
    with open(file_path, "rb") as f:
        assert f.read() == sample_bytes

    # 4. Delete file
    deleted = manager.delete_file(meta.file_id)
    assert deleted is True
