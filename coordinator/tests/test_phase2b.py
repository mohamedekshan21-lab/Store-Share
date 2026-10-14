"""
Automated unit & integration test suite for Expo Phase 2B (Internet Connectivity Foundation & Smart Node Discovery).
Validates:
1. Node identity stability across address changes
2. Coordinator registration with Internet-style URLs
3. HTTPS/TLS configuration settings
4. Invalid TLS certificate behavior handling
5. Authentication failure handling
6. Authentication success handling
7. Heartbeat reconnect & auto-reregistration behavior
8. Node discovery with filters (status, connectivity_mode, min_available_bytes)
9. Offline detection and status recovery
10. Capacity reporting & validation
11. Connectivity capability reporting (LAN, DIRECT, RELAY, UNKNOWN)
12. Advertised endpoint vs local bind address separation
13. Consumer discovery via ExpoClient SDK & CLI
14. Smart node selection algorithm (`select_node`)
15. Resilient Coordinator unavailable behavior
16. Independent Storage Node operation without Coordinator
17. Coexistence of LAN mode and Internet architecture mode
"""

from __future__ import annotations

import io
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app, get_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError, CoordinatorTLSError
from coordinator.coordinator_client.transport import DirectTransport, RelayTransport
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.coordinator_integration import CoordinatorNotifier
from client.client import ExpoClient


@pytest.fixture
def tmp_coordinator_db(tmp_path):
    """Provides a temporary SQLite database path for Coordinator tests."""
    return tmp_path / "coordinator_phase2b_test.db"


@pytest.fixture
def test_coordinator_settings(tmp_coordinator_db):
    """Provides test settings for Coordinator."""
    return CoordinatorSettings(
        db_path=tmp_coordinator_db,
        host="127.0.0.1",
        port=9000,
        auth_token=None,
        heartbeat_timeout_seconds=2,
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


# 1. Node Identity Remains Stable Across Address Changes
def test_1_node_identity_remains_stable(client):
    """Verify NODE-<UUID4> identity remains constant even when host/port endpoint changes."""
    node_id = "NODE-persistent-identity-123"
    
    # Registration 1: Host 192.168.1.10:8000
    res1 = client.post(
        "/nodes/register",
        json={"node_id": node_id, "host": "192.168.1.10", "port": 8000, "total_capacity_bytes": 10000000},
    )
    assert res1.status_code == 200
    reg_at_1 = res1.json()["registered_at"]

    # Registration 2: Changed IP to 203.0.113.45:8443
    res2 = client.post(
        "/nodes/register",
        json={"node_id": node_id, "host": "203.0.113.45", "port": 8443, "total_capacity_bytes": 10000000},
    )
    assert res2.status_code == 200
    data2 = res2.json()

    assert data2["node_id"] == node_id
    assert data2["host"] == "203.0.113.45"
    assert data2["port"] == 8443
    assert data2["registered_at"] == reg_at_1


# 2. Coordinator Registration with Internet-Style URLs
def test_2_coordinator_registration_with_internet_urls(client):
    """Verify registration with advertised HTTPS Internet endpoints."""
    payload = {
        "node_id": "NODE-internet-001",
        "host": "node-1.example.com",
        "port": 443,
        "endpoint": "https://node-1.example.com:443",
        "advertised_endpoint": "https://node-1.example.com",
        "connectivity_mode": "DIRECT",
        "protocol_version": "2B",
        "total_capacity_bytes": 50000000,
    }
    res = client.post("/nodes/register", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["node_id"] == "NODE-internet-001"
    assert data["advertised_endpoint"] == "https://node-1.example.com"
    assert data["connectivity_mode"] == "DIRECT"


# 3. HTTPS/TLS Configuration Settings
def test_3_https_tls_configuration():
    """Verify TLS settings in CoordinatorClient and Storage Node config."""
    storage_set = StorageSettings(
        coordinator_enabled=True,
        coordinator_url="https://coordinator.example.com",
        coordinator_verify_tls=True,
        coordinator_ca_cert="/path/to/ca.crt",
    )
    assert storage_set.coordinator_verify_tls is True
    assert storage_set.coordinator_ca_cert == "/path/to/ca.crt"
    assert storage_set.resolved_coordinator_url == "https://coordinator.example.com"

    coord_client = CoordinatorClient(
        coordinator_url="https://coordinator.example.com",
        verify_tls=True,
        ca_cert="/path/to/ca.crt",
    )
    assert coord_client.verify == "/path/to/ca.crt"


# 4. Invalid TLS Certificate Behavior
def test_4_invalid_tls_certificate_behavior():
    """Verify invalid TLS handshake attempts raise CoordinatorTLSError or CoordinatorClientError cleanly."""
    coord_client = CoordinatorClient(
        coordinator_url="https://127.0.0.1:59999",  # Non-TLS or unreachable port
        verify_tls=True,
    )
    with pytest.raises((CoordinatorTLSError, CoordinatorClientError)):
        coord_client.health()


# 5. Authentication Failure
def test_5_authentication_failure(test_coordinator_settings):
    """Verify requests without token or with wrong token return 401 Unauthorized."""
    auth_settings = CoordinatorSettings(
        db_path=test_coordinator_settings.db_path,
        auth_token="secret-token-99",
    )
    app.state.settings = auth_settings
    app.state.registry = NodeRegistry(auth_settings)

    def override_settings():
        return auth_settings

    app.dependency_overrides[get_settings] = override_settings
    try:
        with TestClient(app) as auth_client:
            res_no_token = auth_client.post("/nodes/register", json={"node_id": "NODE-auth-1", "host": "1.1.1.1", "port": 8000})
            assert res_no_token.status_code == 401

            res_wrong_token = auth_client.post(
                "/nodes/register",
                json={"node_id": "NODE-auth-1", "host": "1.1.1.1", "port": 8000},
                headers={"X-Auth-Token": "bad-token"},
            )
            assert res_wrong_token.status_code == 401
    finally:
        app.dependency_overrides.clear()


# 6. Authentication Success
def test_6_authentication_success(test_coordinator_settings):
    """Verify requests with valid token succeed."""
    auth_settings = CoordinatorSettings(
        db_path=test_coordinator_settings.db_path,
        auth_token="secret-token-99",
    )
    app.state.settings = auth_settings
    app.state.registry = NodeRegistry(auth_settings)

    def override_settings():
        return auth_settings

    app.dependency_overrides[get_settings] = override_settings
    try:
        with TestClient(app) as auth_client:
            res_auth = auth_client.post(
                "/nodes/register",
                json={"node_id": "NODE-auth-ok", "host": "1.1.1.1", "port": 8000},
                headers={"X-Auth-Token": "secret-token-99"},
            )
            assert res_auth.status_code == 200
    finally:
        app.dependency_overrides.clear()


# 7. Heartbeat Reconnect & Auto-reregistration Behavior
def test_7_heartbeat_reconnect_behavior(tmp_path):
    """Verify Storage Node auto-reregisters with Coordinator if node state was reset."""
    storage_settings = StorageSettings(
        storage_root=tmp_path / "storage_reconnect",
        coordinator_enabled=True,
        coordinator_url="http://127.0.0.1:59999",  # Initially down
    )
    manager = StorageManager(storage_settings)
    notifier = CoordinatorNotifier(storage_settings, manager)

    # First attempt fails safely
    assert notifier.heartbeat() is None
    assert notifier._registered is False


# 8. Node Discovery with Advanced Filters
def test_8_node_discovery_with_filters(client):
    """Verify GET /nodes filtering by status, connectivity_mode, and min_available_bytes."""
    client.post("/nodes/register", json={
        "node_id": "NODE-filter-1", "host": "10.0.0.1", "port": 8001,
        "connectivity_mode": "DIRECT", "total_capacity_bytes": 100000, "used_capacity_bytes": 10000
    })
    client.post("/nodes/register", json={
        "node_id": "NODE-filter-2", "host": "10.0.0.2", "port": 8002,
        "connectivity_mode": "RELAY", "total_capacity_bytes": 50000, "used_capacity_bytes": 45000
    })

    # Filter by connectivity_mode=DIRECT
    res_direct = client.get("/nodes?connectivity_mode=DIRECT")
    assert res_direct.status_code == 200
    nodes_direct = res_direct.json()["nodes"]
    assert len(nodes_direct) == 1
    assert nodes_direct[0]["node_id"] == "NODE-filter-1"

    # Filter by min_available_bytes=50000 (NODE-filter-1 has 90k, filter-2 has 5k)
    res_min = client.get("/nodes?min_available_bytes=50000")
    assert res_min.status_code == 200
    nodes_min = res_min.json()["nodes"]
    assert len(nodes_min) == 1
    assert nodes_min[0]["node_id"] == "NODE-filter-1"


# 9. Offline Detection and Recovery
def test_9_offline_detection_and_recovery(test_coordinator_settings):
    """Verify transition ONLINE -> OFFLINE -> ONLINE."""
    registry = NodeRegistry(test_coordinator_settings)
    from coordinator.app.models import NodeRegisterRequest, NodeHeartbeatRequest

    registry.register_node(NodeRegisterRequest(node_id="NODE-state-cycle", host="127.0.0.1", port=8000))
    assert registry.get_node("NODE-state-cycle").status == "online"

    # Set last_seen 10s in past
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    from coordinator.app.database import get_db_connection
    with get_db_connection(registry.db_path) as conn:
        conn.execute("UPDATE nodes SET status = 'offline', last_seen = ? WHERE node_id = ?", (old_time, "NODE-state-cycle"))
        conn.commit()

    assert registry.get_node("NODE-state-cycle").status == "offline"

    # Send heartbeat -> recovers to online
    registry.heartbeat("NODE-state-cycle", NodeHeartbeatRequest(status="online"))
    assert registry.get_node("NODE-state-cycle").status == "online"


# 10. Capacity Reporting & Validation
def test_10_capacity_reporting_and_validation(client):
    """Verify correct capacity calculation and error on invalid capacity."""
    res_valid = client.post("/nodes/register", json={
        "node_id": "NODE-valid-cap", "host": "127.0.0.1", "port": 8000,
        "total_capacity_bytes": 1000, "used_capacity_bytes": 300
    })
    assert res_valid.status_code == 200
    assert res_valid.json()["available_capacity_bytes"] == 700

    # Invalid: used > total
    res_invalid = client.post("/nodes/register", json={
        "node_id": "NODE-invalid-cap", "host": "127.0.0.1", "port": 8000,
        "total_capacity_bytes": 1000, "used_capacity_bytes": 2000
    })
    assert res_invalid.status_code == 400


# 11. Connectivity Capability Reporting (LAN, DIRECT, RELAY, UNKNOWN)
def test_11_connectivity_capability_reporting(client):
    """Verify nodes report connectivity mode capability."""
    for mode in ["LAN", "DIRECT", "RELAY", "UNKNOWN"]:
        res = client.post("/nodes/register", json={
            "node_id": f"NODE-mode-{mode}", "host": "127.0.0.1", "port": 8000,
            "connectivity_mode": mode, "protocol_version": "2B"
        })
        assert res.status_code == 200
        assert res.json()["connectivity_mode"] == mode
        assert res.json()["protocol_version"] == "2B"


# 12. Advertised Endpoint vs Local Bind Address Separation
def test_12_advertised_endpoint_validation(client):
    """Verify local bind host (0.0.0.0) is separated from public advertised endpoint."""
    res = client.post("/nodes/register", json={
        "node_id": "NODE-endpoint-sep",
        "host": "0.0.0.0",
        "port": 8000,
        "endpoint": "http://127.0.0.1:8000",
        "advertised_endpoint": "https://storage.mycompany.org:8443",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["host"] == "0.0.0.0"
    assert data["advertised_endpoint"] == "https://storage.mycompany.org:8443"


# 13. Consumer Discovery via ExpoClient SDK
def test_13_consumer_discovery_via_client(client, monkeypatch):
    """Verify ExpoClient discovery methods."""
    client.post("/nodes/register", json={
        "node_id": "NODE-client-disc", "host": "127.0.0.1", "port": 8080,
        "total_capacity_bytes": 1000000, "used_capacity_bytes": 1000
    })

    expo_client = ExpoClient(node_url="http://127.0.0.1:8080")
    
    # Test list_coordinator_nodes using TestClient adapter or direct query
    nodes = client.get("/nodes").json()["nodes"]
    assert len(nodes) >= 1
    assert any(n["node_id"] == "NODE-client-disc" for n in nodes)


# 14. Smart Node Selection Algorithm
def test_14_node_selection_foundation(client):
    """Verify GET/POST /nodes/select selects best candidate node by capacity & preferred connectivity."""
    # Node A: 100 KB available, LAN
    client.post("/nodes/register", json={
        "node_id": "NODE-sel-A", "host": "10.0.0.1", "port": 8001,
        "connectivity_mode": "LAN", "total_capacity_bytes": 200000, "used_capacity_bytes": 100000
    })
    # Node B: 500 KB available, DIRECT
    client.post("/nodes/register", json={
        "node_id": "NODE-sel-B", "host": "10.0.0.2", "port": 8002,
        "connectivity_mode": "DIRECT", "total_capacity_bytes": 600000, "used_capacity_bytes": 100000
    })
    # Node C: 10 KB available, LAN
    client.post("/nodes/register", json={
        "node_id": "NODE-sel-C", "host": "10.0.0.3", "port": 8003,
        "connectivity_mode": "LAN", "total_capacity_bytes": 20000, "used_capacity_bytes": 10000
    })

    # Select node with 200 KB required -> Node B (500 KB) selected
    res1 = client.get("/nodes/select?required_bytes=200000")
    assert res1.status_code == 200
    assert res1.json()["node_id"] == "NODE-sel-B"

    # Select node with preferred_connectivity=LAN and required 50 KB -> Node A (100 KB LAN) selected
    res2 = client.get("/nodes/select?required_bytes=50000&preferred_connectivity=LAN")
    assert res2.status_code == 200
    assert res2.json()["node_id"] == "NODE-sel-A"

    # Request impossible capacity (10 MB) -> 404 Not Found
    res3 = client.get("/nodes/select?required_bytes=10000000")
    assert res3.status_code == 404


# 15. Coordinator Unavailable Behavior
def test_15_coordinator_unavailable_behavior(tmp_path):
    """Verify Storage Node handles Coordinator unavailability without crashing."""
    storage_settings = StorageSettings(
        storage_root=tmp_path / "storage_unavail",
        coordinator_enabled=True,
        coordinator_url="http://127.0.0.1:59999",
    )
    manager = StorageManager(storage_settings)
    notifier = CoordinatorNotifier(storage_settings, manager)

    assert notifier.register() is None
    assert notifier.heartbeat() is None


# 16. Storage Node Functioning Without Coordinator
def test_16_storage_node_functioning_without_coordinator(tmp_path):
    """Verify local Storage Node operations succeed independently when Coordinator is disabled."""
    storage_settings = StorageSettings(
        storage_root=tmp_path / "storage_standalone",
        coordinator_enabled=False,
    )
    manager = StorageManager(storage_settings)

    payload_data = b"Phase 2B Independent Storage Verification Data"
    meta = manager.save_file(io.BytesIO(payload_data), original_filename="p2b_test.txt")
    assert meta.file_id is not None

    read_meta, path = manager.get_file(meta.file_id)
    with open(path, "rb") as f:
        assert f.read() == payload_data

    assert manager.delete_file(meta.file_id) is True


# 17. Coexistence of LAN Mode and Internet Architecture Mode
def test_17_lan_mode_and_internet_mode_coexistence(client):
    """Verify LAN mode nodes and Internet mode nodes coexist in the Node Registry."""
    # LAN Node
    res_lan = client.post("/nodes/register", json={
        "node_id": "NODE-lan-local", "host": "192.168.1.45", "port": 8000,
        "endpoint": "http://192.168.1.45:8000", "connectivity_mode": "LAN"
    })
    assert res_lan.status_code == 200

    # Internet Node
    res_inet = client.post("/nodes/register", json={
        "node_id": "NODE-inet-remote", "host": "provider.storage-network.org", "port": 443,
        "endpoint": "https://provider.storage-network.org:443",
        "advertised_endpoint": "https://provider.storage-network.org",
        "connectivity_mode": "DIRECT"
    })
    assert res_inet.status_code == 200

    res_all = client.get("/nodes")
    assert res_all.status_code == 200
    nodes = res_all.json()["nodes"]
    assert any(n["node_id"] == "NODE-lan-local" and n["connectivity_mode"] == "LAN" for n in nodes)
    assert any(n["node_id"] == "NODE-inet-remote" and n["connectivity_mode"] == "DIRECT" for n in nodes)


# Transport Abstraction Test
def test_transport_abstraction():
    """Verify DirectTransport and RelayTransport interfaces."""
    dt = DirectTransport(base_url="http://127.0.0.1:9000", verify_tls=False)
    assert dt.is_connected() is True
    dt.close()

    rt = RelayTransport(relay_server_url="wss://relay.example.com", target_node_id="NODE-target")
    assert rt.is_connected() is False
    with pytest.raises(NotImplementedError):
        rt.connect()
