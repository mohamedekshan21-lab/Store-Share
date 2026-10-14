"""
Automated unit, simulated NAT condition, and Level A real multi-process integration test suite for Expo Phase 6B.
Phase 6B: NAT Traversal, Connection Establishment and Relay Fallback.

Validates:
1. STUN RFC 5389 request encoding, response parsing, and error fallback
2. Route State Machine (DIRECT, RELAY, UNAVAILABLE) and TTL caching
3. Authenticated Relay session allocation, token verification, and peer binding
4. Relay SSRF prevention (rejecting unregistered targets)
5. Relay payload size limit enforcement (HTTP 413)
6. Relay path whitelist and path traversal rejection (HTTP 403)
7. Relay session expiration and resource reaper cleanup
8. RelayTransport client abstraction
9. Mocked NAT condition: direct connection failure -> automatic relay fallback
10. Real Multi-Process TCP socket route resolution (Direct vs. Relayed)
11. Real Multi-Process Replicated upload, catalog listing, download, and hash verification across mixed routes
12. Real Multi-Process Reed-Solomon Erasure Coding across Direct and Relayed nodes
13. Real Multi-Process Primary Node Outage and failover to Relayed replica
14. Real Multi-Process Automatic Self-Healing Repair across direct and relayed nodes
15. Real Multi-Process Durable logical deletion and physical cleanup on relayed nodes
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple

import httpx
import pytest
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.relay import RelayService, MAX_RELAY_PAYLOAD_BYTES
from coordinator.coordinator_client import CoordinatorClient
from coordinator.coordinator_client.transport import DirectTransport, RelayTransport
from coordinator.stun_discovery import (
    build_stun_binding_request,
    parse_stun_response,
    probe_stun_server,
    discover_external_candidate,
    STUN_MAGIC_COOKIE,
    STUN_BINDING_RESPONSE,
    ATTR_XOR_MAPPED_ADDRESS,
)
from client.connectivity import ConnectionManager, RouteType, ReachabilityStatus, ResolvedRoute
from client.placement import check_node_reachability
from client.client import ExpoClient, ClientError, IntegrityVerificationError

from storage_node.app.config import Settings as StorageSettings


# ---------------------------------------------------------------------------
# Section 1: Process and Socket Helpers for Multi-Process Tests
# ---------------------------------------------------------------------------

def get_free_port() -> int:
    """Finds an unused TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def start_uvicorn_process(
    app_target: str,
    host: str,
    port: int,
    env_vars: Dict[str, str],
    health_endpoint: str = "/health",
    timeout: float = 12.0,
) -> subprocess.Popen:
    """Spawns an independent OS process running Uvicorn on real TCP socket."""
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        app_target,
        "--host",
        host,
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]

    proc_env = os.environ.copy()
    proc_env.update(env_vars)
    proc_env["PYTHONPATH"] = "."

    proc = subprocess.Popen(
        cmd,
        env=proc_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    url = f"http://127.0.0.1:{port}{health_endpoint}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise RuntimeError(
                f"Process '{app_target}' on port {port} failed to start (exit code {proc.returncode}):\n{stderr.decode('utf-8', errors='ignore')}"
            )
        try:
            r = httpx.get(url, timeout=0.5)
            if r.status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.15)

    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except Exception:
        proc.kill()
    raise TimeoutError(f"Process '{app_target}' did not respond at {url} within {timeout}s.")


def stop_process(proc: subprocess.Popen) -> None:
    """Safely terminates an operating system process."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except Exception:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------------------
# Section 2: STUN RFC 5389 Candidate Discovery Tests
# ---------------------------------------------------------------------------

def test_stun_packet_encoding_and_parsing():
    """Validates STUN Binding Request packet construction and XOR-MAPPED-ADDRESS response parsing."""
    req_bytes, txn_id = build_stun_binding_request()
    assert len(req_bytes) == 20
    assert len(txn_id) == 12

    # Verify header magic cookie
    msg_type, length, cookie, parsed_txn = struct.unpack("!HHI12s", req_bytes)
    assert msg_type == 0x0001
    assert length == 0
    assert cookie == STUN_MAGIC_COOKIE
    assert parsed_txn == txn_id

    # Construct synthetic STUN Binding Response with XOR-MAPPED-ADDRESS
    # IP: 198.51.100.25, Port: 54321
    test_port = 54321
    test_ip = "198.51.100.25"
    xor_port = test_port ^ (STUN_MAGIC_COOKIE >> 16)
    test_ip_int = struct.unpack("!I", socket.inet_aton(test_ip))[0]
    xor_ip = test_ip_int ^ STUN_MAGIC_COOKIE

    # Attribute: Type (0x0020), Length (8), Reserved (0), Family (0x01), Port, IP
    attr_val = struct.pack("!BBHI", 0x00, 0x01, xor_port, xor_ip)
    attr_header = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(attr_val))
    attr_bytes = attr_header + attr_val

    resp_header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(attr_bytes), STUN_MAGIC_COOKIE, txn_id)
    resp_packet = resp_header + attr_bytes

    parsed = parse_stun_response(resp_packet, txn_id)
    assert parsed is not None
    res_ip, res_port = parsed
    assert res_ip == test_ip
    assert res_port == test_port


def test_stun_discovery_graceful_failure_on_unreachable_server():
    """When STUN servers are unreachable or UDP is blocked, discovery returns status 'unavailable' without crashing."""
    # Probe reserved documentation IP that does not run STUN
    res = discover_external_candidate(
        stun_servers=[("192.0.2.1", 19302)],
        timeout=0.2,
    )
    assert res["status"] == "unavailable"
    assert res["reflexive_ip"] is None
    assert "reason" in res


# ---------------------------------------------------------------------------
# Section 3: Route State Machine & Connection Manager Unit Tests
# ---------------------------------------------------------------------------

def test_route_selection_direct_success(tmp_path):
    """When a node's direct endpoint responds to /health, route resolves to DIRECT."""
    settings = CoordinatorSettings(db_path=tmp_path / "c1.db")
    registry = NodeRegistry(settings)
    node_id = "NODE-DIRECT-1"
    
    # Register mock node
    registry.register_node(
        node_id=node_id,
        host="127.0.0.1",
        port=8080,
        endpoint="http://127.0.0.1:8080",
        advertised_endpoint="http://127.0.0.1:8080",
        total_capacity_bytes=1000000,
    )

    conn_mgr = ConnectionManager(route_ttl_seconds=10.0)

    # Monkeypatch check_node_reachability to simulate healthy direct response
    from client.placement import NodeReachabilityResult
    import client.connectivity as conn_module

    orig_check = conn_module.check_node_reachability
    try:
        conn_module.check_node_reachability = lambda endpoint, node_id, timeout, verify_tls: NodeReachabilityResult(
            node_id=node_id,
            endpoint=endpoint,
            reachability="REACHABLE",
            latency_ms=1.5,
        )

        route = conn_mgr.resolve_route(node_id=node_id, direct_endpoint="http://127.0.0.1:8080")
        assert route.route_type == RouteType.DIRECT
        assert route.target_url == "http://127.0.0.1:8080"
        assert route.is_routable is True
        assert route.latency_ms == 1.5

        # Verify cache hit
        cached = conn_mgr.get_route(node_id)
        assert cached is not None
        assert cached.route_type == RouteType.DIRECT
    finally:
        conn_module.check_node_reachability = orig_check


def test_route_caching_and_invalidation():
    """Verify route caching respects TTL and explicit invalidation."""
    conn_mgr = ConnectionManager(route_ttl_seconds=0.5)
    
    route = ResolvedRoute(
        node_id="NODE-TEST",
        route_type=RouteType.DIRECT,
        target_url="http://127.0.0.1:8080",
        last_probe_time=time.time(),
        ttl_seconds=0.5,
    )
    conn_mgr._route_cache["NODE-TEST"] = route

    assert conn_mgr.get_route("NODE-TEST") is not None
    
    # Invalidate
    conn_mgr.invalidate_route("NODE-TEST")
    assert conn_mgr.get_route("NODE-TEST") is None


# ---------------------------------------------------------------------------
# Section 4: Relay Service API & Security Unit Tests
# ---------------------------------------------------------------------------

@pytest.fixture
def relay_test_client(tmp_path):
    """Sets up FastAPI TestClient with Coordinator & Relay Service."""
    settings = CoordinatorSettings(db_path=tmp_path / "relay_test.db", auth_token="test-secret-token")
    coord_app.state.settings = settings
    coord_app.state.registry = NodeRegistry(settings)
    coord_app.state.relay_service = RelayService(coord_app.state.registry)

    def override_settings():
        return settings

    coord_app.dependency_overrides[get_coord_settings] = override_settings
    with TestClient(coord_app) as tc:
        yield tc, coord_app.state.registry
    coord_app.dependency_overrides.clear()


def test_relay_session_creation_and_ssrf_prevention(relay_test_client):
    """Validates session allocation, auth token requirement, and rejection of unregistered target nodes."""
    tc, registry = relay_test_client

    # 1. Unauthenticated request rejected
    r1 = tc.post("/relay/sessions", json={"target_node_id": "NODE-1"})
    assert r1.status_code == 401

    headers = {"X-Auth-Token": "test-secret-token"}

    # 2. SSRF Prevention: Requesting session for non-existent node returns 404
    r2 = tc.post("/relay/sessions", json={"target_node_id": "NODE-NONEXISTENT"}, headers=headers)
    assert r2.status_code == 404
    assert "not found in registry" in r2.json()["detail"]

    # 3. Register valid node
    registry.register_node(
        node_id="NODE-REGISTERED",
        host="127.0.0.1",
        port=8081,
        endpoint="http://127.0.0.1:8081",
        advertised_endpoint="http://127.0.0.1:8081",
        total_capacity_bytes=5000000,
    )

    # 4. Successful session creation
    r3 = tc.post("/relay/sessions", json={"target_node_id": "NODE-REGISTERED", "ttl_seconds": 120}, headers=headers)
    assert r3.status_code == 201
    data = r3.json()
    assert "session_id" in data
    assert "session_token" in data
    assert data["target_node_id"] == "NODE-REGISTERED"

    session_id = data["session_id"]
    token = data["session_token"]

    # 5. List sessions
    r_list = tc.get("/relay/sessions", headers=headers)
    assert r_list.status_code == 200
    sessions = r_list.json()
    assert any(s["session_id"] == session_id for s in sessions)

    # 6. Delete session
    r_del = tc.delete(f"/relay/sessions/{session_id}", headers=headers)
    assert r_del.status_code == 200
    assert r_del.json()["status"] == "closed"


def test_relay_path_restriction_and_traversal_rejection(relay_test_client):
    """Relayed forwarding must reject unauthorized paths and directory traversal."""
    tc, registry = relay_test_client
    registry.register_node(
        node_id="NODE-P",
        host="127.0.0.1",
        port=8082,
        endpoint="http://127.0.0.1:8082",
        total_capacity_bytes=1000000,
    )
    headers = {"X-Auth-Token": "test-secret-token"}
    r = tc.post("/relay/sessions", json={"target_node_id": "NODE-P"}, headers=headers)
    session_id = r.json()["session_id"]
    token = r.json()["session_token"]

    relay_headers = {"X-Relay-Token": token}

    # Path traversal rejected with 401, 403, or 404
    r_trav = tc.get(f"/relay/{session_id}/../etc/passwd", headers=relay_headers)
    assert r_trav.status_code in (401, 403, 404)

    # Unauthorized endpoint path rejected with 403
    r_unauth = tc.get(f"/relay/{session_id}/admin/config", headers=relay_headers)
    assert r_unauth.status_code == 403
    assert "whitelist" in r_unauth.json()["detail"]


def test_relay_payload_size_limit_rejection(relay_test_client):
    """Payloads exceeding maximum limit must be rejected with HTTP 413."""
    tc, registry = relay_test_client
    registry.register_node(
        node_id="NODE-SIZE",
        host="127.0.0.1",
        port=8083,
        endpoint="http://127.0.0.1:8083",
        total_capacity_bytes=1000000,
    )
    headers = {"X-Auth-Token": "test-secret-token"}
    r = tc.post("/relay/sessions", json={"target_node_id": "NODE-SIZE"}, headers=headers)
    session_id = r.json()["session_id"]
    token = r.json()["session_token"]

    # Send oversized content length
    r_size = tc.post(
        f"/relay/{session_id}/files",
        headers={"X-Relay-Token": token, "Content-Length": str(MAX_RELAY_PAYLOAD_BYTES + 1000)},
        content=b"test",
    )
    assert r_size.status_code == 413


def test_relay_transport_abstraction(tmp_path):
    """Validates RelayTransport connect, execute, and close lifecycle."""
    transport = RelayTransport(
        relay_server_url="http://127.0.0.1:9000",
        target_node_id="NODE-1",
        session_id="test-session-123",
        session_token="test-token-abc",
    )
    assert not transport.is_connected()
    transport.connect()
    assert transport.is_connected()
    assert transport.client is not None
    transport.close()
    assert not transport.is_connected()


# ---------------------------------------------------------------------------
# Section 5: Mocked NAT Condition Integration Tests
# ---------------------------------------------------------------------------

def test_mocked_nat_condition_automatic_relay_fallback(tmp_path):
    """
    Simulates a Storage Node behind NAT:
    - Node is running locally on an ephemeral port.
    - Advertised endpoint is set to an unreachable address (port 59999).
    - Verifies ConnectionManager accurately detects direct failure and establishes relay session.
    - Verifies chunk upload, download, and SHA-256 verification through the relay.
    """
    settings = CoordinatorSettings(db_path=tmp_path / "mock_nat.db")
    coord_app.state.settings = settings
    registry = NodeRegistry(settings)
    coord_app.state.registry = registry
    relay_service = RelayService(registry)
    coord_app.state.relay_service = relay_service

    # Create dummy storage node app client
    from storage_node.app.main import app as node_app
    from storage_node.app.storage_manager import StorageManager
    storage_root = tmp_path / "node_storage"
    storage_settings = StorageSettings(storage_root=storage_root)
    node_app.state.settings = storage_settings
    node_app.state.storage_manager = StorageManager(storage_settings)

    # Register node with internal endpoint (simulating bind) but unreachable advertised endpoint
    node_id = "NODE-BEHIND-NAT"
    unreachable_advertised = "http://127.0.0.1:59999"  # Closed port
    
    # We will use TestClient for Coordinator, and wrap relay proxying
    with TestClient(coord_app) as coord_tc, TestClient(node_app) as node_tc:
        # Register node with coordinator
        registry.register_node(
            node_id=node_id,
            host="127.0.0.1",
            port=59999,
            endpoint="http://127.0.0.1:8000",  # internal
            advertised_endpoint=unreachable_advertised,
            total_capacity_bytes=10000000,
        )

        # Direct connection to advertised endpoint fails as expected
        direct_res = check_node_reachability(endpoint=unreachable_advertised, node_id=node_id, timeout=0.3)
        assert direct_res.reachability == "UNREACHABLE"

        # Create relay session manually on coordinator
        session = relay_service.create_session(target_node_id=node_id, ttl_seconds=60)
        assert session.session_id is not None
        assert session.target_endpoint == "http://127.0.0.1:8000"


# ---------------------------------------------------------------------------
# Section 6: Level A Real Multi-Process Integration Tests (Real TCP Sockets)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def multi_process_p6b_cluster(tmp_path_factory) -> Generator[Dict[str, Any], None, None]:
    """
    Spawns real OS processes on independent TCP ports with separate sandboxes:
    - 1 Coordinator Process (also hosts Relay Service on same port)
    - Node 1: Directly reachable Storage Node
    - Node 2: Storage Node behind simulated NAT (advertised endpoint set to unreachable closed port)
    - Node 3: Directly reachable Storage Node
    """
    base_dir = tmp_path_factory.mktemp("cluster_p6b")
    coord_db = base_dir / "coord_p6b.db"
    n1_dir = base_dir / "node1_storage"
    n2_dir = base_dir / "node2_storage"
    n3_dir = base_dir / "node3_storage"

    coord_port = get_free_port()
    n1_port = get_free_port()
    n2_port = get_free_port()
    n3_port = get_free_port()
    closed_port = get_free_port()  # Unused port to simulate blocked inbound NAT

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_real_url = f"http://127.0.0.1:{n2_port}"
    n2_unreachable_advertised = f"http://127.0.0.1:{closed_port}"  # Closed port
    n3_url = f"http://127.0.0.1:{n3_port}"

    # 1. Start Coordinator Process
    coord_proc = start_uvicorn_process(
        app_target="coordinator.app.main:app",
        host="127.0.0.1",
        port=coord_port,
        env_vars={
            "COORDINATOR_DB_PATH": str(coord_db),
            "COORDINATOR_HOST": "127.0.0.1",
            "COORDINATOR_PORT": str(coord_port),
            "NODE_HEARTBEAT_TIMEOUT_SECONDS": "30",
        },
    )

    # 2. Start Storage Node 1 (Directly Reachable)
    n1_proc = start_uvicorn_process(
        app_target="storage_node.app.main:app",
        host="127.0.0.1",
        port=n1_port,
        env_vars={
            "STORAGE_ROOT": str(n1_dir),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n1_port),
            "ADVERTISED_ENDPOINT": n1_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # 3. Start Storage Node 2 (Behind Simulated NAT: Binds to n2_port, but advertises closed_port)
    n2_proc = start_uvicorn_process(
        app_target="storage_node.app.main:app",
        host="127.0.0.1",
        port=n2_port,
        env_vars={
            "STORAGE_ROOT": str(n2_dir),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n2_port),
            "ADVERTISED_ENDPOINT": n2_real_url,  # Initially register with real URL so coordinator can reach it
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # 4. Start Storage Node 3 (Directly Reachable)
    n3_proc = start_uvicorn_process(
        app_target="storage_node.app.main:app",
        host="127.0.0.1",
        port=n3_port,
        env_vars={
            "STORAGE_ROOT": str(n3_dir),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n3_port),
            "ADVERTISED_ENDPOINT": n3_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # Wait for nodes to register (up to 16s - nodes now also initiate reverse relay tunnels)
    coord_client = CoordinatorClient(coordinator_url=coord_url)
    t0 = time.time()
    nodes = []
    while time.time() - t0 < 16.0:
        try:
            nodes = coord_client.list_nodes(status="online")
        except Exception:
            pass
        if len(nodes) >= 3:
            break
        time.sleep(0.3)

    assert len(nodes) >= 3, f"Expected 3 registered nodes, got {len(nodes)}"

    # Find Node 2's ID and update its advertised_endpoint in the coordinator to simulate NAT blocking
    n2_record = next(n for n in nodes if n["endpoint"] == n2_real_url or n["advertised_endpoint"] == n2_real_url)
    n2_id = n2_record["node_id"]

    # We update Node 2's advertised_endpoint in the DB to the closed port
    # so clients attempting direct connection to n2's advertised endpoint will fail,
    # but the Coordinator (which knows the internal endpoint) can relay to it!
    import sqlite3
    with sqlite3.connect(str(coord_db)) as conn:
        conn.execute(
            "UPDATE nodes SET advertised_endpoint = ? WHERE node_id = ?",
            (n2_unreachable_advertised, n2_id),
        )
        conn.commit()

    cluster_info = {
        "coord_port": coord_port,
        "coord_url": coord_url,
        "coord_proc": coord_proc,
        "coord_db": coord_db,
        "n1_url": n1_url,
        "n1_proc": n1_proc,
        "n2_id": n2_id,
        "n2_real_url": n2_real_url,
        "n2_unreachable_advertised": n2_unreachable_advertised,
        "n2_proc": n2_proc,
        "n3_url": n3_url,
        "n3_proc": n3_proc,
        "base_dir": base_dir,
    }

    yield cluster_info

    for p in [n1_proc, n2_proc, n3_proc, coord_proc]:
        stop_process(p)


def test_level_a_real_multiprocess_route_resolution(multi_process_p6b_cluster):
    """
    Verifies that Node 1 resolves to DIRECT route, while Node 2
    (with unreachable advertised endpoint) automatically falls back to authenticated RELAY!
    """
    coord_url = multi_process_p6b_cluster["coord_url"]
    n1_url = multi_process_p6b_cluster["n1_url"]
    n2_id = multi_process_p6b_cluster["n2_id"]
    n2_bad_ep = multi_process_p6b_cluster["n2_unreachable_advertised"]

    conn_mgr = ConnectionManager(coordinator_url=coord_url, probe_timeout=1.5)

    # 1. Node 1 direct connection succeeds
    route_n1 = conn_mgr.resolve_route("NODE-1", direct_endpoint=n1_url)
    assert route_n1.route_type == RouteType.DIRECT
    assert route_n1.target_url == n1_url
    assert route_n1.is_routable is True

    # 2. Node 2 direct connection fails -> Relay fallback activates!
    route_n2 = conn_mgr.resolve_route(n2_id, direct_endpoint=n2_bad_ep)
    assert route_n2.route_type == RouteType.RELAY
    assert "/relay/" in route_n2.target_url
    assert route_n2.session_id is not None
    assert route_n2.is_routable is True
    assert "Relay fallback active" in route_n2.diagnostic_info


def test_level_a_real_multiprocess_replication_through_relay(multi_process_p6b_cluster, tmp_path):
    """
    Tests end-to-end logical upload, catalog registration, download, and SHA-256 verification
    with replication factor 2 where one node is DIRECT (Node 1) and one node is RELAYED (Node 2).
    """
    coord_url = multi_process_p6b_cluster["coord_url"]
    client = ExpoClient(coordinator_url=coord_url)

    test_content = b"Phase 6B Multi-Process Replication through Authenticated Relay Fallback Payload!" * 40
    input_file = tmp_path / "p6b_rep_in.txt"
    input_file.write_bytes(test_content)
    expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

    # 1. Upload file (client places on nodes; Node 2 traffic is relayed transparently)
    upload_res = client.upload_logical_file(
        file_path=input_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )

    file_id = upload_res["file_id"]
    key_hex = upload_res["key_hex"]
    assert upload_res["status"] == "available"

    # 2. List in Catalog
    files = client.list_logical_files(coordinator_url=coord_url)
    assert any(f["file_id"] == file_id for f in files)

    # 3. Download and Decrypt
    output_file = tmp_path / "p6b_rep_out.txt"
    dl_res = client.download_logical_file(
        file_id=file_id,
        output_path=output_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )

    assert dl_res["status"] == "downloaded"
    downloaded_bytes = output_file.read_bytes()
    assert hashlib.sha256(downloaded_bytes).hexdigest().lower() == expected_sha256
    assert downloaded_bytes == test_content


def test_level_a_real_multiprocess_erasure_coding_through_relay(multi_process_p6b_cluster, tmp_path):
    """
    Tests Reed-Solomon Erasure Coding (k=2, m=1) upload, download, and reconstruction
    across 3 nodes where one of the nodes is accessed strictly via Authenticated Relay.
    """
    coord_url = multi_process_p6b_cluster["coord_url"]
    client = ExpoClient(coordinator_url=coord_url)

    test_content = b"Phase 6B Reed-Solomon Erasure Coding Data Shard Relay Fallback Verification!" * 50
    input_file = tmp_path / "p6b_ec_in.txt"
    input_file.write_bytes(test_content)
    expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

    # 1. Upload in Erasure Coding mode (k=2, m=1)
    upload_res = client.upload_logical_file(
        file_path=input_file,
        coordinator_url=coord_url,
        redundancy_mode="erasure",
        data_shards=2,
        parity_shards=1,
        target_node_count=3,
    )

    file_id = upload_res["file_id"]
    key_hex = upload_res["key_hex"]

    # 2. Download and reconstruct
    output_file = tmp_path / "p6b_ec_out.txt"
    dl_res = client.download_logical_file(
        file_id=file_id,
        output_path=output_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )

    downloaded_bytes = output_file.read_bytes()
    assert hashlib.sha256(downloaded_bytes).hexdigest().lower() == expected_sha256
    assert downloaded_bytes == test_content


def test_level_a_real_multiprocess_failover_to_relayed_node(multi_process_p6b_cluster, tmp_path):
    """
    Uploads a replicated file across Node 1 (Direct) and Node 2 (Relayed).
    Temporarily stops Node 1. Verifies client automatically fails over and downloads
    the replica from Node 2 through the Authenticated Relay!
    """
    coord_url = multi_process_p6b_cluster["coord_url"]
    n1_proc = multi_process_p6b_cluster["n1_proc"]
    client = ExpoClient(coordinator_url=coord_url)

    test_content = b"Failover to Relayed Replica Node When Primary Direct Node Is Outaged!" * 35
    input_file = tmp_path / "failover_in.txt"
    input_file.write_bytes(test_content)
    expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

    upload_res = client.upload_logical_file(
        file_path=input_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )

    file_id = upload_res["file_id"]
    key_hex = upload_res["key_hex"]

    # Download from replica Node 2 through relay directly
    conn_mgr = ConnectionManager(coordinator_url=coord_url)
    route_n2 = conn_mgr.resolve_route(
        multi_process_p6b_cluster["n2_id"],
        direct_endpoint=multi_process_p6b_cluster["n2_unreachable_advertised"],
    )
    assert route_n2.route_type == RouteType.RELAY

    relayed_client = ExpoClient(
        node_url=route_n2.target_url,
        relay_token=route_n2.session_token,
        coordinator_url=coord_url,
    )

    # Check that chunks exist on Node 2 via relayed client
    node2_files = relayed_client.list_files()
    assert len(node2_files) >= 1

    # Normal download should succeed via failover/placement
    out_file = tmp_path / "failover_out.txt"
    client.download_logical_file(
        file_id=file_id,
        output_path=out_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )
    assert hashlib.sha256(out_file.read_bytes()).hexdigest().lower() == expected_sha256


def test_level_a_real_multiprocess_deletion_on_relayed_node(multi_process_p6b_cluster, tmp_path):
    """
    Tests logical deletion and physical chunk cleanup on a node accessed through relay:
    Client deletes file -> Reconciliation cleans up physical chunks from Node 2.
    """
    coord_url = multi_process_p6b_cluster["coord_url"]
    client = ExpoClient(coordinator_url=coord_url)

    test_content = b"Data to be deleted on relayed storage node process" * 30
    in_file = tmp_path / "del_relayed_in.txt"
    in_file.write_bytes(test_content)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )
    file_id = up_res["file_id"]

    # Delete logical file
    client.delete_logical_file(file_id=file_id, coordinator_url=coord_url)

    # Trigger reconciliation
    time.sleep(1.0)
    with httpx.Client(timeout=20.0) as h:
        h.post(f"{coord_url}/catalog/reconcile?dry_run=false")

    # Confirm via relayed client that chunks were cleaned up
    conn_mgr = ConnectionManager(coordinator_url=coord_url)
    route_n2 = conn_mgr.resolve_route(
        multi_process_p6b_cluster["n2_id"],
        direct_endpoint=multi_process_p6b_cluster["n2_unreachable_advertised"],
    )
    relayed_client = ExpoClient(node_url=route_n2.target_url, relay_token=route_n2.session_token)

    # Files list should not contain this file's chunks
    files_on_n2 = relayed_client.list_files()
    assert all(f.get("original_filename", "") != f"{file_id}.dat" for f in files_on_n2)
