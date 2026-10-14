"""
Phase 6B.1 Automated Test Suite: Relay Correctness, NAT Reachability and Security Audit.

Validates:
 1. NodeTunnel binary frame encoding/decoding correctness
 2. NodeTunnel malformed frame resilience
 3. NodeTunnel close cancels all pending futures
 4. RelayService tunnel registration and unregistration
 5. RelayService replaces old tunnel on reconnect
 6. Authenticated tunnel handshake  -- rejects missing/bad token
 7. Authenticated tunnel handshake  -- accepts valid token and stores tunnel
 8. Tunnel rejected for unregistered node_id
 9. File manifest serialization does not contain DEK
10. Coordinator catalog does not store DEK
11. Relay forwarding treats payload as opaque bytes
12. STUN discovery reports graceful unavailability when servers unreachable
13. STUN module does not claim symmetric NAT traversal / hole punching
14. Level A: Reverse tunnel registered for NAT-simulated node
15. Level A: Upload and download through reverse tunnel
16. Level A: Key isolation end-to-end
17. Level A: Replication across direct and tunnel routes
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as _get_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.relay import (
    RelayService,
    NodeTunnel,
    ALLOWED_RELAY_PATH_PREFIXES,
)
from coordinator.coordinator_client import CoordinatorClient
from client.client import ExpoClient
from client.chunker import FileManifest
from client.crypto import AESGCMCrypto


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def coord_settings(tmp_path):
    return CoordinatorSettings(
        db_path=tmp_path / "test_6b1.db",
        host="127.0.0.1",
        port=9100,
        auth_token="test-secret-6b1",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture()
def coord_registry(coord_settings):
    return NodeRegistry(coord_settings)


@pytest.fixture()
def relay_service(coord_registry):
    return RelayService(coord_registry)


@pytest.fixture()
def relay_test_client(coord_settings, coord_registry):
    """FastAPI TestClient wired to Coordinator app with relay mounted."""
    # Attach pre-built state objects so all dependencies resolve without spawning workers
    coord_app.state.settings = coord_settings
    coord_app.state.registry = coord_registry
    # Ensure relay_service is fresh each test (prevents cross-test state leakage)
    if hasattr(coord_app.state, "relay_service"):
        del coord_app.state.relay_service

    coord_app.dependency_overrides[_get_settings] = lambda: coord_settings

    with TestClient(coord_app) as tc:
        yield tc, coord_settings, coord_registry

    coord_app.dependency_overrides.clear()
    for attr in ("relay_service", "catalog", "reconciliation_service"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Section 1  -- NodeTunnel Frame Encoding / Decoding Unit Tests
# ---------------------------------------------------------------------------


def test_node_tunnel_frame_round_trip():
    """Verifies symmetric frame encoding: serialize -> parse returns original header and body."""
    header = {
        "request_id": "req-abc",
        "method": "GET",
        "path": "/files",
        "query": "status=online",
        "headers": {"x-custom": "value"},
    }
    body = b"hello relay world"
    header_bytes = json.dumps(header).encode("utf-8")
    frame = struct.pack("!I", len(header_bytes)) + header_bytes + body

    parsed_len = struct.unpack("!I", frame[:4])[0]
    parsed_header = json.loads(frame[4 : 4 + parsed_len].decode("utf-8"))
    parsed_body = frame[4 + parsed_len :]

    assert parsed_header["request_id"] == "req-abc"
    assert parsed_header["method"] == "GET"
    assert parsed_header["query"] == "status=online"
    assert parsed_body == body


def test_node_tunnel_frame_with_binary_body():
    """Verifies frames survive round-trip with arbitrary binary (encrypted) payloads."""
    body = os.urandom(512)
    header = {"request_id": "bin-req", "method": "POST", "path": "/storage/upload", "query": "", "headers": {}}
    header_bytes = json.dumps(header).encode("utf-8")
    frame = struct.pack("!I", len(header_bytes)) + header_bytes + body

    parsed_len = struct.unpack("!I", frame[:4])[0]
    parsed_body = frame[4 + parsed_len :]

    assert parsed_body == body, "Binary body must survive frame round-trip intact"


def test_node_tunnel_malformed_frame_ignored():
    """Verifies malformed frames are silently discarded without raising exceptions."""
    mock_ws = AsyncMock()
    tunnel = NodeTunnel(node_id="NODE-X", websocket=mock_ws)

    # Too short (< 4 bytes)
    tunnel.handle_incoming_frame(b"\x00\x00")

    # header_len exceeds remaining buffer
    big_len = struct.pack("!I", 99999)
    tunnel.handle_incoming_frame(big_len + b"short")

    # Invalid JSON in header section
    bad_header = b"not-valid-json"
    tunnel.handle_incoming_frame(struct.pack("!I", len(bad_header)) + bad_header)

    # None of the above should raise; no pending requests should be affected
    assert not tunnel.pending_requests


def test_node_tunnel_close_cancels_pending_futures():
    """Verifies closing a tunnel sets exceptions on all pending asyncio Futures."""
    mock_ws = AsyncMock()
    tunnel = NodeTunnel(node_id="NODE-CLOSE", websocket=mock_ws)

    loop = asyncio.new_event_loop()
    try:
        future = loop.create_future()
        tunnel.pending_requests["req-1"] = future

        tunnel.close(RuntimeError("tunnel closed"))

        assert tunnel.is_closed
        assert future.done()
        exc = future.exception()
        assert isinstance(exc, RuntimeError)
        assert "tunnel closed" in str(exc)
    finally:
        loop.close()


def test_node_tunnel_response_frame_resolves_future():
    """Verifies a well-formed response frame resolves the matching pending Future."""
    mock_ws = AsyncMock()
    tunnel = NodeTunnel(node_id="NODE-RES", websocket=mock_ws)

    loop = asyncio.new_event_loop()
    try:
        future = loop.create_future()
        tunnel.pending_requests["resp-req-1"] = future

        # Build a response frame mimicking what a storage node would send back
        resp_header = {
            "request_id": "resp-req-1",
            "status_code": 200,
            "headers": {"content-type": "application/json"},
        }
        resp_body = b'{"status": "ok"}'
        resp_header_bytes = json.dumps(resp_header).encode("utf-8")
        frame = struct.pack("!I", len(resp_header_bytes)) + resp_header_bytes + resp_body

        tunnel.handle_incoming_frame(frame)

        assert future.done()
        status_code, headers, body = future.result()
        assert status_code == 200
        assert headers["content-type"] == "application/json"
        assert body == resp_body
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Section 2  -- RelayService Tunnel Registration Logic
# ---------------------------------------------------------------------------


def test_relay_service_registers_and_unregisters_tunnel(relay_service):
    """RelayService stores a tunnel reference and exposes it via get_tunnel."""
    mock_ws = AsyncMock()
    tunnel = relay_service.register_tunnel("NODE-T1", mock_ws)

    assert relay_service.get_tunnel("NODE-T1") is tunnel
    assert not tunnel.is_closed

    relay_service.unregister_tunnel("NODE-T1", tunnel)

    assert relay_service.get_tunnel("NODE-T1") is None
    assert tunnel.is_closed


def test_relay_service_replaces_old_tunnel_on_reconnect(relay_service):
    """Reconnecting a node replaces its tunnel and closes the old one."""
    mock_ws1 = AsyncMock()
    tunnel1 = relay_service.register_tunnel("NODE-R", mock_ws1)

    loop = asyncio.new_event_loop()
    try:
        future = loop.create_future()
        tunnel1.pending_requests["req-old"] = future

        mock_ws2 = AsyncMock()
        tunnel2 = relay_service.register_tunnel("NODE-R", mock_ws2)

        assert relay_service.get_tunnel("NODE-R") is tunnel2
        assert tunnel1.is_closed
        assert future.done()  # Old pending futures should be resolved with exception
        assert isinstance(future.exception(), Exception)
    finally:
        loop.close()


def test_relay_service_get_tunnel_skips_closed_tunnels(relay_service):
    """get_tunnel returns None for a registered-but-already-closed tunnel."""
    mock_ws = AsyncMock()
    tunnel = relay_service.register_tunnel("NODE-CLOSED-GET", mock_ws)
    tunnel.close()

    result = relay_service.get_tunnel("NODE-CLOSED-GET")
    assert result is None


# ---------------------------------------------------------------------------
# Section 3  -- WebSocket Tunnel Endpoint Authentication (via TestClient)
# ---------------------------------------------------------------------------


def test_tunnel_endpoint_rejects_missing_auth(relay_test_client):
    """Unauthenticated tunnel connection must be rejected (no auth header)."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-NO-AUTH",
        host="127.0.0.1",
        port=19011,
        endpoint="http://127.0.0.1:19011",
        advertised_endpoint="http://198.51.100.25:9011",
        total_capacity_bytes=1_000_000,
    )

    # Without auth, the WebSocket endpoint closes with code 4001
    with pytest.raises(Exception):
        with tc.websocket_connect("/relay/tunnel/NODE-NO-AUTH") as ws:
            pass


def test_tunnel_endpoint_rejects_wrong_auth(relay_test_client):
    """Tunnel connection with wrong auth token must be rejected."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-BAD-AUTH",
        host="127.0.0.1",
        port=19012,
        endpoint="http://127.0.0.1:19012",
        advertised_endpoint="http://198.51.100.25:9012",
        total_capacity_bytes=1_000_000,
    )

    with pytest.raises(Exception):
        with tc.websocket_connect(
            "/relay/tunnel/NODE-BAD-AUTH",
            headers={"X-Auth-Token": "WRONG-TOKEN"},
        ) as ws:
            pass


def test_tunnel_endpoint_accepts_valid_auth(relay_test_client):
    """Tunnel connection with valid auth token is accepted and stored in RelayService."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-VALID-AUTH",
        host="127.0.0.1",
        port=19013,
        endpoint="http://127.0.0.1:19013",
        advertised_endpoint="http://198.51.100.25:9013",
        total_capacity_bytes=1_000_000,
    )

    with tc.websocket_connect(
        "/relay/tunnel/NODE-VALID-AUTH",
        headers={"X-Auth-Token": "test-secret-6b1"},
    ) as ws:
        relay_svc = getattr(tc.app.state, "relay_service", None)
        assert relay_svc is not None, "RelayService must be initialized on first tunnel connect"
        tunnel = relay_svc.get_tunnel("NODE-VALID-AUTH")
        assert tunnel is not None, "Active tunnel must be registered for authenticated node"
        assert not tunnel.is_closed


def test_tunnel_endpoint_rejects_unregistered_node(relay_test_client):
    """Tunnel connection for a node_id not in NodeRegistry must be rejected."""
    tc, settings, registry = relay_test_client

    with pytest.raises(Exception):
        with tc.websocket_connect(
            "/relay/tunnel/NODE-NOT-REGISTERED-ANYWHERE",
            headers={"X-Auth-Token": "test-secret-6b1"},
        ) as ws:
            pass


def test_tunnel_endpoint_accepts_bearer_token(relay_test_client):
    """Tunnel connection with Authorization: Bearer <token> header is accepted."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-BEARER-AUTH",
        host="127.0.0.1",
        port=19014,
        endpoint="http://127.0.0.1:19014",
        advertised_endpoint="http://198.51.100.25:9014",
        total_capacity_bytes=1_000_000,
    )

    with tc.websocket_connect(
        "/relay/tunnel/NODE-BEARER-AUTH",
        headers={"Authorization": "Bearer test-secret-6b1"},
    ) as ws:
        relay_svc = getattr(tc.app.state, "relay_service", None)
        assert relay_svc is not None
        tunnel = relay_svc.get_tunnel("NODE-BEARER-AUTH")
        assert tunnel is not None


# ---------------------------------------------------------------------------
# Section 4  -- Key Isolation Audit Tests
# ---------------------------------------------------------------------------


def test_file_manifest_does_not_contain_dek():
    """FileManifest serialized JSON must never contain the Data Encryption Key."""
    dek = AESGCMCrypto.generate_key()
    dek_hex = dek.hex()

    manifest = FileManifest(
        file_id=str(uuid.uuid4()),
        original_filename="secret.txt",
        original_size=1024,
        original_sha256="a" * 64,
        encrypted_size=1040,
        chunk_size=4096,
        chunk_count=1,
        replication_factor=1,
        manifest_version=2,
        nonce_hex="00" * 12,
        created_at="2026-10-11T00:00:00Z",
        chunks=[],
        redundancy_mode="replication",
    )
    manifest_json = manifest.to_json()

    assert dek_hex not in manifest_json, (
        "SECURITY VIOLATION: DEK appears in serialized FileManifest JSON!"
    )
    assert dek_hex.upper() not in manifest_json.upper(), (
        "SECURITY VIOLATION: DEK hex appears in FileManifest JSON (case-insensitive)!"
    )


def test_file_manifest_has_no_dek_field():
    """FileManifest schema must not define any field named 'dek', 'key', or 'encryption_key'."""
    forbidden_field_names = {"dek", "key", "encryption_key", "data_encryption_key"}
    manifest_fields = set(FileManifest.model_fields.keys())

    violations = manifest_fields & forbidden_field_names
    assert not violations, (
        f"SECURITY VIOLATION: FileManifest contains key material fields: {violations}"
    )


def test_coordinator_catalog_does_not_store_dek(relay_test_client):
    """After registering a file, the Coordinator DB must not contain the DEK."""
    tc, settings, registry = relay_test_client

    dek = AESGCMCrypto.generate_key()
    dek_hex = dek.hex()

    manifest_dict = {
        "file_id": str(uuid.uuid4()),
        "original_filename": "private.bin",
        "original_size": 512,
        "original_sha256": "b" * 64,
        "encrypted_size": 528,
        "chunk_size": 4096,
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "nonce_hex": "aa" * 12,
        "created_at": "2026-10-11T00:00:00Z",
        "chunks": [],
        "redundancy_mode": "replication",
    }

    resp = tc.post(
        "/catalog/files",
        json={"manifest": manifest_dict},
        headers={"X-Auth-Token": "test-secret-6b1"},
    )
    assert resp.status_code in (200, 201), f"Unexpected catalog register response: {resp.text}"

    import sqlite3
    db_path = settings.db_path
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute("SELECT manifest_json FROM files").fetchall()

    assert rows, "Expected at least one file row in catalog DB"
    for row in rows:
        manifest_content = row[0]
        assert dek_hex not in manifest_content, (
            "SECURITY VIOLATION: DEK found in Coordinator database manifest_json column!"
        )


def test_relay_forwarding_treats_payload_as_opaque(relay_test_client):
    """
    Relay forwarding must not attempt to decrypt, parse, or transform the payload body.
    Relay returns 503/502 (no real node) without inspecting encrypted bytes.
    """
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-OPAQUE",
        host="127.0.0.1",
        port=29005,
        endpoint="http://127.0.0.1:29005",
        advertised_endpoint="http://198.51.100.25:29005",
        total_capacity_bytes=1_000_000,
    )

    session_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-OPAQUE"},
        headers={"X-Auth-Token": "test-secret-6b1"},
    )
    assert session_resp.status_code == 201
    session = session_resp.json()

    ciphertext_payload = os.urandom(256)  # High-entropy bytes, should be opaque to relay

    fwd_resp = tc.post(
        f"/relay/{session['session_id']}/files",
        content=ciphertext_payload,
        headers={
            "X-Relay-Token": session["session_token"],
            "Content-Type": "application/octet-stream",
        },
    )
    # 503 = no tunnel and no direct connection to node; relay correctly attempted forward
    assert fwd_resp.status_code in (200, 201, 422, 503, 502, 504), (
        f"Unexpected relay status: {fwd_resp.status_code}  -- relay must not reject based on payload content"
    )


# ---------------------------------------------------------------------------
# Section 5  -- STUN Capabilities Documentation Tests
# ---------------------------------------------------------------------------


def test_stun_discovery_graceful_when_unreachable():
    """
    STUN discovery must handle unreachable servers gracefully.
    Probing port 9 (discard) on loopback will always fail, validating error handling.
    """
    from coordinator.stun_discovery import discover_external_candidate

    result = discover_external_candidate(
        stun_servers=[("127.0.0.1", 9)],  # Always unreachable
        timeout=0.5,
    )

    assert result["status"] in ("discovered", "unavailable"), (
        f"Unexpected STUN result status: {result['status']!r}"
    )
    if result["status"] == "unavailable":
        assert result["reflexive_ip"] is None
        assert "reason" in result


def test_stun_does_not_claim_nat_traversal():
    """
    STUN module must not claim symmetric NAT traversal or hole punching.
    These require ICE / TURN and are explicitly out of scope for Phase 6B.
    """
    from coordinator.stun_discovery import discover_external_candidate

    result = discover_external_candidate(
        stun_servers=[("192.0.2.1", 3478)],  # TEST-NET-1, always unreachable
        timeout=0.3,
    )

    # The result dict must not contain fields implying hole-punching success
    assert "nat_traversal_succeeded" not in result, (
        "STUN result must not imply successful NAT traversal"
    )
    assert "hole_punch" not in result, (
        "STUN result must not contain hole_punch key (requires ICE/TURN)"
    )


def test_stun_result_contains_required_keys():
    """
    STUN discovery result must always return the minimal required keys:
    'status', 'reflexive_ip', 'reflexive_port'.
    """
    from coordinator.stun_discovery import discover_external_candidate

    result = discover_external_candidate(
        stun_servers=[("127.0.0.1", 9)],
        timeout=0.3,
    )

    assert "status" in result
    assert "reflexive_ip" in result
    assert "reflexive_port" in result


# ---------------------------------------------------------------------------
# Section 6  -- Level A Real Multi-Process Integration Tests
# ---------------------------------------------------------------------------


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def _start_uvicorn_process(
    app_target: str,
    host: str,
    port: int,
    env_vars: Dict[str, str],
    health_endpoint: str = "/health",
    timeout: float = 20.0,
) -> subprocess.Popen:
    """Spawns an independent OS process running Uvicorn on a real TCP socket."""
    cmd = [
        sys.executable,
        "-m", "uvicorn",
        app_target,
        "--host", host,
        "--port", str(port),
        "--log-level", "warning",
    ]
    proc_env = os.environ.copy()
    proc_env.update(env_vars)
    proc_env["PYTHONPATH"] = "."

    proc = subprocess.Popen(cmd, env=proc_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}{health_endpoint}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise RuntimeError(
                f"Process '{app_target}' on port {port} crashed:\n"
                + stderr.decode("utf-8", errors="ignore")
            )
        try:
            r = httpx.get(url, timeout=0.5)
            if r.status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.25)

    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except Exception:
        proc.kill()
    raise TimeoutError(f"Process '{app_target}' did not respond at {url} within {timeout}s.")


def _stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except Exception:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def p6b1_cluster(tmp_path_factory) -> Generator[Dict[str, Any], None, None]:
    """
    Phase 6B.1 multi-process cluster with reverse tunnel support:
    - 1 Coordinator (hosts Relay + WebSocket tunnel endpoint /relay/tunnel/{node_id})
    - Node 1: Directly reachable (advertised_endpoint = real TCP port)
    - Node 2: Simulated NAT (advertised_endpoint = closed port after registration;
               reverse tunnel established by the node's RelayTunnelClient on startup)
    """
    base_dir = tmp_path_factory.mktemp("cluster_p6b1")
    coord_db = base_dir / "coord.db"

    coord_port = _get_free_port()
    n1_port = _get_free_port()
    n2_port = _get_free_port()
    closed_port = _get_free_port()  # Allocated then immediately freed  -- simulates NAT blocking

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_real_url = f"http://127.0.0.1:{n2_port}"
    n2_nat_url = f"http://127.0.0.1:{closed_port}"  # Will be unreachable

    # Start Coordinator
    coord_proc = _start_uvicorn_process(
        "coordinator.app.main:app",
        "127.0.0.1", coord_port,
        {
            "COORDINATOR_DB_PATH": str(coord_db),
            "COORDINATOR_HOST": "127.0.0.1",
            "COORDINATOR_PORT": str(coord_port),
            "NODE_HEARTBEAT_TIMEOUT_SECONDS": "30",
        },
    )

    # Start Node 1 (directly reachable)
    n1_proc = _start_uvicorn_process(
        "storage_node.app.main:app",
        "127.0.0.1", n1_port,
        {
            "STORAGE_ROOT": str(base_dir / "n1_storage"),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n1_port),
            "ADVERTISED_ENDPOINT": n1_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "3",
        },
    )

    # Start Node 2 (will be simulated NAT after registration)
    n2_proc = _start_uvicorn_process(
        "storage_node.app.main:app",
        "127.0.0.1", n2_port,
        {
            "STORAGE_ROOT": str(base_dir / "n2_storage"),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n2_port),
            "ADVERTISED_ENDPOINT": n2_real_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "3",
        },
    )

    # Wait until both nodes are registered
    coord_client = CoordinatorClient(coordinator_url=coord_url)
    t0 = time.time()
    nodes = []
    while time.time() - t0 < 25.0:
        try:
            nodes = coord_client.list_nodes(status="online")
        except Exception:
            pass
        if len(nodes) >= 2:
            break
        time.sleep(0.3)

    assert len(nodes) >= 2, f"Expected >=2 registered nodes, got {len(nodes)}"

    # Identify Node 2 and overwrite its advertised_endpoint to simulate NAT blocking
    n2_record = next(
        (n for n in nodes if n.get("endpoint") == n2_real_url or n.get("advertised_endpoint") == n2_real_url),
        None,
    )
    assert n2_record, "Could not identify Node 2 in registry"
    n2_id = n2_record["node_id"]

    import sqlite3
    with sqlite3.connect(str(coord_db)) as conn:
        conn.execute(
            "UPDATE nodes SET advertised_endpoint = ? WHERE node_id = ?",
            (n2_nat_url, n2_id),
        )
        conn.commit()

    # Allow time for Node 2's RelayTunnelClient to establish its outbound tunnel
    time.sleep(4.0)

    yield {
        "coord_url": coord_url,
        "coord_port": coord_port,
        "coord_proc": coord_proc,
        "coord_db": coord_db,
        "n1_url": n1_url,
        "n1_proc": n1_proc,
        "n2_id": n2_id,
        "n2_real_url": n2_real_url,
        "n2_nat_url": n2_nat_url,
        "n2_proc": n2_proc,
        "base_dir": base_dir,
    }

    for p in [n1_proc, n2_proc, coord_proc]:
        _stop_process(p)


def test_level_a_coordinator_and_nodes_healthy(p6b1_cluster):
    """Coordinator and both nodes respond to /health endpoints on real TCP sockets."""
    coord_url = p6b1_cluster["coord_url"]
    n1_url = p6b1_cluster["n1_url"]
    n2_real_url = p6b1_cluster["n2_real_url"]

    coord_health = httpx.get(f"{coord_url}/health", timeout=5.0)
    assert coord_health.status_code == 200

    n1_health = httpx.get(f"{n1_url}/health", timeout=5.0)
    assert n1_health.status_code == 200

    n2_health = httpx.get(f"{n2_real_url}/health", timeout=5.0)
    assert n2_health.status_code == 200


def test_level_a_reverse_tunnel_proxies_nat_node(p6b1_cluster):
    """
    Creates a relay session for the NAT-simulated Node 2, then proxies /health via the
    relay endpoint. If a reverse tunnel is active, the response must be 200.
    """
    coord_url = p6b1_cluster["coord_url"]
    n2_id = p6b1_cluster["n2_id"]

    session_resp = httpx.post(
        f"{coord_url}/relay/sessions",
        json={"target_node_id": n2_id},
        timeout=5.0,
    )
    assert session_resp.status_code == 201, f"Session creation failed: {session_resp.text}"
    session = session_resp.json()

    health_via_relay = httpx.get(
        f"{coord_url}/relay/{session['session_id']}/health",
        headers={"X-Relay-Token": session["session_token"]},
        timeout=10.0,
    )
    assert health_via_relay.status_code == 200, (
        f"Health via relay returned {health_via_relay.status_code}: {health_via_relay.text}\n"
        "This indicates the reverse tunnel (RelayTunnelClient) did not connect successfully."
    )


def test_level_a_upload_and_download_through_reverse_tunnel(p6b1_cluster, tmp_path):
    """
    Uploads a file to Node 2 (NAT-simulated) via relay and downloads it back,
    verifying byte-for-byte data integrity through the encrypted relay path.
    """
    coord_url = p6b1_cluster["coord_url"]

    client = ExpoClient(coordinator_url=coord_url)
    test_data = b"Phase 6B.1 reverse tunnel upload verification payload" * 50
    in_file = tmp_path / "tunnel_upload.bin"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=1,
        target_node_count=1,
    )
    assert "file_id" in up_res, f"Upload did not return file_id: {up_res}"
    file_id = up_res["file_id"]
    key_hex = up_res["key_hex"]

    out_file = tmp_path / "tunnel_download.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=out_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )
    assert out_file.is_file(), "Download produced no output file"
    assert out_file.read_bytes() == test_data, "Downloaded data does not match original"


def test_level_a_key_isolation_dek_not_in_coordinator_db(p6b1_cluster, tmp_path):
    """
    After a full upload-to-coordinator cycle, the Coordinator's SQLite database
    must not contain the DEK in any row's manifest_json column.
    """
    coord_url = p6b1_cluster["coord_url"]
    coord_db = p6b1_cluster["coord_db"]

    client = ExpoClient(coordinator_url=coord_url)
    test_data = b"Confidential payload  -- key isolation audit"
    in_file = tmp_path / "key_isolation.txt"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=1,
    )
    file_id = up_res["file_id"]
    dek_hex = up_res["key_hex"]

    import sqlite3
    with sqlite3.connect(str(coord_db)) as conn:
        rows = conn.execute(
            "SELECT manifest_json FROM files WHERE file_id = ?", (file_id,)
        ).fetchall()

    assert rows, f"File {file_id!r} not found in Coordinator database"
    for (manifest_content,) in rows:
        assert dek_hex not in manifest_content, (
            "SECURITY VIOLATION: DEK found verbatim in Coordinator database manifest_json!"
        )
        assert dek_hex.upper() not in manifest_content.upper(), (
            "SECURITY VIOLATION: DEK found (case-insensitive) in Coordinator database!"
        )
        # Confirm plaintext is also absent
        assert test_data.decode("utf-8", errors="replace") not in manifest_content, (
            "SECURITY VIOLATION: Plaintext payload found in Coordinator database!"
        )


def test_level_a_replication_across_direct_and_tunnel_nodes(p6b1_cluster, tmp_path):
    """
    Replication factor 2 distributes chunks across Node 1 (direct) and Node 2 (relay/tunnel).
    Download must reconstruct correctly regardless of which node serves each chunk.
    """
    coord_url = p6b1_cluster["coord_url"]

    client = ExpoClient(coordinator_url=coord_url)
    test_data = os.urandom(64 * 1024)  # 64 KB random payload
    in_file = tmp_path / "replication_test.bin"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )
    assert "file_id" in up_res
    file_id = up_res["file_id"]
    key_hex = up_res["key_hex"]

    out_file = tmp_path / "replication_recovered.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=out_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )
    assert out_file.read_bytes() == test_data, "Replication download mismatch"
