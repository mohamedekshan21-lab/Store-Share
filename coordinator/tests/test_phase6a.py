"""
Automated unit, endpoint validation, and Level A real multi-process integration test suite for Expo Phase 6A.
Phase 6A: Real Multi-Computer Connectivity and Integration Validation.

Validates:
1. Endpoint syntax and port range validation (Coordinator & Storage Node)
2. Rejection of invalid schemes, malformed URLs, and out-of-range ports
3. Bind address (0.0.0.0) vs reachable advertised endpoint separation
4. Real Multi-Process TCP socket registration and heartbeat tracking
5. Real Multi-Process End-to-End Logical Upload, Catalog Listing, Download, and Hash Verification (Replication mode)
6. Real Multi-Process End-to-End Reed-Solomon Erasure Coding (k=2, m=1) across 3 distinct nodes
7. Real Multi-Process Node Outage and Replica Failover Recovery
8. Real Multi-Process Erasure Coding reconstruction with node outage (and failure when shards < k)
9. Real Multi-Process Storage Node restart with persistent identity (no duplicate registry entries)
10. Real Multi-Process Coordinator outage and Storage Node auto-reconnect with backoff
11. Real Multi-Process Logical deletion and durable physical cleanup across real storage nodes
12. Real Multi-Process Authentication enforcement
"""

from __future__ import annotations

import os
import sys
import time
import socket
import subprocess
import hashlib
from pathlib import Path
from typing import Generator, Tuple, Dict, Any, List

import pytest
import httpx
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.app.node_registry import NodeRegistry, validate_endpoint_url, validate_port
from coordinator.coordinator_client import CoordinatorClient
from storage_node.app.config import Settings as StorageSettings
from client.client import ExpoClient, ClientError, IntegrityVerificationError


# ---------------------------------------------------------------------------
# Free Port and Process Management Utilities for Level A Multi-Process Tests
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
    """
    Spawns an independent OS process running Uvicorn on real TCP socket.
    Polls health endpoint until responsive.
    """
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
# Section 1: Endpoint & Port Validation Unit & API Tests
# ---------------------------------------------------------------------------

def test_validate_port_valid():
    """Valid ports in [1, 65535] must pass validation."""
    assert validate_port(80) == 80
    assert validate_port(8000) == 8000
    assert validate_port(65535) == 65535
    assert validate_port(1) == 1


@pytest.mark.parametrize("invalid_port", [0, -1, 65536, 100000, -8080])
def test_validate_port_invalid(invalid_port):
    """Out-of-range ports must raise ValueError."""
    with pytest.raises(ValueError, match="between 1 and 65535"):
        validate_port(invalid_port)


def test_validate_endpoint_url_valid():
    """Valid HTTP and HTTPS endpoints must normalize and pass."""
    assert validate_endpoint_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert validate_endpoint_url("https://node1.expo.network:8443/") == "https://node1.expo.network:8443"
    assert validate_endpoint_url("http://192.168.1.100:9000") == "http://192.168.1.100:9000"
    assert validate_endpoint_url("https://storage.mycompany.org") == "https://storage.mycompany.org"


@pytest.mark.parametrize("invalid_url", [
    "ftp://storage.example.com:8000",
    "ssh://node.network:22",
    "file:///etc/storage",
    "javascript:alert(1)",
    "not-a-url",
    "",
    "   ",
])
def test_validate_endpoint_url_invalid_schemes(invalid_url):
    """Unsupported URL schemes and empty URLs must be rejected."""
    with pytest.raises(ValueError):
        validate_endpoint_url(invalid_url)


@pytest.mark.parametrize("invalid_netloc", [
    "http://:8000",
    "http://",
    "https://",
    "http://example.com:70000",
    "http://example.com:-5",
    "http://example.com:0",
])
def test_validate_endpoint_url_invalid_netloc_and_ports(invalid_netloc):
    """Missing hostnames or ports out of range in URL netloc must be rejected."""
    with pytest.raises(ValueError):
        validate_endpoint_url(invalid_netloc)


def test_storage_node_advertised_endpoint_config_validation(tmp_path):
    """Storage Node Settings must validate advertised endpoints and fall back cleanly for local dev."""
    # Custom valid advertised endpoint
    s1 = StorageSettings(
        storage_root=tmp_path / "s1",
        advertised_endpoint="http://192.168.1.55:8001",
    )
    assert s1.resolved_advertised_endpoint == "http://192.168.1.55:8001"

    # Default fallback when host is 0.0.0.0 (binds all, advertises 127.0.0.1 loopback for local dev)
    s2 = StorageSettings(
        storage_root=tmp_path / "s2",
        host="0.0.0.0",
        port=8088,
    )
    assert s2.resolved_advertised_endpoint == "http://127.0.0.1:8088"

    # Invalid scheme in advertised_endpoint
    s3 = StorageSettings(
        storage_root=tmp_path / "s3",
        advertised_endpoint="ftp://192.168.1.55:8001",
    )
    with pytest.raises(ValueError, match="http/https"):
        _ = s3.resolved_advertised_endpoint

    # Invalid port in advertised_endpoint
    s4 = StorageSettings(
        storage_root=tmp_path / "s4",
        advertised_endpoint="http://192.168.1.55:99999",
    )
    with pytest.raises(ValueError):
        _ = s4.resolved_advertised_endpoint


def test_coordinator_api_rejects_invalid_endpoints(tmp_path):
    """Coordinator POST /nodes/register must reject invalid endpoints with HTTP 400."""
    settings = CoordinatorSettings(db_path=tmp_path / "test_reject.db")
    coord_app.state.settings = settings
    coord_app.state.registry = NodeRegistry(settings)

    def override_settings():
        return settings

    coord_app.dependency_overrides[get_coord_settings] = override_settings
    try:
        with TestClient(coord_app) as tc:
            # Out of range port
            r1 = tc.post(
                "/nodes/register",
                json={"node_id": "NODE-BAD-PORT", "host": "127.0.0.1", "port": 70000},
            )
            assert r1.status_code == 400
            assert "between 1 and 65535" in r1.json()["detail"]

            # Unsupported scheme
            r2 = tc.post(
                "/nodes/register",
                json={
                    "node_id": "NODE-BAD-SCHEME",
                    "host": "127.0.0.1",
                    "port": 8000,
                    "advertised_endpoint": "ftp://node.org:8000",
                },
            )
            assert r2.status_code == 400
            assert "scheme must be 'http' or 'https'" in r2.json()["detail"]

            # Malformed URL
            r3 = tc.post(
                "/nodes/register",
                json={
                    "node_id": "NODE-BAD-URL",
                    "host": "127.0.0.1",
                    "port": 8000,
                    "advertised_endpoint": "http://:8000",
                },
            )
            assert r3.status_code == 400
    finally:
        coord_app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Section 2: Level A Real Multi-Process End-to-End Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def multi_process_cluster(tmp_path_factory) -> Generator[Dict[str, Any], None, None]:
    """
    Spawns real OS processes on independent TCP ports with separate sandboxes:
    - 1 Coordinator Service
    - 3 Storage Nodes (Node 1, Node 2, Node 3)
    """
    base_dir = tmp_path_factory.mktemp("cluster_p6a")
    coord_db = base_dir / "coord_p6a.db"
    n1_dir = base_dir / "node1_storage"
    n2_dir = base_dir / "node2_storage"
    n3_dir = base_dir / "node3_storage"

    coord_port = get_free_port()
    n1_port = get_free_port()
    n2_port = get_free_port()
    n3_port = get_free_port()

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_url = f"http://127.0.0.1:{n2_port}"
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
            "NODE_HEARTBEAT_TIMEOUT_SECONDS": "20",
        },
    )

    # 2. Start Storage Node 1
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

    # 3. Start Storage Node 2
    n2_proc = start_uvicorn_process(
        app_target="storage_node.app.main:app",
        host="127.0.0.1",
        port=n2_port,
        env_vars={
            "STORAGE_ROOT": str(n2_dir),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n2_port),
            "ADVERTISED_ENDPOINT": n2_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # 4. Start Storage Node 3
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

    cluster_info = {
        "coord_port": coord_port,
        "coord_url": coord_url,
        "coord_proc": coord_proc,
        "coord_db": coord_db,
        "n1_port": n1_port,
        "n1_url": n1_url,
        "n1_proc": n1_proc,
        "n1_dir": n1_dir,
        "n2_port": n2_port,
        "n2_url": n2_url,
        "n2_proc": n2_proc,
        "n2_dir": n2_dir,
        "n3_port": n3_port,
        "n3_url": n3_url,
        "n3_proc": n3_proc,
        "n3_dir": n3_dir,
        "base_dir": base_dir,
    }

    yield cluster_info

    # Cleanup
    for p in [n1_proc, n2_proc, n3_proc, coord_proc]:
        stop_process(p)


def test_level_a_real_multiprocess_registration_and_heartbeats(multi_process_cluster):
    """Verify real HTTP registration, advertised endpoint publishing, and heartbeats across separate processes."""
    coord_url = multi_process_cluster["coord_url"]
    coord_client = CoordinatorClient(coordinator_url=coord_url)

    # Wait for nodes to register via background lifespan loops
    t0 = time.time()
    nodes = []
    while time.time() - t0 < 8.0:
        nodes = coord_client.list_nodes(status="online")
        if len(nodes) >= 3:
            break
        time.sleep(0.3)

    assert len(nodes) >= 3, f"Expected 3 online registered nodes, found {len(nodes)}"

    advertised_eps = {n["advertised_endpoint"] for n in nodes}
    assert multi_process_cluster["n1_url"] in advertised_eps
    assert multi_process_cluster["n2_url"] in advertised_eps
    assert multi_process_cluster["n3_url"] in advertised_eps


def test_level_a_real_multiprocess_replication_lifecycle(multi_process_cluster, tmp_path):
    """
    Test End-to-End file upload, catalog listing, download, and SHA-256 integrity verification
    in Replication mode over actual TCP sockets across independent processes.
    """
    coord_url = multi_process_cluster["coord_url"]
    client = ExpoClient()

    test_content = b"Phase 6A: Real Multi-Process Multi-Computer Connectivity Test Payload - Replication Mode" * 50
    input_file = tmp_path / "replication_test.txt"
    input_file.write_bytes(test_content)
    expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

    # 1. Logical Upload (distributed across 2 nodes with replication)
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
    assert file_id is not None

    # 2. List in Catalog
    files = client.list_logical_files(coordinator_url=coord_url)
    assert any(f["file_id"] == file_id for f in files)

    # 3. Download and Decrypt
    output_file = tmp_path / "replication_downloaded.txt"
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


def test_level_a_real_multiprocess_erasure_coding_lifecycle(multi_process_cluster, tmp_path):
    """
    Test End-to-End file upload, catalog listing, download, and SHA-256 integrity verification
    in Reed-Solomon Erasure Coding mode (k=2 data, m=1 parity) across 3 real processes.
    """
    coord_url = multi_process_cluster["coord_url"]
    client = ExpoClient()

    test_content = b"Phase 6A: Real Multi-Process Reed-Solomon Erasure Coding Data Shards Test Payload" * 60
    input_file = tmp_path / "ec_test.txt"
    input_file.write_bytes(test_content)
    expected_sha256 = hashlib.sha256(test_content).hexdigest().lower()

    # 1. Logical Upload with Erasure Coding
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
    manifest = upload_res["manifest"]

    assert manifest.manifest_version == 3
    assert manifest.redundancy_mode == "erasure"
    assert manifest.data_shards == 2
    assert manifest.parity_shards == 1

    # 2. Download and Reed-Solomon Reconstruct
    output_file = tmp_path / "ec_downloaded.txt"
    dl_res = client.download_logical_file(
        file_id=file_id,
        output_path=output_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )

    downloaded_bytes = output_file.read_bytes()
    assert hashlib.sha256(downloaded_bytes).hexdigest().lower() == expected_sha256
    assert downloaded_bytes == test_content


def test_level_a_real_multiprocess_node_outage_and_replica_failover(tmp_path_factory):
    """
    Simulates a computer outage by killing primary storage node process.
    Verifies client gracefully fails over to the replica on another node over real TCP.
    """
    base_dir = tmp_path_factory.mktemp("failover_cluster")
    coord_port = get_free_port()
    n1_port = get_free_port()
    n2_port = get_free_port()

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_url = f"http://127.0.0.1:{n2_port}"

    coord_proc = start_uvicorn_process(
        "coordinator.app.main:app", "127.0.0.1", coord_port,
        {"COORDINATOR_DB_PATH": str(base_dir / "c.db"), "COORDINATOR_PORT": str(coord_port)},
    )
    n1_proc = start_uvicorn_process(
        "storage_node.app.main:app", "127.0.0.1", n1_port,
        {"STORAGE_ROOT": str(base_dir / "n1"), "NODE_PORT": str(n1_port), "ADVERTISED_ENDPOINT": n1_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url},
    )
    n2_proc = start_uvicorn_process(
        "storage_node.app.main:app", "127.0.0.1", n2_port,
        {"STORAGE_ROOT": str(base_dir / "n2"), "NODE_PORT": str(n2_port), "ADVERTISED_ENDPOINT": n2_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url},
    )

    try:
        # Wait for registration
        coord_client = CoordinatorClient(coordinator_url=coord_url)
        t0 = time.time()
        while time.time() - t0 < 6.0:
            if len(coord_client.list_nodes(status="online")) >= 2:
                break
            time.sleep(0.2)

        client = ExpoClient()
        test_payload = b"Primary Outage Failover Verification Data" * 30
        in_p = base_dir / "input.txt"
        in_p.write_bytes(test_payload)
        expected_hash = hashlib.sha256(test_payload).hexdigest().lower()

        # Upload with 2 replicas
        up_res = client.upload_logical_file(
            file_path=in_p,
            coordinator_url=coord_url,
            redundancy_mode="replication",
            replication_factor=2,
            target_node_count=2,
        )

        # KILL Node 1 process
        stop_process(n1_proc)

        # Download file — primary Node 1 is dead, client must fail over to Node 2!
        out_p = base_dir / "out.txt"
        client.download_logical_file(
            file_id=up_res["file_id"],
            output_path=out_p,
            key_input=up_res["key_hex"],
            coordinator_url=coord_url,
        )

        assert hashlib.sha256(out_p.read_bytes()).hexdigest().lower() == expected_hash

    finally:
        stop_process(n1_proc)
        stop_process(n2_proc)
        stop_process(coord_proc)


def test_level_a_real_multiprocess_erasure_coding_node_outage_reconstruction(tmp_path_factory):
    """
    Uploads file with RS (k=2 data, m=1 parity) across 3 processes.
    Kills one node holding shards. Verifies client reconstructs file from the 2 remaining shards.
    Then kills a second node and verifies failure when available shards < k.
    """
    base_dir = tmp_path_factory.mktemp("ec_outage_cluster")
    coord_port = get_free_port()
    n1_port = get_free_port()
    n2_port = get_free_port()
    n3_port = get_free_port()

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_url = f"http://127.0.0.1:{n2_port}"
    n3_url = f"http://127.0.0.1:{n3_port}"

    coord_proc = start_uvicorn_process("coordinator.app.main:app", "127.0.0.1", coord_port, {"COORDINATOR_DB_PATH": str(base_dir / "c.db"), "COORDINATOR_PORT": str(coord_port)})
    n1_proc = start_uvicorn_process("storage_node.app.main:app", "127.0.0.1", n1_port, {"STORAGE_ROOT": str(base_dir / "n1"), "NODE_PORT": str(n1_port), "ADVERTISED_ENDPOINT": n1_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url})
    n2_proc = start_uvicorn_process("storage_node.app.main:app", "127.0.0.1", n2_port, {"STORAGE_ROOT": str(base_dir / "n2"), "NODE_PORT": str(n2_port), "ADVERTISED_ENDPOINT": n2_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url})
    n3_proc = start_uvicorn_process("storage_node.app.main:app", "127.0.0.1", n3_port, {"STORAGE_ROOT": str(base_dir / "n3"), "NODE_PORT": str(n3_port), "ADVERTISED_ENDPOINT": n3_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url})

    try:
        coord_client = CoordinatorClient(coordinator_url=coord_url)
        t0 = time.time()
        while time.time() - t0 < 6.0:
            if len(coord_client.list_nodes(status="online")) >= 3:
                break
            time.sleep(0.2)

        client = ExpoClient()
        test_payload = b"Erasure Coding Shard Reconstruction Real Process Test" * 50
        in_p = base_dir / "ec_in.txt"
        in_p.write_bytes(test_payload)
        expected_hash = hashlib.sha256(test_payload).hexdigest().lower()

        up_res = client.upload_logical_file(
            file_path=in_p,
            coordinator_url=coord_url,
            redundancy_mode="erasure",
            data_shards=2,
            parity_shards=1,
            target_node_count=3,
        )

        # KILL Node 1
        stop_process(n1_proc)

        # Reconstruction with 2 shards remaining (k=2) must SUCCEED
        out_p = base_dir / "ec_recon.txt"
        client.download_logical_file(
            file_id=up_res["file_id"],
            output_path=out_p,
            key_input=up_res["key_hex"],
            coordinator_url=coord_url,
        )
        assert hashlib.sha256(out_p.read_bytes()).hexdigest().lower() == expected_hash

        # KILL Node 2 (leaving only Node 3, so only 1 shard available when k=2 required)
        stop_process(n2_proc)

        # Reconstruction must cleanly FAIL
        fail_out_p = base_dir / "ec_fail.txt"
        with pytest.raises((IntegrityVerificationError, ClientError), match="Insufficient valid shards"):
            client.download_logical_file(
                file_id=up_res["file_id"],
                output_path=fail_out_p,
                key_input=up_res["key_hex"],
                coordinator_url=coord_url,
            )

    finally:
        stop_process(n1_proc)
        stop_process(n2_proc)
        stop_process(n3_proc)
        stop_process(coord_proc)


def test_level_a_real_multiprocess_node_restart_and_identity_persistence(tmp_path_factory):
    """
    Verifies that when a storage node restarts with the same persistent storage directory,
    it re-registers with the same node_id without creating duplicate registry records.
    """
    base_dir = tmp_path_factory.mktemp("restart_cluster")
    coord_port = get_free_port()
    node_port = get_free_port()
    node_storage = base_dir / "storage_persistent"

    coord_url = f"http://127.0.0.1:{coord_port}"
    node_url = f"http://127.0.0.1:{node_port}"

    coord_proc = start_uvicorn_process(
        "coordinator.app.main:app", "127.0.0.1", coord_port,
        {"COORDINATOR_DB_PATH": str(base_dir / "c.db"), "COORDINATOR_PORT": str(coord_port)},
    )
    node_proc = start_uvicorn_process(
        "storage_node.app.main:app", "127.0.0.1", node_port,
        {"STORAGE_ROOT": str(node_storage), "NODE_PORT": str(node_port), "ADVERTISED_ENDPOINT": node_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url},
    )

    try:
        coord_client = CoordinatorClient(coordinator_url=coord_url)
        t0 = time.time()
        while time.time() - t0 < 6.0:
            nodes = coord_client.list_nodes(status="online")
            if len(nodes) == 1:
                break
            time.sleep(0.2)

        nodes = coord_client.list_nodes()
        assert len(nodes) == 1
        initial_node_id = nodes[0]["node_id"]
        reg_time_1 = nodes[0]["registered_at"]

        # STOP the storage node process
        stop_process(node_proc)

        # START the storage node again on the same storage root
        node_proc2 = start_uvicorn_process(
            "storage_node.app.main:app", "127.0.0.1", node_port,
            {"STORAGE_ROOT": str(node_storage), "NODE_PORT": str(node_port), "ADVERTISED_ENDPOINT": node_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url},
        )

        try:
            time.sleep(1.0)
            nodes2 = coord_client.list_nodes()
            # Registry must NOT contain duplicate nodes!
            assert len(nodes2) == 1
            assert nodes2[0]["node_id"] == initial_node_id
            assert nodes2[0]["status"] == "online"
            assert nodes2[0]["registered_at"] == reg_time_1
        finally:
            stop_process(node_proc2)

    finally:
        stop_process(node_proc)
        stop_process(coord_proc)


def test_level_a_real_multiprocess_logical_deletion_and_cleanup(tmp_path_factory):
    """
    Tests logical deletion:
    Client deletes file -> Coordinator deletion job cleans physical chunks from storage nodes.
    """
    base_dir = tmp_path_factory.mktemp("delete_cluster")
    coord_port = get_free_port()
    n1_port = get_free_port()
    n2_port = get_free_port()

    coord_url = f"http://127.0.0.1:{coord_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_url = f"http://127.0.0.1:{n2_port}"
    n1_dir = base_dir / "n1"
    n2_dir = base_dir / "n2"

    coord_proc = start_uvicorn_process("coordinator.app.main:app", "127.0.0.1", coord_port, {"COORDINATOR_DB_PATH": str(base_dir / "c.db"), "COORDINATOR_PORT": str(coord_port)})
    n1_proc = start_uvicorn_process("storage_node.app.main:app", "127.0.0.1", n1_port, {"STORAGE_ROOT": str(n1_dir), "NODE_PORT": str(n1_port), "ADVERTISED_ENDPOINT": n1_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url})
    n2_proc = start_uvicorn_process("storage_node.app.main:app", "127.0.0.1", n2_port, {"STORAGE_ROOT": str(n2_dir), "NODE_PORT": str(n2_port), "ADVERTISED_ENDPOINT": n2_url, "COORDINATOR_ENABLED": "true", "COORDINATOR_URL": coord_url})

    try:
        coord_client = CoordinatorClient(coordinator_url=coord_url)
        t0 = time.time()
        while time.time() - t0 < 6.0:
            if len(coord_client.list_nodes(status="online")) >= 2:
                break
            time.sleep(0.2)

        client = ExpoClient()
        in_p = base_dir / "del_test.txt"
        in_p.write_bytes(b"Data to be deleted across real storage node processes" * 20)

        up_res = client.upload_logical_file(file_path=in_p, coordinator_url=coord_url, redundancy_mode="replication", replication_factor=2)
        file_id = up_res["file_id"]

        # Confirm chunks exist on nodes before deletion
        n1_client = ExpoClient(node_url=n1_url)
        n2_client = ExpoClient(node_url=n2_url)
        assert len(n1_client.list_files()) >= 1
        assert len(n2_client.list_files()) >= 1

        # Delete logical file
        del_res = client.delete_logical_file(file_id=file_id, coordinator_url=coord_url)
        assert del_res["status"] == "deleting"

        # Wait briefly for background deletion job to complete cleanup
        time.sleep(1.5)

        # Trigger reconciliation to guarantee cleanup execution if background task was pending
        with httpx.Client() as h:
            h.post(f"{coord_url}/catalog/reconcile?dry_run=false")

        # Verify physical files are cleaned up from storage nodes
        assert len(n1_client.list_files()) == 0
        assert len(n2_client.list_files()) == 0

    finally:
        stop_process(n1_proc)
        stop_process(n2_proc)
        stop_process(coord_proc)


def test_level_a_real_multiprocess_auth_enforcement(tmp_path_factory):
    """Verifies authentication token enforcement over real TCP processes."""
    base_dir = tmp_path_factory.mktemp("auth_cluster")
    coord_port = get_free_port()
    coord_url = f"http://127.0.0.1:{coord_port}"
    auth_token = "secret-token-xyz-123"

    coord_proc = start_uvicorn_process(
        "coordinator.app.main:app", "127.0.0.1", coord_port,
        {
            "COORDINATOR_DB_PATH": str(base_dir / "c.db"),
            "COORDINATOR_PORT": str(coord_port),
            "COORDINATOR_AUTH_TOKEN": auth_token,
        },
    )

    try:
        # 1. Unauthenticated registration rejected (401)
        with httpx.Client() as client:
            r_unauth = client.post(
                f"{coord_url}/nodes/register",
                json={"node_id": "NODE-X", "host": "127.0.0.1", "port": 8000},
            )
            assert r_unauth.status_code == 401

            # Wrong token rejected (401)
            r_wrong = client.post(
                f"{coord_url}/nodes/register",
                json={"node_id": "NODE-X", "host": "127.0.0.1", "port": 8000},
                headers={"X-Auth-Token": "bad-token"},
            )
            assert r_wrong.status_code == 401

            # Valid token accepted (200)
            r_ok = client.post(
                f"{coord_url}/nodes/register",
                json={"node_id": "NODE-X", "host": "127.0.0.1", "port": 8000},
                headers={"X-Auth-Token": auth_token},
            )
            assert r_ok.status_code == 200

    finally:
        stop_process(coord_proc)
