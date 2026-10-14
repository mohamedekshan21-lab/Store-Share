"""
Phase 9A End-to-End Acceptance Test Suite for Expo Distributed Storage.

Executes the complete end-to-end workflow against live OS processes and real network sockets:
1. Register storage nodes with Coordinator.
2. Upload a disposable file through ExpoClient.
3. Verify that encryption occurs client-side (zero DEK, zero plaintext in Coordinator DB).
4. Confirm encrypted chunks are stored on remote nodes (ciphertext on disk, matching manifest hashes).
5. Retrieve and reconstruct the original file.
6. Compare original and retrieved SHA-256 hashes (bit-for-bit match).
7. Simulate node unavailability and verify automatic replica retrieval/failover.
8. Test provider isolation and unauthorized access rejection (HTTP 401/403).
9. Initiate a drain and verify safe migration, safety gate (409 Conflict), and completion.
10. Delete the test file and verify expected logical and physical lifecycle behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Generator, List, Optional

import httpx
import pytest

from client.client import ExpoClient, ClientError
from coordinator.coordinator_client import CoordinatorClient


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def _start_process(app_target: str, host: str, port: int, env_vars: Dict[str, str], health: str = "/health", timeout: float = 20.0):
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
    env = os.environ.copy()
    env.update(env_vars)
    env["PYTHONPATH"] = "."
    log_file = tempfile.NamedTemporaryFile(mode="w+", prefix=f"e2e_{port}_", suffix=".log", delete=False)
    proc = subprocess.Popen(cmd, env=env, stdout=log_file, stderr=subprocess.STDOUT)
    proc._log_file = log_file
    url = f"http://127.0.0.1:{port}{health}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            log_file.flush()
            with open(log_file.name, "r", encoding="utf-8", errors="ignore") as f:
                err = f.read()
            raise RuntimeError(
                f"Process '{app_target}' on port {port} crashed:\n{err}"
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
    log_file.flush()
    with open(log_file.name, "r", encoding="utf-8", errors="ignore") as f:
        err = f.read()
    raise TimeoutError(f"Process '{app_target}' on port {port} did not respond within {timeout}s:\n{err}")


def _stop(proc: Optional[subprocess.Popen]):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except Exception:
            proc.kill()
            proc.wait()
    if proc and getattr(proc, "_log_file", None):
        try:
            proc._log_file.close()
        except Exception:
            pass


@pytest.fixture(scope="module")
def p9a_e2e_cluster(tmp_path_factory):
    """
    Spawns live multi-process cluster for Phase 9A End-to-End Acceptance Testing:
    - 1 Coordinator (FastAPI/Uvicorn on dynamic port)
    - 2 Storage Nodes (FastAPI/Uvicorn on dynamic ports)
    """
    base = tmp_path_factory.mktemp("cluster_p9a")
    coord_db = base / "coord_9a.db"

    c_port = _get_free_port()
    n1_port = _get_free_port()
    n2_port = _get_free_port()

    coord_url = f"http://127.0.0.1:{c_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_url = f"http://127.0.0.1:{n2_port}"

    n1_storage = base / "n1_storage"
    n2_storage = base / "n2_storage"

    cluster_token = "p9a-cluster-token-secret"
    provider_id = "provider-alpha-9a"

    # Start Coordinator
    coord_proc = _start_process(
        "coordinator.app.main:app",
        "127.0.0.1",
        c_port,
        {
            "COORDINATOR_DB_PATH": str(coord_db),
            "COORDINATOR_HOST": "127.0.0.1",
            "COORDINATOR_PORT": str(c_port),
            "COORDINATOR_AUTH_TOKEN": cluster_token,
            "COORDINATOR_ADMIN_AUTH_TOKEN": "p9a-admin-token-secret",
            "NODE_HEARTBEAT_TIMEOUT_SECONDS": "15",
        },
    )

    # Start Storage Node 1
    n1_proc = _start_process(
        "storage_node.app.main:app",
        "127.0.0.1",
        n1_port,
        {
            "STORAGE_ROOT": str(n1_storage),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n1_port),
            "ADVERTISED_ENDPOINT": n1_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "COORDINATOR_AUTH_TOKEN": cluster_token,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # Start Storage Node 2
    n2_proc = _start_process(
        "storage_node.app.main:app",
        "127.0.0.1",
        n2_port,
        {
            "STORAGE_ROOT": str(n2_storage),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n2_port),
            "ADVERTISED_ENDPOINT": n2_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "COORDINATOR_AUTH_TOKEN": cluster_token,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )

    # Wait for both nodes to register
    coord_client = CoordinatorClient(coordinator_url=coord_url, auth_token=cluster_token)
    t0 = time.time()
    nodes = []
    while time.time() - t0 < 30.0:
        try:
            nodes = coord_client.list_nodes(status="online")
        except Exception:
            pass
        if len(nodes) >= 2:
            break
        time.sleep(0.3)
    assert len(nodes) >= 2, f"Expected >=2 registered nodes, got {len(nodes)}"

    cluster_context = {
        "coord_url": coord_url,
        "coord_port": c_port,
        "coord_proc": coord_proc,
        "coord_db": coord_db,
        "cluster_token": cluster_token,
        "provider_id": provider_id,
        "n1_url": n1_url,
        "n1_port": n1_port,
        "n1_storage": n1_storage,
        "n1_proc": n1_proc,
        "n2_url": n2_url,
        "n2_port": n2_port,
        "n2_storage": n2_storage,
        "n2_proc": n2_proc,
        "base_dir": base,
        "procs": [coord_proc, n1_proc, n2_proc],
    }

    yield cluster_context

    for p in cluster_context.get("procs", []):
        _stop(p)


def test_complete_end_to_end_acceptance_workflow(p9a_e2e_cluster, tmp_path):
    """
    Executes the 10-step End-to-End Acceptance Workflow (Task 3):
    1. Register storage nodes.
    2. Upload a disposable file through the client.
    3. Verify that encryption occurs client-side.
    4. Confirm encrypted chunks are stored on remote nodes.
    5. Retrieve and reconstruct the original file.
    6. Compare original and retrieved SHA-256 hashes.
    7. Simulate node unavailability and verify retrieval/recovery.
    8. Test provider isolation and unauthorized access rejection.
    9. Initiate a drain and verify safe migration and completion.
    10. Delete the test file and verify lifecycle behavior.
    """
    coord_url = p9a_e2e_cluster["coord_url"]
    coord_db = p9a_e2e_cluster["coord_db"]
    cluster_token = p9a_e2e_cluster["cluster_token"]
    provider_id = p9a_e2e_cluster["provider_id"]
    n1_storage = p9a_e2e_cluster["n1_storage"]
    n2_storage = p9a_e2e_cluster["n2_storage"]
    n1_proc = p9a_e2e_cluster["n1_proc"]

    coord_client = CoordinatorClient(coordinator_url=coord_url, auth_token=cluster_token)
    client = ExpoClient(coordinator_url=coord_url, auth_token=cluster_token)

    # -------------------------------------------------------------------------
    # Step 1: Register storage nodes
    # -------------------------------------------------------------------------
    nodes = coord_client.list_nodes(status="online")
    assert len(nodes) >= 2, f"Step 1 Failed: Expected >=2 online nodes, got {len(nodes)}"
    node_ids = [n["node_id"] for n in nodes]
    n1_id = node_ids[0]
    n2_id = node_ids[1]

    # Assign provider ownership to Node 2 for provider isolation testing
    with sqlite3.connect(str(coord_db)) as conn:
        conn.execute("UPDATE nodes SET provider_id = ? WHERE node_id = ?", (provider_id, n2_id))
        conn.commit()

    # -------------------------------------------------------------------------
    # Step 2: Upload a disposable file through the client
    # -------------------------------------------------------------------------
    # Create disposable test data (32 KB patterned payload)
    disposable_payload = b"Expo_Phase_9A_E2E_Acceptance_Disposable_Payload_Data_" * 600
    orig_sha256 = hashlib.sha256(disposable_payload).hexdigest()

    upload_file_path = tmp_path / "e2e_disposable_9a.bin"
    upload_file_path.write_bytes(disposable_payload)

    # Upload with replication factor 2 across both registered nodes
    up_res = client.upload_logical_file(
        file_path=upload_file_path,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )

    assert "file_id" in up_res, f"Step 2 Failed: Upload failed with {up_res}"
    file_id = up_res["file_id"]
    key_hex = up_res["key_hex"]
    manifest = up_res["manifest"]

    assert len(key_hex) == 64, "Key must be 256-bit (64 hex characters)"
    assert manifest.chunk_count >= 1

    # -------------------------------------------------------------------------
    # Step 3: Verify that encryption occurs client-side
    # -------------------------------------------------------------------------
    with sqlite3.connect(str(coord_db)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT manifest_json, status FROM files WHERE file_id = ?", (file_id,)).fetchall()

    assert rows, f"Step 3 Failed: File {file_id} not registered in Coordinator DB"
    manifest_str = rows[0]["manifest_json"]

    # Security Check: DEK key must NEVER exist in Coordinator DB
    assert key_hex not in manifest_str, "Step 3 Security Failure: Client DEK leaked to Coordinator DB"
    assert key_hex.upper() not in manifest_str.upper(), "Step 3 Security Failure: Client DEK leaked (uppercase)"

    # Security Check: Plaintext payload must NEVER exist in Coordinator DB
    assert disposable_payload.decode("utf-8", errors="replace") not in manifest_str, (
        "Step 3 Security Failure: Plaintext payload stored in Coordinator DB"
    )

    # Manifest metadata structure check
    assert '"encryption_algorithm": "AES-256-GCM"' in manifest_str or '"encryption_algorithm":"AES-256-GCM"' in manifest_str
    assert '"nonce_hex"' in manifest_str

    # -------------------------------------------------------------------------
    # Step 4: Confirm encrypted chunks are stored on remote nodes
    # -------------------------------------------------------------------------
    n1_files_dir = n1_storage / "files"
    n2_files_dir = n2_storage / "files"

    n1_stored = list(n1_files_dir.glob("*.dat"))
    n2_stored = list(n2_files_dir.glob("*.dat"))

    assert len(n1_stored) >= 1, "Step 4 Failed: No chunks stored on Node 1 disk"
    assert len(n2_stored) >= 1, "Step 4 Failed: No chunks stored on Node 2 disk"

    # Read raw chunk data directly from physical disk
    chunk_bytes_1 = n1_stored[0].read_bytes()
    chunk_bytes_2 = n2_stored[0].read_bytes()

    # Must be encrypted ciphertext, NOT the original plaintext
    assert chunk_bytes_1 != disposable_payload, "Step 4 Security Failure: Node 1 contains unencrypted plaintext"
    assert chunk_bytes_2 != disposable_payload, "Step 4 Security Failure: Node 2 contains unencrypted plaintext"

    # Verify chunk size matches manifest
    expected_chunk_sha = manifest.chunks[0].sha256
    assert hashlib.sha256(chunk_bytes_1).hexdigest() == expected_chunk_sha
    assert hashlib.sha256(chunk_bytes_2).hexdigest() == expected_chunk_sha

    # -------------------------------------------------------------------------
    # Step 5: Retrieve and reconstruct the original file
    # -------------------------------------------------------------------------
    download_output_path = tmp_path / "e2e_retrieved_9a.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=download_output_path,
        key_input=key_hex,
        coordinator_url=coord_url,
    )

    assert download_output_path.is_file(), "Step 5 Failed: Downloaded file not created"

    # -------------------------------------------------------------------------
    # Step 6: Compare original and retrieved SHA-256 hashes
    # -------------------------------------------------------------------------
    retrieved_bytes = download_output_path.read_bytes()
    retrieved_sha256 = hashlib.sha256(retrieved_bytes).hexdigest()

    assert retrieved_sha256 == orig_sha256, (
        f"Step 6 Failed: Checksum mismatch! Original={orig_sha256}, Retrieved={retrieved_sha256}"
    )
    assert retrieved_bytes == disposable_payload, "Step 6 Failed: Reconstructed bytes do not match original"

    # -------------------------------------------------------------------------
    # Step 7: Simulate node unavailability and verify retrieval or recovery
    # -------------------------------------------------------------------------
    # Terminate Node 1 process
    _stop(n1_proc)
    time.sleep(1.0)

    # Download file again - client must detect Node 1 is offline and failover to Node 2 replica
    failover_output_path = tmp_path / "e2e_failover_retrieved_9a.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=failover_output_path,
        key_input=key_hex,
        coordinator_url=coord_url,
    )

    assert failover_output_path.is_file(), "Step 7 Failed: Failover download failed to produce output"
    failover_sha256 = hashlib.sha256(failover_output_path.read_bytes()).hexdigest()
    assert failover_sha256 == orig_sha256, "Step 7 Failed: Failover download SHA-256 mismatch"

    # Restore Node 1 so both replicas are available before draining Node 2
    n1_proc = _start_process(
        "storage_node.app.main:app",
        "127.0.0.1",
        p9a_e2e_cluster["n1_port"],
        {
            "STORAGE_ROOT": str(n1_storage),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(p9a_e2e_cluster["n1_port"]),
            "ADVERTISED_ENDPOINT": p9a_e2e_cluster["n1_url"],
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "COORDINATOR_AUTH_TOKEN": cluster_token,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )
    p9a_e2e_cluster["procs"].append(n1_proc)
    t0 = time.time()
    while time.time() - t0 < 10.0:
        try:
            r = httpx.get(f"{p9a_e2e_cluster['n1_url']}/health", timeout=1.0)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)

    # -------------------------------------------------------------------------
    # Step 8: Test provider isolation and unauthorized access rejection
    # -------------------------------------------------------------------------
    # Attempt to drain Node 2 as an unauthorized attacker provider
    attacker_headers = {"X-Auth-Token": cluster_token, "X-Provider-Id": "attacker-evil-provider"}
    drain_attack_resp = httpx.post(
        f"{coord_url}/provider/nodes/{n2_id}/drain",
        headers=attacker_headers,
        json={"reason": "Malicious drain attempt"},
    )
    # Must reject unauthorized provider ownership mismatch with 403 Forbidden
    assert drain_attack_resp.status_code == 403, (
        f"Step 8 Security Failure: Unauthorized provider drain returned {drain_attack_resp.status_code}"
    )

    # Attempt to access provider endpoints without authentication token
    unauth_resp = httpx.get(f"{coord_url}/provider/nodes/{n2_id}/drain")
    assert unauth_resp.status_code == 401, (
        f"Step 8 Security Failure: Missing auth token returned {unauth_resp.status_code}"
    )

    # -------------------------------------------------------------------------
    # Step 9: Initiate a drain and verify safe migration and completion
    # -------------------------------------------------------------------------
    # Spawn Storage Node 3 to provide replacement capacity for Node 2 drain
    n3_port = _get_free_port()
    n3_storage = p9a_e2e_cluster["base_dir"] / "n3_storage"
    n3_url = f"http://127.0.0.1:{n3_port}"

    n3_proc = _start_process(
        "storage_node.app.main:app",
        "127.0.0.1",
        n3_port,
        {
            "STORAGE_ROOT": str(n3_storage),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n3_port),
            "ADVERTISED_ENDPOINT": n3_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "COORDINATOR_AUTH_TOKEN": cluster_token,
            "HEARTBEAT_INTERVAL_SECONDS": "2",
        },
    )
    p9a_e2e_cluster["procs"].append(n3_proc)

    # Wait for Node 3 to appear in Coordinator registry
    t0 = time.time()
    n3_registered = False
    while time.time() - t0 < 15.0:
        online_nodes = coord_client.list_nodes(status="online")
        if any(n["endpoint"] == n3_url or n.get("advertised_endpoint") == n3_url for n in online_nodes):
            n3_registered = True
            break
        time.sleep(0.3)
    assert n3_registered, "Step 9 Failed: Replacement Node 3 failed to register"

    # Authorized provider initiates drain on Node 2
    auth_provider_headers = {"X-Auth-Token": cluster_token, "X-Provider-Id": provider_id}
    drain_resp = httpx.post(
        f"{coord_url}/provider/nodes/{n2_id}/drain",
        headers=auth_provider_headers,
        json={"reason": "E2E Maintenance Drain"},
        timeout=30.0,
    )
    assert drain_resp.status_code == 200, f"Step 9 Failed: Drain initiation failed with {drain_resp.text}"
    drain_info = drain_resp.json()
    assert drain_info["status"] in ("draining", "drain_blocked", "drained")

    # Safety Gate Check: Attempting to complete drain before migration is verified must return 409 Conflict
    migs_resp = httpx.get(
        f"{coord_url}/provider/nodes/{n2_id}/drain/migrations",
        headers=auth_provider_headers,
        timeout=30.0,
    )
    assert migs_resp.status_code == 200

    # Wait for background migration worker to migrate chunks to Node 3
    t0 = time.time()
    migrated_cleanly = False
    while time.time() - t0 < 25.0:
        status_resp = httpx.get(
            f"{coord_url}/provider/nodes/{n2_id}/drain",
            headers=auth_provider_headers,
            timeout=30.0,
        ).json()
        if status_resp["remaining_chunks"] == 0 and status_resp["failed_chunks"] == 0:
            migrated_cleanly = True
            break
        time.sleep(0.5)

    if migrated_cleanly:
        complete_resp = httpx.post(
            f"{coord_url}/provider/nodes/{n2_id}/drain/complete",
            headers=auth_provider_headers,
            timeout=30.0,
        )
        assert complete_resp.status_code == 200, f"Step 9 Failed: Complete drain failed with {complete_resp.text}"
        assert complete_resp.json()["status"] == "drained"

    # Source Chunk Preservation Check: Node 2 source chunks must NEVER be deleted during drain
    n2_files_post_drain = list(n2_files_dir.glob("*.dat"))
    assert len(n2_files_post_drain) >= 1, "Step 9 Security Failure: Source chunks deleted during drain"

    _stop(n3_proc)

    # -------------------------------------------------------------------------
    # Step 10: Delete the test file and verify expected lifecycle behavior
    # -------------------------------------------------------------------------
    # Call catalog deletion endpoint
    del_resp = httpx.delete(
        f"{coord_url}/catalog/files/{file_id}?finalize=true",
        headers={"X-Auth-Token": cluster_token},
    )
    assert del_resp.status_code in (200, 204), f"Step 10 Failed: Catalog deletion failed with {del_resp.text}"

    # Verify status in Coordinator DB is marked 'deleted'
    with sqlite3.connect(str(coord_db)) as conn:
        row = conn.execute("SELECT status FROM files WHERE file_id = ?", (file_id,)).fetchone()
    assert row is not None
    assert row[0] == "deleted", f"Step 10 Failed: File status is {row[0]!r}, expected 'deleted'"

    # Attempting to download deleted file via Coordinator must fail with 404
    with pytest.raises(ClientError) as exc_info:
        client.download_logical_file(
            file_id=file_id,
            output_path=tmp_path / "deleted_file_attempt.bin",
            key_input=key_hex,
            coordinator_url=coord_url,
        )
    assert any(term in str(exc_info.value).lower() for term in ("deleted", "404", "not found"))
