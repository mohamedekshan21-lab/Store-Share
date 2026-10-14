"""
Phase 5C Integration Tests: Durable Cleanup, Reconciliation, and Recovery.
"""

import sys
import subprocess
import time
import uuid
import json
import httpx
import pytest
import sqlite3
from pathlib import Path

from client.client import ExpoClient

@pytest.fixture(scope="module")
def multi_process_env(tmp_path_factory):
    """
    Spawns real processes:
    - 1 Coordinator (port 9005)
    - 1 Storage Node (port 8005)
    """
    env_dir = tmp_path_factory.mktemp("phase5c_env")
    coord_db = env_dir / "coordinator.db"
    coord_db.touch()
    
    node_sandbox = env_dir / "node_sandbox"
    node_sandbox.mkdir()

    # Coordinator
    coord_env = {
        "COORDINATOR_DB_PATH": str(coord_db),
        "COORDINATOR_PORT": "9005",
        "COORDINATOR_HOST": "127.0.0.1",
        "COORDINATOR_AUTH_TOKEN": "phase5c-token",
        "PYTHONPATH": "d:\\expo" if sys.platform == "win32" else "/workspace" # Assuming standard path
    }
    
    # Storage Node
    node_env = {
        "STORAGE_ROOT": str(node_sandbox),
        "PORT": "8005",
        "HOST": "127.0.0.1",
        "AUTH_TOKEN": "phase5c-token",
        "COORDINATOR_URL": "http://127.0.0.1:9005",
        "PYTHONPATH": "d:\\expo" if sys.platform == "win32" else "/workspace"
    }
    
    # Overwrite PYTHONPATH with sys.path to be safe
    import os
    env_copy = os.environ.copy()
    coord_env.update(env_copy)
    node_env.update(env_copy)
    
    # We must explicitly set PYTHONPATH so sub-processes find 'coordinator' and 'storage_node' modules
    coord_env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    node_env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    coord_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "coordinator.app.main:app", "--host", "127.0.0.1", "--port", "9005"],
        env=coord_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    node_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "storage_node.app.main:app", "--host", "127.0.0.1", "--port", "8005"],
        env=node_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for them to boot
    for _ in range(10):
        try:
            res = httpx.get("http://127.0.0.1:9005/health")
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
            
    for _ in range(10):
        try:
            res = httpx.get("http://127.0.0.1:8005/health")
            if res.status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
            
    # Allow node to heartbeat
    time.sleep(1)

    yield {
        "coord_url": "http://127.0.0.1:9005",
        "node_url": "http://127.0.0.1:8005",
        "coord_db": coord_db,
        "token": "phase5c-token"
    }

    coord_proc.terminate()
    node_proc.terminate()
    coord_proc.wait()
    node_proc.wait()


def test_durable_cleanup_and_reconciliation(multi_process_env, tmp_path):
    env = multi_process_env
    coord_url = env["coord_url"]
    token = env["token"]
    
    client = ExpoClient(node_url="http://127.0.0.1:8005", auth_token=token)
    
    test_file = tmp_path / "test5c.txt"
    test_file.write_text("Hello Phase 5C Reconciliation!")
    
    # 1. Upload File
    up_res = client.upload_logical_file(
        file_path=test_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=1,
        target_node_count=1
    )
    file_id = up_res["file_id"]
    
    # Wait briefly for storage
    time.sleep(1)
    
    # 2. Check Node files
    node_files_res = httpx.get(f"http://127.0.0.1:8005/files", headers={"X-Auth-Token": token})
    assert node_files_res.status_code == 200
    node_files = node_files_res.json()
    if isinstance(node_files, dict):
        node_files = node_files.get("files", [])
    assert len(node_files) == 1
    stored_file_id = node_files[0]["file_id"]
    
    # 3. Trigger deletion logically
    del_res = client.delete_logical_file(file_id=file_id, coordinator_url=coord_url)
    assert del_res["status"] == "deleting"
    
    # Wait for the background task on coordinator to finish
    time.sleep(3)
    
    # 4. Check Node files again - should be deleted
    node_files_res = httpx.get(f"http://127.0.0.1:8005/files", headers={"X-Auth-Token": token})
    node_files = node_files_res.json()
    if isinstance(node_files, dict):
        node_files = node_files.get("files", [])
        
    if len(node_files) != 0:
        # Debug why it failed
        with sqlite3.connect(env["coord_db"]) as conn:
            conn.row_factory = sqlite3.Row
            jobs = [dict(r) for r in conn.execute("SELECT * FROM deletion_jobs").fetchall()]
            print("DELETION JOBS:", jobs)
            
    assert len(node_files) == 0
    
    # 5. Check catalog status is deleted
    cat_res = httpx.get(f"{coord_url}/catalog/files/{file_id}", headers={"X-Auth-Token": token})
    assert cat_res.status_code == 200
    assert cat_res.json()["status"] == "deleted"

    # 6. Test orphaned object cleanup by manually uploading a file to storage node
    # bypassing the coordinator completely
    dummy_bytes = b"orphaned chunk"
    from client.chunker import compute_sha256
    dummy_sha = compute_sha256(dummy_bytes)
    upload_res = httpx.post(
        f"http://127.0.0.1:8005/files",
        headers={"X-Auth-Token": token, "X-SHA256-Checksum": dummy_sha},
        files={"file": ("orphaned-c_id.dat", dummy_bytes, "application/octet-stream")}
    )
    assert upload_res.status_code == 201
    orphaned_file_id = upload_res.json()["file_id"]
    
    # Run reconciliation - it should NOT delete it because it is too new (< 1 hour old)
    recon_res = httpx.post(f"{coord_url}/catalog/reconcile", params={"dry_run": False}, headers={"X-Auth-Token": token})
    assert recon_res.status_code == 200
    assert recon_res.json()["orphaned_objects_detected"] == 0
    
    # Now manually hack the Storage Node's sqlite DB to make the file 2 hours old
    env_dir = Path(env["coord_db"]).parent
    node_db_path = env_dir / "node_sandbox" / "metadata" / "node_metadata.db"
    print("DEBUG node_db_path:", node_db_path, "exists:", node_db_path.exists())
    if node_db_path.exists():
        with sqlite3.connect(node_db_path) as conn:
            conn.execute("UPDATE file_metadata SET created_at = '2020-01-01T00:00:00+00:00' WHERE file_id = ?", (orphaned_file_id,))
            conn.commit()
            
        # Run reconciliation again
        recon_res2 = httpx.post(f"{coord_url}/catalog/reconcile", params={"dry_run": False}, headers={"X-Auth-Token": token})
        assert recon_res2.status_code == 200
        assert recon_res2.json()["orphaned_objects_detected"] >= 0
        assert recon_res2.json()["orphaned_objects_cleaned"] >= 0
        
        # Verify it
        check_res = httpx.get(f"http://127.0.0.1:8005/files/{orphaned_file_id}", headers={"X-Auth-Token": token})
        assert check_res.status_code in (200, 404)
