"""
Phase 10B Storage Node Security Tests.
Covers:
1. Cryptographic HMAC capability verification (signature, tampering, expiry).
2. Capability scoping (operation isolation, chunk binding, node binding).
3. Upload replay prevention (consumed JTI tracking with 409 Conflict).
4. Download authorization & non-probing (401/403 before file existence check).
5. Delete authorization (upload/download capabilities cannot delete).
6. Chunk enumeration protection (GET /files restricted from consumers).
7. Atomic quota reservations under concurrent uploads (preventing TOCTOU races).
8. Cleanup of reservations and temporary files upon failed/aborted uploads.
"""

from __future__ import annotations

import io
import multiprocessing
import os
import threading
import time
import uuid
import pytest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient

from storage_node.app.config import Settings
from storage_node.app.main import app, get_manager
from storage_node.app.storage_manager import StorageManager, QuotaExceededError, WriterLock
from storage_node.app.capability import (
    create_capability,
    verify_capability,
    CapabilityToken,
    InvalidCapabilitySignatureError,
    ExpiredCapabilityError,
    ScopeMismatchCapabilityError,
    MalformedCapabilityError,
)


def _mp_worker_reserve_quota(settings_dict: dict, q: multiprocessing.Queue):
    """Worker process function to test cross-process quota contention."""
    try:
        settings = Settings(**settings_dict)
        mgr = StorageManager(settings)
        res_id = mgr.reserve_quota(10 * 1024)
        q.put(("success", res_id))
    except Exception as e:
        q.put(("fail", type(e).__name__, str(e)))


def _mp_worker_active_upload(settings_dict: dict, temp_name: str, q_ready: multiprocessing.Queue, q_done: multiprocessing.Queue):
    """Worker process holding an active upload lock and reservation."""
    try:
        settings = Settings(**settings_dict)
        mgr = StorageManager(settings)
        res_id = mgr.reserve_quota(5000, temp_filename=temp_name)
        temp_file = mgr.temp_dir / temp_name
        lock_file = mgr.temp_dir / (temp_name.replace(".tmp", "") + ".lock")
        temp_file.write_bytes(b"active in-flight chunk upload payload")
        with WriterLock(lock_file):
            q_ready.put(("ready", res_id, os.getpid()))
            q_done.get()
    except Exception as e:
        q_ready.put(("error", str(e)))


def _mp_worker_abandoned_upload(settings_dict: dict, temp_name: str, q_ready: multiprocessing.Queue):
    """Worker process creating reservation and holding lock until forcefully terminated."""
    try:
        settings = Settings(**settings_dict)
        mgr = StorageManager(settings)
        res_id = mgr.reserve_quota(5000, temp_filename=temp_name)
        temp_file = mgr.temp_dir / temp_name
        lock_file = mgr.temp_dir / (temp_name.replace(".tmp", "") + ".lock")
        temp_file.write_bytes(b"abandoned upload chunk payload")
        lock = WriterLock(lock_file)
        lock.__enter__()
        q_ready.put(("ready", res_id, os.getpid()))
        time.sleep(300)
    except Exception as e:
        q_ready.put(("error", str(e)))


@pytest.fixture
def secret() -> str:
    return "test-capability-secret-key-32bytes-entropy-minimum!"


@pytest.fixture
def secure_bundle(tmp_path: Path, secret: str):
    settings = Settings(
        storage_root=tmp_path / "secure_sandbox",
        storage_quota_gb=0.0001,  # ~100 KB
        capability_secret=secret,
        auth_token="coord-internal-secret-token",
        environment="production",
    )
    manager = StorageManager(settings)
    app.dependency_overrides[get_manager] = lambda: manager
    app.state.settings = settings
    client = TestClient(app)
    yield client, manager, settings
    app.dependency_overrides.clear()


# ============================================================================
# 1. Capability Token Unit Tests
# ============================================================================

def test_capability_token_creation_and_verification(secret: str):
    chunk_id = str(uuid.uuid4())
    account_id = str(uuid.uuid4())
    test_node_id = "NODE-UNIT-10B"

    raw_token = create_capability(
        secret=secret,
        node_id=test_node_id,
        chunk_id=chunk_id,
        op="upload",
        account_id=account_id,
        ttl_seconds=60,
        expected_size=1024,
        expected_sha256="aabbcc",
    )

    token = verify_capability(
        token_str=raw_token,
        secret=secret,
        expected_node_id=test_node_id,
        expected_chunk_id=chunk_id,
        expected_op="upload",
    )
    assert token.chunk_id == chunk_id
    assert token.node_id == test_node_id
    assert token.op == "upload"
    assert token.account_id == account_id
    assert token.expected_size == 1024
    assert token.expected_sha256 == "aabbcc"


def test_capability_signature_tampering_rejected(secret: str):
    chunk_id = str(uuid.uuid4())
    test_node_id = "NODE-UNIT-10B"
    raw_token = create_capability(
        secret=secret,
        node_id=test_node_id,
        chunk_id=chunk_id,
        op="download",
    )

    # Tampered signature
    parts = raw_token.split(".")
    tampered_sig = parts[0] + "." + parts[1] + ".invalidSig=="
    with pytest.raises(InvalidCapabilitySignatureError):
        verify_capability(
            token_str=tampered_sig,
            secret=secret,
            expected_node_id=test_node_id,
            expected_chunk_id=chunk_id,
            expected_op="download",
        )

    # Wrong secret
    with pytest.raises(InvalidCapabilitySignatureError):
        verify_capability(
            token_str=raw_token,
            secret="different-secret-key-altogether!",
            expected_node_id=test_node_id,
            expected_chunk_id=chunk_id,
            expected_op="download",
        )


def test_capability_expiration_enforced(secret: str):
    chunk_id = str(uuid.uuid4())
    test_node_id = "NODE-UNIT-10B"
    # Create expired token
    raw_token = create_capability(
        secret=secret,
        node_id=test_node_id,
        chunk_id=chunk_id,
        op="upload",
        ttl_seconds=-10,  # Expired 10 seconds ago
    )

    with pytest.raises(ExpiredCapabilityError):
        verify_capability(
            token_str=raw_token,
            secret=secret,
            expected_node_id=test_node_id,
            expected_chunk_id=chunk_id,
            expected_op="upload",
        )


def test_capability_scope_mismatch_rejected(secret: str):
    chunk_a = str(uuid.uuid4())
    chunk_b = str(uuid.uuid4())
    test_node_id = "NODE-UNIT-10B"

    raw_token = create_capability(
        secret=secret,
        node_id=test_node_id,
        chunk_id=chunk_a,
        op="upload",
    )

    # Operation mismatch: upload capability cannot be used for download
    with pytest.raises(ScopeMismatchCapabilityError, match="operation mismatch"):
        verify_capability(
            token_str=raw_token,
            secret=secret,
            expected_node_id=test_node_id,
            expected_chunk_id=chunk_a,
            expected_op="download",
        )

    # Chunk ID mismatch: capability for chunk_a cannot be used for chunk_b
    with pytest.raises(ScopeMismatchCapabilityError, match="chunk mismatch"):
        verify_capability(
            token_str=raw_token,
            secret=secret,
            expected_node_id=test_node_id,
            expected_chunk_id=chunk_b,
            expected_op="upload",
        )

    # Node ID mismatch: capability for test_node_id cannot be used for other node
    with pytest.raises(ScopeMismatchCapabilityError, match="node mismatch"):
        verify_capability(
            token_str=raw_token,
            secret=secret,
            expected_node_id="NODE-OTHER-99",
            expected_chunk_id=chunk_a,
            expected_op="upload",
        )


# ============================================================================
# 2. Storage Node Route Authorization & Protection Tests
# ============================================================================

def test_upload_requires_valid_capability_in_production(secure_bundle, secret: str):
    client, manager, _ = secure_bundle
    chunk_id = str(uuid.uuid4())
    content = b"Phase 10B protected chunk data payload"

    # 1. Upload without capability in production -> 401
    res = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
    )
    assert res.status_code == 401

    # 2. Upload with download capability -> 403 Forbidden
    down_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="download")
    res = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": down_cap},
    )
    assert res.status_code == 403
    assert "operation mismatch" in res.json()["detail"].lower()

    # 3. Upload with valid upload capability -> 201 Created
    up_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="upload")
    res = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )
    assert res.status_code == 201
    assert res.json()["file_id"] == chunk_id


def test_upload_replay_protection_enforces_one_time_use(secure_bundle, secret: str):
    client, manager, _ = secure_bundle
    chunk_id = str(uuid.uuid4())
    content = b"Replay test payload"
    up_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="upload")

    # First use -> 201 Created
    res1 = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )
    assert res1.status_code == 201

    # Replay same upload capability -> 409 Conflict
    res2 = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )
    assert res2.status_code == 409
    assert "already been consumed" in res2.json()["detail"].lower()


def test_download_authorization_and_non_probing(secure_bundle, secret: str):
    client, manager, _ = secure_bundle
    chunk_id = str(uuid.uuid4())
    content = b"Chunk payload for download verification"

    # Store chunk first
    up_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="upload")
    r_up = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )
    assert r_up.status_code == 201

    # Download with upload capability -> 403 Forbidden
    r_wrong_op = client.get(
        f"/files/{chunk_id}",
        headers={"X-Capability-Token": up_cap},
    )
    assert r_wrong_op.status_code == 403

    # Download with valid download capability -> 200 OK
    down_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="download")
    r_down = client.get(
        f"/files/{chunk_id}",
        headers={"X-Capability-Token": down_cap},
    )
    assert r_down.status_code == 200
    assert r_down.content == content

    # Non-probing behavior: Requesting a non-existent chunk WITHOUT valid capability returns 401/403, NOT 404
    non_existent = str(uuid.uuid4())
    r_probe_no_cap = client.get(f"/files/{non_existent}")
    assert r_probe_no_cap.status_code in (401, 403)
    assert r_probe_no_cap.status_code != 404

    # Non-probing with capability for a DIFFERENT chunk -> returns 403 Forbidden, NOT 404
    r_probe_mismatch = client.get(
        f"/files/{non_existent}",
        headers={"X-Capability-Token": down_cap},  # down_cap is for chunk_id, not non_existent
    )
    assert r_probe_mismatch.status_code == 403
    assert r_probe_mismatch.status_code != 404


def test_delete_authorization(secure_bundle, secret: str):
    client, manager, _ = secure_bundle
    chunk_id = str(uuid.uuid4())
    content = b"Chunk payload for delete authorization test"

    up_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="upload")
    client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )

    down_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="download")
    del_cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="delete")

    # Download capability cannot delete
    r_fail = client.delete(f"/files/{chunk_id}", headers={"X-Capability-Token": down_cap})
    assert r_fail.status_code == 403

    # Upload capability cannot delete
    r_fail_up = client.delete(f"/files/{chunk_id}", headers={"X-Capability-Token": up_cap})
    assert r_fail_up.status_code == 403

    # Delete capability deletes successfully
    r_del = client.delete(f"/files/{chunk_id}", headers={"X-Capability-Token": del_cap})
    assert r_del.status_code == 200
    assert r_del.json()["status"] == "deleted"


def test_chunk_enumeration_prevented_for_consumers(secure_bundle, secret: str):
    client, manager, _ = secure_bundle
    # Ordinary user with capability cannot list files
    cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=str(uuid.uuid4()), op="download")
    r_enum_cap = client.get("/files", headers={"X-Capability-Token": cap})
    assert r_enum_cap.status_code == 403

    # Request without coordinator token is rejected
    r_no_auth = client.get("/files")
    assert r_no_auth.status_code == 401

    # Request with valid coordinator internal token is accepted
    r_coord = client.get("/files", headers={"X-Auth-Token": "coord-internal-secret-token"})
    assert r_coord.status_code == 200
    assert isinstance(r_coord.json(), list)


# ============================================================================
# 3. Atomic Quota Enforcement & Concurrency Tests
# ============================================================================

def test_atomic_quota_reservation_under_concurrent_uploads(tmp_path: Path, secret: str):
    # Set quota to 15 KB strictly
    quota_bytes = 15 * 1024
    node_settings = Settings(
        storage_root=tmp_path / "quota_sandbox",
        storage_quota_gb=quota_bytes / (1024 ** 3),
        capability_secret=secret,
        environment="development",
    )
    manager = StorageManager(node_settings)
    app.dependency_overrides[get_manager] = lambda: manager
    app.state.settings = node_settings
    client = TestClient(app)

    # Prepare two 10 KB payloads. 10 KB + 10 KB = 20 KB > 15 KB quota!
    payload_size = 10 * 1024
    content = b"X" * payload_size

    chunk_1 = str(uuid.uuid4())
    chunk_2 = str(uuid.uuid4())

    cap_1 = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_1, op="upload", expected_size=payload_size)
    cap_2 = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_2, op="upload", expected_size=payload_size)

    results = []

    def run_upload(cid, cap):
        try:
            res = client.post(
                "/files",
                files={"file": (f"{cid}.dat", io.BytesIO(content), "application/octet-stream")},
                headers={"X-Capability-Token": cap},
            )
            return res.status_code
        except Exception as e:
            return str(e)

    # Launch concurrently
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_upload, chunk_1, cap_1)
        f2 = executor.submit(run_upload, chunk_2, cap_2)
        results = [f1.result(), f2.result()]

    app.dependency_overrides.clear()

    # Exactly one must succeed (201) and one must be rejected for quota (507)
    assert 201 in results, f"Expected one upload to succeed, got results: {results}"
    assert 507 in results, f"Expected one upload to fail with 507 Quota Exceeded, got: {results}"

    # Verify storage usage never exceeded quota
    assert manager.get_used_bytes() <= quota_bytes
    assert manager.get_active_reserved_bytes() == 0


def test_aborted_upload_releases_reservation_and_cleans_tmp(tmp_path: Path, secret: str):
    node_settings = Settings(
        storage_root=tmp_path / "abort_sandbox",
        storage_quota_gb=0.001,
        capability_secret=secret,
    )
    manager = StorageManager(node_settings)

    class FailingStream(io.BytesIO):
        def read(self, size=-1):
            chunk = super().read(min(size, 1024))
            if self.tell() > 2048:
                raise ConnectionResetError("Client disconnected mid-stream")
            return chunk

    corrupt_data = b"Y" * (8 * 1024)
    stream = FailingStream(corrupt_data)
    chunk_id = str(uuid.uuid4())

    with pytest.raises(ConnectionResetError):
        manager.save_file(
            file_obj=stream,
            original_filename=f"{chunk_id}.dat",
            file_id=chunk_id,
            expected_size=len(corrupt_data),
        )

    # Verification: Reservation released and 0 bytes used
    assert manager.get_used_bytes() == 0
    assert manager.get_active_reserved_bytes() == 0

    # Verification: No orphaned .tmp files remain in temp_dir
    tmp_files = list(manager.temp_dir.glob("*.tmp"))
    assert len(tmp_files) == 0


def test_storage_manager_startup_reconciles_stale_reservations(tmp_path: Path, secret: str):
    node_settings = Settings(
        storage_root=tmp_path / "restart_sandbox",
        storage_quota_gb=0.001,
        capability_secret=secret,
    )
    manager = StorageManager(node_settings)

    # Manually inject an active reservation and an orphaned .tmp file in temp_dir
    res_id = manager.reserve_quota(5000)
    orphan_tmp = manager.temp_dir / "stale_upload.tmp"
    orphan_tmp.write_bytes(b"stale data bytes" * 100)

    assert manager.get_active_reserved_bytes() == 5000
    assert orphan_tmp.is_file()

    # Re-initialize StorageManager (simulating process restart)
    restarted_manager = StorageManager(node_settings)

    # Stale reservations cleared and orphaned .tmp file removed
    assert restarted_manager.get_active_reserved_bytes() == 0
    assert not orphan_tmp.exists()


def test_concurrent_upload_replay_rejected_with_409(tmp_path: Path, secret: str):
    """Verifies two simultaneous upload requests with the same capability cannot bypass replay protection."""
    node_settings = Settings(
        storage_root=tmp_path / "concurrent_replay_sandbox",
        storage_quota_gb=1.0,
        capability_secret=secret,
        environment="production",
    )
    manager = StorageManager(node_settings)
    app.dependency_overrides[get_manager] = lambda: manager
    app.state.settings = node_settings
    client = TestClient(app)

    chunk_id = str(uuid.uuid4())
    cap = create_capability(secret=secret, node_id=manager.node_id, chunk_id=chunk_id, op="upload")
    content = b"Simultaneous upload test data"

    barrier = threading.Barrier(2)
    results = []

    def do_upload():
        try:
            barrier.wait(timeout=5)
            r = client.post(
                "/files",
                files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
                headers={"X-Capability-Token": cap},
            )
            return r.status_code
        except Exception:
            return 500

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(do_upload)
        f2 = ex.submit(do_upload)
        results = [f1.result(), f2.result()]

    app.dependency_overrides.clear()
    assert 201 in results, f"Expected one upload to succeed, got: {results}"
    assert 409 in results, f"Expected concurrent replay to fail with 409, got: {results}"


def test_cross_process_quota_contention_separate_processes(tmp_path: Path, secret: str):
    """Verifies that two independent OS processes sharing one storage root cannot oversubscribe quota."""
    quota_bytes = 15 * 1024  # 15 KB quota
    settings_dict = {
        "storage_root": tmp_path / "cross_process_quota_sandbox",
        "storage_quota_gb": quota_bytes / (1024 ** 3),
        "capability_secret": secret,
        "environment": "development",
    }
    # Initialize DB first
    initial_settings = Settings(**settings_dict)
    StorageManager(initial_settings)

    q = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=_mp_worker_reserve_quota, args=(settings_dict, q))
    p2 = multiprocessing.Process(target=_mp_worker_reserve_quota, args=(settings_dict, q))
    p1.start()
    p2.start()
    p1.join(timeout=10)
    p2.join(timeout=10)

    results = [q.get(timeout=2), q.get(timeout=2)]
    statuses = [r[0] for r in results]

    # Exactly one process must succeed, and one must fail with QuotaExceededError
    assert "success" in statuses, f"Expected one process to successfully reserve, got: {results}"
    assert "fail" in statuses, f"Expected one process to fail with QuotaExceededError, got: {results}"

    mgr = StorageManager(initial_settings)
    assert mgr.get_active_reserved_bytes() <= quota_bytes


def test_active_upload_surviving_another_worker_startup_separate_processes(tmp_path: Path, secret: str):
    """Verifies starting a second worker cannot delete a temporary file or reservation belonging to an active worker."""
    settings_dict = {
        "storage_root": tmp_path / "startup_survival_sandbox",
        "storage_quota_gb": 1.0,
        "capability_secret": secret,
        "environment": "development",
    }
    initial_settings = Settings(**settings_dict)
    StorageManager(initial_settings)

    q_ready = multiprocessing.Queue()
    q_done = multiprocessing.Queue()
    p_active = multiprocessing.Process(
        target=_mp_worker_active_upload,
        args=(settings_dict, "active_writer.tmp", q_ready, q_done)
    )
    p_active.start()

    msg = q_ready.get(timeout=5)
    assert msg[0] == "ready", f"Worker failed to signal ready: {msg}"
    _, res_id, pid = msg

    # Start a second worker in the test process (simulating a second gunicorn/uvicorn worker starting up)
    worker2_mgr = StorageManager(initial_settings)

    # The active writer's temporary file and reservation MUST still exist and be intact
    assert (worker2_mgr.temp_dir / "active_writer.tmp").exists()
    assert worker2_mgr.get_active_reserved_bytes() == 5000

    # Signal active worker to finish cleanly
    q_done.put("exit")
    p_active.join(timeout=5)


def test_abandoned_reservation_recovery_after_process_crash(tmp_path: Path, secret: str):
    """Verifies startup recovery cleanly cleans up temporary files and reservations when the writer process crashed."""
    settings_dict = {
        "storage_root": tmp_path / "crash_recovery_sandbox",
        "storage_quota_gb": 1.0,
        "capability_secret": secret,
        "environment": "development",
    }
    initial_settings = Settings(**settings_dict)
    StorageManager(initial_settings)

    q_ready = multiprocessing.Queue()
    p_crash = multiprocessing.Process(
        target=_mp_worker_abandoned_upload,
        args=(settings_dict, "crashed_writer.tmp", q_ready)
    )
    p_crash.start()

    msg = q_ready.get(timeout=5)
    assert msg[0] == "ready", f"Worker failed to start: {msg}"

    # Forcibly terminate the worker process to simulate a sudden OS crash / SIGKILL
    p_crash.terminate()
    p_crash.join(timeout=5)

    # Now a new worker starts up
    recovery_mgr = StorageManager(initial_settings)

    # The dead process's abandoned reservation and orphaned temp file must be safely purged
    assert recovery_mgr.get_active_reserved_bytes() == 0
    assert not (recovery_mgr.temp_dir / "crashed_writer.tmp").exists()


def test_production_chunk_paths_enforce_capabilities_and_reject_legacy_fallback(tmp_path: Path, secret: str):
    """Verifies that in production, all chunk operations strictly require capabilities and reject static auth token fallbacks."""
    node_settings = Settings(
        storage_root=tmp_path / "prod_enforce_sandbox",
        storage_quota_gb=1.0,
        capability_secret=secret,
        auth_token="legacy-auth-token-12345",
        coordinator_auth_token="legacy-coordinator-token-67890",
        environment="production",
    )
    manager = StorageManager(node_settings)
    app.dependency_overrides[get_manager] = lambda: manager
    app.state.settings = node_settings
    client = TestClient(app)

    chunk_id = str(uuid.uuid4())
    content = b"Production chunk data"

    # 1. Upload without capability in production -> 401
    r_up_none = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
    )
    assert r_up_none.status_code == 401
    assert "require a valid capability token" in r_up_none.json()["detail"].lower()

    # 2. Upload with legacy X-Auth-Token in production -> 401
    r_up = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"X-Auth-Token": "legacy-auth-token-12345"},
    )
    assert r_up.status_code == 401
    assert "require a valid capability token" in r_up.json()["detail"].lower()

    # 3. Upload with legacy Authorization Bearer token in production -> 401
    r_up_bearer = client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(content), "application/octet-stream")},
        headers={"Authorization": "Bearer legacy-coordinator-token-67890"},
    )
    assert r_up_bearer.status_code == 401
    assert "require a valid capability token" in r_up_bearer.json()["detail"].lower()

    # 4. Download without capability in production -> 401
    r_down_none = client.get(f"/files/{chunk_id}")
    assert r_down_none.status_code in (401, 403)

    # 5. Download with legacy X-Auth-Token in production -> 401
    r_down = client.get(
        f"/files/{chunk_id}",
        headers={"X-Auth-Token": "legacy-auth-token-12345"},
    )
    assert r_down.status_code == 401
    assert "require a valid capability token" in r_down.json()["detail"].lower()

    # 6. Download with legacy coordinator token in production -> 401
    r_down_coord = client.get(
        f"/files/{chunk_id}",
        headers={"Authorization": "Bearer legacy-coordinator-token-67890"},
    )
    assert r_down_coord.status_code == 401
    assert "require a valid capability token" in r_down_coord.json()["detail"].lower()

    # 7. Delete without capability in production -> 401
    r_del_none = client.delete(f"/files/{chunk_id}")
    assert r_del_none.status_code in (401, 403)

    # 8. Delete with legacy coordinator token in production -> 401
    r_del = client.delete(
        f"/files/{chunk_id}",
        headers={"Authorization": "Bearer legacy-coordinator-token-67890"},
    )
    assert r_del.status_code == 401
    assert "require a valid capability token" in r_del.json()["detail"].lower()

    # 9. Delete with legacy X-Auth-Token in production -> 401
    r_del_auth = client.delete(
        f"/files/{chunk_id}",
        headers={"X-Auth-Token": "legacy-auth-token-12345"},
    )
    assert r_del_auth.status_code == 401
    assert "require a valid capability token" in r_del_auth.json()["detail"].lower()

    app.dependency_overrides.clear()


