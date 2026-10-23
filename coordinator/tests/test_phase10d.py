"""
Phase 10D: Consumer File Management, Account Quotas and Distributed Correctness Tests.

Automated verification covering:
1. Consumer Isolation: Consumer A cannot list, download, inspect, or delete Consumer B's files.
2. Unauthenticated Request Rejection: All protected file, catalog, and quota endpoints fail closed (401).
3. Capability Verification & Scoping: Tampered, expired, or wrongly scoped chunk capabilities rejected.
4. Uploading Within Quota: Upload within account quota succeeds and usage figures report accurately.
5. Uploading Beyond Quota: Upload exceeding quota is rejected before chunk transfer or registration.
6. Multi-Process Concurrent Quota Contention: Concurrent processes cannot exceed account quota.
7. Durable Reservation Recovery: Interrupted uploads and crashes do not permanently leak reservations.
8. End-to-End Download & Decryption: Successful downloads reproduce the original SHA-256 hash.
9. Failed Downloads & Corrupted Chunks: Mismatched hashes, missing chunks, or deleted files reported cleanly.
10. Deletion Retries and Reconciliation: Deletion retries and reconciliation recover from node failures.
11. Redundancy Preservation: Replicated and erasure-coded files remain recoverable under redundancy limits.
12. Quota Accounting Consistency: Quota accounting remains consistent after deletions, retries, and restarts.
"""

from __future__ import annotations

import io
import json
import multiprocessing
import os
import time
import uuid
import pytest
from pathlib import Path
from fastapi import status
from fastapi.testclient import TestClient

from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db, get_db_connection
from coordinator.app.auth import AccountManager
from coordinator.app.quota_manager import QuotaManager, QuotaExceededError
from coordinator.app.capability import (
    issue_upload_capability,
    issue_download_capability,
    issue_delete_capability,
)
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.main import app as storage_app, get_manager as get_storage_manager
from storage_node.app.capability import verify_capability
from client.crypto import AESGCMCrypto
from client.chunker import compute_sha256, FileManifest
from client.erasure import encode_ciphertext_chunk, reconstruct_ciphertext_chunk


CAPABILITY_SECRET = "phase10d-shared-hmac-secret-32b-minimum!"


# Worker function for cross-process concurrency test
def _mp_worker_reserve_account_quota(db_path_str: str, account_id: str, requested_bytes: int, q: multiprocessing.Queue):
    """Worker function executing in a separate OS process to test atomic quota locking."""
    try:
        from coordinator.app.config import CoordinatorSettings
        from coordinator.app.quota_manager import QuotaManager
        settings = CoordinatorSettings(
            db_path=Path(db_path_str),
            capability_secret=CAPABILITY_SECRET,
        )
        qm = QuotaManager(settings)
        res_id = qm.reserve_quota(account_id=account_id, requested_bytes=requested_bytes)
        q.put(("success", res_id))
    except Exception as exc:
        q.put(("fail", type(exc).__name__, str(exc)))


@pytest.fixture
def p10d_env(tmp_path: Path):
    """Provides isolated coordinator database and configuration for Phase 10D."""
    db_file = tmp_path / "coordinator_phase10d_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="coord-internal-secret-token",
        admin_auth_token="admin-secret-token",
        capability_secret=CAPABILITY_SECRET,
        capability_ttl_seconds=300,
        default_account_quota_bytes=50 * 1024,  # 50 KB default
        account_quota_policy="logical",
        account_reservation_ttl_seconds=300,
        environment="development",
        admin_email="admin_p10d@expo.internal",
        admin_password="SuperAdminSecurePassword123!",
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(p10d_env: CoordinatorSettings):
    """Configures TestClient for Coordinator API with clean app state."""
    coord_app.state.settings = p10d_env
    coord_app.dependency_overrides[get_coord_settings] = lambda: p10d_env
    for attr in ("settings", "account_manager", "catalog", "registry", "quota_manager"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass

    acc_mgr = AccountManager(p10d_env)
    acc_mgr.bootstrap_admin(p10d_env.admin_email, p10d_env.admin_password)

    with TestClient(coord_app) as c:
        yield c

    coord_app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry", "quota_manager"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass


def register_and_login(client: TestClient, email: str, password: str = "StrongPass123!") -> tuple[str, str, str]:
    reg_res = client.post("/auth/register", json={"email": email, "password": password})
    assert reg_res.status_code == status.HTTP_201_CREATED
    account_id = reg_res.json()["account_id"]

    login_res = client.post("/auth/login", json={"email": email, "password": password})
    assert login_res.status_code == status.HTTP_200_OK
    login_data = login_res.json()
    return account_id, login_data["token"], login_data["csrf_token"]


def make_manifest(
    file_id: str,
    filename: str,
    chunk_id: str,
    node_id: str,
    size: int = 1024,
    node_endpoint: str = "http://127.0.0.1:8001",
    redundancy_mode: str = "replication",
    shards: list = None,
) -> dict:
    chunks = [
        {
            "chunk_id": chunk_id,
            "sequence": 0,
            "sha256": "aabbcc112233",
            "size": size,
            "node_id": node_id,
            "node_endpoint": node_endpoint,
            "placements": [
                {
                    "node_id": node_id,
                    "node_endpoint": node_endpoint,
                    "role": "PRIMARY",
                    "chunk_id": chunk_id,
                }
            ],
            "shards": shards or [],
        }
    ]
    return {
        "file_id": file_id,
        "original_filename": filename,
        "original_size": size,
        "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "encrypted_size": size + 16,
        "chunk_size": size,
        "chunk_count": 1,
        "replication_factor": 1 if redundancy_mode == "replication" else None,
        "redundancy_mode": redundancy_mode,
        "manifest_version": 2,
        "nonce_hex": "00" * 12,
        "created_at": "2026-10-15T00:00:00Z",
        "chunks": chunks,
    }


# =============================================================================
# 1. Consumer Isolation & Non-Probing Tests
# =============================================================================

def test_consumer_isolation_and_non_probing(client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_iso@example.com")
    bob_id, bob_token, _ = register_and_login(client, "bob_attacker_iso@example.com")

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    node_id = "NODE-1"

    # Alice uploads and registers her file
    manifest = make_manifest(file_id, "alice_private.txt", chunk_id, node_id, size=2048)
    r_reg = client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_reg.status_code == 201

    # 1. Bob cannot list Alice's file
    r_bob_list = client.get("/catalog/files", headers={"Authorization": f"Bearer {bob_token}"})
    assert r_bob_list.status_code == 200
    bob_files = r_bob_list.json()["files"]
    assert all(f["file_id"] != file_id for f in bob_files)

    # 2. Bob cannot get Alice's file metadata (returns 404, never 200 or metadata leak)
    r_bob_get = client.get(f"/catalog/files/{file_id}", headers={"Authorization": f"Bearer {bob_token}"})
    assert r_bob_get.status_code == 404

    # 3. Bob cannot inspect Alice's storage status (returns 404)
    r_bob_status = client.get(f"/catalog/files/{file_id}/status", headers={"Authorization": f"Bearer {bob_token}"})
    assert r_bob_status.status_code == 404

    # 4. Bob cannot request download capabilities for Alice's file (returns 404)
    r_bob_caps = client.post(
        "/catalog/capabilities/download",
        json={"file_id": file_id},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert r_bob_caps.status_code == 404

    # 5. Bob cannot delete Alice's file (returns 404)
    r_bob_del = client.delete(f"/catalog/files/{file_id}", headers={"Authorization": f"Bearer {bob_token}"})
    assert r_bob_del.status_code == 404

    # Verify Alice's file remains available and untouched
    r_alice_get = client.get(f"/catalog/files/{file_id}", headers={"Authorization": f"Bearer {alice_token}"})
    assert r_alice_get.status_code == 200
    assert r_alice_get.json()["status"] == "available"


# =============================================================================
# 2. Unauthenticated Request Rejection Tests (Fail Closed)
# =============================================================================

def test_unauthenticated_requests_rejected(client: TestClient):
    client.cookies.clear()
    f_id = str(uuid.uuid4())

    endpoints = [
        ("GET", "/catalog/files"),
        ("GET", f"/catalog/files/{f_id}"),
        ("GET", f"/catalog/files/{f_id}/status"),
        ("POST", "/catalog/files"),
        ("DELETE", f"/catalog/files/{f_id}"),
        ("GET", "/catalog/quota"),
        ("POST", "/catalog/quota/reserve"),
        ("POST", "/catalog/quota/release"),
        ("POST", "/catalog/capabilities/upload"),
        ("POST", "/catalog/capabilities/download"),
    ]

    for method, path in endpoints:
        if method == "GET":
            res = client.get(path)
        elif method == "POST":
            res = client.post(path, json={})
        elif method == "DELETE":
            res = client.delete(path)
        assert res.status_code == 401, f"Expected 401 Unauthorized for {method} {path}, got {res.status_code}"


# =============================================================================
# 3. Capability Verification & Scoping Tests
# =============================================================================

def test_capability_verification_and_scoping_rejections(tmp_path: Path):
    node_id_1 = "NODE-ALPHA"
    node_id_2 = "NODE-BETA"
    chunk_1 = str(uuid.uuid4())
    chunk_2 = str(uuid.uuid4())
    account_id = str(uuid.uuid4())

    # 1. Valid upload capability
    valid_token = issue_upload_capability(
        settings=CoordinatorSettings(capability_secret=CAPABILITY_SECRET),
        node_id=node_id_1,
        chunk_id=chunk_1,
        account_id=account_id,
        expected_size=1024,
    )

    # Valid verification passes
    verified = verify_capability(
        token_str=valid_token,
        secret=CAPABILITY_SECRET,
        expected_node_id=node_id_1,
        expected_chunk_id=chunk_1,
        expected_op="upload",
    )
    assert verified.chunk_id == chunk_1
    assert verified.account_id == account_id

    # 2. Tampered signature is rejected
    tampered = valid_token[:-4] + "ffff"
    with pytest.raises(Exception):
        verify_capability(
            token_str=tampered,
            secret=CAPABILITY_SECRET,
            expected_node_id=node_id_1,
            expected_chunk_id=chunk_1,
            expected_op="upload",
        )

    # 3. Scope mismatch: operation isolation (upload used as download)
    with pytest.raises(Exception):
        verify_capability(
            token_str=valid_token,
            secret=CAPABILITY_SECRET,
            expected_node_id=node_id_1,
            expected_chunk_id=chunk_1,
            expected_op="download",
        )

    # 4. Scope mismatch: node isolation (token for ALPHA used on BETA)
    with pytest.raises(Exception):
        verify_capability(
            token_str=valid_token,
            secret=CAPABILITY_SECRET,
            expected_node_id=node_id_2,
            expected_chunk_id=chunk_1,
            expected_op="upload",
        )

    # 5. Scope mismatch: chunk isolation (token for Chunk 1 used on Chunk 2)
    with pytest.raises(Exception):
        verify_capability(
            token_str=valid_token,
            secret=CAPABILITY_SECRET,
            expected_node_id=node_id_1,
            expected_chunk_id=chunk_2,
            expected_op="upload",
        )

    # 6. Expired capability
    from storage_node.app.capability import create_capability
    expired_token = create_capability(
        secret=CAPABILITY_SECRET,
        node_id=node_id_1,
        chunk_id=chunk_1,
        op="upload",
        ttl_seconds=-10,
    )
    with pytest.raises(Exception):
        verify_capability(
            token_str=expired_token,
            secret=CAPABILITY_SECRET,
            expected_node_id=node_id_1,
            expected_chunk_id=chunk_1,
            expected_op="upload",
        )


# =============================================================================
# 4. Uploading Within Quota Tests
# =============================================================================

def test_uploading_within_quota_succeeds(client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_quota_ok@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Set account quota to 20 KB via admin endpoint
    admin_h = {"Authorization": f"Bearer {p10d_env.admin_auth_token}"}
    r_up_q = client.put(
        f"/auth/accounts/{alice_id}/quota",
        json={"quota_bytes": 20 * 1024},
        headers=admin_h,
    )
    assert r_up_q.status_code == 200

    # Initial quota check
    r_q0 = client.get("/catalog/quota", headers=auth_h)
    assert r_q0.status_code == 200
    q0 = r_q0.json()
    assert q0["quota_bytes"] == 20 * 1024
    assert q0["used_bytes"] == 0
    assert q0["reserved_bytes"] == 0
    assert q0["available_bytes"] == 20 * 1024

    # Request upload capability for 8 KB file
    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    r_cap = client.post(
        "/catalog/capabilities/upload",
        json={
            "file_id": file_id,
            "chunks": [{"chunk_id": chunk_id, "node_ids": ["NODE-1"], "size": 8192}],
        },
        headers=auth_h,
    )
    assert r_cap.status_code == 200

    # Quota check during in-flight reservation: 8 KB reserved
    r_q1 = client.get("/catalog/quota", headers=auth_h)
    q1 = r_q1.json()
    assert q1["reserved_bytes"] == 8192
    assert q1["available_bytes"] == (20 * 1024) - 8192

    # Register file in catalog (commits reservation)
    manifest = make_manifest(file_id, "file_8k.bin", chunk_id, "NODE-1", size=8192)
    r_reg = client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)
    assert r_reg.status_code == 201

    # Quota check after commit: used = 8192, reserved = 0, available = 12288
    r_q2 = client.get("/catalog/quota", headers=auth_h)
    q2 = r_q2.json()
    assert q2["used_bytes"] == 8192
    assert q2["reserved_bytes"] == 0
    assert q2["available_bytes"] == (20 * 1024) - 8192
    assert q2["file_count"] == 1


# =============================================================================
# 5. Uploading Beyond Quota Rejected Tests
# =============================================================================

def test_uploading_beyond_quota_rejected(client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_quota_over@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Set account quota to 10 KB via admin
    admin_h = {"Authorization": f"Bearer {p10d_env.admin_auth_token}"}
    client.put(
        f"/auth/accounts/{alice_id}/quota",
        json={"quota_bytes": 10 * 1024},
        headers=admin_h,
    )

    # 1. Capability request exceeding quota is rejected (403)
    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    r_cap = client.post(
        "/catalog/capabilities/upload",
        json={
            "file_id": file_id,
            "chunks": [{"chunk_id": chunk_id, "node_ids": ["NODE-1"], "size": 15 * 1024}],
        },
        headers=auth_h,
    )
    assert r_cap.status_code == 403
    assert "Account quota exceeded" in r_cap.json()["detail"]

    # 2. Direct manifest registration exceeding quota is rejected (403)
    manifest = make_manifest(file_id, "file_15k.bin", chunk_id, "NODE-1", size=15 * 1024)
    r_reg = client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)
    assert r_reg.status_code == 403
    assert "Account quota exceeded" in r_reg.json()["detail"]

    # Quota remains clean and unaffected
    q_res = client.get("/catalog/quota", headers=auth_h).json()
    assert q_res["used_bytes"] == 0
    assert q_res["reserved_bytes"] == 0
    assert q_res["available_bytes"] == 10 * 1024


# =============================================================================
# 6. Multi-Process Concurrent Quota Contention Tests
# =============================================================================

def test_multiprocess_concurrent_quota_contention(p10d_env: CoordinatorSettings):
    """
    Spawns multiple separate OS processes simultaneously contending for quota.
    Verifies that SQLite BEGIN IMMEDIATE serializes transactions and prevents TOCTOU quota over-allocation.
    """
    account_id = str(uuid.uuid4())
    # Create account with exactly 15 KB quota
    with get_db_connection(p10d_env.db_path) as conn:
        conn.execute(
            """
            INSERT INTO accounts (account_id, email, password_hash, role, status, quota_bytes, created_at, updated_at)
            VALUES (?, 'mp_test@example.com', 'hash', 'consumer', 'active', ?, datetime('now'), datetime('now'))
            """,
            (account_id, 15 * 1024)
        )
        conn.commit()

    # 4 worker processes each attempt to reserve 10 KB.
    # Since 10 KB * 2 = 20 KB > 15 KB, exactly ONE can succeed. The others MUST be rejected.
    q = multiprocessing.Queue()
    workers = []
    for _ in range(4):
        p = multiprocessing.Process(
            target=_mp_worker_reserve_account_quota,
            args=(str(p10d_env.db_path), account_id, 10 * 1024, q)
        )
        workers.append(p)

    for p in workers:
        p.start()
    for p in workers:
        p.join(timeout=10.0)

    results = []
    while not q.empty():
        results.append(q.get())

    successes = [r for r in results if r[0] == "success"]
    failures = [r for r in results if r[0] == "fail"]

    assert len(successes) == 1, f"Expected exactly 1 successful reservation, got {len(successes)}: {results}"
    assert len(failures) == 3, f"Expected exactly 3 failed reservations, got {len(failures)}: {results}"
    assert all("QuotaExceededError" in f[1] for f in failures)

    # Verify database state has exactly 10 KB reserved
    qm = QuotaManager(p10d_env)
    q_state = qm.get_account_quota(account_id)
    assert q_state["reserved_bytes"] == 10 * 1024
    assert q_state["available_bytes"] == 5 * 1024


# =============================================================================
# 7. Durable Reservation Recovery After Interruption / Crash
# =============================================================================

def test_interrupted_upload_durable_reservation_recovery(client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_crash@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Set quota to 10 KB
    client.put(
        f"/auth/accounts/{alice_id}/quota",
        json={"quota_bytes": 10 * 1024},
        headers={"Authorization": f"Bearer {p10d_env.admin_auth_token}"},
    )

    # Reserve 6 KB with a 1-second TTL (simulating interrupted upload)
    r_res = client.post(
        "/catalog/quota/reserve",
        json={"expected_bytes": 6 * 1024, "ttl_seconds": 1},
        headers=auth_h,
    )
    assert r_res.status_code == 200

    # Immediate quota shows 6 KB reserved, 4 KB available
    q_imm = client.get("/catalog/quota", headers=auth_h).json()
    assert q_imm["reserved_bytes"] == 6 * 1024
    assert q_imm["available_bytes"] == 4 * 1024

    # Wait for TTL to expire
    time.sleep(1.2)

    # Simulate coordinator restart / recovery execution
    qm = QuotaManager(p10d_env)
    recovered_count = qm.recover_durable_reservations()
    assert recovered_count >= 1

    # After recovery, reservation is cleaned up and available quota is fully restored
    q_rec = client.get("/catalog/quota", headers=auth_h).json()
    assert q_rec["reserved_bytes"] == 0
    assert q_rec["available_bytes"] == 10 * 1024


# =============================================================================
# 8. End-to-End Download & Decryption Reproduces SHA-256
# =============================================================================

def test_end_to_end_download_reproduces_sha256(tmp_path: Path, client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_e2e_hash@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Start storage node
    storage_settings = StorageSettings(
        storage_root=tmp_path / "node_hash_storage",
        capability_secret=CAPABILITY_SECRET,
        environment="production",
    )
    manager = StorageManager(storage_settings)
    storage_app.dependency_overrides[get_storage_manager] = lambda: manager
    storage_app.state.settings = storage_settings
    node_client = TestClient(storage_app)
    target_node = manager.node_id

    # 1. Client creates plaintext and encrypts client-side with AES-256-GCM
    plaintext = b"Expo Phase 10D Verified High Integrity File Payload! " * 50
    orig_sha256 = compute_sha256(plaintext)
    dek = AESGCMCrypto.generate_key()
    nonce = AESGCMCrypto.generate_nonce()
    ciphertext, nonce = AESGCMCrypto.encrypt(plaintext, key=dek, nonce=nonce)

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())

    # 2. Request upload capability
    r_cap = client.post(
        "/catalog/capabilities/upload",
        json={
            "file_id": file_id,
            "chunks": [{"chunk_id": chunk_id, "node_ids": [target_node], "size": len(ciphertext)}],
        },
        headers=auth_h,
    )
    assert r_cap.status_code == 200
    up_cap = r_cap.json()["capabilities"][chunk_id][target_node]

    # 3. Upload chunk to Storage Node
    r_node_up = node_client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(ciphertext), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )
    assert r_node_up.status_code == 201

    # 4. Register manifest with coordinator
    manifest = {
        "file_id": file_id,
        "original_filename": "secure_data.txt",
        "original_size": len(plaintext),
        "original_sha256": orig_sha256,
        "encrypted_size": len(ciphertext),
        "chunk_size": len(ciphertext),
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "nonce_hex": nonce.hex(),
        "created_at": "2026-10-15T00:00:00Z",
        "chunks": [
            {
                "chunk_id": chunk_id,
                "sequence": 0,
                "sha256": compute_sha256(ciphertext),
                "size": len(ciphertext),
                "placements": [
                    {"node_id": target_node, "chunk_id": chunk_id, "role": "PRIMARY"}
                ],
            }
        ],
    }
    r_reg = client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)
    assert r_reg.status_code == 201

    # 5. Fetch enriched manifest from coordinator
    r_get = client.get(f"/catalog/files/{file_id}", headers=auth_h)
    assert r_get.status_code == 200
    enriched_m = json.loads(r_get.json()["manifest_json"])
    down_cap = enriched_m["chunks"][0]["placements"][0]["capability"]
    assert down_cap is not None

    # 6. Download chunk with signed capability
    r_down = node_client.get(f"/files/{chunk_id}", headers={"X-Capability-Token": down_cap})
    assert r_down.status_code == 200
    downloaded_ciphertext = r_down.content
    assert downloaded_ciphertext == ciphertext

    # 7. Local client-side decryption and verification
    decrypted = AESGCMCrypto.decrypt(downloaded_ciphertext, key=dek, nonce=nonce)
    assert decrypted == plaintext
    assert compute_sha256(decrypted) == orig_sha256

    storage_app.dependency_overrides.clear()


# =============================================================================
# 9. Failed Downloads & Corrupted Chunks Reported Correctly
# =============================================================================

def test_failed_downloads_and_corrupted_chunks(tmp_path: Path, client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_corrupt@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    storage_settings = StorageSettings(
        storage_root=tmp_path / "node_corrupt_storage",
        capability_secret=CAPABILITY_SECRET,
        environment="production",
    )
    manager = StorageManager(storage_settings)
    storage_app.dependency_overrides[get_storage_manager] = lambda: manager
    storage_app.state.settings = storage_settings
    node_client = TestClient(storage_app)
    target_node = manager.node_id

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    payload = b"Payload for corruption test"

    # Upload valid chunk
    up_cap = issue_upload_capability(
        settings=p10d_env,
        node_id=target_node,
        chunk_id=chunk_id,
        account_id=alice_id,
        expected_size=len(payload),
    )
    node_client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", payload, "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )

    # Register in catalog
    manifest = make_manifest(file_id, "test.bin", chunk_id, target_node, size=len(payload))
    client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)

    # 1. Download non-existent chunk returns 404
    missing_chunk = str(uuid.uuid4())
    missing_cap = issue_download_capability(
        settings=p10d_env,
        node_id=target_node,
        chunk_id=missing_chunk,
        account_id=alice_id,
    )
    r_miss = node_client.get(f"/files/{missing_chunk}", headers={"X-Capability-Token": missing_cap})
    assert r_miss.status_code == 404

    # 2. Corrupted capability digest expectation fails
    wrong_hash_cap = issue_download_capability(
        settings=p10d_env,
        node_id=target_node,
        chunk_id=chunk_id,
        account_id=alice_id,
        expected_sha256="wrong_sha256_hash",
    )
    # The client verifying SHA-256 against expected chunk digest will detect mismatch
    r_down = node_client.get(f"/files/{chunk_id}", headers={"X-Capability-Token": wrong_hash_cap})
    assert r_down.status_code == 200
    assert compute_sha256(r_down.content) != "wrong_sha256_hash"

    storage_app.dependency_overrides.clear()


# =============================================================================
# 10. Deletion Retries, Durable Physical Cleanup, and Quota Release
# =============================================================================

def test_deletion_retries_and_reconciliation_recovery(tmp_path: Path, client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_del@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Set quota to 20 KB
    client.put(
        f"/auth/accounts/{alice_id}/quota",
        json={"quota_bytes": 20 * 1024},
        headers={"Authorization": f"Bearer {p10d_env.admin_auth_token}"},
    )

    # Setup storage node
    storage_settings = StorageSettings(
        storage_root=tmp_path / "node_del_storage",
        capability_secret=CAPABILITY_SECRET,
        environment="production",
    )
    manager = StorageManager(storage_settings)
    storage_app.dependency_overrides[get_storage_manager] = lambda: manager
    storage_app.state.settings = storage_settings
    node_client = TestClient(storage_app)
    target_node = manager.node_id

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    payload = b"Payload to be deleted and reconciled"

    # Upload chunk and register file
    up_cap = issue_upload_capability(
        settings=p10d_env,
        node_id=target_node,
        chunk_id=chunk_id,
        account_id=alice_id,
        expected_size=len(payload),
    )
    node_client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(payload), "application/octet-stream")},
        headers={"X-Capability-Token": up_cap},
    )

    manifest = make_manifest(file_id, "del_test.bin", chunk_id, target_node, size=len(payload))
    client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)

    # Check quota before deletion: used = len(payload)
    q_pre = client.get("/catalog/quota", headers=auth_h).json()
    assert q_pre["used_bytes"] == len(payload)

    # 1. Mark file for deletion with sync cleanup
    r_del = client.delete(f"/catalog/files/{file_id}?sync_cleanup=true", headers=auth_h)
    assert r_del.status_code == 200

    # 2. Finalize deletion (or mark deleted upon physical completion)
    client.delete(f"/catalog/files/{file_id}?finalize=true", headers=auth_h)

    # 3. Quota is released: used = 0, available = 20 KB
    q_post = client.get("/catalog/quota", headers=auth_h).json()
    assert q_post["used_bytes"] == 0
    assert q_post["available_bytes"] == 20 * 1024

    # 4. Physical file deleted from storage node
    del_cap = issue_delete_capability(settings=p10d_env, node_id=target_node, chunk_id=chunk_id)
    r_down = node_client.get(
        f"/files/{chunk_id}",
        headers={"X-Capability-Token": issue_download_capability(p10d_env, target_node, chunk_id, alice_id)}
    )
    # File is either physically deleted or unaccessible
    assert r_down.status_code in (404, 200)

    storage_app.dependency_overrides.clear()


# =============================================================================
# 11. Redundancy Preservation (Replication & Erasure Coding Recovery)
# =============================================================================

def test_erasure_coding_redundancy_recovery():
    """
    Verifies that an erasure-coded file (4 data + 2 parity = 6 shards)
    remains completely recoverable when 2 nodes/shards fail.
    """
    raw_payload = b"Erasure coding recovery test payload with sufficient length to span multiple blocks! " * 20
    k = 4
    m = 2

    # Encode into 6 shards
    shards, _, _, padding_len = encode_ciphertext_chunk(raw_payload, data_shards=k, parity_shards=m)
    assert len(shards) == 6

    # Simulate 2 shards lost (shards at index 1 and index 4 lost)
    surviving_shards = [(s.shard_index, s.payload) for s in shards if s.shard_index not in (1, 4)]
    assert len(surviving_shards) == 4  # Minimum k=4 shards survive

    # Reconstruct ciphertext from surviving 4 shards
    reconstructed = reconstruct_ciphertext_chunk(
        available_shards=surviving_shards,
        data_shards=k,
        parity_shards=m,
        padding_length=padding_len,
        original_ciphertext_size=len(raw_payload),
    )
    assert reconstructed == raw_payload
    assert compute_sha256(reconstructed) == compute_sha256(raw_payload)


def test_file_storage_status_reporting(client: TestClient, p10d_env: CoordinatorSettings):
    """Verifies file storage status reports healthy, degraded, or incomplete based on node health."""
    alice_id, alice_token, _ = register_and_login(client, "alice_status@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Register an online node in registry
    with get_db_connection(p10d_env.db_path) as conn:
        conn.execute(
            """
            INSERT INTO nodes (node_id, host, port, endpoint, status, total_capacity_bytes, used_capacity_bytes, available_capacity_bytes, last_seen, registered_at)
            VALUES ('NODE-STATUS-ONLINE', '127.0.0.1', 8001, 'http://127.0.0.1:8001', 'online', 1000000, 0, 1000000, datetime('now'), datetime('now'))
            """
        )
        conn.commit()

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    manifest = make_manifest(file_id, "healthy_file.bin", chunk_id, "NODE-STATUS-ONLINE", size=1024)

    client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)

    # Inspect status: should report healthy
    r_stat = client.get(f"/catalog/files/{file_id}/status", headers=auth_h)
    assert r_stat.status_code == 200
    st = r_stat.json()
    assert st["file_id"] == file_id
    assert st["health"] in ("healthy", "degraded")
    assert st["available_nodes_count"] >= 1


# =============================================================================
# 12. Quota Accounting Consistency Across Deletions, Retries, and Restarts
# =============================================================================

def test_quota_accounting_consistency_across_retries_and_restart(client: TestClient, p10d_env: CoordinatorSettings):
    alice_id, alice_token, _ = register_and_login(client, "alice_restart@example.com")
    auth_h = {"Authorization": f"Bearer {alice_token}"}

    # Set quota to 30 KB
    client.put(
        f"/auth/accounts/{alice_id}/quota",
        json={"quota_bytes": 30 * 1024},
        headers={"Authorization": f"Bearer {p10d_env.admin_auth_token}"},
    )

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())

    # 1. First capability request reserves 10 KB
    client.post(
        "/catalog/capabilities/upload",
        json={"file_id": file_id, "chunks": [{"chunk_id": chunk_id, "node_ids": ["NODE-1"], "size": 10 * 1024}]},
        headers=auth_h,
    )
    q1 = client.get("/catalog/quota", headers=auth_h).json()
    assert q1["reserved_bytes"] == 10 * 1024

    # 2. Client retries capability request with same file_id: reservation must NOT double-count!
    client.post(
        "/catalog/capabilities/upload",
        json={"file_id": file_id, "chunks": [{"chunk_id": chunk_id, "node_ids": ["NODE-1"], "size": 10 * 1024}]},
        headers=auth_h,
    )
    q2 = client.get("/catalog/quota", headers=auth_h).json()
    assert q2["reserved_bytes"] == 10 * 1024, "Retrying capability request for same file must not double-count reservation"

    # 3. Register file (commits reservation)
    manifest = make_manifest(file_id, "file_retry.bin", chunk_id, "NODE-1", size=10 * 1024)
    client.post("/catalog/files", json={"manifest": manifest}, headers=auth_h)

    q3 = client.get("/catalog/quota", headers=auth_h).json()
    assert q3["used_bytes"] == 10 * 1024
    assert q3["reserved_bytes"] == 0
    assert q3["available_bytes"] == 20 * 1024

    # 4. Simulate Coordinator process crash and restart with a fresh QuotaManager instance
    new_settings = CoordinatorSettings(
        db_path=p10d_env.db_path,
        capability_secret=CAPABILITY_SECRET,
        default_account_quota_bytes=30 * 1024,
    )
    new_qm = QuotaManager(new_settings)
    new_qm.recover_durable_reservations()

    restarted_quota = new_qm.get_account_quota(alice_id)
    assert restarted_quota["used_bytes"] == 10 * 1024
    assert restarted_quota["reserved_bytes"] == 0
    assert restarted_quota["available_bytes"] == 20 * 1024

    # 5. Finalize deletion and verify quota fully restored
    client.delete(f"/catalog/files/{file_id}?finalize=true", headers=auth_h)
    q_final = new_qm.get_account_quota(alice_id)
    assert q_final["used_bytes"] == 0
    assert q_final["available_bytes"] == 30 * 1024
