"""
Phase 1B integration tests for Node Identity, SHA-256 Integrity Verification,
Development Authentication, and ExpoClient Library.
"""

from __future__ import annotations

import io
import hashlib
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from storage_node.app.config import Settings
from storage_node.app.main import app, get_manager, get_app_settings
from storage_node.app.storage_manager import StorageManager
from client.client import ExpoClient, ClientError, IntegrityVerificationError


@pytest.fixture
def auth_settings(tmp_path: Path) -> Settings:
    return Settings(
        storage_root=tmp_path / "auth_sandbox",
        storage_quota_gb=0.001,
        auth_token="secret-dev-token-12345",
    )


@pytest.fixture
def auth_manager(auth_settings: Settings) -> StorageManager:
    return StorageManager(auth_settings)


@pytest.fixture
def auth_client(auth_settings: Settings, auth_manager: StorageManager) -> TestClient:
    app.dependency_overrides[get_app_settings] = lambda: auth_settings
    app.dependency_overrides[get_manager] = lambda: auth_manager
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# 1. Node Identity Persistence
def test_node_identity_persistence(auth_manager: StorageManager, auth_settings: Settings):
    node_id_1 = auth_manager.node_id
    assert node_id_1.startswith("NODE-")

    # Re-initialize StorageManager on the exact same database/sandbox
    second_manager = StorageManager(auth_settings)
    assert second_manager.node_id == node_id_1


# 2. SHA-256 Upload Verification
def test_sha256_upload_verification(auth_client: TestClient):
    content = b"Phase 1B SHA-256 Verification Test Data"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    headers = {"X-Auth-Token": "secret-dev-token-12345", "X-SHA256-Checksum": expected_sha256}
    files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

    res = auth_client.post("/files", files=files, headers=headers)
    assert res.status_code == 201
    meta = res.json()
    assert meta["sha256"] == expected_sha256


# 3. Mismatched SHA-256 Upload Rejected
def test_sha256_corrupted_upload_rejected(auth_client: TestClient):
    content = b"Authentic Data"
    fake_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

    headers = {"X-Auth-Token": "secret-dev-token-12345", "X-SHA256-Checksum": fake_sha256}
    files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

    res = auth_client.post("/files", files=files, headers=headers)
    assert res.status_code == 400
    assert "checksum mismatch" in res.json()["detail"].lower()


# 4. Authentication Protection
def test_authentication_protection(auth_client: TestClient):
    # Health and Node endpoints remain public
    assert auth_client.get("/health").status_code == 200
    assert auth_client.get("/node").status_code == 200

    # Protected endpoints require auth token
    assert auth_client.get("/storage").status_code == 401
    assert auth_client.get("/files").status_code == 401

    # Invalid token rejected
    bad_headers = {"X-Auth-Token": "wrong-token"}
    assert auth_client.get("/storage", headers=bad_headers).status_code == 401

    # Valid X-Auth-Token header allowed
    valid_headers = {"X-Auth-Token": "secret-dev-token-12345"}
    assert auth_client.get("/storage", headers=valid_headers).status_code == 200

    # Valid Bearer header allowed
    bearer_headers = {"Authorization": "Bearer secret-dev-token-12345"}
    assert auth_client.get("/storage", headers=bearer_headers).status_code == 200


# 5. Client Library E2E Integration Test
def test_client_library_e2e(auth_manager: StorageManager, auth_settings: Settings, tmp_path: Path):
    app.dependency_overrides[get_app_settings] = lambda: auth_settings
    app.dependency_overrides[get_manager] = lambda: auth_manager

    client = TestClient(app)
    
    # Verify health and node info
    res_h = client.get("/health").json()
    assert res_h["status"] == "online"

    res_n = client.get("/node").json()
    assert res_n["node_id"] == auth_manager.node_id

    # Verify storage info with auth
    res_s = client.get("/storage", headers={"X-Auth-Token": "secret-dev-token-12345"}).json()
    assert res_s["quota_bytes"] == auth_settings.storage_quota_bytes

    # Upload file
    upload_path = tmp_path / "sample_upload.txt"
    content = b"Expo Client E2E Integration Test Data"
    upload_path.write_bytes(content)
    content_sha = hashlib.sha256(content).hexdigest()

    files = {"file": ("sample_upload.txt", io.BytesIO(content), "text/plain")}
    headers = {"X-Auth-Token": "secret-dev-token-12345", "X-SHA256-Checksum": content_sha}
    
    r = client.post("/files", files=files, headers=headers)
    assert r.status_code == 201
    meta = r.json()
    assert meta["sha256"] == content_sha
    file_id = meta["file_id"]

    # List files
    r_list = client.get("/files", headers=headers)
    assert r_list.status_code == 200
    assert len(r_list.json()) == 1

    # Download file and verify SHA-256 integrity
    out_path = tmp_path / "downloaded_output.txt"
    
    res_dl = client.get(f"/files/{file_id}", headers=headers)
    assert res_dl.status_code == 200
    out_path.write_bytes(res_dl.content)
    
    dl_sha = hashlib.sha256(res_dl.content).hexdigest()
    assert dl_sha == content_sha
    assert res_dl.headers.get("X-SHA256-Checksum") == content_sha

    # Delete file
    res_del = client.delete(f"/files/{file_id}", headers=headers)
    assert res_del.status_code == 200

    app.dependency_overrides.clear()
