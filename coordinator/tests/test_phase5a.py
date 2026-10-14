"""
Phase 5A: Unified Storage Metadata and File Catalog Tests
Tests logical file registration, catalog listing, metadata retrieval, and safe deletion.
"""

import pytest
from fastapi.testclient import TestClient
import uuid
import json

from coordinator.app.main import app, get_settings
from coordinator.app.config import CoordinatorSettings


@pytest.fixture
def test_settings(tmp_path):
    settings = CoordinatorSettings(
        db_path=tmp_path / "test_coordinator_5a.db",
        auth_token="dev-token-5a"
    )
    # Re-initialize DB
    from coordinator.app.database import init_db
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(test_settings):
    if hasattr(app.state, "catalog"):
        delattr(app.state, "catalog")
    if hasattr(app.state, "settings"):
        delattr(app.state, "settings")
    app.dependency_overrides[get_settings] = lambda: test_settings
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def generate_mock_manifest(file_id: str) -> dict:
    return {
        "file_id": file_id,
        "original_filename": f"test_{file_id}.txt",
        "original_size": 1024,
        "original_sha256": "abcdef123456",
        "encrypted_size": 1056,
        "chunk_size": 1024,
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "encryption_algorithm": "AES-256-GCM",
        "nonce_hex": "1234567890abcdef12345678",
        "created_at": "2023-10-10T10:00:00Z",
        "chunks": [],
        "redundancy_mode": "replication"
    }


def test_register_logical_file(client):
    file_id = str(uuid.uuid4())
    manifest = generate_mock_manifest(file_id)

    # Register file
    res = client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"X-Auth-Token": "dev-token-5a"}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["file_id"] == file_id
    assert data["owner_id"] == "dev-token-5a"
    assert data["original_filename"] == manifest["original_filename"]
    assert data["status"] == "available"
    assert json.loads(data["manifest_json"])["original_sha256"] == manifest["original_sha256"]


def test_list_logical_files(client):
    file_id_1 = str(uuid.uuid4())
    file_id_2 = str(uuid.uuid4())

    client.post(
        "/catalog/files",
        json={"manifest": generate_mock_manifest(file_id_1)},
        headers={"X-Auth-Token": "dev-token-5a"}
    )
    client.post(
        "/catalog/files",
        json={"manifest": generate_mock_manifest(file_id_2)},
        headers={"X-Auth-Token": "dev-token-5a"}
    )

    res = client.get("/catalog/files", headers={"X-Auth-Token": "dev-token-5a"})
    assert res.status_code == 200
    data = res.json()
    assert len(data["files"]) == 2
    assert {data["files"][0]["file_id"], data["files"][1]["file_id"]} == {file_id_1, file_id_2}


def test_get_logical_file(client):
    file_id = str(uuid.uuid4())
    manifest = generate_mock_manifest(file_id)

    client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"X-Auth-Token": "dev-token-5a"}
    )

    res = client.get(f"/catalog/files/{file_id}", headers={"X-Auth-Token": "dev-token-5a"})
    assert res.status_code == 200
    data = res.json()
    assert data["file_id"] == file_id


def test_unauthorized_access(client):
    file_id = str(uuid.uuid4())
    manifest = generate_mock_manifest(file_id)

    # User 1 uploads
    client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"X-Auth-Token": "dev-token-5a"}
    )

    # User 2 attempts to fetch without token
    res = client.get(f"/catalog/files/{file_id}")
    assert res.status_code == 401

    # Using wrong token will fail completely due to the hardcoded development token in settings
    # But if there were multiple users, we would test cross-user isolation.
    res_wrong = client.get(f"/catalog/files/{file_id}", headers={"X-Auth-Token": "wrong-token"})
    assert res_wrong.status_code == 401


def test_mark_file_deleting(client):
    file_id = str(uuid.uuid4())
    client.post(
        "/catalog/files",
        json={"manifest": generate_mock_manifest(file_id)},
        headers={"X-Auth-Token": "dev-token-5a"}
    )

    res = client.delete(f"/catalog/files/{file_id}", headers={"X-Auth-Token": "dev-token-5a"})
    assert res.status_code == 200
    assert res.json()["status"] == "deleting"

    # Listed files should not include 'deleting' files
    list_res = client.get("/catalog/files", headers={"X-Auth-Token": "dev-token-5a"})
    assert len(list_res.json()["files"]) == 0

    # Getting the file explicitly should still work
    get_res = client.get(f"/catalog/files/{file_id}", headers={"X-Auth-Token": "dev-token-5a"})
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "deleted"
