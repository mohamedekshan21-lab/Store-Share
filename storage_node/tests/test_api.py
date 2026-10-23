"""
FastAPI integration & endpoint security tests for Expo Storage Node.
"""

from __future__ import annotations

import io
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from storage_node.app.config import Settings
from storage_node.app.main import app, get_manager, get_app_settings
from storage_node.app.storage_manager import StorageManager


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    return Settings(
        storage_root=tmp_path / "api_sandbox",
        storage_quota_gb=0.0001  # ~100 KB quota for fast testing
    )


@pytest.fixture
def client(test_settings: Settings) -> TestClient:
    manager = StorageManager(test_settings)
    app.state.settings = test_settings
    app.dependency_overrides[get_manager] = lambda: manager
    app.dependency_overrides[get_app_settings] = lambda: test_settings
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "online"}


def test_storage_endpoint(client: TestClient, test_settings: Settings):
    response = client.get("/storage")
    assert response.status_code == 200
    data = response.json()
    assert data["quota_bytes"] == test_settings.storage_quota_bytes
    assert data["used_bytes"] == 0
    assert data["available_bytes"] == test_settings.storage_quota_bytes


def test_upload_and_download_flow(client: TestClient):
    content = b"Sample Expo Storage Node file content"
    files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}
    
    # 1. Upload
    upload_res = client.post("/files", files=files)
    assert upload_res.status_code == 201
    meta = upload_res.json()
    file_id = meta["file_id"]
    assert meta["original_filename"] == "test.txt"
    assert meta["size"] == len(content)

    # 2. List
    list_res = client.get("/files")
    assert list_res.status_code == 200
    file_list = list_res.json()
    assert len(file_list) == 1
    assert file_list[0]["file_id"] == file_id

    # 3. Download
    download_res = client.get(f"/files/{file_id}")
    assert download_res.status_code == 200
    assert download_res.content == content

    # 4. Delete
    delete_res = client.delete(f"/files/{file_id}")
    assert delete_res.status_code == 200
    assert delete_res.json() == {"status": "deleted", "file_id": file_id}

    # 5. Download after delete returns 404
    assert client.get(f"/files/{file_id}").status_code == 404


def test_quota_exceeded_via_api(client: TestClient, test_settings: Settings):
    quota = test_settings.storage_quota_bytes
    oversized_content = b"Z" * (quota + 1024)
    files = {"file": ("big.dat", io.BytesIO(oversized_content), "application/octet-stream")}

    res = client.post("/files", files=files)
    assert res.status_code == 507
    assert "Quota exceeded" in res.json()["detail"] or "Insufficient storage" in res.json()["detail"]


@pytest.mark.parametrize(
    "bad_id",
    [
        "../etc/passwd",
        "..\\Windows\\System32",
        "C:\\boot.ini",
        "../../test",
    ],
)
def test_path_traversal_via_api(client: TestClient, bad_id: str):
    res_get = client.get(f"/files/{bad_id}")
    assert res_get.status_code in (400, 404)

    res_del = client.delete(f"/files/{bad_id}")
    assert res_del.status_code in (400, 404)


def test_get_nonexistent_file(client: TestClient):
    import uuid
    random_uuid = str(uuid.uuid4())
    res = client.get(f"/files/{random_uuid}")
    assert res.status_code == 404
