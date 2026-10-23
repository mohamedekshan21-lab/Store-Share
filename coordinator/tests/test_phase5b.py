"""
Phase 5B: Unified File-Management API Tests
Tests the client's unified lifecycle integrating Coordinator Catalog and Storage Nodes.
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.coordinator_client import CoordinatorClient
from client.client import ExpoClient, ClientError
from client.chunker import compute_sha256

from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.main import app as storage_app


class NodeTestClient:
    def __init__(self, storage_manager, app):
        self.sm = storage_manager
        self.app = app
        self._tc = TestClient(app, raise_server_exceptions=False)
        self.app.state.storage_manager = self.sm
        self.app.state.settings = self.sm.settings

    def post(self, *args, **kwargs):
        return self._tc.post(*args, **kwargs)
        
    def get(self, *args, **kwargs):
        return self._tc.get(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._tc.delete(*args, **kwargs)


def create_storage_node_app(tmp_path, folder_name):
    root = tmp_path / folder_name
    settings = StorageSettings(storage_root=root, auth_token="dev-token")
    sm = StorageManager(settings)
    return sm, NodeTestClient(sm, storage_app)


@pytest.fixture
def phase5b_env(tmp_path):
    # Setup Coordinator
    db_path = tmp_path / "coordinator_5b.db"
    coord_settings = CoordinatorSettings(db_path=db_path, auth_token="dev-token")
    
    from coordinator.app.database import init_db
    init_db(coord_settings.db_path)
    
    coord_app.state.settings = coord_settings
    coord_app.dependency_overrides[get_coord_settings] = lambda: coord_settings
    coord_tc = TestClient(coord_app)
    
    # Setup Nodes
    nodes_info = {}
    for name in ["a", "b", "c", "d"]:
        sm, tc = create_storage_node_app(tmp_path, f"node_{name}")
        n_id = f"NODE-{name.upper()}"
        endpoint = f"http://node-{name}:8000"
        nodes_info[n_id] = (tc, endpoint)

    # Register nodes directly into DB for Coordinator placement
    with coord_tc:
        for n_id, (_, ep) in nodes_info.items():
            res = coord_tc.post("/nodes/register", json={
                "node_id": n_id,
                "host": f"node-{n_id[-1].lower()}",
                "port": 8000,
                "total_capacity_bytes": 10000000,
                "used_capacity_bytes": 0,
                "available_capacity_bytes": 10000000,
                "endpoint": ep,
                "advertised_endpoint": ep,
                "connectivity_mode": "LAN",
                "protocol_version": "2B"
            }, headers={"X-Auth-Token": "dev-token"})
            assert res.status_code == 200

    yield coord_tc, nodes_info

    coord_app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass



def test_unified_lifecycle_replication(phase5b_env, tmp_path):
    coord_tc, nodes_info = phase5b_env

    # We patch CoordinatorClient to use TestClient for this test
    original_request = CoordinatorClient._request
    def mocked_coord_request(self_cc, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers.update(self_cc._get_headers())
        if method.upper() == "GET":
            res = coord_tc.get(path, headers=headers, **kwargs)
        elif method.upper() == "POST":
            res = coord_tc.post(path, headers=headers, **kwargs)
        elif method.upper() == "DELETE":
            res = coord_tc.delete(path, headers=headers, **kwargs)
        else:
            raise Exception("Method not mocked")
        
        # mock raise_for_status
        def rfs():
            if res.status_code >= 400:
                from httpx import HTTPStatusError, Request, Response
                raise HTTPStatusError("Error", request=Request(method, path), response=Response(res.status_code, text=res.text))
        res.raise_for_status = rfs
        return res
    
    CoordinatorClient._request = mocked_coord_request

    try:
        class TestUnifiedClient(ExpoClient):
            def __init__(self):
                super().__init__(node_url="http://node-a:8000", auth_token="dev-token")
                self.nodes_info = nodes_info
                
            def upload_chunk_bytes(self, chunk_bytes: bytes, filename: str):
                for n_id, (tc, ep) in nodes_info.items():
                    if ep == self.base_url:
                        local_sha = compute_sha256(chunk_bytes)
                        res = tc.post("/files", files={"file": (filename, chunk_bytes, "application/octet-stream")}, headers={"X-Auth-Token": "dev-token", "X-SHA256-Checksum": local_sha})
                        if res.status_code == 201:
                            return res.json()
                        raise ClientError(f"Upload fail {res.status_code}")
                raise ClientError(f"Unknown endpoint: {self.base_url}")

            def download_chunk_bytes(self, file_id: str) -> bytes:
                for n_id, (tc, ep) in nodes_info.items():
                    if ep == self.base_url:
                        res = tc.get(f"/files/{file_id}", headers={"X-Auth-Token": "dev-token"})
                        if res.status_code == 200:
                            return res.content
                        
                        # Try listing and finding by stored_filename just in case
                        lres = tc.get("/files", headers={"X-Auth-Token": "dev-token"})
                        if lres.status_code == 200:
                            for f in lres.json().get("files", []):
                                if f.get("stored_filename") == file_id or f.get("file_id") == file_id or f.get("original_filename") == file_id:
                                    res2 = tc.get(f"/files/{f['file_id']}", headers={"X-Auth-Token": "dev-token"})
                                    if res2.status_code == 200:
                                        return res2.content
                        raise ClientError(f"File not found on node {n_id}")
                raise ClientError(f"Unknown endpoint: {self.base_url}")

            def delete_file(self, file_id: str) -> bool:
                for n_id, (tc, ep) in nodes_info.items():
                    if ep == self.base_url:
                        # Attempt to delete by looking up ID
                        res = tc.delete(f"/files/{file_id}", headers={"X-Auth-Token": "dev-token"})
                        if res.status_code in (200, 204):
                            return True
                        # Fallback for chunk_id
                        lres = tc.get("/files", headers={"X-Auth-Token": "dev-token"})
                        if lres.status_code == 200:
                            for f in lres.json().get("files", []):
                                orig = f.get("original_filename", "")
                                if f.get("stored_filename") == file_id or orig == file_id or orig == f"{file_id}.dat":
                                    res2 = tc.delete(f"/files/{f['file_id']}", headers={"X-Auth-Token": "dev-token"})
                                    return res2.status_code in (200, 204)
                        raise ClientError("Not found")
                return False

        client = TestUnifiedClient()
        test_file = tmp_path / "unified.txt"
        test_file.write_text("Unified lifecycle testing!", encoding="utf-8")

        # 1. Upload Logical File
        up_res = client.upload_logical_file(
            file_path=test_file,
            coordinator_url="http://mock-coordinator",
            redundancy_mode="replication",
            replication_factor=2,
            target_node_count=2
        )
        file_id = up_res["file_id"]
        key_hex = up_res["key_hex"]
        assert up_res["status"] == "available"

        # 2. List Logical Files
        list_res = client.list_logical_files(coordinator_url="http://mock-coordinator")
        assert len(list_res) == 1
        assert list_res[0]["file_id"] == file_id

        # 3. Download Logical File
        out_file = tmp_path / "downloaded.txt"
        dl_res = client.download_logical_file(
            file_id=file_id,
            output_path=out_file,
            key_input=key_hex,
            coordinator_url="http://mock-coordinator"
        )
        assert dl_res["status"] == "downloaded"
        assert out_file.read_text(encoding="utf-8") == "Unified lifecycle testing!"

        # 4. Delete Logical File
        del_res = client.delete_logical_file(
            file_id=file_id,
            coordinator_url="http://mock-coordinator"
        )
        assert del_res["status"] == "deleting"
        assert del_res["physical_success_count"] == 0

        # Verify listed as deleted (omitted from normal list)
        list_res_after = client.list_logical_files(coordinator_url="http://mock-coordinator")
        assert len(list_res_after) == 0

    finally:
        CoordinatorClient._request = original_request
