"""
Phase 10B Coordinator Security Tests.
Covers:
1. Coordinator issuance of narrowly scoped HMAC upload capability tokens.
2. Unauthenticated capability request rejection (401).
3. Multi-tenant ownership isolation: Consumer Bob cannot request download capabilities for Alice's files.
4. Automatic download capability enrichment in GET /catalog/files/{file_id}.
5. End-to-end integration: Coordinator capabilities authorize Storage Node upload, download, and delete flows.
"""

from __future__ import annotations

import io
import json
import uuid
import pytest
from pathlib import Path
from fastapi import status
from fastapi.testclient import TestClient

from coordinator.app.main import app as coord_app, get_settings as get_coord_settings
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db
from coordinator.app.auth import AccountManager
from coordinator.app.capability import issue_upload_capability, issue_download_capability, issue_delete_capability
from storage_node.app.config import Settings as StorageSettings
from storage_node.app.storage_manager import StorageManager
from storage_node.app.main import app as storage_app, get_manager as get_storage_manager
from storage_node.app.capability import verify_capability


CAPABILITY_SECRET = "phase10b-coordinator-shared-hmac-secret-key-32b!"


@pytest.fixture
def p10b_env(tmp_path: Path):
    """Provides isolated coordinator database and configuration."""
    db_file = tmp_path / "coordinator_phase10b_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="coord-internal-secret-token",
        admin_auth_token="admin-secret-token",
        capability_secret=CAPABILITY_SECRET,
        capability_ttl_seconds=300,
        environment="development",
        admin_email="admin_p10b@expo.internal",
        admin_password="SuperAdminSecurePassword123!",
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(p10b_env: CoordinatorSettings):
    """Configures TestClient for Coordinator API."""
    coord_app.state.settings = p10b_env
    coord_app.dependency_overrides[get_coord_settings] = lambda: p10b_env
    if hasattr(coord_app.state, "account_manager"):
        delattr(coord_app.state, "account_manager")
    if hasattr(coord_app.state, "catalog"):
        delattr(coord_app.state, "catalog")

    acc_mgr = AccountManager(p10b_env)
    acc_mgr.bootstrap_admin(p10b_env.admin_email, p10b_env.admin_password)

    with TestClient(coord_app) as c:
        yield c

    coord_app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry"):
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


def make_manifest(file_id: str, filename: str, chunk_id: str, node_id: str, size: int = 1024) -> dict:
    return {
        "file_id": file_id,
        "original_filename": filename,
        "original_size": size,
        "original_sha256": "aabbcc112233" * 5,
        "encrypted_size": size + 16,
        "chunk_size": size,
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "nonce_hex": "00" * 12,
        "created_at": "2026-10-14T00:00:00Z",
        "chunks": [
            {
                "chunk_id": chunk_id,
                "sequence": 0,
                "sha256": "chunkhash123",
                "size": size,
                "node_id": node_id,
                "node_endpoint": "http://127.0.0.1:8001",
                "placements": [
                    {
                        "node_id": node_id,
                        "node_endpoint": "http://127.0.0.1:8001",
                        "role": "PRIMARY",
                        "chunk_id": chunk_id,
                    }
                ],
            }
        ],
    }


# =============================================================================
# Coordinator Capability Issuance & Multi-Tenant Isolation Tests
# =============================================================================

def test_coordinator_upload_capabilities_endpoint(client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_cap_up@example.com")
    chunk_1 = str(uuid.uuid4())
    chunk_2 = str(uuid.uuid4())

    # 1. Unauthenticated request is rejected (401)
    client.cookies.clear()
    unauth_res = client.post(
        "/catalog/capabilities/upload",
        json={
            "file_id": str(uuid.uuid4()),
            "chunks": [{"chunk_id": chunk_1, "node_ids": ["NODE-A"], "size": 1024}],
        },
    )
    assert unauth_res.status_code == 401

    # 2. Authenticated consumer requests upload capabilities -> 200 OK
    auth_headers = {"Authorization": f"Bearer {alice_token}"}
    req_body = {
        "file_id": str(uuid.uuid4()),
        "chunks": [
            {"chunk_id": chunk_1, "node_ids": ["NODE-A", "NODE-B"], "size": 1024, "sha256": "hash1"},
            {"chunk_id": chunk_2, "node_ids": ["NODE-C"], "size": 2048, "sha256": "hash2"},
        ],
    }
    res = client.post("/catalog/capabilities/upload", json=req_body, headers=auth_headers)
    assert res.status_code == 200
    caps = res.json()["capabilities"]

    assert chunk_1 in caps
    assert "NODE-A" in caps[chunk_1]
    assert "NODE-B" in caps[chunk_1]
    assert chunk_2 in caps
    assert "NODE-C" in caps[chunk_2]

    # Verify cryptographic signature on issued token
    tok_a = caps[chunk_1]["NODE-A"]
    verified = verify_capability(
        token_str=tok_a,
        secret=CAPABILITY_SECRET,
        expected_node_id="NODE-A",
        expected_chunk_id=chunk_1,
        expected_op="upload",
    )
    assert verified.account_id == alice_id
    assert verified.expected_size == 1024
    assert verified.expected_sha256 == "hash1"


def test_coordinator_download_capabilities_ownership_isolation(client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_owner@example.com")
    bob_id, bob_token, _ = register_and_login(client, "bob_attacker@example.com")

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    node_id = "NODE-1"

    # Alice registers her file
    manifest = make_manifest(file_id, "alice_secret.txt", chunk_id, node_id)
    r_reg = client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_reg.status_code == 201

    # 1. Alice requests download capabilities for her own file -> 200 OK
    r_alice_cap = client.post(
        "/catalog/capabilities/download",
        json={"file_id": file_id, "items": [{"chunk_id": chunk_id, "node_id": node_id}]},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_alice_cap.status_code == 200
    alice_caps = r_alice_cap.json()["capabilities"]
    assert chunk_id in alice_caps
    assert node_id in alice_caps[chunk_id]

    # 2. Bob attempts to request download capabilities for Alice's file -> 404 / 403 Forbidden
    r_bob_cap = client.post(
        "/catalog/capabilities/download",
        json={"file_id": file_id, "items": [{"chunk_id": chunk_id, "node_id": node_id}]},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert r_bob_cap.status_code in (403, 404)


def test_catalog_file_manifest_enriched_with_download_capabilities(client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_enrich@example.com")

    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    node_id = "NODE-ENRICH-1"

    manifest = make_manifest(file_id, "data.bin", chunk_id, node_id)
    client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    # Alice retrieves file details
    r_get = client.get(
        f"/catalog/files/{file_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_get.status_code == 200
    rec = r_get.json()
    manifest_obj = json.loads(rec["manifest_json"])

    # Verify that placement was enriched with signed capability
    placement = manifest_obj["chunks"][0]["placements"][0]
    assert "capability" in placement
    cap_token = placement["capability"]
    assert cap_token is not None

    # Verify capability signature and claims
    verified = verify_capability(
        token_str=cap_token,
        secret=CAPABILITY_SECRET,
        expected_node_id=node_id,
        expected_chunk_id=chunk_id,
        expected_op="download",
    )
    assert verified.account_id == alice_id
    assert verified.op == "download"


# =============================================================================
# End-to-End Integration: Coordinator + Storage Node Lifecycle
# =============================================================================

def test_end_to_end_capability_upload_download_delete_lifecycle(tmp_path: Path, client: TestClient):
    alice_id, alice_token, _ = register_and_login(client, "alice_e2e@example.com")

    # Set up real Storage Node with shared capability secret
    storage_settings = StorageSettings(
        storage_root=tmp_path / "e2e_node_storage",
        capability_secret=CAPABILITY_SECRET,
        environment="production",
    )
    manager = StorageManager(storage_settings)
    storage_app.dependency_overrides[get_storage_manager] = lambda: manager
    storage_app.state.settings = storage_settings
    node_client = TestClient(storage_app)

    target_node_id = manager.node_id
    file_id = str(uuid.uuid4())
    chunk_id = str(uuid.uuid4())
    payload = b"End-to-end verified chunk ciphertext payload 10B"

    # Step 1: Coordinator issues upload capability to Alice
    up_res = client.post(
        "/catalog/capabilities/upload",
        json={
            "file_id": file_id,
            "chunks": [{"chunk_id": chunk_id, "node_ids": [target_node_id], "size": len(payload)}],
        },
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert up_res.status_code == 200
    upload_cap = up_res.json()["capabilities"][chunk_id][target_node_id]

    # Step 2: Upload chunk to Storage Node using the signed upload capability
    r_node_up = node_client.post(
        "/files",
        files={"file": (f"{chunk_id}.dat", io.BytesIO(payload), "application/octet-stream")},
        headers={"X-Capability-Token": upload_cap},
    )
    assert r_node_up.status_code == 201

    # Step 3: Register file in Coordinator catalog
    manifest = make_manifest(file_id, "e2e_file.bin", chunk_id, target_node_id, size=len(payload))
    r_reg = client.post(
        "/catalog/files",
        json={"manifest": manifest},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_reg.status_code == 201

    # Step 4: Retrieve file from catalog (enriched with signed download capability)
    r_cat_get = client.get(
        f"/catalog/files/{file_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r_cat_get.status_code == 200
    enriched_manifest = json.loads(r_cat_get.json()["manifest_json"])
    download_cap = enriched_manifest["chunks"][0]["placements"][0]["capability"]
    assert download_cap is not None

    # Step 5: Download chunk from Storage Node using the signed download capability
    r_node_down = node_client.get(
        f"/files/{chunk_id}",
        headers={"X-Capability-Token": download_cap},
    )
    assert r_node_down.status_code == 200
    assert r_node_down.content == payload

    # Step 6: Delete chunk using delete capability issued by coordinator
    delete_cap = issue_delete_capability(
        settings=client.app.state.settings,
        node_id=target_node_id,
        chunk_id=chunk_id,
    )
    r_node_del = node_client.delete(
        f"/files/{chunk_id}",
        headers={"X-Capability-Token": delete_cap},
    )
    assert r_node_del.status_code == 200
    assert r_node_del.json()["status"] == "deleted"

    storage_app.dependency_overrides.clear()
