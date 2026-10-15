"""
Role-Based Access Control (RBAC) and Security Boundary Tests for Store-Share.

Validates that server-side authorization enforces strict separation among:
- ADMIN (cluster infrastructure, audit, accounting policy, provider enrollment, user lifecycle)
- PROVIDER (own node management, own capacity/credits, own safe-drain requests)
- CONSUMER (own encrypted file catalog, upload/download/delete own files)
- STORAGE NODE DAEMONS (machine authentication, heartbeats, chunk registration)

Ensures zero-knowledge isolation: Coordinator and Admin never access encryption keys or plaintext files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from coordinator.app.main import app
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.metering import MeteringService
from coordinator.app.accounting import AccountingService
from coordinator.app.auth import ProviderSessionManager
from coordinator.app.drain_service import NodeDrainService
from coordinator.app.file_catalog import FileCatalog
from coordinator.app.user_auth import (
    UserManager,
    Role,
    create_access_token,
)


@pytest.fixture
def rbac_settings(tmp_path: Path) -> CoordinatorSettings:
    db_file = tmp_path / "coordinator_rbac_test.db"
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="machine-node-daemon-token-99999",
        admin_auth_token="machine-admin-token-88888",
        jwt_secret="rbac-test-jwt-secret-key-0123456789abcdef",
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=30,
        jwt_issuer="store-share-coordinator",
        jwt_audience="store-share-network",
    )


@pytest.fixture
def rbac_client(rbac_settings: CoordinatorSettings) -> Generator[TestClient, None, None]:
    init_db(rbac_settings.db_path)
    app.state.settings = rbac_settings
    app.state.registry = NodeRegistry(rbac_settings)
    app.state.catalog = FileCatalog(rbac_settings)
    app.state.metering_service = MeteringService(rbac_settings)
    app.state.accounting_service = AccountingService(rbac_settings)
    app.state.session_manager = ProviderSessionManager(rbac_settings)
    app.state.drain_service = NodeDrainService(rbac_settings)
    app.state.user_manager = UserManager(rbac_settings)

    with TestClient(app) as client:
        yield client


@pytest.fixture
def tokens(rbac_settings: CoordinatorSettings):
    """Generates typed JWT access tokens for testing all three human roles."""
    mgr = UserManager(rbac_settings)
    admin_user = mgr.create_user("admin_user", "admin@storeshare.net", "AdminPassword123!", Role.ADMIN.value)
    provider_user = mgr.create_user(
        "provider_alpha",
        "alpha@nodes.io",
        "ProviderPassword123!",
        Role.PROVIDER.value,
        provider_id="provider-alpha",
    )
    other_provider_user = mgr.create_user(
        "provider_beta",
        "beta@nodes.io",
        "ProviderPassword123!",
        Role.PROVIDER.value,
        provider_id="provider-beta",
    )
    consumer_alice = mgr.create_user(
        "consumer_alice",
        "alice@consumer.org",
        "ConsumerPassword123!",
        Role.CONSUMER.value,
    )
    consumer_bob = mgr.create_user(
        "consumer_bob",
        "bob@consumer.org",
        "ConsumerPassword123!",
        Role.CONSUMER.value,
    )

    return {
        "admin": create_access_token(admin_user, rbac_settings),
        "provider_alpha": create_access_token(provider_user, rbac_settings),
        "provider_beta": create_access_token(other_provider_user, rbac_settings),
        "consumer_alice": create_access_token(consumer_alice, rbac_settings),
        "consumer_bob": create_access_token(consumer_bob, rbac_settings),
    }


# =============================================================================
# 1. Admin RBAC Permissions Tests
# =============================================================================

def test_admin_can_manage_users(rbac_client: TestClient, tokens: dict):
    """Admin role can list all users, change roles, and modify account status."""
    headers = {"Authorization": f"Bearer {tokens['admin']}"}

    # 1. List users
    res = rbac_client.get("/auth/admin/users", headers=headers)
    assert res.status_code == 200
    assert res.json()["count"] >= 5

    # 2. Promote consumer to provider
    users = res.json()["users"]
    alice = next(u for u in users if u["username"] == "consumer_alice")

    role_res = rbac_client.post(
        f"/auth/admin/users/{alice['user_id']}/role",
        headers=headers,
        json={"role": "provider", "provider_id": "provider-alice-promoted"},
    )
    assert role_res.status_code == 200
    assert role_res.json()["role"] == "provider"

    # 3. Deactivate and reactivate status
    status_res = rbac_client.post(
        f"/auth/admin/users/{alice['user_id']}/status",
        headers=headers,
        json={"is_active": False},
    )
    assert status_res.status_code == 200
    assert status_res.json()["is_active"] is False


def test_admin_can_access_policy_and_reconciliation(rbac_client: TestClient, tokens: dict):
    """Admin can update accounting policy and run catalog reconciliation."""
    headers = {"Authorization": f"Bearer {tokens['admin']}"}

    # Policy update
    policy_res = rbac_client.put(
        "/accounting/policy",
        headers=headers,
        json={
            "storage_rate_per_gb_hour": 0.005,
            "egress_rate_per_gb": 0.02,
            "ingress_rate_per_gb": 0.005,
            "repair_rate_per_gb": 0.03,
            "policy_version": "2.0-admin",
            "effective_date": "2026-10-15T00:00:00Z",
            "last_updated_by": "admin_user",
        },
    )
    assert policy_res.status_code == 200
    assert policy_res.json()["policy_version"] == "2.0-admin"

    # Catalog reconciliation
    recon_res = rbac_client.post("/catalog/reconcile?dry_run=true", headers=headers)
    assert recon_res.status_code == 200
    assert "status" in recon_res.json()
    assert recon_res.json()["status"] == "dry_run"


# =============================================================================
# 2. Provider Isolation Tests
# =============================================================================

def test_provider_cannot_access_admin_or_consumer_routes(rbac_client: TestClient, tokens: dict):
    """Provider role is forbidden from admin endpoints and consumer file catalogs."""
    headers = {"Authorization": f"Bearer {tokens['provider_alpha']}"}

    # 1. Admin user management -> 403
    res_admin = rbac_client.get("/auth/admin/users", headers=headers)
    assert res_admin.status_code == 403

    # 2. Admin policy update -> 403
    res_policy = rbac_client.put(
        "/accounting/policy",
        headers=headers,
        json={
            "storage_rate_per_gb_hour": 0.1,
            "egress_rate_per_gb": 0.1,
            "ingress_rate_per_gb": 0.1,
            "repair_rate_per_gb": 0.1,
            "policy_version": "rogue",
            "effective_date": "2026-10-15T00:00:00Z",
            "last_updated_by": "rogue",
        },
    )
    assert res_policy.status_code == 403

    # 3. Consumer file catalog -> 403
    res_catalog = rbac_client.get("/catalog/files", headers=headers)
    assert res_catalog.status_code == 403
    assert "Provider accounts cannot access consumer file catalogs" in res_catalog.json()["detail"]


def test_provider_cross_tenant_isolation(
    rbac_client: TestClient, tokens: dict, rbac_settings: CoordinatorSettings
):
    """Provider A cannot access or control Provider B's storage nodes."""
    registry: NodeRegistry = app.state.registry

    # Register node for provider-alpha
    node_alpha = registry.register_node(
        node_id="node-alpha-1",
        host="127.0.0.1",
        port=9010,
        total_capacity_bytes=50000000000,
        provider_id="provider-alpha",
    )

    # Register node for provider-beta
    node_beta = registry.register_node(
        node_id="node-beta-1",
        host="127.0.0.1",
        port=9020,
        total_capacity_bytes=50000000000,
        provider_id="provider-beta",
    )

    headers_alpha = {"Authorization": f"Bearer {tokens['provider_alpha']}"}

    # 1. Provider Alpha accesses own node -> 200
    res_own = rbac_client.get("/provider/nodes/node-alpha-1/detail", headers=headers_alpha)
    assert res_own.status_code == 200

    # 2. Provider Alpha tries to inspect Provider Beta's node -> 403 Forbidden
    res_other = rbac_client.get("/provider/nodes/node-beta-1/detail", headers=headers_alpha)
    assert res_other.status_code == 403
    assert "Access denied" in res_other.json()["detail"]

    # 3. Provider Alpha tries to deregister Provider Beta's node -> 403 Forbidden
    res_del = rbac_client.delete("/nodes/node-beta-1", headers=headers_alpha)
    assert res_del.status_code == 403
    assert "not authorized to deregister node belonging to provider" in res_del.json()["detail"]


# =============================================================================
# 3. Consumer Isolation and File Ownership Tests
# =============================================================================

def test_consumer_isolated_from_admin_and_provider(rbac_client: TestClient, tokens: dict):
    """Consumer cannot access administrative endpoints or provider dashboards."""
    headers = {"Authorization": f"Bearer {tokens['consumer_alice']}"}

    # 1. Provider overview -> 403
    res_prov = rbac_client.get("/provider/overview", headers=headers)
    assert res_prov.status_code == 403
    assert "Consumer accounts cannot access provider management" in res_prov.json()["detail"]

    # 2. Storage node deregistration -> 403
    res_del_node = rbac_client.delete("/nodes/some-node", headers=headers)
    assert res_del_node.status_code == 403

    # 3. Catalog reconciliation -> 403
    res_recon = rbac_client.post("/catalog/reconcile", headers=headers)
    assert res_recon.status_code == 403

    # 4. Cluster accounting summary -> 403
    res_acct = rbac_client.get("/accounting/cluster/summary", headers=headers)
    assert res_acct.status_code == 403


def test_consumer_file_ownership_strict_boundary(
    rbac_client: TestClient, tokens: dict, rbac_settings: CoordinatorSettings
):
    """Consumer Alice's file cannot be accessed, read, or deleted by Consumer Bob."""
    catalog: FileCatalog = app.state.catalog

    # Register an encrypted file owned by consumer_alice
    manifest_data = {
        "file_id": "file-alice-private-001",
        "file_name": "passwords_encrypted.enc",
        "file_size": 2048,
        "chunk_size": 1024,
        "replication_factor": 2,
        "redundancy_mode": "REPLICATION",
        "chunks": [
            {
                "chunk_id": "chunk-0",
                "chunk_index": 0,
                "size_bytes": 1024,
                "sha256": "0" * 64,
                "nodes": ["node-alpha-1"],
            }
        ],
    }

    catalog.register_file("consumer_alice", manifest_data)

    headers_alice = {"Authorization": f"Bearer {tokens['consumer_alice']}"}
    headers_bob = {"Authorization": f"Bearer {tokens['consumer_bob']}"}

    # 1. Alice can view her own file metadata
    res_alice_get = rbac_client.get("/catalog/files/file-alice-private-001", headers=headers_alice)
    assert res_alice_get.status_code == 200
    assert res_alice_get.json()["file_id"] == "file-alice-private-001"

    # 2. Bob attempts to access Alice's file -> 403 Forbidden
    res_bob_get = rbac_client.get("/catalog/files/file-alice-private-001", headers=headers_bob)
    assert res_bob_get.status_code in (403, 404)
    if res_bob_get.status_code == 403:
        assert "permission" in res_bob_get.json()["detail"].lower()

    # 3. Bob attempts to delete Alice's file -> 403 Forbidden
    res_bob_del = rbac_client.delete("/catalog/files/file-alice-private-001", headers=headers_bob)
    assert res_bob_del.status_code in (403, 404)

    # 4. In file listing: Alice sees her file, Bob's file list does NOT contain Alice's file
    alice_list = rbac_client.get("/catalog/files", headers=headers_alice).json()
    bob_list = rbac_client.get("/catalog/files", headers=headers_bob).json()

    assert any(f["file_id"] == "file-alice-private-001" for f in alice_list["files"])
    assert not any(f["file_id"] == "file-alice-private-001" for f in bob_list["files"])


# =============================================================================
# 4. Storage Node Machine Authentication Regression Tests
# =============================================================================

def test_storage_node_machine_token_still_works(rbac_client: TestClient, rbac_settings: CoordinatorSettings):
    """Legacy/Machine X-Auth-Token for node heartbeats and registrations continues to work."""
    machine_headers = {"X-Auth-Token": rbac_settings.auth_token}

    # 1. Node registration via machine token
    reg_payload = {
        "node_id": "machine-node-daemon-01",
        "host": "127.0.0.1",
        "port": 9050,
        "endpoint": "http://127.0.0.1:9050",
        "total_capacity_bytes": 100000000000,
        "provider_id": "provider-alpha",
    }
    res_reg = rbac_client.post("/nodes/register", headers=machine_headers, json=reg_payload)
    assert res_reg.status_code == 200
    assert res_reg.json()["node_id"] == "machine-node-daemon-01"

    # 2. Node heartbeat via machine token
    hb_payload = {
        "status": "online",
        "available_capacity_bytes": 95000000000,
        "used_capacity_bytes": 5000000000,
    }
    res_hb = rbac_client.post(
        "/nodes/machine-node-daemon-01/heartbeat",
        headers=machine_headers,
        json=hb_payload,
    )
    assert res_hb.status_code == 200
    assert res_hb.json()["status"] == "online"
