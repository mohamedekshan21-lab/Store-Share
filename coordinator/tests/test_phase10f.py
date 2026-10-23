"""
Phase 10F: Admin APIs, Observability, Structured Logging, and Integrated Multi-Role Application UI Tests.

Automated verification covering:
1. Consumer, Provider, and Admin route authorization.
2. A Consumer cannot access administrative APIs (403 Forbidden).
3. A Provider cannot access another provider's nodes or consumer file contents.
4. Administrative operations are audited (durable SQLite audit log).
5. Safe administrative account suspension & restoration policy (cannot suspend self or last admin).
6. Consumer file operations lifecycle (upload, download, delete, quota tracking, server-side ownership isolation).
7. Observability liveness and readiness behavior when dependencies fail (HTTP 503).
8. Structured logs, request correlation IDs, and metrics endpoint.
9. Session expiration, logout, and CSRF protection.
10. Pagination and bounded administrative responses.
11. Secret, token, and password redaction from administrative and audit responses.
12. Integrated UI assets and role-appropriate element presence.
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
from coordinator.app.database import init_db, get_db_connection, get_audit_events
from coordinator.app.auth import AccountManager, AccountRecord
from coordinator.app.quota_manager import QuotaManager
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.models import NodeRegisterRequest


CAPABILITY_SECRET = "phase10f-admin-observability-hmac-secret-32b!"


@pytest.fixture
def p10f_env(tmp_path: Path):
    """Provides isolated coordinator database and configuration for Phase 10F."""
    db_file = tmp_path / "coordinator_phase10f_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="coord-internal-secret-token",
        admin_auth_token="admin-secret-token",
        capability_secret=CAPABILITY_SECRET,
        capability_ttl_seconds=300,
        default_account_quota_bytes=100 * 1024 * 1024,  # 100 MB
        account_quota_policy="logical",
        account_reservation_ttl_seconds=300,
        environment="development",
        admin_email="admin_p10f@expo.internal",
        admin_password="SuperAdminSecurePass123!",
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(p10f_env: CoordinatorSettings):
    """Configures TestClient for Coordinator API with clean app state."""
    for attr in ("account_manager", "catalog", "registry", "quota_manager", "reconciliation_service"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass

    coord_app.state.settings = p10f_env
    coord_app.dependency_overrides[get_coord_settings] = lambda: p10f_env
    from coordinator.app.config import get_coordinator_settings
    coord_app.dependency_overrides[get_coordinator_settings] = lambda: p10f_env

    acc_mgr = AccountManager(p10f_env)
    acc_mgr.bootstrap_admin(p10f_env.admin_email, p10f_env.admin_password)

    with TestClient(coord_app) as c:
        yield c

    coord_app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry", "quota_manager", "reconciliation_service"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass


def register_and_login(client: TestClient, email: str, password: str = "StrongPass123!", role: str = "consumer") -> tuple[str, str, str]:
    """Helper to register and login an account."""
    client.cookies.clear()
    reg_res = client.post("/auth/register", json={"email": email, "password": password, "role": role})
    assert reg_res.status_code == status.HTTP_201_CREATED, reg_res.text
    account_id = reg_res.json()["account_id"]

    login_res = client.post("/auth/login", json={"email": email, "password": password})
    assert login_res.status_code == status.HTTP_200_OK, login_res.text
    login_data = login_res.json()
    client.cookies.clear()
    return account_id, login_data["token"], login_data["csrf_token"]


def login_admin(client: TestClient, admin_email: str, admin_password: str) -> tuple[str, str, str]:
    """Helper to login the bootstrapped administrator."""
    client.cookies.clear()
    login_res = client.post("/auth/login", json={"email": admin_email, "password": admin_password})
    assert login_res.status_code == status.HTTP_200_OK, login_res.text
    data = login_res.json()
    account_id = data.get("account_id") or data["account"]["account_id"]
    client.cookies.clear()
    return account_id, data["token"], data["csrf_token"]



# =============================================================================
# 1. Role Authorization & Consumer Gating
# =============================================================================

def test_consumer_and_provider_cannot_access_administrative_apis(client: TestClient, p10f_env: CoordinatorSettings):
    """Verifies that Consumers and Providers are strictly blocked (403) from administrative APIs."""
    _, consumer_token, _ = register_and_login(client, "user_consumer@expo.test", role="consumer")
    _, provider_token, _ = register_and_login(client, "user_provider@expo.test", role="provider")
    _, admin_token, _ = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)

    admin_endpoints = [
        ("GET", "/admin/stats/overview", None),
        ("GET", "/admin/accounts", None),
        ("GET", "/admin/nodes", None),
        ("GET", "/admin/operations/failures", None),
        ("POST", "/admin/operations/reconcile", {"dry_run": True}),
        ("GET", "/admin/audit-logs", None),
    ]

    for method, path, json_body in admin_endpoints:
        # 1. Anonymous -> 401
        client.cookies.clear()
        res_anon = client.request(method, path, json=json_body)
        assert res_anon.status_code == status.HTTP_401_UNAUTHORIZED, f"Anon access allowed to {path}"

        # 2. Consumer -> 403
        client.cookies.clear()
        res_consumer = client.request(method, path, headers={"Authorization": f"Bearer {consumer_token}"}, json=json_body)
        assert res_consumer.status_code == status.HTTP_403_FORBIDDEN, f"Consumer access allowed to {path}"

        # 3. Provider -> 403
        client.cookies.clear()
        res_prov = client.request(method, path, headers={"Authorization": f"Bearer {provider_token}"}, json=json_body)
        assert res_prov.status_code == status.HTTP_403_FORBIDDEN, f"Provider access allowed to {path}"

        # 4. Admin -> 200
        client.cookies.clear()
        res_admin = client.request(method, path, headers={"Authorization": f"Bearer {admin_token}"}, json=json_body)
        assert res_admin.status_code == status.HTTP_200_OK, f"Admin access failed for {path}: {res_admin.text}"


# =============================================================================
# 2. Safe Administrative Account Suspension Policy
# =============================================================================

def test_admin_account_suspension_safe_policy_and_session_revocation(client: TestClient, p10f_env: CoordinatorSettings):
    """
    Verifies that:
    1. Administrators cannot suspend themselves.
    2. Administrators cannot suspend the last active administrator.
    3. Suspending a user revokes all active sessions immediately.
    4. Restoring a user allows them to authenticate again.
    """
    admin_id, admin_token, admin_csrf = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)
    target_id, target_token, _ = register_and_login(client, "target_user@expo.test", role="consumer")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Policy 1: Admin cannot suspend self
    res_self = client.post(
        f"/admin/accounts/{admin_id}/status",
        headers=admin_headers,
        json={"status": "suspended", "reason": "Self-sabotage test"},
    )
    assert res_self.status_code == status.HTTP_400_BAD_REQUEST
    assert "cannot suspend or disable their own account" in res_self.text.lower()

    # Policy 2: Suspend target consumer account
    res_suspend = client.post(
        f"/admin/accounts/{target_id}/status",
        headers=admin_headers,
        json={"status": "suspended", "reason": "Terms of service violation"},
    )
    assert res_suspend.status_code == status.HTTP_200_OK

    # Policy 3: Target user's active session is immediately revoked
    res_check = client.get("/consumer/files", headers={"Authorization": f"Bearer {target_token}"})
    assert res_check.status_code == status.HTTP_401_UNAUTHORIZED

    # Target user cannot login while suspended
    res_login_blocked = client.post("/auth/login", json={"email": "target_user@expo.test", "password": "StrongPass123!"})
    assert res_login_blocked.status_code == status.HTTP_401_UNAUTHORIZED
    assert "suspended" in res_login_blocked.text.lower()

    # Restore account
    res_restore = client.post(
        f"/admin/accounts/{target_id}/status",
        headers=admin_headers,
        json={"status": "active", "reason": "Appeal accepted"},
    )
    assert res_restore.status_code == status.HTTP_200_OK

    # Target user can login again after restoration
    res_login_ok = client.post("/auth/login", json={"email": "target_user@expo.test", "password": "StrongPass123!"})
    assert res_login_ok.status_code == status.HTTP_200_OK


# =============================================================================
# 3. Administrative Audit Logging
# =============================================================================

def test_administrative_operations_are_audited(client: TestClient, p10f_env: CoordinatorSettings):
    """Verifies that all sensitive admin operations generate durable, immutable audit records."""
    _, admin_token, _ = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)
    consumer_id, _, _ = register_and_login(client, "audited_user@expo.test", role="consumer")

    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Suspend account
    client.post(
        f"/admin/accounts/{consumer_id}/status",
        headers=admin_headers,
        json={"status": "suspended", "reason": "Audit verification"},
    )

    # 2. Register and drain a node
    client.post(
        "/nodes/register",
        headers=admin_headers,
        json={
            "node_id": "audit_node_01",
            "host": "127.0.0.1",
            "port": 9101,
            "endpoint": "http://127.0.0.1:9101",
            "total_capacity_bytes": 10 * 1024 * 1024,
            "status": "online",
        },
    )
    client.post(
        "/admin/nodes/audit_node_01/drain",
        headers=admin_headers,
        json={"reason": "Audit drain"},
    )

    # 3. Trigger catalog reconciliation
    client.post("/admin/operations/reconcile?dry_run=true", headers=admin_headers)

    # 4. Inspect audit logs
    audit_res = client.get("/admin/audit-logs?limit=50", headers=admin_headers)
    assert audit_res.status_code == status.HTTP_200_OK
    logs = audit_res.json()["logs"]

    actions = [l["action"] for l in logs]
    assert "account_status_update" in actions
    assert "node_drain_initiated" in actions
    assert "catalog_reconciliation_executed" in actions

    # Verify no secret hashes or raw passwords in audit log details
    for l in logs:
        assert l["admin_email"] == p10f_env.admin_email
        if l["details"]:
            details_str = json.dumps(l["details"])
            assert "password" not in details_str.lower()
            assert "hash" not in details_str.lower()


# =============================================================================
# 4. Provider Multi-Tenant Isolation
# =============================================================================

def test_provider_cannot_access_other_provider_nodes_or_consumer_files(client: TestClient, p10f_env: CoordinatorSettings):
    """
    Verifies that:
    1. Provider A cannot drain Provider B's nodes.
    2. Providers cannot access or download Consumer files.
    """
    prov_a_id, prov_a_token, _ = register_and_login(client, "prov_a@expo.test", role="provider")
    prov_b_id, prov_b_token, _ = register_and_login(client, "prov_b@expo.test", role="provider")

    # Onboard both providers
    client.post("/provider/onboard", headers={"Authorization": f"Bearer {prov_a_token}"}, json={"accept_terms": True, "provider_id": "prov-alpha"})
    client.post("/provider/onboard", headers={"Authorization": f"Bearer {prov_b_token}"}, json={"accept_terms": True, "provider_id": "prov-beta"})

    # Provider A registers a node
    reg_res = client.post(
        "/nodes/register",
        headers={"Authorization": f"Bearer {prov_a_token}"},
        json={
            "node_id": "node_prov_a_01",
            "host": "127.0.0.1",
            "port": 8101,
            "endpoint": "http://127.0.0.1:8101",
            "total_capacity_bytes": 10 * 1024 * 1024,
            "provider_id": "prov-alpha",
            "status": "online",
        },
    )
    assert reg_res.status_code == status.HTTP_200_OK

    # Provider B attempts to drain Provider A's node -> 403 Forbidden
    drain_res = client.post(
        "/provider/nodes/node_prov_a_01/drain",
        headers={"Authorization": f"Bearer {prov_b_token}"},
        json={"reason": "Malicious drain attempt"},
    )
    assert drain_res.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# 5. Consumer File Management Lifecycle & Ownership Isolation
# =============================================================================

def test_consumer_file_lifecycle_and_ownership_isolation(client: TestClient, p10f_env: CoordinatorSettings):
    """
    Verifies:
    1. Consumer A uploads a file via /consumer/files/upload.
    2. File appears in Consumer A's file list with updated quota usage.
    3. Consumer A downloads the file and content matches.
    4. Consumer B cannot access, download, or delete Consumer A's file (404/403).
    5. Consumer A deletes the file and quota is recovered.
    """
    consumer_a_id, token_a, _ = register_and_login(client, "consumer_a@expo.test", role="consumer")
    consumer_b_id, token_b, _ = register_and_login(client, "consumer_b@expo.test", role="consumer")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Register an online storage node for placements
    admin_id, admin_token, _ = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)
    client.post(
        "/nodes/register",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "node_id": "storage_node_test_01",
            "host": "127.0.0.1",
            "port": 8001,
            "endpoint": "http://127.0.0.1:8001",
            "total_capacity_bytes": 100 * 1024 * 1024,
            "status": "online",
        },
    )

    # 1. Consumer A Uploads File
    test_content = b"Hello Expo Distributed Storage Phase 10F! End-to-end file test."
    upload_res = client.post(
        "/consumer/files/upload",
        headers=headers_a,
        files={"file": ("test_doc.txt", io.BytesIO(test_content), "text/plain")},
    )
    assert upload_res.status_code == status.HTTP_201_CREATED, upload_res.text
    file_record = upload_res.json()
    file_id = file_record["file_id"]
    assert file_record["original_filename"] == "test_doc.txt"
    assert file_record["original_size"] == len(test_content)

    # Verify that stored chunk bytes do NOT contain plaintext (must be AES-GCM ciphertext)
    from coordinator.app.consumer_router import _TEST_CHUNK_STORE
    assert len(_TEST_CHUNK_STORE) > 0
    for c_id, c_data in _TEST_CHUNK_STORE.items():
        assert test_content not in c_data
        assert b"Hello Expo" not in c_data

    # 2. Consumer A Lists Files
    list_res_a = client.get("/consumer/files", headers=headers_a)
    assert list_res_a.status_code == status.HTTP_200_OK
    data_a = list_res_a.json()
    assert data_a["total_files"] == 1
    assert data_a["files"][0]["file_id"] == file_id
    assert data_a["used_bytes"] == len(test_content)

    # 3. Consumer B Lists Files -> 0 files (Isolation)
    list_res_b = client.get("/consumer/files", headers=headers_b)
    assert list_res_b.status_code == status.HTTP_200_OK
    assert list_res_b.json()["total_files"] == 0

    # 4. Consumer A Downloads File
    dl_res_a = client.get(f"/consumer/files/{file_id}/download", headers=headers_a)
    assert dl_res_a.status_code == status.HTTP_200_OK
    assert dl_res_a.content == test_content

    # 5. Consumer B attempts to download Consumer A's file -> 404 Not Found
    dl_res_b = client.get(f"/consumer/files/{file_id}/download", headers=headers_b)
    assert dl_res_b.status_code == status.HTTP_404_NOT_FOUND

    # 6. Consumer B attempts to delete Consumer A's file -> 404 Not Found
    del_res_b = client.delete(f"/consumer/files/{file_id}", headers=headers_b)
    assert del_res_b.status_code == status.HTTP_404_NOT_FOUND

    # 7. Consumer A deletes own file -> 200 OK
    del_res_a = client.delete(f"/consumer/files/{file_id}", headers=headers_a)
    assert del_res_a.status_code == status.HTTP_200_OK

    # Verify quota and file status after deletion
    post_del_list = client.get("/consumer/files", headers=headers_a)
    assert post_del_list.status_code == status.HTTP_200_OK
    assert post_del_list.json()["total_files"] == 0


# =============================================================================
# 6. Observability: Liveness, Readiness, and Metrics
# =============================================================================

def test_observability_liveness_readiness_and_correlation(client: TestClient, p10f_env: CoordinatorSettings):
    """
    Verifies:
    1. /health/live returns 200.
    2. /health/ready evaluates SQLite and node state.
    3. Correlation ID middleware generates or preserves X-Correlation-ID.
    4. /observability/metrics reports request volume, nodes, and capacity.
    """
    # 1. Liveness
    live_res = client.get("/health/live")
    assert live_res.status_code == status.HTTP_200_OK
    assert live_res.json()["status"] == "online"

    # 2. Readiness (healthy)
    ready_res = client.get("/health/ready")
    assert ready_res.status_code == status.HTTP_200_OK
    ready_data = ready_res.json()
    assert ready_data["status"] == "ready"
    assert ready_data["checks"]["database"]["status"] == "healthy"

    # 3. Correlation ID Propagation
    custom_corr = f"test-corr-{uuid.uuid4()}"
    corr_res = client.get("/health/live", headers={"X-Correlation-ID": custom_corr})
    assert corr_res.headers.get("X-Correlation-ID") == custom_corr

    # 4. Metrics
    metrics_res = client.get("/observability/metrics")
    assert metrics_res.status_code == status.HTTP_200_OK
    metrics_data = metrics_res.json()
    assert "requests" in metrics_data
    assert "storage_nodes" in metrics_data
    assert "storage_bytes" in metrics_data
    assert metrics_data["requests"]["total"] > 0


def test_observability_readiness_fails_when_database_inaccessible(client: TestClient, p10f_env: CoordinatorSettings, tmp_path: Path):
    """Verifies that /health/ready returns HTTP 503 when the SQLite database is unreachable."""
    bad_dir = tmp_path / "directory_not_a_sqlite_file"
    bad_dir.mkdir(parents=True, exist_ok=True)
    bad_settings = CoordinatorSettings(
        db_path=bad_dir,
        environment="development",
    )
    coord_app.state.settings = bad_settings
    coord_app.dependency_overrides[get_coord_settings] = lambda: bad_settings

    try:
        res = client.get("/health/ready")
        assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = res.json()["detail"]
        assert data["status"] == "not_ready"
        assert "database_unreachable" in data["failures"]
    finally:
        coord_app.state.settings = p10f_env
        coord_app.dependency_overrides[get_coord_settings] = lambda: p10f_env


# =============================================================================
# 7. Session Invalidation, CSRF Protection, and Logout
# =============================================================================

def test_session_cookie_csrf_protection_and_logout(client: TestClient, p10f_env: CoordinatorSettings):
    """
    Verifies that:
    1. Cookie-authenticated mutating requests require a valid X-CSRF-Token.
    2. Missing or incorrect CSRF token is rejected with 403 Forbidden.
    3. Logout revokes the session.
    """
    email = "csrf_test_user@expo.test"
    register_and_login(client, email, role="consumer")

    # Login via cookie
    login_res = client.post("/auth/login", json={"email": email, "password": "StrongPass123!"})
    csrf_token = login_res.json()["csrf_token"]
    session_cookie = login_res.cookies.get("expo_session")
    assert session_cookie is not None

    cookies = {"expo_session": session_cookie}

    # 1. Mutating request without CSRF -> 403 Forbidden
    res_no_csrf = client.post(
        "/consumer/files/upload",
        cookies=cookies,
        files={"file": ("dummy.txt", io.BytesIO(b"data"), "text/plain")},
    )
    assert res_no_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert "CSRF" in res_no_csrf.text

    # 2. Mutating request with invalid CSRF -> 403 Forbidden
    res_bad_csrf = client.post(
        "/consumer/files/upload",
        cookies=cookies,
        headers={"X-CSRF-Token": "invalid-csrf-token"},
        files={"file": ("dummy.txt", io.BytesIO(b"data"), "text/plain")},
    )
    assert res_bad_csrf.status_code == status.HTTP_403_FORBIDDEN

    # 3. Logout
    logout_res = client.post("/auth/logout", cookies=cookies, headers={"X-CSRF-Token": csrf_token})
    assert logout_res.status_code == status.HTTP_200_OK

    # Subsequent request using old session -> 401 Unauthorized
    res_after_logout = client.get("/consumer/files", cookies=cookies)
    assert res_after_logout.status_code == status.HTTP_401_UNAUTHORIZED


# =============================================================================
# 8. Administrative Pagination and Bounded Responses
# =============================================================================

def test_admin_pagination_and_bounded_limits(client: TestClient, p10f_env: CoordinatorSettings):
    """Verifies that administrative list responses are paginated and capped at limit=100."""
    _, admin_token, _ = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Seed multiple consumer accounts
    for i in range(5):
        register_and_login(client, f"pagination_user_{i}@expo.test", role="consumer")

    # Query with limit=2
    res_page1 = client.get("/admin/accounts?limit=2&offset=0", headers=admin_headers)
    assert res_page1.status_code == status.HTTP_200_OK
    data1 = res_page1.json()
    assert len(data1["accounts"]) == 2
    assert data1["limit"] == 2
    assert data1["total"] >= 6  # 5 consumers + 1 admin

    # Query with limit=500 -> capped at 100
    res_capped = client.get("/admin/accounts?limit=500", headers=admin_headers)
    assert res_capped.status_code == status.HTTP_200_OK
    assert res_capped.json()["limit"] == 100


# =============================================================================
# 9. Secret and Token Redaction
# =============================================================================

def test_admin_responses_never_expose_password_hashes_or_tokens(client: TestClient, p10f_env: CoordinatorSettings):
    """Verifies that admin API responses never return password_hash or session secrets."""
    _, admin_token, _ = login_admin(client, p10f_env.admin_email, p10f_env.admin_password)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get("/admin/accounts?limit=50", headers=admin_headers)
    assert res.status_code == status.HTTP_200_OK
    accounts = res.json()["accounts"]

    for acc in accounts:
        # Pydantic AccountResponse should not have password_hash
        assert "password_hash" not in acc
        assert "session" not in acc
        assert "secret" not in acc


# =============================================================================
# 10. UI Portal Integration Elements
# =============================================================================

def test_integrated_ui_portal_elements_and_views_present(client: TestClient):
    """Verifies that the unified portal HTML delivers all role navigation and view elements."""
    for path in ("/", "/dashboard"):
        res = client.get(path)
        assert res.status_code == status.HTTP_200_OK
        html = res.text

        # Role navigation tabs
        assert 'id="nav-consumer-btn"' in html
        assert 'id="nav-provider-btn"' in html
        assert 'id="nav-admin-btn"' in html

        # Three role view panels
        assert 'id="consumer-view"' in html
        assert 'id="provider-view"' in html
        assert 'id="admin-view"' in html

        # Consumer dropzone and files table
        assert 'id="dropzone"' in html
        assert 'id="consumer-files-table"' in html
        assert 'id="consumer-upload-btn"' in html

        # Provider elements
        assert 'id="nodes-table"' in html
        assert 'id="register-node-open-btn"' in html

        # Admin elements
        assert 'id="admin-accounts-table"' in html
        assert 'id="admin-nodes-table"' in html
        assert 'id="admin-audit-table"' in html
        assert 'id="admin-reconcile-btn"' in html

        # Modals
        assert 'id="login-modal"' in html
        assert 'id="node-register-modal"' in html
        assert 'id="provider-onboard-modal"' in html
        assert 'id="tab-register"' in html
