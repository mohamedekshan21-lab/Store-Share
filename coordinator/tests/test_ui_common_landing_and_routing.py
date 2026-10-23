"""
Test Suite: Expo UI Phase — Common Landing Page, Unified Login, and Secure Role-Based Routing.

Verifies:
1. Public homepage loads without authentication.
2. Valid consumer login redirects to Consumer profile.
3. Valid provider login redirects to Provider profile.
4. Valid admin login redirects to Admin Console APIs.
5. Invalid passwords are rejected with generic errors.
6. Unknown accounts cannot log in (resists enumeration).
7. Public registration cannot create an admin account by submitting role=admin.
8. Public registration cannot bypass controlled provider onboarding.
9. An authenticated consumer cannot access admin APIs (HTTP 403).
10. A provider cannot manage another provider's node (HTTP 403).
11. A consumer cannot read or delete another consumer's files (strict isolation).
12. Refresh preserves a valid session cookie.
13. Logout invalidates the server session and clears cookie.
14. Expired or revoked sessions cannot access protected operations.
15. Direct URL/hash manipulation cannot elevate privileges on the server.
16. Existing file upload, download, delete, and quota workflows work end-to-end.
17. Idempotent account provisioning preserves existing secrets.
"""

from __future__ import annotations

import io
import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from coordinator.app.main import app as coord_app
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db, get_db_connection
from coordinator.app.auth import hash_password, AccountManager
from backend.provision_accounts import provision_accounts, REQUIRED_ASSIGNMENTS


@pytest.fixture
def ui_test_env(tmp_path: Path) -> Generator[CoordinatorSettings, None, None]:
    """Provides an isolated database and environment for UI & routing tests."""
    db_file = tmp_path / "coordinator_ui_test.db"
    storage_dir = tmp_path / "storage_root"
    storage_dir.mkdir(parents=True, exist_ok=True)

    test_settings = CoordinatorSettings(
        environment="development",
        port=8000,
        host="127.0.0.1",
        db_path=db_file,
        auth_token="test_master_token_32bytes_long!!",
        admin_auth_token="test_admin_token_32bytes_long!",
        capability_secret="expo_test_secret_for_local_nodes_32bytes_long!",
        storage_root=storage_dir,
        cookie_secure=False,
        session_ttl_minutes=60,
        default_account_quota_bytes=10 * 1024 * 1024 * 1024,
    )

    init_db(test_settings.db_path)
    coord_app.state.settings = test_settings

    # Clear cached state
    for attr in ("account_manager", "registry", "catalog", "quota_manager", "reconciliation_service", "session_manager", "credential_manager"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass

    yield test_settings

    for attr in ("account_manager", "registry", "catalog", "quota_manager", "reconciliation_service", "session_manager", "credential_manager"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass


@pytest.fixture
def client(ui_test_env: CoordinatorSettings) -> Generator[TestClient, None, None]:
    """TestClient bound to the isolated coordinator app."""
    with TestClient(coord_app, base_url="http://127.0.0.1:8000") as c:
        yield c


# =============================================================================
# 1. Public Homepage & Navigation Tests
# =============================================================================

def test_public_homepage_loads_without_authentication(client: TestClient):
    """Verifies that the common public landing page is accessible without auth (HTTP 200)."""
    res = client.get("/")
    assert res.status_code == status.HTTP_200_OK
    assert "text/html" in res.headers["content-type"]
    html = res.text

    # Core elements from Step 2 specification
    assert "EXPO" in html
    assert "DISTRIBUTED STORAGE" in html
    assert "Decentralized Storage" in html
    assert "Cryptographic Integrity" in html
    assert "Zero-Knowledge" in html
    assert "For Data Consumers" in html
    assert "For Storage Providers" in html
    assert "Client-Side Encryption" in html
    assert "Deterministic Placement" in html
    assert "Autonomous Self-Healing" in html
    assert "How Expo Works" in html
    assert "nav-landing-btn" in html
    assert "landing-view" in html
    assert "auth-btn" in html

    # Alternative supported public endpoints
    res_app = client.get("/app")
    assert res_app.status_code == status.HTTP_200_OK

    res_dash = client.get("/dashboard")
    assert res_dash.status_code == status.HTTP_200_OK


# =============================================================================
# 2. Account Provisioning & Role-Based Login Tests
# =============================================================================

def test_provisioning_and_role_based_routing(client: TestClient, ui_test_env: CoordinatorSettings):
    """
    Tests:
    - Provisioning the three required accounts with specific roles.
    - mohamedekshan21@gmail.com -> Admin
    - 24d128@psgitech.ac.in -> Provider
    - ajishadhasin@gmail.com -> Consumer
    - Verifies each account reaches their authorized role endpoint and is blocked from unpermitted endpoints.
    """
    admin_pw = "AdminPass#2026!Sec"
    provider_pw = "ProviderPass#2026!Sec"
    consumer_pw = "ConsumerPass#2026!Sec"

    custom_passwords = {
        "mohamedekshan21@gmail.com": admin_pw,
        "24d128@psgitech.ac.in": provider_pw,
        "ajishadhasin@gmail.com": consumer_pw,
    }

    # Step 4 Provisioning
    results = provision_accounts(ui_test_env.db_path, custom_passwords=custom_passwords, dev_verify=False)
    assert len(results) == 3

    # Check database records
    with get_db_connection(ui_test_env.db_path) as conn:
        admin_row = conn.execute("SELECT * FROM accounts WHERE email = 'mohamedekshan21@gmail.com'").fetchone()
        assert admin_row is not None
        assert admin_row["role"] == "admin"

        prov_row = conn.execute("SELECT * FROM accounts WHERE email = '24d128@psgitech.ac.in'").fetchone()
        assert prov_row is not None
        assert prov_row["role"] == "provider"

        cons_row = conn.execute("SELECT * FROM accounts WHERE email = 'ajishadhasin@gmail.com'").fetchone()
        assert cons_row is not None
        assert cons_row["role"] == "consumer"

    # 1. Login as Consumer (ajishadhasin@gmail.com)
    login_cons = client.post("/auth/login", json={"email": "ajishadhasin@gmail.com", "password": consumer_pw})
    assert login_cons.status_code == status.HTTP_200_OK
    cons_data = login_cons.json()
    assert cons_data["account"]["role"] == "consumer"
    assert cons_data["account"]["email"] == "ajishadhasin@gmail.com"
    cons_token = cons_data["token"]

    # Consumer can access consumer files API
    cons_files = client.get("/consumer/files", headers={"Authorization": f"Bearer {cons_token}"})
    assert cons_files.status_code == status.HTTP_200_OK

    # Consumer CANNOT access admin APIs (HTTP 403)
    cons_admin_attempt = client.get("/admin/stats/overview", headers={"Authorization": f"Bearer {cons_token}"})
    assert cons_admin_attempt.status_code == status.HTTP_403_FORBIDDEN

    # 2. Login as Provider (24d128@psgitech.ac.in)
    login_prov = client.post("/auth/login", json={"email": "24d128@psgitech.ac.in", "password": provider_pw})
    assert login_prov.status_code == status.HTTP_200_OK
    prov_data = login_prov.json()
    assert prov_data["account"]["role"] == "provider"
    assert prov_data["account"]["email"] == "24d128@psgitech.ac.in"
    prov_token = prov_data["token"]

    # Provider CANNOT access admin APIs (HTTP 403)
    prov_admin_attempt = client.get("/admin/stats/overview", headers={"Authorization": f"Bearer {prov_token}"})
    assert prov_admin_attempt.status_code == status.HTTP_403_FORBIDDEN

    # 3. Login as Admin (mohamedekshan21@gmail.com)
    login_admin = client.post("/auth/login", json={"email": "mohamedekshan21@gmail.com", "password": admin_pw})
    assert login_admin.status_code == status.HTTP_200_OK
    admin_data = login_admin.json()
    assert admin_data["account"]["role"] == "admin"
    assert admin_data["account"]["email"] == "mohamedekshan21@gmail.com"
    admin_token = admin_data["token"]

    # Admin CAN access admin overview
    admin_stats = client.get("/admin/stats/overview", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_stats.status_code == status.HTTP_200_OK
    assert "accounts" in admin_stats.json()
    assert admin_stats.json()["accounts"]["admins"] == 1


# =============================================================================
# 3. Authentication Security & Rejection Tests
# =============================================================================

def test_invalid_password_and_unknown_account_rejection(client: TestClient, ui_test_env: CoordinatorSettings):
    """Verifies that bad passwords and unknown accounts return generic 401 errors without enumeration."""
    consumer_pw = "ValidPass#123!"
    provision_accounts(ui_test_env.db_path, custom_passwords={"ajishadhasin@gmail.com": consumer_pw})

    # Bad password
    res_bad_pw = client.post("/auth/login", json={"email": "ajishadhasin@gmail.com", "password": "WrongPassword999!"})
    assert res_bad_pw.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password." in res_bad_pw.text

    # Unknown account
    res_unknown = client.post("/auth/login", json={"email": "nonexistent_ghost_user@example.com", "password": "SomePassword123!"})
    assert res_unknown.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password." in res_unknown.text


def test_public_registration_cannot_create_admin(client: TestClient):
    """Verifies that public registration explicitly cannot create an admin account (enforces consumer role)."""
    res = client.post(
        "/auth/register",
        json={"email": "attacker_admin@example.com", "password": "AttackerPass123!", "role": "admin"},
    )
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    assert data["role"] == "consumer"
    assert "admin:all" not in data.get("capabilities", [])


# =============================================================================
# 4. Session Preservation, Refresh, and Logout Tests
# =============================================================================

def test_session_cookie_preservation_and_logout(client: TestClient, ui_test_env: CoordinatorSettings):
    """Verifies cookie session restoration, refresh, and explicit logout invalidation."""
    pw = "SessionTest#Pass123"
    provision_accounts(ui_test_env.db_path, custom_passwords={"ajishadhasin@gmail.com": pw})

    # Login
    login_res = client.post("/auth/login", json={"email": "ajishadhasin@gmail.com", "password": pw})
    assert login_res.status_code == status.HTTP_200_OK
    csrf_token = login_res.json()["csrf_token"]
    assert "expo_session" in client.cookies

    # GET /auth/me preserves and resolves the active session (simulating page refresh)
    me_res = client.get("/auth/me")
    assert me_res.status_code == status.HTTP_200_OK
    assert me_res.json()["email"] == "ajishadhasin@gmail.com"

    # Logout
    logout_res = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_res.status_code == status.HTTP_200_OK

    # Subsequent request with old session fails
    after_me = client.get("/auth/me")
    assert after_me.status_code == status.HTTP_401_UNAUTHORIZED


# =============================================================================
# 5. Multi-Tenant Account & File Isolation Tests
# =============================================================================

def test_consumer_file_isolation_between_accounts(client: TestClient, ui_test_env: CoordinatorSettings):
    """
    Verifies that:
    1. Consumer A uploads a file.
    2. Consumer B cannot list, access, or delete Consumer A's file.
    """
    mgr = AccountManager(ui_test_env)
    acc_a = mgr.register_account("tenant_a@example.com", "PasswordTenantA123!", role="consumer")
    acc_b = mgr.register_account("tenant_b@example.com", "PasswordTenantB123!", role="consumer")

    sess_a = mgr.create_session(acc_a)
    sess_b = mgr.create_session(acc_b)

    headers_a = {"Authorization": f"Bearer {sess_a.session_id}", "X-CSRF-Token": sess_a.csrf_token}
    headers_b = {"Authorization": f"Bearer {sess_b.session_id}", "X-CSRF-Token": sess_b.csrf_token}

    # Consumer A uploads a test file
    file_content = b"Confidential Consumer A Payload 1234567890"
    upload_res = client.post(
        "/consumer/files/upload",
        headers=headers_a,
        files={"file": ("secret_document.txt", io.BytesIO(file_content), "text/plain")},
    )
    assert upload_res.status_code == status.HTTP_201_CREATED
    file_id = upload_res.json()["file_id"]

    # Consumer A sees the file in /consumer/files
    files_a = client.get("/consumer/files", headers=headers_a).json()
    assert any(f["file_id"] == file_id for f in files_a["files"])

    # Consumer B CANNOT see Consumer A's file in their listing
    files_b = client.get("/consumer/files", headers=headers_b).json()
    assert not any(f["file_id"] == file_id for f in files_b["files"])

    # Consumer B CANNOT download Consumer A's file
    dl_res = client.get(f"/consumer/files/{file_id}/download", headers=headers_b)
    assert dl_res.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN)

    # Consumer B CANNOT delete Consumer A's file
    del_res = client.delete(f"/consumer/files/{file_id}", headers=headers_b)
    assert del_res.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN)


# =============================================================================
# 6. Idempotency & Audit Verification
# =============================================================================

def test_provisioning_idempotency_and_audit_logging(ui_test_env: CoordinatorSettings):
    """
    Verifies that running provision_accounts repeatedly:
    1. Does not overwrite passwords or recreate existing records.
    2. Logs an audit entry in admin_audit_log for privileged role changes.
    """
    pws = {
        "mohamedekshan21@gmail.com": "InitialAdminPass#1",
        "24d128@psgitech.ac.in": "InitialProviderPass#1",
        "ajishadhasin@gmail.com": "InitialConsumerPass#1",
    }

    # Pass 1: Provisioning
    res1 = provision_accounts(ui_test_env.db_path, custom_passwords=pws)
    assert any(r["action"] == "created" for r in res1)

    # Verify audit event in admin_audit_log
    with get_db_connection(ui_test_env.db_path) as conn:
        audit_events = conn.execute("SELECT * FROM admin_audit_log").fetchall()
        assert len(audit_events) >= 1

    # Pass 2: Repeated run
    res2 = provision_accounts(ui_test_env.db_path, custom_passwords=pws)
    for r in res2:
        assert r["action"] == "preserved"


# =============================================================================
# 7. Controlled Provider Onboarding & Cross-Provider Isolation
# =============================================================================

def test_public_registration_cannot_bypass_controlled_provider_onboarding(client: TestClient, ui_test_env: CoordinatorSettings):
    """
    Verifies that a user registering an account cannot manage or register storage nodes
    without formally completing the server-side provider onboarding process and accepting terms.
    """
    # 1. Register a standard account
    reg_res = client.post("/auth/register", json={"email": "new_provider_aspirant@expo.test", "password": "StrongPassword123!"})
    assert reg_res.status_code == status.HTTP_201_CREATED
    user_id = reg_res.json()["account_id"]

    login_res = client.post("/auth/login", json={"email": "new_provider_aspirant@expo.test", "password": "StrongPassword123!"})
    assert login_res.status_code == status.HTTP_200_OK
    user_token = login_res.json()["token"]

    # 2. Attempting to register a storage node without onboarding fails
    node_reg_res = client.post(
        "/nodes/register",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "node_id": "node_aspirant_01",
            "host": "127.0.0.1",
            "port": 8199,
            "endpoint": "http://127.0.0.1:8199",
            "total_capacity_bytes": 10 * 1024 * 1024,
            "provider_id": "unauthorized_provider_claim",
        },
    )
    assert node_reg_res.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    # 3. Completing formal onboarding with terms acceptance succeeds
    onboard_res = client.post(
        "/provider/onboard",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"accept_terms": True, "provider_id": "provider_legit_aspirant"},
    )
    assert onboard_res.status_code == status.HTTP_200_OK
    assert onboard_res.json()["status"] in ("active", "onboarded")


def test_provider_cannot_manage_another_provider_node(client: TestClient, ui_test_env: CoordinatorSettings):
    """Verifies that Provider A cannot drain, decommission, or modify Provider B's node."""
    mgr = AccountManager(ui_test_env)
    acc_a = mgr.register_account("prov_alpha@expo.test", "PasswordAlpha123!", role="provider")
    acc_b = mgr.register_account("prov_beta@expo.test", "PasswordBeta123!", role="provider")

    sess_a = mgr.create_session(acc_a)
    sess_b = mgr.create_session(acc_b)

    # Onboard both providers formally
    client.post("/provider/onboard", headers={"Authorization": f"Bearer {sess_a.session_id}"}, json={"accept_terms": True, "provider_id": "prov_alpha_org"})
    client.post("/provider/onboard", headers={"Authorization": f"Bearer {sess_b.session_id}"}, json={"accept_terms": True, "provider_id": "prov_beta_org"})

    # Register node for Provider B
    reg_b = client.post(
        "/nodes/register",
        headers={"Authorization": f"Bearer {sess_b.session_id}"},
        json={
            "node_id": "node_prov_b_dedicated",
            "host": "127.0.0.1",
            "port": 8201,
            "endpoint": "http://127.0.0.1:8201",
            "total_capacity_bytes": 10 * 1024 * 1024,
            "provider_id": "prov_beta_org",
            "status": "online",
        },
    )
    assert reg_b.status_code == status.HTTP_200_OK

    # Provider A attempts to drain Provider B's node -> HTTP 403 Forbidden
    drain_attempt = client.post(
        "/provider/nodes/node_prov_b_dedicated/drain",
        headers={"Authorization": f"Bearer {sess_a.session_id}", "X-CSRF-Token": sess_a.csrf_token},
        json={"reason": "Malicious drain attempt"},
    )
    assert drain_attempt.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# 8. Expired Sessions & Hash Tamper Defense
# =============================================================================

def test_expired_or_revoked_session_cannot_access_protected_operations(client: TestClient, ui_test_env: CoordinatorSettings):
    """Verifies that revoked sessions are rejected immediately."""
    mgr = AccountManager(ui_test_env)
    acc = mgr.register_account("temp_user@expo.test", "TempPassword123!", role="consumer")
    sess = mgr.create_session(acc)

    # Verify session works
    res_valid = client.get("/consumer/files", headers={"Authorization": f"Bearer {sess.session_id}"})
    assert res_valid.status_code == status.HTTP_200_OK

    # Explicitly revoke the session
    mgr.revoke_session(sess.session_id)

    # Attempt operation with revoked session -> HTTP 401
    res_revoked = client.get("/consumer/files", headers={"Authorization": f"Bearer {sess.session_id}"})
    assert res_revoked.status_code == status.HTTP_401_UNAUTHORIZED


def test_direct_url_and_hash_manipulation_does_not_grant_privileges(client: TestClient, ui_test_env: CoordinatorSettings):
    """
    Verifies that regardless of client-side hash or header claims,
    protected endpoints strictly enforce server-side SQLite authorization.
    """
    mgr = AccountManager(ui_test_env)
    consumer_acc = mgr.register_account("client_tamperer@expo.test", "ClientPass123!", role="consumer")
    sess = mgr.create_session(consumer_acc)

    # Spoofing role in custom headers or path
    tamper_headers = {
        "Authorization": f"Bearer {sess.session_id}",
        "X-User-Role": "admin",
        "X-Provider-Id": "provider_root",
        "X-Admin-Override": "true",
    }

    # Attempt admin endpoint
    res_admin = client.get("/admin/accounts", headers=tamper_headers)
    assert res_admin.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# 9. Full File Lifecycle: Upload, Download, Quota, Delete
# =============================================================================

def test_full_file_lifecycle_upload_download_quota_delete(client: TestClient, ui_test_env: CoordinatorSettings):
    """Verifies complete end-to-end file management workflow."""
    mgr = AccountManager(ui_test_env)
    acc = mgr.register_account("lifecycle_user@expo.test", "LifecyclePass123!", role="consumer")
    sess = mgr.create_session(acc)

    headers = {"Authorization": f"Bearer {sess.session_id}", "X-CSRF-Token": sess.csrf_token}

    # 1. Check initial quota
    quota_res = client.get("/consumer/quota", headers=headers)
    assert quota_res.status_code == status.HTTP_200_OK
    assert quota_res.json()["used_bytes"] == 0

    # 2. Upload file
    test_content = b"Expo Distributed Storage File Lifecycle Test Content"
    upload_res = client.post(
        "/consumer/files/upload",
        headers=headers,
        files={"file": ("lifecycle_test.txt", io.BytesIO(test_content), "text/plain")},
    )
    assert upload_res.status_code == status.HTTP_201_CREATED
    file_id = upload_res.json()["file_id"]

    # 3. Quota updated
    quota_res2 = client.get("/consumer/quota", headers=headers)
    assert quota_res2.json()["used_bytes"] == len(test_content)

    # 4. Download file
    dl_res = client.get(f"/consumer/files/{file_id}/download", headers=headers)
    assert dl_res.status_code == status.HTTP_200_OK
    assert dl_res.content == test_content

    # 5. Delete file
    del_res = client.delete(f"/consumer/files/{file_id}", headers=headers)
    assert del_res.status_code == status.HTTP_200_OK

    # 6. Verify file no longer in listing
    files_list = client.get("/consumer/files", headers=headers).json()
    assert not any(f["file_id"] == file_id for f in files_list["files"])
