"""
Phase 10A: Critical Security Hardening, Multi-Tenant Identity, and Cross-User Isolation Tests.

Automated verification covering:
1. Consumer Alice cannot list Consumer Bob's files.
2. Alice cannot read Bob's manifest or retrieve Bob's logical file.
3. Alice cannot delete Bob's file or overwrite/hijack Bob's file ID.
4. User-supplied owner_id and X-Provider-Id cannot change the authenticated identity.
5. A token containing "admin" does not grant admin rights.
6. Missing production authentication configuration fails closed (401).
7. Only explicitly provisioned administrators can use administrator-protected endpoints.
8. Invalid, expired and revoked sessions are rejected (401).
9. Logout invalidates the relevant session and clears cookies.
10. Passwords are stored securely using Argon2id.
11. Public registration cannot create administrator accounts.
12. Legacy file ownership reassignment and migration idempotence.
"""

from __future__ import annotations

import json
import uuid
import pytest
from pathlib import Path
from fastapi import status
from fastapi.testclient import TestClient
from argon2 import PasswordHasher

from coordinator.app.main import app, get_settings
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db, get_db_connection, reassign_legacy_file_ownership
from coordinator.app.auth import AccountManager, hash_password, verify_password


@pytest.fixture
def p10a_env(tmp_path: Path):
    """Provides isolated test database and settings for Phase 10A security tests."""
    db_file = tmp_path / "coordinator_phase10a_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="p10a-coord-token",
        admin_auth_token="p10a-explicit-admin-token",
        environment="development",
        admin_email="admin_bootstrap@expo.internal",
        admin_password="SuperAdminSecurePassword123!",
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def client(p10a_env: CoordinatorSettings):
    """Configures TestClient with overridden settings and clean app state."""
    app.state.settings = p10a_env
    app.dependency_overrides[get_settings] = lambda: p10a_env
    if hasattr(app.state, "account_manager"):
        delattr(app.state, "account_manager")
    if hasattr(app.state, "catalog"):
        delattr(app.state, "catalog")

    # Bootstrap the configured administrator on test startup
    acc_mgr = AccountManager(p10a_env)
    acc_mgr.bootstrap_admin(p10a_env.admin_email, p10a_env.admin_password)

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry"):
        if hasattr(app.state, attr):
            try:
                delattr(app.state, attr)
            except Exception:
                pass


def make_manifest(file_id: str, filename: str, size: int = 2048) -> dict:
    return {
        "file_id": file_id,
        "original_filename": filename,
        "original_size": size,
        "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "encrypted_size": size + 32,
        "chunk_size": 1024,
        "chunk_count": 2,
        "replication_factor": 2,
        "manifest_version": 2,
        "encryption_algorithm": "AES-256-GCM",
        "chunks": [
            {
                "chunk_id": f"chunk-{file_id}-0",
                "chunk_index": 0,
                "sha256": "chunk0hash",
                "size_bytes": 1024,
                "encrypted_size_bytes": 1040,
                "node_ids": ["node-1", "node-2"],
            },
            {
                "chunk_id": f"chunk-{file_id}-1",
                "chunk_index": 1,
                "sha256": "chunk1hash",
                "size_bytes": 1024,
                "encrypted_size_bytes": 1040,
                "node_ids": ["node-1", "node-2"],
            },
        ],
    }


def register_and_login(client: TestClient, email: str, password: str = "StrongPass123!") -> tuple[str, str, str]:
    """Helper to register and log in an account, returning (account_id, session_token, csrf_token)."""
    reg_res = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_res.status_code == status.HTTP_201_CREATED, reg_res.text
    account_id = reg_res.json()["account_id"]

    login_res = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == status.HTTP_200_OK, login_res.text
    login_data = login_res.json()
    token = login_data["token"]
    csrf = login_data["csrf_token"]
    return account_id, token, csrf


# =============================================================================
# 1. Multi-Tenant File Isolation Tests (Alice vs Bob)
# =============================================================================

def test_consumer_alice_cannot_list_consumer_bob_files(client: TestClient):
    """Requirement 1: Consumer Alice cannot list Consumer Bob's files."""
    alice_id, alice_token, _ = register_and_login(client, "alice_list@example.com")
    bob_id, bob_token, _ = register_and_login(client, "bob_list@example.com")

    # Alice uploads a file
    alice_file_id = str(uuid.uuid4())
    res_a = client.post(
        "/catalog/files",
        json={"manifest": make_manifest(alice_file_id, "alice_secret.txt")},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_a.status_code == 201

    # Bob uploads a file
    bob_file_id = str(uuid.uuid4())
    res_b = client.post(
        "/catalog/files",
        json={"manifest": make_manifest(bob_file_id, "bob_secret.txt")},
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res_b.status_code == 201

    # Alice lists files -> only Alice's file is visible
    alice_list = client.get(
        "/catalog/files",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_list.status_code == 200
    alice_files = [f["file_id"] for f in alice_list.json()["files"]]
    assert alice_file_id in alice_files
    assert bob_file_id not in alice_files

    # Bob lists files -> only Bob's file is visible
    bob_list = client.get(
        "/catalog/files",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert bob_list.status_code == 200
    bob_files = [f["file_id"] for f in bob_list.json()["files"]]
    assert bob_file_id in bob_files
    assert alice_file_id not in bob_files


def test_alice_cannot_read_or_retrieve_bob_file(client: TestClient):
    """Requirement 2: Alice cannot read Bob's manifest or retrieve Bob's logical file."""
    alice_id, alice_token, _ = register_and_login(client, "alice_read@example.com")
    bob_id, bob_token, _ = register_and_login(client, "bob_read@example.com")

    bob_file_id = str(uuid.uuid4())
    client.post(
        "/catalog/files",
        json={"manifest": make_manifest(bob_file_id, "bob_confidential.pdf")},
        headers={"Authorization": f"Bearer {bob_token}"},
    )

    # Alice tries to read Bob's file by ID -> 404 Not Found
    res = client.get(
        f"/catalog/files/{bob_file_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND

    # Bob can read his own file
    res_bob = client.get(
        f"/catalog/files/{bob_file_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert res_bob.status_code == status.HTTP_200_OK
    assert res_bob.json()["file_id"] == bob_file_id


def test_alice_cannot_delete_or_hijack_bob_file(client: TestClient):
    """Requirement 3 & 4: Alice cannot delete Bob's file or overwrite/hijack Bob's file ID."""
    alice_id, alice_token, _ = register_and_login(client, "alice_del@example.com")
    bob_id, bob_token, _ = register_and_login(client, "bob_del@example.com")

    bob_file_id = str(uuid.uuid4())
    client.post(
        "/catalog/files",
        json={"manifest": make_manifest(bob_file_id, "bob_protected.docx")},
        headers={"Authorization": f"Bearer {bob_token}"},
    )

    # Alice attempts to delete Bob's file -> 404 Not Found
    del_res = client.delete(
        f"/catalog/files/{bob_file_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert del_res.status_code == status.HTTP_404_NOT_FOUND

    # Bob's file remains active and intact
    check_bob = client.get(
        f"/catalog/files/{bob_file_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert check_bob.status_code == status.HTTP_200_OK
    assert check_bob.json()["status"] == "available"

    # Alice attempts to register a new file with Bob's file_id -> 403 Forbidden
    hijack_res = client.post(
        "/catalog/files",
        json={"manifest": make_manifest(bob_file_id, "alice_hijack.txt")},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert hijack_res.status_code == status.HTTP_403_FORBIDDEN


def test_user_supplied_owner_id_and_provider_id_cannot_change_authenticated_identity(client: TestClient):
    """Requirement 4: User-supplied owner_id or X-Provider-Id header cannot spoof identity."""
    alice_id, alice_token, _ = register_and_login(client, "alice_spoof@example.com")

    file_id = str(uuid.uuid4())
    spoofed_owner = "bob-fake-uuid-12345"
    manifest = make_manifest(file_id, "spoof_test.txt")
    manifest["owner_id"] = spoofed_owner

    # Alice sends a spoofed owner_id in body and X-Provider-Id in headers
    res = client.post(
        "/catalog/files",
        json={"manifest": manifest, "owner_id": spoofed_owner},
        headers={
            "Authorization": f"Bearer {alice_token}",
            "X-Provider-Id": "victim_provider_999",
        },
    )
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    # Server-derived owner_id MUST be Alice's UUID, completely ignoring spoofed_owner
    assert data["owner_id"] == alice_id
    assert data["owner_id"] != spoofed_owner


# =============================================================================
# 2. Administrator Privilege Escalation Hardening Tests
# =============================================================================

def test_token_containing_admin_does_not_grant_admin_rights(tmp_path: Path):
    """Requirement 5: A token string containing 'admin' does NOT grant administrator rights."""
    db_file = tmp_path / "admin_substring_test.db"
    # auth_token intentionally contains 'admin' in lowercase and uppercase
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="dev-ordinary-admin-token-user",
        admin_auth_token="separate-real-admin-token",
        environment="development",
    )
    init_db(db_file)
    app.state.settings = settings
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with TestClient(app) as tc:
            # 1. Register a node belonging to other_provider
            tc.post(
                "/nodes/register",
                json={"node_id": "NODE-1", "host": "10.0.0.1", "port": 8000, "provider_id": "other_provider"},
                headers={"X-Auth-Token": "dev-ordinary-admin-token-user", "X-Provider-Id": "other_provider"},
            )

            # 2. Ordinary token with 'admin' substring tries to act as another provider with admin override
            res = tc.post(
                "/provider/nodes/NODE-1/scheduling",
                json={"is_schedulable": False},
                headers={
                    "X-Auth-Token": "dev-ordinary-admin-token-user",
                    "X-Provider-Id": "attacker_provider",
                    "X-Admin-Override": "true",
                },
            )
            # Must be rejected with 403 Forbidden (not an admin)
            assert res.status_code == status.HTTP_403_FORBIDDEN
    finally:
        app.dependency_overrides.clear()
        for attr in ("settings", "account_manager", "catalog", "registry"):
            if hasattr(app.state, attr):
                try:
                    delattr(app.state, attr)
                except Exception:
                    pass


def test_missing_production_auth_configuration_fails_closed(tmp_path: Path):
    """Requirement 6: Missing production authentication configuration fails closed (401)."""
    db_file = tmp_path / "prod_fail_closed.db"
    # Production environment with NO tokens configured
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token=None,
        admin_auth_token=None,
        environment="production",
    )
    init_db(db_file)
    app.state.settings = settings
    app.dependency_overrides[get_settings] = lambda: settings
    if hasattr(app.state, "account_manager"):
        delattr(app.state, "account_manager")
    try:
        with TestClient(app) as tc:
            # 1. Protected node registration endpoint fails closed
            res_node = tc.post(
                "/nodes/register",
                json={"node_id": "NODE-PROD", "host": "127.0.0.1", "port": 8001},
            )
            assert res_node.status_code == status.HTTP_401_UNAUTHORIZED

            # 2. Protected catalog listing fails closed
            res_cat = tc.get("/catalog/files")
            assert res_cat.status_code == status.HTTP_401_UNAUTHORIZED

            # 3. Provider overview fails closed
            res_prov = tc.get("/provider/overview")
            assert res_prov.status_code == status.HTTP_401_UNAUTHORIZED
    finally:
        app.dependency_overrides.clear()
        for attr in ("settings", "account_manager", "catalog", "registry"):
            if hasattr(app.state, attr):
                try:
                    delattr(app.state, attr)
                except Exception:
                    pass


def test_only_explicitly_provisioned_administrators_can_use_admin_endpoints(client: TestClient, p10a_env: CoordinatorSettings):
    """Requirement 7: Only explicitly provisioned administrators can use administrative endpoints."""
    # 1. Ordinary consumer attempts administrative reversal -> 401/403
    _, alice_token, _ = register_and_login(client, "alice_nonadmin@example.com")
    res_unauth = client.post(
        "/accounting/credits/reverse",
        json={"entry_id": "ent-1", "reason": "Unauthorized test"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_unauth.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    # 2. Log in as the explicitly bootstrapped administrator
    login_admin = client.post(
        "/auth/login",
        json={"email": p10a_env.admin_email, "password": p10a_env.admin_password},
    )
    assert login_admin.status_code == status.HTTP_200_OK
    admin_data = login_admin.json()
    assert admin_data["account"]["role"] == "admin"

    # 3. Dedicated administrative token works for admin operations
    res_admin_token = client.post(
        "/accounting/credits/reverse",
        json={"entry_id": "nonexistent-entry", "reason": "Admin test"},
        headers={"X-Auth-Token": p10a_env.admin_auth_token},
    )
    # Entry doesn't exist -> 404, proving authentication passed
    assert res_admin_token.status_code == status.HTTP_404_NOT_FOUND


def test_public_registration_cannot_assign_admin_role(client: TestClient):
    """Requirement 4 (Task 1): Do not permit public registration to assign an administrator role."""
    # Pass role='admin' in payload
    res = client.post(
        "/auth/register",
        json={
            "email": "hacker@example.com",
            "password": "HackerPassword123!",
            "role": "admin",
        },
    )
    # Even if client tries to request role='admin', register endpoint enforces consumer role
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    assert data["role"] == "consumer"
    assert "admin:all" not in data["capabilities"]


# =============================================================================
# 3. Session and Password Security Tests
# =============================================================================

def test_invalid_expired_and_revoked_sessions_rejected(client: TestClient, p10a_env: CoordinatorSettings):
    """Requirement 8: Invalid, expired and revoked sessions are rejected."""
    # 1. Bogus session token -> 401
    res_bogus = client.get("/auth/me", headers={"Authorization": "Bearer bogus_session_token"})
    assert res_bogus.status_code == status.HTTP_401_UNAUTHORIZED

    # 2. Create expired session directly
    acc_mgr = AccountManager(p10a_env)
    acc = acc_mgr.register_account("expire_test@example.com", "Password1234!")
    # Negative duration -> already expired
    expired_sess = acc_mgr.create_session(acc, duration_seconds=-10)

    res_exp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {expired_sess.session_id}"},
    )
    assert res_exp.status_code == status.HTTP_401_UNAUTHORIZED

    # 3. Revoke active session -> 401
    active_sess = acc_mgr.create_session(acc, duration_seconds=3600)
    res_active = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {active_sess.session_id}"},
    )
    assert res_active.status_code == status.HTTP_200_OK

    acc_mgr.revoke_session(active_sess.session_id)
    res_revoked = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {active_sess.session_id}"},
    )
    assert res_revoked.status_code == status.HTTP_401_UNAUTHORIZED


def test_logout_invalidates_relevant_session_and_clears_cookie(client: TestClient):
    """Requirement 9: Logout invalidates the relevant session and clears browser cookies."""
    _, token, csrf = register_and_login(client, "logout_user@example.com")

    # Verify session works
    res_me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_me.status_code == status.HTTP_200_OK

    # Logout
    res_logout = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_logout.status_code == status.HTTP_200_OK
    assert "expo_session" in res_logout.headers.get("set-cookie", "")

    # Session is now invalid
    res_after = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_after.status_code == status.HTTP_401_UNAUTHORIZED


def test_passwords_stored_using_argon2id(p10a_env: CoordinatorSettings):
    """Requirement 10: Passwords are stored using Argon2id."""
    acc_mgr = AccountManager(p10a_env)
    raw_pass = "MySecretArgon2Password#2026"
    acc = acc_mgr.register_account("argon_test@example.com", raw_pass)

    with get_db_connection(p10a_env.db_path) as conn:
        row = conn.execute(
            "SELECT password_hash FROM accounts WHERE account_id = ?",
            (acc.account_id,),
        ).fetchone()

        assert row is not None
        stored_hash = row["password_hash"]

        # 1. Hash format verification: must start with $argon2id$
        assert stored_hash.startswith("$argon2id$")
        # 2. Raw password must never be stored anywhere in plaintext
        assert raw_pass not in stored_hash
        # 3. Argon2id verification succeeds
        ph = PasswordHasher()
        assert ph.verify(stored_hash, raw_pass) is True


# =============================================================================
# 4. Database Migration & Compatibility Tests
# =============================================================================

def test_legacy_file_ownership_reassignment_utility(p10a_env: CoordinatorSettings):
    """Task 3 & 5: Verified reassignment of files from legacy shared tokens to account UUIDs."""
    legacy_token = "legacy-shared-coord-token-42"
    target_account_id = str(uuid.uuid4())
    file_id_1 = str(uuid.uuid4())
    file_id_2 = str(uuid.uuid4())

    with get_db_connection(p10a_env.db_path) as conn:
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, created_at, updated_at) "
            "VALUES (?, ?, 'f1.txt', 100, 'available', 'replication', 2, '2026-01-01', '2026-01-01')",
            (file_id_1, legacy_token),
        )
        conn.execute(
            "INSERT INTO files (file_id, owner_id, original_filename, original_size, status, redundancy_mode, manifest_version, created_at, updated_at) "
            "VALUES (?, ?, 'f2.txt', 200, 'available', 'replication', 2, '2026-01-01', '2026-01-01')",
            (file_id_2, legacy_token),
        )
        conn.commit()

    # Perform migration
    count = reassign_legacy_file_ownership(p10a_env.db_path, legacy_token, target_account_id)
    assert count == 2

    # Verify both records now have target_account_id
    with get_db_connection(p10a_env.db_path) as conn:
        rows = conn.execute("SELECT owner_id FROM files WHERE file_id IN (?, ?)", (file_id_1, file_id_2)).fetchall()
        for r in rows:
            assert r["owner_id"] == target_account_id


def test_migration_idempotence_preserves_all_tables(p10a_env: CoordinatorSettings):
    """Task 5: Repeated application of init_db does not corrupt or reset data."""
    with get_db_connection(p10a_env.db_path) as conn:
        initial_tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    # Run init_db multiple times
    init_db(p10a_env.db_path)
    init_db(p10a_env.db_path)

    with get_db_connection(p10a_env.db_path) as conn:
        after_tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    assert initial_tables == after_tables
    assert "accounts" in after_tables
    assert "account_sessions" in after_tables
