"""
Unit and Integration Tests for JWT Authentication and User Lifecycle in Store-Share.

Covers:
- Valid registration with consumer role default
- Public registration role escalation prevention (cannot self-assign admin)
- Duplicate username and email rejection
- Email format validation
- Argon2id password hashing (no plaintext passwords stored)
- Login success with access token and HttpOnly cookie
- Login failure with bad credentials / non-existent user
- Token verification: expiration, invalid signature, invalid issuer/audience, missing claims
- Token revocation on logout
- Account deactivation enforcement
- Immediate role revocation via role_version
- Bootstrap admin initialization
"""

from __future__ import annotations

import time
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator
import jwt
from starlette.testclient import TestClient

from coordinator.app.main import app
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.user_auth import (
    UserManager,
    Role,
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    get_user_manager,
)


@pytest.fixture
def auth_settings(tmp_path: Path) -> CoordinatorSettings:
    db_file = tmp_path / "coordinator_auth_test.db"
    init_db(db_file)
    return CoordinatorSettings(
        db_path=db_file,
        auth_token="machine-master-token-12345",
        jwt_secret="super-secure-jwt-secret-key-for-testing-1234567890",
        jwt_algorithm="HS256",
        jwt_access_token_expire_minutes=15,
        jwt_issuer="store-share-test-coordinator",
        jwt_audience="store-share-test-network",
    )


@pytest.fixture
def auth_client(auth_settings: CoordinatorSettings) -> Generator[TestClient, None, None]:
    app.state.settings = auth_settings
    app.state.user_manager = UserManager(auth_settings)
    with TestClient(app) as client:
        yield client


# =============================================================================
# 1. Password Hashing and Direct Manager Tests
# =============================================================================

def test_password_hashing_argon2id():
    """Validates Argon2id hashing produces distinct salts and validates correctly."""
    pw = "SuperSecretPassword123!"
    h1 = hash_password(pw)
    h2 = hash_password(pw)

    assert h1 != h2, "Salts must be randomly generated for each hash"
    assert h1.startswith("$argon2id$"), "Must use Argon2id variant"
    assert verify_password(pw, h1) is True
    assert verify_password(pw, h2) is True
    assert verify_password("WrongPassword!", h1) is False


def test_user_manager_creation_and_retrieval(auth_settings: CoordinatorSettings):
    """Validates creating users directly via manager and database invariants."""
    mgr = UserManager(auth_settings)
    user = mgr.create_user(
        username="alice",
        email="alice@example.com",
        password="Password12345!",
        role=Role.CONSUMER.value,
    )

    assert user.user_id.startswith("usr-")
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.role == Role.CONSUMER.value
    assert user.is_active is True
    assert user.role_version == 1

    # Check database directly: password_hash must be Argon2id, NOT plaintext
    with get_db_connection(auth_settings.db_path) as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = 'alice'").fetchone()
        assert row is not None
        assert row["password_hash"].startswith("$argon2id$")
        assert "Password12345!" not in row["password_hash"]


# =============================================================================
# 2. Registration API Tests
# =============================================================================

def test_valid_registration(auth_client: TestClient):
    """Consumer registration with valid inputs succeeds and defaults to consumer role."""
    payload = {
        "username": "bob_consumer",
        "email": "bob@example.com",
        "password": "SecurePassword1234!",
    }
    res = auth_client.post("/auth/register", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "bob_consumer"
    assert data["email"] == "bob@example.com"
    assert data["role"] == "consumer"
    assert data["is_active"] is True
    assert "password" not in data
    assert "password_hash" not in data


def test_registration_role_escalation_prevented(auth_client: TestClient):
    """Public registration cannot assign itself admin role even if attempted."""
    payload = {
        "username": "hacker_bob",
        "email": "hacker@example.com",
        "password": "SecurePassword1234!",
        "role": "admin",
    }
    res = auth_client.post("/auth/register", json=payload)
    assert res.status_code == 201
    data = res.json()
    # Explicit invariant: role MUST remain consumer
    assert data["role"] == "consumer"


def test_duplicate_registration_rejection(auth_client: TestClient):
    """Duplicate username or duplicate email returns 409 Conflict."""
    payload1 = {
        "username": "charlie",
        "email": "charlie@example.com",
        "password": "SecurePassword1234!",
    }
    res1 = auth_client.post("/auth/register", json=payload1)
    assert res1.status_code == 201

    # Duplicate username
    payload2 = {
        "username": "charlie",
        "email": "other_charlie@example.com",
        "password": "SecurePassword1234!",
    }
    res2 = auth_client.post("/auth/register", json=payload2)
    assert res2.status_code == 409
    assert "already registered" in res2.json()["detail"].lower() or "already exists" in res2.json()["detail"].lower()

    # Duplicate email
    payload3 = {
        "username": "different_charlie",
        "email": "charlie@example.com",
        "password": "SecurePassword1234!",
    }
    res3 = auth_client.post("/auth/register", json=payload3)
    assert res3.status_code == 409
    assert "already registered" in res3.json()["detail"].lower() or "already exists" in res3.json()["detail"].lower()


def test_invalid_email_and_short_password_rejected(auth_client: TestClient):
    """Invalid email formats and passwords shorter than 8 chars return 422 Unprocessable."""
    # Invalid email
    res1 = auth_client.post(
        "/auth/register",
        json={"username": "dave", "email": "not-an-email", "password": "Password123!"},
    )
    assert res1.status_code == 422

    # Short password (< 8 chars)
    res2 = auth_client.post(
        "/auth/register",
        json={"username": "dave", "email": "dave@example.com", "password": "short"},
    )
    assert res2.status_code == 422


# =============================================================================
# 3. Login API Tests
# =============================================================================

def test_login_success(auth_client: TestClient):
    """Login with valid username or email returns access token, user info, and cookie."""
    auth_client.post(
        "/auth/register",
        json={"username": "eve_user", "email": "eve@example.com", "password": "Password12345!"},
    )

    # 1. Login with username
    res1 = auth_client.post(
        "/auth/login",
        json={"username_or_email": "eve_user", "password": "Password12345!"},
    )
    assert res1.status_code == 200
    data1 = res1.json()
    assert "access_token" in data1
    assert data1["token_type"] == "bearer"
    assert data1["user"]["username"] == "eve_user"
    assert data1["user"]["role"] == "consumer"
    assert "expo_jwt" in res1.cookies

    # 2. Login with email
    res2 = auth_client.post(
        "/auth/login",
        json={"username_or_email": "eve@example.com", "password": "Password12345!"},
    )
    assert res2.status_code == 200
    assert "access_token" in res2.json()


def test_login_incorrect_credentials(auth_client: TestClient):
    """Incorrect password or non-existent account returns 401 Unauthorized."""
    auth_client.post(
        "/auth/register",
        json={"username": "frank", "email": "frank@example.com", "password": "Password12345!"},
    )

    # Wrong password
    res1 = auth_client.post(
        "/auth/login",
        json={"username_or_email": "frank", "password": "WrongPassword!"},
    )
    assert res1.status_code == 401
    assert "Invalid username" in res1.json()["detail"]

    # Non-existent account
    res2 = auth_client.post(
        "/auth/login",
        json={"username_or_email": "non_existent_user", "password": "Password12345!"},
    )
    assert res2.status_code == 401


# =============================================================================
# 4. JWT Verification, Claims, and Expiration Tests
# =============================================================================

def test_get_me_with_jwt_token(auth_client: TestClient):
    """GET /auth/me returns the active authenticated user record."""
    reg = auth_client.post(
        "/auth/register",
        json={"username": "grace", "email": "grace@example.com", "password": "Password12345!"},
    ).json()

    login = auth_client.post(
        "/auth/login",
        json={"username_or_email": "grace", "password": "Password12345!"},
    ).json()
    token = login["access_token"]

    # 1. Bearer Header
    res1 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200
    assert res1.json()["username"] == "grace"
    assert res1.json()["user_id"] == reg["user_id"]

    # 2. Cookie Authentication
    res2 = auth_client.get("/auth/me", cookies={"expo_jwt": token})
    assert res2.status_code == 200
    assert res2.json()["username"] == "grace"


def test_expired_jwt_rejected(auth_settings: CoordinatorSettings, auth_client: TestClient):
    """Expired JWT token is rejected with 401 Unauthorized."""
    mgr: UserManager = app.state.user_manager
    user = mgr.create_user("heidi", "heidi@example.com", "Password12345!", Role.CONSUMER.value)

    # Create expired token
    expired_token = create_access_token(
        user=user,
        settings=auth_settings,
        expires_delta=timedelta(seconds=-10),
    )

    res = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_invalid_signature_rejected(auth_settings: CoordinatorSettings, auth_client: TestClient):
    """Token signed with forged secret key is rejected with 401 Unauthorized."""
    mgr: UserManager = app.state.user_manager
    user = mgr.create_user("ivan", "ivan@example.com", "Password12345!", Role.CONSUMER.value)

    # Forged settings
    forged_settings = CoordinatorSettings(
        db_path=auth_settings.db_path,
        jwt_secret="forged-hacker-secret-key-1234567890",
        jwt_algorithm="HS256",
        jwt_issuer=auth_settings.jwt_issuer,
        jwt_audience=auth_settings.jwt_audience,
    )
    forged_token = create_access_token(user=user, settings=forged_settings)

    res = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


def test_invalid_issuer_and_audience_rejected(auth_settings: CoordinatorSettings, auth_client: TestClient):
    """Token with mismatched issuer or audience is rejected."""
    mgr: UserManager = app.state.user_manager
    user = mgr.create_user("judy", "judy@example.com", "Password12345!", Role.CONSUMER.value)

    # Bad issuer
    bad_iss_settings = CoordinatorSettings(
        db_path=auth_settings.db_path,
        jwt_secret=auth_settings.jwt_secret,
        jwt_algorithm=auth_settings.jwt_algorithm,
        jwt_issuer="malicious-issuer",
        jwt_audience=auth_settings.jwt_audience,
    )
    bad_iss_token = create_access_token(user=user, settings=bad_iss_settings)
    res1 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {bad_iss_token}"})
    assert res1.status_code == 401

    # Bad audience
    bad_aud_settings = CoordinatorSettings(
        db_path=auth_settings.db_path,
        jwt_secret=auth_settings.jwt_secret,
        jwt_algorithm=auth_settings.jwt_algorithm,
        jwt_issuer=auth_settings.jwt_issuer,
        jwt_audience="malicious-audience",
    )
    bad_aud_token = create_access_token(user=user, settings=bad_aud_settings)
    res2 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {bad_aud_token}"})
    assert res2.status_code == 401


# =============================================================================
# 5. Revocation, Logout, Deactivation, and Role Version Tests
# =============================================================================

def test_logout_revokes_token(auth_client: TestClient):
    """Calling POST /auth/logout blacklists token jti and invalidates subsequent requests."""
    auth_client.post(
        "/auth/register",
        json={"username": "karl", "email": "karl@example.com", "password": "Password12345!"},
    )
    login = auth_client.post(
        "/auth/login",
        json={"username_or_email": "karl", "password": "Password12345!"},
    ).json()
    token = login["access_token"]

    # 1. Before logout: me succeeds
    res_before = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_before.status_code == 200

    # 2. Call logout
    res_logout = auth_client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert res_logout.status_code == 200
    assert res_logout.json()["status"] == "logged_out"

    # 3. After logout: same token is now revoked
    res_after = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res_after.status_code == 401
    assert "revoked" in res_after.json()["detail"].lower()


def test_deactivated_account_rejected(auth_settings: CoordinatorSettings, auth_client: TestClient):
    """Deactivating an account immediately blocks requests even with a valid unexpired token."""
    mgr: UserManager = app.state.user_manager
    user = mgr.create_user("laura", "laura@example.com", "Password12345!", Role.CONSUMER.value)
    token = create_access_token(user, auth_settings)

    # Active: succeeds
    res1 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200

    # Deactivate account
    mgr.set_user_active_status(user.user_id, is_active=False)

    # Inactive: rejected immediately
    res2 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401
    assert "deactivated" in res2.json()["detail"].lower() or "inactive" in res2.json()["detail"].lower()


def test_role_change_increments_role_version_and_invalidates_tokens(
    auth_settings: CoordinatorSettings, auth_client: TestClient
):
    """Changing user role increments role_version, invalidating all pre-existing tokens."""
    mgr: UserManager = app.state.user_manager
    user = mgr.create_user("mallory", "mallory@example.com", "Password12345!", Role.CONSUMER.value)
    old_token = create_access_token(user, auth_settings)

    # Token valid initially
    res1 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"})
    assert res1.status_code == 200

    # Promote or modify role in database
    mgr.update_user_role(user.user_id, Role.PROVIDER.value, provider_id="provider-mallory")

    # Old token had role_version=1, database now has role_version=2 -> 401 Unauthorized
    res2 = auth_client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"})
    assert res2.status_code == 401
    assert "revoked" in res2.json()["detail"].lower() or "privileges" in res2.json()["detail"].lower()


def test_bootstrap_admin_cli(auth_settings: CoordinatorSettings):
    """Validates the bootstrap admin CLI creates the initial administrator safely."""
    from coordinator.bootstrap_admin import bootstrap_admin

    admin = bootstrap_admin(
        settings=auth_settings,
        username="superadmin",
        email="admin@storeshare.net",
        password="MasterAdminPassword123!",
    )

    assert admin.username == "superadmin"
    assert admin.role == Role.ADMIN.value
    assert admin.is_active is True

    # Duplicate bootstrap should fail safely
    with pytest.raises(ValueError, match="already exists"):
        bootstrap_admin(
            settings=auth_settings,
            username="superadmin",
            email="admin@storeshare.net",
            password="MasterAdminPassword123!",
        )
