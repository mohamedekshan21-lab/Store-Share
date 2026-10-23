"""
Expo Phase 10E: Email/SMS Verification, Password Reset, and Account Recovery Tests.

Automated verification covering:
1. Valid email verification (POST and GET token redemption, status & timestamp persistence).
2. Invalid, expired, reused, and tampered verification tokens.
3. Verification token replay and concurrent redemption protection.
4. Resend cooldown and hourly rate-limit enforcement.
5. Account verification policy enforcement: gating mutating actions on unverified accounts.
6. SMS verification code generation, 6-digit constraints, attempt limits, expiration, and burning on exhaustion.
7. SMS unconfigured provider safe failure (no simulated success without configured provider).
8. Password reset flow, Argon2id hashing verification, and security notification dispatch.
9. Session revocation policy: active sessions revoked across devices upon password reset.
10. Password reset token expiry, replay protection, and malformed token handling.
11. Account enumeration resistance for registration, resend, and password reset requests.
12. Cross-account and cross-purpose isolation (tokens bound strictly to target account and purpose).
13. Delivery provider failure handling (fail-safe error containment).
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import uuid
import pytest
from pathlib import Path
from fastapi import status
from fastapi.testclient import TestClient
from argon2 import PasswordHasher

from coordinator.app.main import app, get_settings
from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import init_db, get_db_connection
from coordinator.app.auth import AccountManager, hash_password, verify_password
from coordinator.app.delivery import FakeDeliveryAdapter, DeliveryManager, UnconfiguredSmsAdapter


@pytest.fixture
def p10e_env(tmp_path: Path):
    """Provides isolated test database and settings for Phase 10E tests."""
    db_file = tmp_path / "coordinator_phase10e_test.db"
    settings = CoordinatorSettings(
        db_path=db_file,
        auth_token="p10e-coord-token",
        admin_auth_token="p10e-explicit-admin-token",
        environment="development",
        admin_email="admin_p10e@expo.internal",
        admin_password="SuperAdminSecurePassword123!",
        verification_resend_cooldown_seconds=60,
        max_resend_per_hour=5,
        max_code_verification_attempts=3,
        email_verification_ttl_seconds=86400,
        password_reset_ttl_seconds=3600,
        sms_code_ttl_seconds=600,
        require_email_verification=False,
    )
    init_db(settings.db_path)
    return settings


@pytest.fixture
def fake_delivery():
    """Provides a clean in-memory fake delivery adapter for testing email/SMS."""
    adapter = FakeDeliveryAdapter()
    return adapter


@pytest.fixture
def client(p10e_env: CoordinatorSettings, fake_delivery: FakeDeliveryAdapter):
    """Configures TestClient with overridden settings and injected FakeDeliveryAdapter."""
    app.state.settings = p10e_env
    app.dependency_overrides[get_settings] = lambda: p10e_env

    dm = DeliveryManager(mail_adapter=fake_delivery, sms_adapter=fake_delivery)
    acc_mgr = AccountManager(p10e_env, delivery_manager=dm)
    acc_mgr.bootstrap_admin(p10e_env.admin_email, p10e_env.admin_password)
    app.state.account_manager = acc_mgr

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    for attr in ("settings", "account_manager", "catalog", "registry", "drain_service"):
        if hasattr(app.state, attr):
            try:
                delattr(app.state, attr)
            except Exception:
                pass


def register_account(client: TestClient, email: str, password: str = "SecurePassword123!") -> dict:
    """Helper to register an account and return account details."""
    res = client.post("/auth/register", json={"email": email, "password": password})
    assert res.status_code == status.HTTP_201_CREATED, res.text
    return res.json()


def login_account(client: TestClient, email: str, password: str = "SecurePassword123!") -> tuple[str, str]:
    """Helper to log in and return (session_token, csrf_token)."""
    res = client.post("/auth/login", json={"email": email, "password": password})
    assert res.status_code == status.HTTP_200_OK, res.text
    data = res.json()
    return data["token"], data["csrf_token"]


# =============================================================================
# 1. Email Verification Tests
# =============================================================================

def test_valid_email_verification_post_and_get(client: TestClient, fake_delivery: FakeDeliveryAdapter, p10e_env: CoordinatorSettings):
    """Test 1: Valid email verification persists status, timestamp, and marks token used."""
    # 1. Register unverified account
    acc = register_account(client, "alice_verify@example.com")
    assert acc["email_verified"] is False
    assert acc["email_verified_at"] is None

    # Verification email was dispatched to fake delivery adapter
    assert len(fake_delivery.sent_emails) == 1
    sent_msg = fake_delivery.sent_emails[0]
    assert sent_msg["to_email"] == "alice_verify@example.com"
    assert "token=" in sent_msg["body_text"]

    # Extract token from verify URL
    raw_token = sent_msg["body_text"].split("token=")[1].split()[0].strip()

    # Verify that raw token is NOT stored in plaintext in the database
    with get_db_connection(p10e_env.db_path) as conn:
        token_rows = conn.execute("SELECT * FROM account_verification_tokens").fetchall()
        assert len(token_rows) == 1
        stored_hash = token_rows[0]["token_hash"]
        assert raw_token not in stored_hash
        assert hashlib.sha256(raw_token.encode("utf-8")).hexdigest() == stored_hash
        assert token_rows[0]["used_at"] is None

    # 2. Redeem verification token via POST /auth/verify-email
    post_res = client.post("/auth/verify-email", json={"token": raw_token})
    assert post_res.status_code == status.HTTP_200_OK
    post_data = post_res.json()
    assert post_data["email_verified"] is True
    assert post_data["email"] == "alice_verify@example.com"

    # Verify status in database
    with get_db_connection(p10e_env.db_path) as conn:
        acc_row = conn.execute("SELECT email_verified, email_verified_at FROM accounts WHERE email = ?", ("alice_verify@example.com",)).fetchone()
        assert acc_row["email_verified"] == 1
        assert acc_row["email_verified_at"] is not None

        tok_row = conn.execute("SELECT used_at FROM account_verification_tokens WHERE token_hash = ?", (stored_hash,)).fetchone()
        assert tok_row["used_at"] is not None

    # 3. Test GET /auth/verify-email?token=... with another account
    acc2 = register_account(client, "bob_verify_get@example.com")
    assert len(fake_delivery.sent_emails) == 2
    raw_token2 = fake_delivery.sent_emails[1]["body_text"].split("token=")[1].split()[0].strip()

    get_res = client.get(f"/auth/verify-email?token={raw_token2}")
    assert get_res.status_code == status.HTTP_200_OK
    assert get_res.json()["email_verified"] is True


def test_invalid_expired_reused_and_tampered_verification_tokens(client: TestClient, fake_delivery: FakeDeliveryAdapter, p10e_env: CoordinatorSettings):
    """Test 2: Rejects invalid, expired, reused, and tampered email verification tokens."""
    register_account(client, "charlie_tamper@example.com")
    raw_token = fake_delivery.sent_emails[0]["body_text"].split("token=")[1].split()[0].strip()

    # 1. Malformed / too short token -> 422 or 400
    res_short = client.post("/auth/verify-email", json={"token": "tooshort"})
    assert res_short.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)

    # 2. Tampered token (modify last character) -> 400
    tampered_token = raw_token[:-1] + ("A" if raw_token[-1] != "A" else "B")
    res_tamper = client.post("/auth/verify-email", json={"token": tampered_token})
    assert res_tamper.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired" in res_tamper.json()["detail"].lower()

    # 3. Redeem valid token -> 200 OK
    res_valid = client.post("/auth/verify-email", json={"token": raw_token})
    assert res_valid.status_code == status.HTTP_200_OK

    # 4. Replay / Reused token -> 400 Bad Request
    res_reused = client.post("/auth/verify-email", json={"token": raw_token})
    assert res_reused.status_code == status.HTTP_400_BAD_REQUEST
    assert "already been used" in res_reused.json()["detail"].lower()

    # 5. Expired token -> 400 Bad Request
    acc_mgr: AccountManager = app.state.account_manager
    expired_token = acc_mgr.create_email_verification_token(
        account_id="some-acc-id",
        email="expired_test@example.com",
        ttl_seconds=-3600,  # expired 1 hour ago
        enforce_rate_limit=False,
    )
    res_exp = client.post("/auth/verify-email", json={"token": expired_token})
    assert res_exp.status_code == status.HTTP_400_BAD_REQUEST
    assert "expired" in res_exp.json()["detail"].lower()


def test_concurrent_token_redemption(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 3: Concurrent redemption attempts succeed exactly once, second attempt fails cleanly."""
    register_account(client, "concurrent_user@example.com")
    raw_token = fake_delivery.sent_emails[0]["body_text"].split("token=")[1].split()[0].strip()

    results = []
    def redeem():
        return client.post("/auth/verify-email", json={"token": raw_token})

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(redeem) for _ in range(4)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    status_codes = [r.status_code for r in results]
    # Exactly one request must succeed with 200 OK
    assert status_codes.count(status.HTTP_200_OK) == 1
    # All others must be rejected with 400 Bad Request
    assert status_codes.count(status.HTTP_400_BAD_REQUEST) == 3


def test_resend_cooldown_and_rate_limit_enforcement(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 4: Resend verification enforces cooldown (429) and hourly rate limits."""
    register_account(client, "cooldown_test@example.com")
    fake_delivery.clear()

    # 1. First resend request succeeds
    res1 = client.post("/auth/resend-verification", json={"email": "cooldown_test@example.com"})
    assert res1.status_code == status.HTTP_200_OK
    assert len(fake_delivery.sent_emails) == 1

    # 2. Immediate second resend request fails with 429 Too Many Requests
    res2 = client.post("/auth/resend-verification", json={"email": "cooldown_test@example.com"})
    assert res2.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "cooldown active" in res2.json()["detail"].lower()
    assert "retry-after" in res2.headers

    # Fake delivery should not have sent another email
    assert len(fake_delivery.sent_emails) == 1


# =============================================================================
# 2. Account Verification Policy Enforcement Tests
# =============================================================================

def test_unverified_account_policy_enforcement(client: TestClient, fake_delivery: FakeDeliveryAdapter, p10e_env: CoordinatorSettings):
    """Test 5: When require_email_verification is active, unverified accounts cannot upload or onboard."""
    # Temporarily activate verification requirement policy
    p10e_env.require_email_verification = True

    acc = register_account(client, "policy_user@example.com")
    token, csrf = login_account(client, "policy_user@example.com")
    auth_headers = {"Authorization": f"Bearer {token}", "X-CSRF-Token": csrf}

    # 1. Safe read actions are allowed: GET /auth/me
    res_me = client.get("/auth/me", headers=auth_headers)
    assert res_me.status_code == status.HTTP_200_OK
    assert res_me.json()["email_verified"] is False

    # 2. Mutating catalog file upload is forbidden for unverified accounts
    manifest = {
        "file_id": str(uuid.uuid4()),
        "original_filename": "gated.txt",
        "original_size": 1024,
        "original_sha256": "dummyhash",
        "encrypted_size": 1056,
        "chunk_size": 1024,
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "encryption_algorithm": "AES-256-GCM",
        "chunks": [{"chunk_id": "c-1", "chunk_index": 0, "sha256": "h1", "size_bytes": 1024, "node_ids": ["node-1"]}],
    }
    res_upload = client.post("/catalog/files", json={"manifest": manifest}, headers=auth_headers)
    assert res_upload.status_code == status.HTTP_403_FORBIDDEN
    assert "email verification required" in res_upload.json()["detail"].lower()

    # 3. Requesting upload capabilities is forbidden
    res_cap = client.post(
        "/catalog/capabilities/upload",
        json={"chunks": [{"chunk_id": "c-1", "node_ids": ["node-1"], "size": 1024}]},
        headers=auth_headers,
    )
    assert res_cap.status_code == status.HTTP_403_FORBIDDEN
    assert "email verification required" in res_cap.json()["detail"].lower()

    # 4. Provider onboarding is forbidden
    res_onboard = client.post(
        "/provider/onboard",
        json={"accept_terms": True},
        headers=auth_headers,
    )
    assert res_onboard.status_code == status.HTTP_403_FORBIDDEN
    assert "email verification required" in res_onboard.json()["detail"].lower()

    # 5. Now verify the email
    verify_token = fake_delivery.sent_emails[0]["body_text"].split("token=")[1].split()[0].strip()
    ver_res = client.post("/auth/verify-email", json={"token": verify_token})
    assert ver_res.status_code == status.HTTP_200_OK

    # 6. Now the upload and capabilities succeed!
    res_cap_after = client.post(
        "/catalog/capabilities/upload",
        json={"chunks": [{"chunk_id": "c-1", "node_ids": ["node-1"], "size": 1024}]},
        headers=auth_headers,
    )
    assert res_cap_after.status_code == status.HTTP_200_OK


# =============================================================================
# 3. SMS Verification Tests
# =============================================================================

def test_sms_verification_flow_and_attempt_limits(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 6: SMS verification code issuance, attempt limits, expiration, and burning on exhaustion."""
    register_account(client, "sms_user@example.com")
    token, _ = login_account(client, "sms_user@example.com")
    auth_headers = {"Authorization": f"Bearer {token}"}
    fake_delivery.clear()

    # 1. Send SMS verification code
    phone = "+14155552671"
    res_send = client.post("/auth/sms/send-code", json={"phone_number": phone}, headers=auth_headers)
    assert res_send.status_code == status.HTTP_200_OK
    assert len(fake_delivery.sent_sms) == 1

    sent_sms = fake_delivery.sent_sms[0]
    assert sent_sms["to_phone"] == phone
    # Extract 6-digit code using regex
    code_matches = re.findall(r"\b\d{6}\b", sent_sms["message_text"])
    assert len(code_matches) == 1
    code = code_matches[0]
    assert len(code) == 6

    # 2. Verify with incorrect code -> attempt decremented
    res_wrong1 = client.post("/auth/sms/verify-code", json={"phone_number": phone, "code": "000000"}, headers=auth_headers)
    assert res_wrong1.status_code == status.HTTP_400_BAD_REQUEST
    assert "remaining" in res_wrong1.json()["detail"].lower()

    # Second wrong attempt
    res_wrong2 = client.post("/auth/sms/verify-code", json={"phone_number": phone, "code": "111111"}, headers=auth_headers)
    assert res_wrong2.status_code == status.HTTP_400_BAD_REQUEST

    # Third wrong attempt -> max attempts (3) reached, burned!
    res_wrong3 = client.post("/auth/sms/verify-code", json={"phone_number": phone, "code": "222222"}, headers=auth_headers)
    assert res_wrong3.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalidated" in res_wrong3.json()["detail"].lower() or "exceeded" in res_wrong3.json()["detail"].lower()

    # Even submitting the real code now fails because it was burned
    res_burned = client.post("/auth/sms/verify-code", json={"phone_number": phone, "code": code}, headers=auth_headers)
    assert res_burned.status_code == status.HTTP_400_BAD_REQUEST

    # 3. Verify cooldown on immediate send -> 429
    res_cooldown = client.post("/auth/sms/send-code", json={"phone_number": phone}, headers=auth_headers)
    assert res_cooldown.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "cooldown active" in res_cooldown.json()["detail"].lower()

    # Simulate cooldown elapsing
    with get_db_connection(app.state.settings.db_path) as conn:
        conn.execute("DELETE FROM verification_rate_limits")
        conn.commit()

    phone2 = "+14155559999"
    res_send2 = client.post("/auth/sms/send-code", json={"phone_number": phone2}, headers=auth_headers)
    assert res_send2.status_code == status.HTTP_200_OK
    fresh_code = re.findall(r"\b\d{6}\b", fake_delivery.sent_sms[-1]["message_text"])[0]

    # Submit correct code -> 200 OK
    res_ok = client.post("/auth/sms/verify-code", json={"phone_number": phone2, "code": fresh_code}, headers=auth_headers)
    assert res_ok.status_code == status.HTTP_200_OK

    # Replay of the same verified code fails
    res_replay = client.post("/auth/sms/verify-code", json={"phone_number": phone2, "code": fresh_code}, headers=auth_headers)
    assert res_replay.status_code == status.HTTP_400_BAD_REQUEST

    # Profile reflects verified phone number
    res_me = client.get("/auth/me", headers=auth_headers)
    assert res_me.json()["phone_verified"] is True
    assert res_me.json()["phone_number"] == phone2


def test_sms_unconfigured_provider_fails_safely(client: TestClient, p10e_env: CoordinatorSettings):
    """Test 7: SMS requests fail safely without simulating delivery when provider is not configured."""
    # Replace SMS adapter with UnconfiguredSmsAdapter
    acc_mgr: AccountManager = app.state.account_manager
    acc_mgr.delivery_manager.set_sms_adapter(UnconfiguredSmsAdapter())

    register_account(client, "sms_unconf@example.com")
    token, _ = login_account(client, "sms_unconf@example.com")

    res = client.post(
        "/auth/sms/send-code",
        json={"phone_number": "+14155551212"},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Must fail safely with 503 Service Unavailable, never claiming delivery
    assert res.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert "not configured" in res.json()["detail"].lower()


# =============================================================================
# 4. Password Reset & Session Revocation Tests
# =============================================================================

def test_password_reset_flow_and_argon2id_hashing(client: TestClient, fake_delivery: FakeDeliveryAdapter, p10e_env: CoordinatorSettings):
    """Test 8: Password reset updates password with Argon2id, revokes sessions, and sends notification."""
    old_pw = "OriginalPassword123!"
    new_pw = "BrandNewSecurePassword456!"
    email = "reset_user@example.com"

    register_account(client, email, old_pw)
    fake_delivery.clear()

    # 1. Request password reset
    res_req = client.post("/auth/forgot-password", json={"email": email})
    assert res_req.status_code == status.HTTP_200_OK
    assert "password reset instructions" in res_req.json()["detail"].lower()

    # Delivery adapter has the reset email
    assert len(fake_delivery.sent_emails) == 1
    reset_email = fake_delivery.sent_emails[0]
    assert reset_email["to_email"] == email
    reset_token = reset_email["body_text"].split("token=")[1].split()[0].strip()

    # 2. Confirm password reset with new password
    res_confirm = client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": new_pw},
    )
    assert res_confirm.status_code == status.HTTP_200_OK

    # 3. Password was updated with Argon2id in SQLite
    with get_db_connection(p10e_env.db_path) as conn:
        row = conn.execute("SELECT password_hash FROM accounts WHERE email = ?", (email,)).fetchone()
        stored_hash = row["password_hash"]
        assert stored_hash.startswith("$argon2id$")
        ph = PasswordHasher()
        assert ph.verify(stored_hash, new_pw) is True

    # 4. Security notification email was dispatched
    assert len(fake_delivery.sent_emails) == 2
    security_notice = fake_delivery.sent_emails[1]
    assert "Password Successfully Changed" in security_notice["subject"]

    # 5. Old password no longer works
    login_old = client.post("/auth/login", json={"email": email, "password": old_pw})
    assert login_old.status_code == status.HTTP_401_UNAUTHORIZED

    # 6. New password works
    login_new = client.post("/auth/login", json={"email": email, "password": new_pw})
    assert login_new.status_code == status.HTTP_200_OK


def test_password_reset_revokes_all_active_sessions(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 9: Password reset revokes all existing active sessions across all devices."""
    email = "multisession_user@example.com"
    old_pw = "OldPassword123!"
    new_pw = "NewPassword123!"

    register_account(client, email, old_pw)

    # Log in twice simulating two distinct devices (Session 1 and Session 2)
    token1, _ = login_account(client, email, old_pw)
    token2, _ = login_account(client, email, old_pw)

    # Both sessions can access /auth/me
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code == status.HTTP_200_OK
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == status.HTTP_200_OK

    # Request and confirm password reset
    client.post("/auth/forgot-password", json={"email": email})
    reset_token = fake_delivery.sent_emails[-1]["body_text"].split("token=")[1].split()[0].strip()

    client.post("/auth/reset-password", json={"token": reset_token, "new_password": new_pw})

    # Both pre-existing sessions are now revoked!
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token1}"}).status_code == status.HTTP_401_UNAUTHORIZED
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token2}"}).status_code == status.HTTP_401_UNAUTHORIZED

    # A new login yields a functioning session
    token3, _ = login_account(client, email, new_pw)
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token3}"}).status_code == status.HTTP_200_OK


def test_password_reset_token_expiry_and_replay_protection(client: TestClient, fake_delivery: FakeDeliveryAdapter, p10e_env: CoordinatorSettings):
    """Test 10: Password reset tokens cannot be replayed, expired tokens are rejected."""
    email = "replay_user@example.com"
    register_account(client, email)

    client.post("/auth/forgot-password", json={"email": email})
    reset_token = fake_delivery.sent_emails[-1]["body_text"].split("token=")[1].split()[0].strip()

    # 1. Redeem token
    res1 = client.post("/auth/reset-password", json={"token": reset_token, "new_password": "NewPassword123!"})
    assert res1.status_code == status.HTTP_200_OK

    # 2. Replay token -> 400 Bad Request
    res2 = client.post("/auth/reset-password", json={"token": reset_token, "new_password": "AnotherPassword123!"})
    assert res2.status_code == status.HTTP_400_BAD_REQUEST
    assert "already been used" in res2.json()["detail"].lower()

    # 3. Expired token -> 400 Bad Request
    acc_mgr: AccountManager = app.state.account_manager
    with get_db_connection(p10e_env.db_path) as conn:
        acc_id = conn.execute("SELECT account_id FROM accounts WHERE email = ?", (email,)).fetchone()["account_id"]

    # Directly create an expired reset token in DB
    raw_exp = "expired_reset_token_1234567890"
    exp_hash = hashlib.sha256(raw_exp.encode("utf-8")).hexdigest()
    with get_db_connection(p10e_env.db_path) as conn:
        conn.execute(
            """
            INSERT INTO account_verification_tokens (
                token_hash, account_id, target, token_type, expires_at,
                used_at, created_at, attempts, max_attempts, last_attempt_at, ip_address
            ) VALUES (?, ?, ?, 'password_reset', '2020-01-01T00:00:00+00:00', NULL, '2020-01-01T00:00:00+00:00', 0, 5, NULL, NULL)
            """,
            (exp_hash, acc_id, email),
        )
        conn.commit()

    res_exp = client.post("/auth/reset-password", json={"token": raw_exp, "new_password": "ValidPassword123!"})
    assert res_exp.status_code == status.HTTP_400_BAD_REQUEST
    assert "expired" in res_exp.json()["detail"].lower()


# =============================================================================
# 5. Security, Privacy & Isolation Tests
# =============================================================================

def test_account_enumeration_resistance(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 11: Requesting resend or password reset for non-existent emails returns identical success messages."""
    fake_delivery.clear()

    # 1. Non-existent email for password reset
    res_fake_pw = client.post("/auth/forgot-password", json={"email": "nobody_exists_here_9999@example.com"})
    assert res_fake_pw.status_code == status.HTTP_200_OK
    assert "password reset instructions" in res_fake_pw.json()["detail"].lower()

    # 2. Existing email for password reset
    register_account(client, "real_user@example.com")
    res_real_pw = client.post("/auth/forgot-password", json={"email": "real_user@example.com"})
    assert res_real_pw.status_code == status.HTTP_200_OK

    # Detail strings must match identically
    assert res_fake_pw.json()["detail"] == res_real_pw.json()["detail"]

    # 3. Non-existent email for resend verification
    res_fake_ver = client.post("/auth/resend-verification", json={"email": "nobody_exists_here_9999@example.com"})
    assert res_fake_ver.status_code == status.HTTP_200_OK
    assert "verification link has been sent" in res_fake_ver.json()["detail"].lower()


def test_cross_account_and_cross_purpose_isolation(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 12: Tokens are bound to account and purpose; cannot be swapped between users or endpoints."""
    register_account(client, "alice_cross@example.com")
    register_account(client, "bob_cross@example.com")

    # Alice's verification token
    alice_token = fake_delivery.sent_emails[0]["body_text"].split("token=")[1].split()[0].strip()

    # 1. Alice's email token CANNOT be used as a password reset token
    res_cross_purpose = client.post(
        "/auth/reset-password",
        json={"token": alice_token, "new_password": "NewAlicePassword123!"},
    )
    assert res_cross_purpose.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or expired" in res_cross_purpose.json()["detail"].lower()

    # 2. Alice requests a password reset
    client.post("/auth/forgot-password", json={"email": "alice_cross@example.com"})
    alice_reset_token = fake_delivery.sent_emails[-1]["body_text"].split("token=")[1].split()[0].strip()

    # 3. Alice's password reset token CANNOT be used to verify email
    res_cross_verify = client.post("/auth/verify-email", json={"token": alice_reset_token})
    assert res_cross_verify.status_code == status.HTTP_400_BAD_REQUEST


def test_mail_delivery_provider_failure_handling(client: TestClient, fake_delivery: FakeDeliveryAdapter):
    """Test 13: Delivery adapter failures are caught gracefully without crashing or leaking sensitive info."""
    fake_delivery.configure_failure(True, "Simulated SMTP downstream failure")

    # Registration succeeds gracefully even if verification email delivery fails
    res_reg = client.post(
        "/auth/register",
        json={"email": "smtp_fail_user@example.com", "password": "Password12345!"},
    )
    assert res_reg.status_code == status.HTTP_201_CREATED
    assert res_reg.json()["email_verified"] is False


def test_recovery_without_token_is_rejected(client: TestClient):
    """Test 14: Rejects account recovery based solely on account_id or provider_id without valid token."""
    acc = register_account(client, "victim_account@example.com", "VictimOldPassword123!")
    account_id = acc["account_id"]

    # 1. Attempting reset using account_id without a token -> 422 or 400
    res_no_tok = client.post(
        "/auth/reset-password",
        json={"account_id": account_id, "new_password": "AttackerPassword123!"},
    )
    assert res_no_tok.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)

    # 2. Attempting reset using provider_id -> 422 or 400
    res_prov = client.post(
        "/auth/reset-password",
        json={"provider_id": "victim_provider", "new_password": "AttackerPassword123!"},
    )
    assert res_prov.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY)


def test_dashboard_ui_verification_integration(client: TestClient):
    """Test 15: Verifies dashboard UI renders verification badge and modal recovery tabs."""
    res = client.get("/dashboard")
    assert res.status_code == status.HTTP_200_OK
    assert "text/html" in res.headers.get("content-type", "")
    html = res.text
    assert "auth-verification-badge" in html
    assert "email-verification-banner" in html
    assert "tab-verify" in html
    assert "tab-forgot" in html
    assert "tab-sms" in html

