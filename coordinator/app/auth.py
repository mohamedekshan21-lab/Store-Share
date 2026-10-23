"""
Authentication and Session Security Subsystem for Expo Coordinator (Phase 8B & Phase 10A).

Provides:
1. Explicit credential-to-provider mapping and role separation (CredentialManager).
2. Cryptographically hashed server-side session management (ProviderSessionManager).
3. Session-bound CSRF token issuance and verification.
4. Tenant isolation and prevention of provider identity spoofing.
5. Distinct account identities, Argon2id password hashing, and user sessions (AccountManager).
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
import re
from typing import Optional, List
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from coordinator.app.database import get_db_connection
from coordinator.app.config import CoordinatorSettings
from coordinator.app.delivery import (
    DeliveryManager,
    DeliveryResult,
    SmtpMailAdapter,
    TwilioSmsAdapter,
    FakeDeliveryAdapter,
    UnconfiguredSmsAdapter,
)

logger = logging.getLogger("expo_auth")


class AuthSecurityError(Exception):
    """Base auth security exception."""
    pass


class RateLimitExceededError(AuthSecurityError):
    """Raised when a verification resend cooldown or rate limit is breached."""
    def __init__(self, message: str, retry_after_seconds: int = 60) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Computes an Argon2id hash of a password."""
    return _hasher.hash(password.strip())


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password.strip())
    except (VerifyMismatchError, InvalidHashError):
        return False


class ProviderCredentialRecord(BaseModel):
    """Explicit authenticated provider credential record stored in SQLite."""
    credential_id: str
    principal_id: str
    provider_id: str
    secret_hash: str
    is_admin: bool = False
    is_active: bool = True
    created_at: str


class ProviderSessionRecord(BaseModel):
    """Authenticated browser session record. Raw session_id is returned only in memory."""
    session_id: str
    session_hash: str
    provider_id: str
    csrf_token: str
    is_admin: bool = False
    created_at: str
    expires_at: str
    last_accessed_at: str


class AccountRecord(BaseModel):
    """Authenticated user account record (Phase 10A & Phase 10E)."""
    account_id: str
    email: str
    password_hash: str
    role: str = "consumer"
    capabilities: List[str] = Field(default_factory=lambda: ["file:read", "file:write"])
    status: str = "active"
    provider_id: Optional[str] = None
    email_verified: bool = False
    email_verified_at: Optional[str] = None
    phone_number: Optional[str] = None
    phone_verified: bool = False
    phone_verified_at: Optional[str] = None
    quota_bytes: int = 10 * 1024 * 1024 * 1024
    created_at: str
    updated_at: str

    def is_admin(self) -> bool:
        return self.role == "admin"


class AccountSessionRecord(BaseModel):
    """Authenticated user session record (Phase 10A)."""
    session_id: str
    session_hash: str
    account_id: str
    email: str
    role: str
    provider_id: Optional[str] = None
    csrf_token: str
    is_admin: bool = False
    created_at: str
    expires_at: str
    last_accessed_at: str


class AuthenticatedPrincipal(BaseModel):
    """Resolved and verified security principal for an API/UI request."""
    principal_id: str
    provider_id: str
    account_id: Optional[str] = None
    is_admin: bool = False
    admin_override: bool = False
    auth_method: str = Field(..., description="'token' or 'session'")
    csrf_token: Optional[str] = None


class CredentialManager:
    """Manages persistent provider credentials, salting/hashing, and role checks."""

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path

    @staticmethod
    def hash_secret_sha256(secret: str) -> str:
        """Computes a cryptographically salted SHA-256 hash of a credential secret (legacy)."""
        salted = f"expo_cred_pepper:{secret.strip()}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()

    @staticmethod
    def hash_secret(secret: str) -> str:
        """Computes Argon2id hash for credential secret (Phase 10A)."""
        return hash_password(secret.strip())

    def register_credential(
        self,
        principal_id: str,
        provider_id: str,
        secret: str,
        is_admin: bool = False,
    ) -> ProviderCredentialRecord:
        """Registers or replaces an explicit credential mapping using Argon2id."""
        clean_principal = principal_id.strip()
        clean_provider = provider_id.strip()
        secret_hash = self.hash_secret(secret)
        now_str = datetime.now(timezone.utc).isoformat()
        cred_id = f"cred-{uuid.uuid4().hex[:12]}"

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO provider_credentials (
                    credential_id, principal_id, provider_id, secret_hash,
                    is_admin, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(principal_id) DO UPDATE SET
                    provider_id = excluded.provider_id,
                    secret_hash = excluded.secret_hash,
                    is_admin = excluded.is_admin,
                    is_active = 1
                """,
                (
                    cred_id,
                    clean_principal,
                    clean_provider,
                    secret_hash,
                    1 if is_admin else 0,
                    now_str,
                ),
            )
            conn.commit()

        return ProviderCredentialRecord(
            credential_id=cred_id,
            principal_id=clean_principal,
            provider_id=clean_provider,
            secret_hash=secret_hash,
            is_admin=is_admin,
            is_active=True,
            created_at=now_str,
        )

    def verify_credential(self, secret: str) -> Optional[ProviderCredentialRecord]:
        """Resolves an active credential by verifying secret hash (Argon2id or legacy SHA-256)."""
        if not secret or not secret.strip():
            return None
        clean_secret = secret.strip()

        # 1. Check legacy SHA-256
        target_hash = self.hash_secret_sha256(clean_secret)
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM provider_credentials WHERE secret_hash = ? AND is_active = 1",
                (target_hash,),
            ).fetchone()

            if row:
                return ProviderCredentialRecord(
                    credential_id=row["credential_id"],
                    principal_id=row["principal_id"],
                    provider_id=row["provider_id"],
                    secret_hash=row["secret_hash"],
                    is_admin=bool(row["is_admin"]),
                    is_active=bool(row["is_active"]),
                    created_at=row["created_at"],
                )

            # 2. Check Argon2id hashed credentials
            argon_rows = conn.execute(
                "SELECT * FROM provider_credentials WHERE secret_hash LIKE '$argon2id$%' AND is_active = 1"
            ).fetchall()
            for a_row in argon_rows:
                if verify_password(clean_secret, a_row["secret_hash"]):
                    return ProviderCredentialRecord(
                        credential_id=a_row["credential_id"],
                        principal_id=a_row["principal_id"],
                        provider_id=a_row["provider_id"],
                        secret_hash=a_row["secret_hash"],
                        is_admin=bool(a_row["is_admin"]),
                        is_active=bool(a_row["is_active"]),
                        created_at=a_row["created_at"],
                    )

            return None

    def revoke_credential(self, principal_id: str) -> bool:
        """Deactivates a principal's credentials."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE provider_credentials SET is_active = 0 WHERE principal_id = ?",
                (principal_id.strip(),),
            )
            conn.commit()
            return cursor.rowcount > 0


class ProviderSessionManager:
    """
    Manages secure browser sessions, expiration, and CSRF token binding.
    Session identifiers are stored only as SHA-256 hashes in SQLite.
    """

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def hash_token(token: str) -> str:
        """Computes SHA-256 hash of an opaque session token."""
        return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

    def create_session(
        self,
        provider_id: str,
        is_admin: bool = False,
        duration_seconds: int = 86400,
    ) -> ProviderSessionRecord:
        """
        Creates a new durable browser session.
        Stores only SHA-256(raw_session_token) in SQLite, never the plaintext token.
        """
        raw_session_token = secrets.token_urlsafe(32)
        session_hash = self.hash_token(raw_session_token)
        csrf_token = secrets.token_urlsafe(32)
        now = self._now()
        expires = now + timedelta(seconds=duration_seconds)
        now_str = now.isoformat()
        expires_str = expires.isoformat()

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO provider_sessions (
                    session_hash, provider_id, csrf_token, is_admin,
                    created_at, expires_at, last_accessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_hash,
                    provider_id.strip(),
                    csrf_token,
                    1 if is_admin else 0,
                    now_str,
                    expires_str,
                    now_str,
                ),
            )
            conn.commit()

        return ProviderSessionRecord(
            session_id=raw_session_token,
            session_hash=session_hash,
            provider_id=provider_id.strip(),
            csrf_token=csrf_token,
            is_admin=is_admin,
            created_at=now_str,
            expires_at=expires_str,
            last_accessed_at=now_str,
        )

    def get_session(self, raw_session_token: str) -> Optional[ProviderSessionRecord]:
        """
        Retrieves and validates an active session using SHA-256 hash lookup.
        Purges expired entries automatically.
        """
        if not raw_session_token or not raw_session_token.strip():
            return None

        clean_token = raw_session_token.strip()
        target_hash = self.hash_token(clean_token)
        now = self._now()
        now_str = now.isoformat()

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM provider_sessions WHERE session_hash = ?",
                (target_hash,),
            ).fetchone()

            if not row:
                return None

            try:
                expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except Exception:
                conn.execute("DELETE FROM provider_sessions WHERE session_hash = ?", (target_hash,))
                conn.commit()
                return None

            if now >= expires_at:
                conn.execute("DELETE FROM provider_sessions WHERE session_hash = ?", (target_hash,))
                conn.commit()
                return None

            conn.execute(
                "UPDATE provider_sessions SET last_accessed_at = ? WHERE session_hash = ?",
                (now_str, target_hash),
            )
            conn.commit()

            return ProviderSessionRecord(
                session_id=clean_token,
                session_hash=row["session_hash"],
                provider_id=row["provider_id"],
                csrf_token=row["csrf_token"],
                is_admin=bool(row["is_admin"]),
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                last_accessed_at=now_str,
            )

    def delete_session(self, raw_session_token: str) -> bool:
        """Terminates and purges a session upon logout."""
        if not raw_session_token or not raw_session_token.strip():
            return False
        target_hash = self.hash_token(raw_session_token.strip())
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM provider_sessions WHERE session_hash = ?",
                (target_hash,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def clean_expired_sessions(self) -> int:
        """Housekeeping to remove all expired sessions from SQLite."""
        now_str = self._now().isoformat()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM provider_sessions WHERE expires_at < ?",
                (now_str,),
            )
            conn.commit()
            return cursor.rowcount

    def revoke_provider_sessions(self, provider_id: str) -> int:
        """Revokes and purges all active sessions for a specific provider."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM provider_sessions WHERE provider_id = ?",
                (provider_id.strip(),),
            )
            conn.commit()
            return cursor.rowcount


class AccountManager:
    """
    Manages user accounts, Argon2id passwords, authenticated sessions,
    email/SMS verification tokens, and account recovery (Phase 10A & 10E).
    """

    def __init__(
        self,
        settings: CoordinatorSettings,
        delivery_manager: Optional[DeliveryManager] = None,
    ) -> None:
        self.settings = settings
        self.db_path = settings.db_path
        if delivery_manager is not None:
            self.delivery_manager = delivery_manager
        else:
            # Build delivery manager from settings
            mail_adapter = SmtpMailAdapter(
                host=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password,
                from_email=settings.smtp_from_email,
                use_tls=settings.smtp_use_tls,
            )
            if settings.sms_provider == "twilio":
                sms_adapter = TwilioSmsAdapter(
                    account_sid=settings.twilio_account_sid,
                    auth_token=settings.twilio_auth_token,
                    from_number=settings.twilio_from_number,
                )
            elif getattr(settings, "is_testing", False) or settings.environment == "testing":
                sms_adapter = FakeDeliveryAdapter()
            else:
                sms_adapter = UnconfiguredSmsAdapter()
            self.delivery_manager = DeliveryManager(mail_adapter=mail_adapter, sms_adapter=sms_adapter)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def hash_token(token: str) -> str:
        """Computes SHA-256 hash of an opaque session or verification token."""
        return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

    def register_account(
        self,
        email: str,
        password: str,
        role: str = "consumer",
        provider_id: Optional[str] = None,
        status: str = "active",
        email_verified: bool = False,
        phone_number: Optional[str] = None,
    ) -> AccountRecord:
        """Registers a new user account with Argon2id password hashing."""
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email or "." not in clean_email:
            raise ValueError("Invalid email format.")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")

        # Security: Prevent public registration from assigning admin role
        if role.lower() == "admin":
            raise ValueError("Cannot register an administrator account via public registration.")

        now_str = self._now().isoformat()
        email_ver_at = now_str if email_verified else None
        account_id = str(uuid.uuid4())
        pw_hash = hash_password(password)
        capabilities = ["file:read", "file:write"]
        if role == "provider" or provider_id:
            capabilities.append("provider:host")
        capabilities_json = json.dumps(capabilities)

        quota_bytes = int(getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024))
        with get_db_connection(self.db_path) as conn:
            existing = conn.execute(
                "SELECT account_id FROM accounts WHERE email = ?",
                (clean_email,),
            ).fetchone()
            if existing:
                raise ValueError("An account with this email already exists.")

            conn.execute(
                """
                INSERT INTO accounts (
                    account_id, email, password_hash, role, capabilities,
                    status, provider_id, email_verified, email_verified_at,
                    phone_number, phone_verified, phone_verified_at,
                    quota_bytes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)
                """,
                (
                    account_id,
                    clean_email,
                    pw_hash,
                    role,
                    capabilities_json,
                    status,
                    provider_id.strip() if provider_id else None,
                    1 if email_verified else 0,
                    email_ver_at,
                    phone_number.strip() if phone_number else None,
                    quota_bytes,
                    now_str,
                    now_str,
                ),
            )
            conn.commit()

        # If not verified and registration succeeds, dispatch initial verification email
        if not email_verified:
            try:
                raw_token = self.create_email_verification_token(
                    account_id=account_id,
                    email=clean_email,
                    enforce_rate_limit=False,
                )
                base_url = getattr(self.settings, "verification_base_url", "http://localhost:9000")
                self.delivery_manager.send_email_verification(clean_email, raw_token, base_url)
            except Exception as e:
                logger.warning("Failed to send initial verification email to %s: %s", clean_email, str(e))

        return AccountRecord(
            account_id=account_id,
            email=clean_email,
            password_hash=pw_hash,
            role=role,
            capabilities=capabilities,
            status=status,
            provider_id=provider_id.strip() if provider_id else None,
            email_verified=email_verified,
            email_verified_at=email_ver_at,
            phone_number=phone_number.strip() if phone_number else None,
            phone_verified=False,
            phone_verified_at=None,
            quota_bytes=quota_bytes,
            created_at=now_str,
            updated_at=now_str,
        )

    def authenticate(self, email: str, password: str) -> Optional[AccountRecord]:
        """Authenticates user credentials using Argon2id verification."""
        clean_email = email.strip().lower()
        if not clean_email or not password:
            return None

        try:
            with get_db_connection(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM accounts WHERE email = ?",
                    (clean_email,),
                ).fetchone()

                if not row:
                    return None

                if not verify_password(password, row["password_hash"]):
                    return None

                caps = []
                if row["capabilities"]:
                    try:
                        caps = json.loads(row["capabilities"])
                    except Exception:
                        caps = [c.strip() for c in row["capabilities"].split(",") if c.strip()]

                q_bytes = int(row["quota_bytes"]) if "quota_bytes" in row.keys() and row["quota_bytes"] is not None else getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024)
                email_ver_at = row["email_verified_at"] if "email_verified_at" in row.keys() else None
                phone_num = row["phone_number"] if "phone_number" in row.keys() else None
                phone_ver = bool(row["phone_verified"]) if "phone_verified" in row.keys() and row["phone_verified"] is not None else False
                phone_ver_at = row["phone_verified_at"] if "phone_verified_at" in row.keys() else None

                return AccountRecord(
                    account_id=row["account_id"],
                    email=row["email"],
                    password_hash=row["password_hash"],
                    role=row["role"],
                    capabilities=caps,
                    status=row["status"],
                    provider_id=row["provider_id"],
                    email_verified=bool(row["email_verified"]),
                    email_verified_at=email_ver_at,
                    phone_number=phone_num,
                    phone_verified=phone_ver,
                    phone_verified_at=phone_ver_at,
                    quota_bytes=q_bytes,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
        except sqlite3.OperationalError:
            return None

    def update_account_quota(self, account_id: str, new_quota_bytes: int) -> bool:
        """Updates configured storage quota for an account."""
        now_str = self._now().isoformat()
        new_quota_bytes = max(0, int(new_quota_bytes))
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE accounts SET quota_bytes = ?, updated_at = ? WHERE account_id = ?",
                (new_quota_bytes, now_str, account_id.strip()),
            )
            conn.commit()
            return cursor.rowcount > 0

    def update_account_capabilities(self, account_id: str, capabilities: List[str]) -> bool:
        """Updates the capabilities granted to an account."""
        now_str = self._now().isoformat()
        caps_json = json.dumps(capabilities)
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE accounts SET capabilities = ?, updated_at = ? WHERE account_id = ?",
                (caps_json, now_str, account_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def create_session(
        self,
        account: AccountRecord,
        duration_seconds: int = 86400,
    ) -> AccountSessionRecord:
        """Issues a new authenticated user session with server-side SHA-256 storage."""
        raw_session_token = secrets.token_urlsafe(32)
        session_hash = self.hash_token(raw_session_token)
        csrf_token = secrets.token_urlsafe(32)
        now = self._now()
        expires = now + timedelta(seconds=duration_seconds)
        now_str = now.isoformat()
        expires_str = expires.isoformat()
        is_admin = (account.role == "admin")

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO account_sessions (
                    session_hash, account_id, email, role, provider_id,
                    csrf_token, is_admin, created_at, expires_at, last_accessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_hash,
                    account.account_id,
                    account.email,
                    account.role,
                    account.provider_id,
                    csrf_token,
                    1 if is_admin else 0,
                    now_str,
                    expires_str,
                    now_str,
                ),
            )
            conn.commit()

        return AccountSessionRecord(
            session_id=raw_session_token,
            session_hash=session_hash,
            account_id=account.account_id,
            email=account.email,
            role=account.role,
            provider_id=account.provider_id,
            csrf_token=csrf_token,
            is_admin=is_admin,
            created_at=now_str,
            expires_at=expires_str,
            last_accessed_at=now_str,
        )

    def get_session(self, raw_session_token: str) -> Optional[AccountSessionRecord]:
        """Validates an active user session by SHA-256 hash lookup and checks expiration."""
        if not raw_session_token or not raw_session_token.strip():
            return None

        clean_token = raw_session_token.strip()
        target_hash = self.hash_token(clean_token)
        now = self._now()
        now_str = now.isoformat()

        try:
            with get_db_connection(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM account_sessions WHERE session_hash = ?",
                    (target_hash,),
                ).fetchone()

                if not row:
                    return None

                try:
                    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                except Exception:
                    conn.execute("DELETE FROM account_sessions WHERE session_hash = ?", (target_hash,))
                    conn.commit()
                    return None

                if now >= expires_at:
                    conn.execute("DELETE FROM account_sessions WHERE session_hash = ?", (target_hash,))
                    conn.commit()
                    return None

                acc_row = conn.execute(
                    "SELECT status FROM accounts WHERE account_id = ?",
                    (row["account_id"],),
                ).fetchone()
                if not acc_row or acc_row["status"] != "active":
                    conn.execute("DELETE FROM account_sessions WHERE session_hash = ?", (target_hash,))
                    conn.commit()
                    return None

                conn.execute(
                    "UPDATE account_sessions SET last_accessed_at = ? WHERE session_hash = ?",
                    (now_str, target_hash),
                )
                conn.commit()

                return AccountSessionRecord(
                    session_id=clean_token,
                    session_hash=row["session_hash"],
                    account_id=row["account_id"],
                    email=row["email"],
                    role=row["role"],
                    provider_id=row["provider_id"],
                    csrf_token=row["csrf_token"],
                    is_admin=bool(row["is_admin"]),
                    created_at=row["created_at"],
                    expires_at=row["expires_at"],
                    last_accessed_at=now_str,
                )
        except sqlite3.OperationalError:
            return None

    def revoke_session(self, raw_session_token: str) -> bool:
        """Revokes an active session token."""
        if not raw_session_token or not raw_session_token.strip():
            return False
        target_hash = self.hash_token(raw_session_token.strip())
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM account_sessions WHERE session_hash = ?",
                    (target_hash,),
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.OperationalError:
            return False

    def get_account(self, account_id: str) -> Optional[AccountRecord]:
        """Retrieves an account record by immutable account_id."""
        try:
            with get_db_connection(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM accounts WHERE account_id = ?",
                    (account_id.strip(),),
                ).fetchone()
                if not row:
                    return None

                caps = []
                if row["capabilities"]:
                    try:
                        caps = json.loads(row["capabilities"])
                    except Exception:
                        caps = [c.strip() for c in row["capabilities"].split(",") if c.strip()]

                q_bytes = int(row["quota_bytes"]) if "quota_bytes" in row.keys() and row["quota_bytes"] is not None else getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024)
                email_ver_at = row["email_verified_at"] if "email_verified_at" in row.keys() else None
                phone_num = row["phone_number"] if "phone_number" in row.keys() else None
                phone_ver = bool(row["phone_verified"]) if "phone_verified" in row.keys() and row["phone_verified"] is not None else False
                phone_ver_at = row["phone_verified_at"] if "phone_verified_at" in row.keys() else None

                return AccountRecord(
                    account_id=row["account_id"],
                    email=row["email"],
                    password_hash=row["password_hash"],
                    role=row["role"],
                    capabilities=caps,
                    status=row["status"],
                    provider_id=row["provider_id"],
                    email_verified=bool(row["email_verified"]),
                    email_verified_at=email_ver_at,
                    phone_number=phone_num,
                    phone_verified=phone_ver,
                    phone_verified_at=phone_ver_at,
                    quota_bytes=q_bytes,
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )
        except sqlite3.OperationalError:
            return None

    def bootstrap_admin(self, admin_email: Optional[str], admin_password: Optional[str]) -> Optional[AccountRecord]:
        """Bootstraps an administrator account from explicit configuration (Phase 10A)."""
        if not admin_email or not admin_password:
            return None
        clean_email = admin_email.strip().lower()
        clean_pw = admin_password.strip()
        if not clean_email or not clean_pw:
            return None

        now_str = self._now().isoformat()
        with get_db_connection(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM accounts WHERE email = ?",
                (clean_email,),
            ).fetchone()

            pw_hash = hash_password(clean_pw)
            caps_json = json.dumps(["file:read", "file:write", "admin:all", "provider:host"])

            if existing:
                conn.execute(
                    """
                    UPDATE accounts
                    SET password_hash = ?, role = 'admin', capabilities = ?,
                        status = 'active', email_verified = 1, updated_at = ?
                    WHERE email = ?
                    """,
                    (pw_hash, caps_json, now_str, clean_email),
                )
                account_id = existing["account_id"]
            else:
                account_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO accounts (
                        account_id, email, password_hash, role, capabilities,
                        status, provider_id, email_verified, created_at, updated_at
                    ) VALUES (?, ?, ?, 'admin', ?, 'active', NULL, 1, ?, ?)
                    """,
                    (account_id, clean_email, pw_hash, caps_json, now_str, now_str),
                )
            conn.commit()

        return self.get_account(account_id)

    # =========================================================================
    # Phase 10E: Rate Limiting, Verification & Account Recovery Implementation
    # =========================================================================

    def check_rate_limit(
        self,
        identifier: str,
        action_type: str,
        cooldown_seconds: int = 60,
        max_per_hour: int = 5,
    ) -> tuple[bool, Optional[str], int]:
        """
        Enforces cooldown and hourly rate limits using persistent SQLite records.
        Returns (is_allowed, reason, retry_after_seconds).
        """
        now = self._now()
        hour_ago_str = (now - timedelta(seconds=3600)).isoformat()
        clean_ident = identifier.strip().lower()

        try:
            with get_db_connection(self.db_path) as conn:
                # 1. Cooldown check: Most recent attempt
                recent = conn.execute(
                    """
                    SELECT attempted_at FROM verification_rate_limits
                    WHERE identifier = ? AND action_type = ?
                    ORDER BY attempted_at DESC LIMIT 1
                    """,
                    (clean_ident, action_type),
                ).fetchone()

                if recent:
                    try:
                        last_dt = datetime.fromisoformat(recent["attempted_at"].replace("Z", "+00:00"))
                        if last_dt.tzinfo is None:
                            last_dt = last_dt.replace(tzinfo=timezone.utc)
                        elapsed = (now - last_dt).total_seconds()
                        if elapsed < cooldown_seconds:
                            wait_time = max(1, int(cooldown_seconds - elapsed))
                            return False, f"Cooldown active. Please wait {wait_time}s before requesting again.", wait_time
                    except Exception:
                        pass

                # 2. Hourly volume check
                count_row = conn.execute(
                    """
                    SELECT COUNT(*) as cnt FROM verification_rate_limits
                    WHERE identifier = ? AND action_type = ? AND attempted_at >= ?
                    """,
                    (clean_ident, action_type, hour_ago_str),
                ).fetchone()

                hourly_count = count_row["cnt"] if count_row else 0
                if hourly_count >= max_per_hour:
                    return False, f"Rate limit exceeded. Maximum {max_per_hour} requests per hour.", 3600

                return True, None, 0
        except sqlite3.OperationalError:
            return True, None, 0

    def record_rate_limit_attempt(
        self,
        identifier: str,
        action_type: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Records an attempt for cooldown and rate limit enforcement."""
        now_str = self._now().isoformat()
        limit_id = str(uuid.uuid4())
        clean_ident = identifier.strip().lower()
        try:
            with get_db_connection(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO verification_rate_limits (limit_id, identifier, action_type, attempted_at, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (limit_id, clean_ident, action_type, now_str, ip_address),
                )
                # Purge entries older than 24 hours
                one_day_ago = (self._now() - timedelta(hours=24)).isoformat()
                conn.execute("DELETE FROM verification_rate_limits WHERE attempted_at < ?", (one_day_ago,))
                conn.commit()
        except sqlite3.OperationalError:
            pass

    def create_email_verification_token(
        self,
        account_id: str,
        email: str,
        ip_address: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        enforce_rate_limit: bool = True,
    ) -> str:
        """
        Generates a cryptographically secure, expiring email verification token.
        Stores only the SHA-256 digest in SQLite.
        Invalidates any previously pending email verification tokens for this account.
        """
        clean_email = email.strip().lower()
        cooldown = getattr(self.settings, "verification_resend_cooldown_seconds", 60)
        max_hour = getattr(self.settings, "max_resend_per_hour", 5)

        if enforce_rate_limit:
            allowed, reason, retry_after = self.check_rate_limit(clean_email, "email_verify_resend", cooldown, max_hour)
            if not allowed:
                raise RateLimitExceededError(reason or "Rate limit exceeded.", retry_after_seconds=retry_after)

            if ip_address:
                allowed_ip, reason_ip, retry_ip = self.check_rate_limit(f"ip:{ip_address}", "email_verify_resend", 0, max_hour * 10)
                if not allowed_ip:
                    raise RateLimitExceededError("Rate limit exceeded from this network location.", retry_after_seconds=retry_ip)

        now = self._now()
        ttl = ttl_seconds or getattr(self.settings, "email_verification_ttl_seconds", 86400)
        expires = now + timedelta(seconds=ttl)
        now_str = now.isoformat()
        expires_str = expires.isoformat()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        with get_db_connection(self.db_path) as conn:
            # Invalidate prior unused email verification tokens for this account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?
                WHERE account_id = ? AND token_type = 'email_verification' AND used_at IS NULL
                """,
                (now_str, account_id),
            )

            conn.execute(
                """
                INSERT INTO account_verification_tokens (
                    token_hash, account_id, target, token_type, expires_at,
                    used_at, created_at, attempts, max_attempts, last_attempt_at, ip_address
                ) VALUES (?, ?, ?, 'email_verification', ?, NULL, ?, 0, ?, NULL, ?)
                """,
                (
                    token_hash,
                    account_id,
                    clean_email,
                    expires_str,
                    now_str,
                    getattr(self.settings, "max_code_verification_attempts", 5),
                    ip_address,
                ),
            )
            conn.commit()

        if enforce_rate_limit:
            self.record_rate_limit_attempt(clean_email, "email_verify_resend", ip_address)
            if ip_address:
                self.record_rate_limit_attempt(f"ip:{ip_address}", "email_verify_resend", ip_address)

        return raw_token

    def verify_email_token(self, raw_token: str) -> tuple[bool, str, Optional[AccountRecord]]:
        """
        Redeems an email verification token.
        Enforces single-use, non-expired, valid digest, and max attempts.
        Updates accounts table email_verified = 1 and persists email_verified_at.
        """
        if not raw_token or not raw_token.strip() or len(raw_token.strip()) < 16:
            return False, "Malformed or invalid email verification token.", None

        clean_token = raw_token.strip()
        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()
        now = self._now()
        now_str = now.isoformat()

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM account_verification_tokens WHERE token_hash = ? AND token_type = 'email_verification'",
                (token_hash,),
            ).fetchone()

            if not row:
                return False, "Invalid or expired verification token.", None

            if row["used_at"] is not None:
                return False, "Verification token has already been used.", None

            # Check expiration
            try:
                expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except Exception:
                return False, "Invalid token expiration metadata.", None

            if now >= expires_at:
                return False, "Verification token has expired.", None

            if row["attempts"] >= row["max_attempts"]:
                return False, "Verification token has exceeded maximum verification attempts.", None

            # Concurrency-safe atomic token burn
            cur = conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?, attempts = attempts + 1, last_attempt_at = ?
                WHERE token_hash = ? AND used_at IS NULL
                """,
                (now_str, now_str, token_hash),
            )
            if cur.rowcount == 0:
                return False, "Verification token was already redeemed concurrently.", None

            account_id = row["account_id"]

            # Update account verification status
            conn.execute(
                """
                UPDATE accounts
                SET email_verified = 1, email_verified_at = ?, updated_at = ?
                WHERE account_id = ?
                """,
                (now_str, now_str, account_id),
            )

            # Invalidate any other pending email verification tokens for this account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?
                WHERE account_id = ? AND token_type = 'email_verification' AND used_at IS NULL
                """,
                (now_str, account_id),
            )
            conn.commit()

        updated_account = self.get_account(account_id)
        return True, "Email verified successfully.", updated_account

    def request_email_verification(self, email: str, ip_address: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Requests email verification link for an account.
        Enumeration-resistant: returns success even if account does not exist or is already verified.
        Dispatches email via delivery_manager.
        """
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            return False, None

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?",
                (clean_email,),
            ).fetchone()

        if not row:
            # Avoid enumeration: record rate limit attempt against IP to prevent abuse
            if ip_address:
                self.record_rate_limit_attempt(f"ip:{ip_address}", "email_verify_resend", ip_address)
            return True, None

        # If already verified, do not send, but return success to prevent enumeration
        if bool(row["email_verified"]):
            return True, None

        # Account exists and is unverified: create token & dispatch email
        raw_token = self.create_email_verification_token(
            account_id=row["account_id"],
            email=clean_email,
            ip_address=ip_address,
            enforce_rate_limit=True,
        )

        base_url = getattr(self.settings, "verification_base_url", "http://localhost:9000")
        self.delivery_manager.send_email_verification(clean_email, raw_token, base_url)
        return True, raw_token

    def request_password_reset(self, email: str, ip_address: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """
        Requests a password reset link for an account.
        Enumeration-resistant: returns True even if account does not exist.
        Generates expiring single-use token and dispatches email via delivery_manager.
        """
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            return False, None

        cooldown = getattr(self.settings, "verification_resend_cooldown_seconds", 60)
        max_hour = getattr(self.settings, "max_resend_per_hour", 5)

        # Enforce IP rate limits
        if ip_address:
            allowed_ip, reason_ip, retry_ip = self.check_rate_limit(f"ip:{ip_address}", "password_reset_request", 0, max_hour * 10)
            if not allowed_ip:
                raise RateLimitExceededError("Rate limit exceeded from this network location.", retry_after_seconds=retry_ip)

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM accounts WHERE email = ?",
                (clean_email,),
            ).fetchone()

        if not row:
            # Avoid enumeration: return True
            if ip_address:
                self.record_rate_limit_attempt(f"ip:{ip_address}", "password_reset_request", ip_address)
            return True, None

        # Check rate limit on email
        allowed, reason, retry_after = self.check_rate_limit(clean_email, "password_reset_request", cooldown, max_hour)
        if not allowed:
            raise RateLimitExceededError(reason or "Rate limit exceeded.", retry_after_seconds=retry_after)

        now = self._now()
        ttl = getattr(self.settings, "password_reset_ttl_seconds", 3600)
        expires = now + timedelta(seconds=ttl)
        now_str = now.isoformat()
        expires_str = expires.isoformat()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        with get_db_connection(self.db_path) as conn:
            # Invalidate any prior unused password reset tokens for this account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?
                WHERE account_id = ? AND token_type = 'password_reset' AND used_at IS NULL
                """,
                (now_str, row["account_id"]),
            )

            conn.execute(
                """
                INSERT INTO account_verification_tokens (
                    token_hash, account_id, target, token_type, expires_at,
                    used_at, created_at, attempts, max_attempts, last_attempt_at, ip_address
                ) VALUES (?, ?, ?, 'password_reset', ?, NULL, ?, 0, ?, NULL, ?)
                """,
                (
                    token_hash,
                    row["account_id"],
                    clean_email,
                    expires_str,
                    now_str,
                    getattr(self.settings, "max_code_verification_attempts", 5),
                    ip_address,
                ),
            )
            conn.commit()

        self.record_rate_limit_attempt(clean_email, "password_reset_request", ip_address)
        if ip_address:
            self.record_rate_limit_attempt(f"ip:{ip_address}", "password_reset_request", ip_address)

        base_url = getattr(self.settings, "verification_base_url", "http://localhost:9000")
        self.delivery_manager.send_password_reset(clean_email, raw_token, base_url)
        return True, raw_token

    def confirm_password_reset(self, raw_token: str, new_password: str) -> tuple[bool, str, Optional[str]]:
        """
        Confirms a password reset with Argon2id hashing and revokes ALL existing active sessions.
        Sends a security notification email to the account owner.
        """
        if not raw_token or not raw_token.strip() or len(raw_token.strip()) < 16:
            return False, "Malformed or invalid password reset token.", None

        if len(new_password) < 8:
            return False, "Password must be at least 8 characters.", None

        clean_token = raw_token.strip()
        token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()
        now = self._now()
        now_str = now.isoformat()

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM account_verification_tokens WHERE token_hash = ? AND token_type = 'password_reset'",
                (token_hash,),
            ).fetchone()

            if not row:
                return False, "Invalid or expired password reset token.", None

            if row["used_at"] is not None:
                return False, "Password reset token has already been used.", None

            try:
                expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except Exception:
                return False, "Invalid token expiration metadata.", None

            if now >= expires_at:
                return False, "Password reset token has expired.", None

            if row["attempts"] >= row["max_attempts"]:
                return False, "Password reset token exceeded maximum verification attempts.", None

            # Concurrency-safe atomic token burn
            cur = conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?, attempts = attempts + 1, last_attempt_at = ?
                WHERE token_hash = ? AND used_at IS NULL
                """,
                (now_str, now_str, token_hash),
            )
            if cur.rowcount == 0:
                return False, "Password reset token already redeemed concurrently.", None

            account_id = row["account_id"]
            new_hash = hash_password(new_password)

            # Update password
            conn.execute(
                """
                UPDATE accounts
                SET password_hash = ?, updated_at = ?
                WHERE account_id = ?
                """,
                (new_hash, now_str, account_id),
            )

            # Revoke ALL active user sessions (Security Requirements 4 & 8)
            conn.execute("DELETE FROM account_sessions WHERE account_id = ?", (account_id,))

            # Invalidate all remaining verification & reset tokens for this account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?
                WHERE account_id = ? AND used_at IS NULL
                """,
                (now_str, account_id),
            )
            conn.commit()

        # Send security notification email
        acc = self.get_account(account_id)
        if acc:
            self.delivery_manager.send_security_notice(
                acc.email,
                "Password Successfully Changed",
                "Your Expo storage account password was recently changed. If you did not perform this action, please contact an administrator immediately.",
            )

        return True, "Password has been successfully reset. Please log in with your new password.", account_id

    def revoke_account_sessions(self, account_id: str) -> int:
        """Revokes all active sessions for a specific account."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM account_sessions WHERE account_id = ?",
                (account_id.strip(),),
            )
            conn.commit()
            return cursor.rowcount

    def request_phone_verification(
        self,
        account_id: str,
        phone_number: str,
        ip_address: Optional[str] = None,
    ) -> tuple[bool, str, Optional[str]]:
        """
        Generates and dispatches a 6-digit SMS verification code.
        Never logs the code or full sensitive phone number.
        Enforces cooldown and per-account, per-number, and per-IP rate limits.
        """
        clean_phone = re.sub(r"[^\d+]", "", phone_number.strip())
        if len(clean_phone) < 8 or len(clean_phone) > 18:
            return False, "Invalid phone number format. Must be E.164 compatible.", None

        cooldown = getattr(self.settings, "verification_resend_cooldown_seconds", 60)
        max_hour = getattr(self.settings, "max_resend_per_hour", 5)

        # Check rate limits on phone number and account
        allowed, reason, retry_after = self.check_rate_limit(f"phone:{clean_phone}", "sms_code_send", cooldown, max_hour)
        if not allowed:
            raise RateLimitExceededError(reason or "SMS rate limit exceeded.", retry_after_seconds=retry_after)

        allowed_acc, reason_acc, retry_acc = self.check_rate_limit(f"acc_sms:{account_id}", "sms_code_send", cooldown, max_hour)
        if not allowed_acc:
            raise RateLimitExceededError(reason_acc or "SMS rate limit exceeded for account.", retry_after_seconds=retry_acc)

        if ip_address:
            allowed_ip, reason_ip, retry_ip = self.check_rate_limit(f"ip_sms:{ip_address}", "sms_code_send", 0, max_hour * 10)
            if not allowed_ip:
                raise RateLimitExceededError("SMS rate limit exceeded from this network location.", retry_after_seconds=retry_ip)

        now = self._now()
        ttl = getattr(self.settings, "sms_code_ttl_seconds", 600)
        expires = now + timedelta(seconds=ttl)
        now_str = now.isoformat()
        expires_str = expires.isoformat()

        # 6-digit numeric code
        raw_code = f"{secrets.randbelow(900000) + 100000:06d}"
        code_hash = hashlib.sha256(f"{account_id}:{raw_code}".encode("utf-8")).hexdigest()

        with get_db_connection(self.db_path) as conn:
            # Invalidate prior unused SMS tokens for this account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?
                WHERE account_id = ? AND token_type = 'sms_verification' AND used_at IS NULL
                """,
                (now_str, account_id),
            )

            conn.execute(
                """
                INSERT INTO account_verification_tokens (
                    token_hash, account_id, target, token_type, expires_at,
                    used_at, created_at, attempts, max_attempts, last_attempt_at, ip_address
                ) VALUES (?, ?, ?, 'sms_verification', ?, NULL, ?, 0, ?, NULL, ?)
                """,
                (
                    code_hash,
                    account_id,
                    clean_phone,
                    expires_str,
                    now_str,
                    getattr(self.settings, "max_code_verification_attempts", 5),
                    ip_address,
                ),
            )
            conn.commit()

        self.record_rate_limit_attempt(f"phone:{clean_phone}", "sms_code_send", ip_address)
        self.record_rate_limit_attempt(f"acc_sms:{account_id}", "sms_code_send", ip_address)
        if ip_address:
            self.record_rate_limit_attempt(f"ip_sms:{ip_address}", "sms_code_send", ip_address)

        # Dispatch via delivery manager (never logs raw code)
        res = self.delivery_manager.send_sms_verification_code(clean_phone, raw_code)
        if not res.success:
            return False, res.error or "Failed to deliver SMS verification code.", raw_code

        return True, "SMS verification code sent successfully.", raw_code

    def verify_phone_code(self, account_id: str, phone_number: str, raw_code: str) -> tuple[bool, str]:
        """
        Verifies 6-digit SMS code against stored hash with attempt limits and burn-on-exhaustion.
        """
        clean_code = raw_code.strip()
        if not clean_code.isdigit() or len(clean_code) != 6:
            return False, "Invalid verification code format. Must be 6 digits."

        clean_phone = re.sub(r"[^\d+]", "", phone_number.strip())
        expected_hash = hashlib.sha256(f"{account_id}:{clean_code}".encode("utf-8")).hexdigest()
        now = self._now()
        now_str = now.isoformat()

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT * FROM account_verification_tokens
                WHERE account_id = ? AND token_type = 'sms_verification' AND used_at IS NULL
                ORDER BY created_at DESC LIMIT 1
                """,
                (account_id,),
            ).fetchone()

            if not row:
                return False, "No active SMS verification request found. Please request a new code."

            # Check expiration
            try:
                expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
            except Exception:
                return False, "Invalid token expiration metadata."

            if now >= expires_at:
                return False, "SMS verification code has expired. Please request a new code."

            if row["attempts"] >= row["max_attempts"]:
                conn.execute(
                    "UPDATE account_verification_tokens SET used_at = ? WHERE token_hash = ?",
                    (now_str, row["token_hash"]),
                )
                conn.commit()
                return False, "Verification attempts exceeded. This code has been invalidated."

            # Verify hash match
            if row["token_hash"] != expected_hash:
                new_attempts = row["attempts"] + 1
                burn = (new_attempts >= row["max_attempts"])
                conn.execute(
                    """
                    UPDATE account_verification_tokens
                    SET attempts = ?, last_attempt_at = ?, used_at = ?
                    WHERE token_hash = ?
                    """,
                    (new_attempts, now_str, now_str if burn else None, row["token_hash"]),
                )
                conn.commit()
                remaining = max(0, row["max_attempts"] - new_attempts)
                if burn:
                    return False, "Invalid code. Maximum attempts exceeded; code has been invalidated."
                return False, f"Invalid verification code. {remaining} attempts remaining."

            # Code matched: burn token and update account
            conn.execute(
                """
                UPDATE account_verification_tokens
                SET used_at = ?, attempts = attempts + 1, last_attempt_at = ?
                WHERE token_hash = ?
                """,
                (now_str, now_str, row["token_hash"]),
            )

            conn.execute(
                """
                UPDATE accounts
                SET phone_number = ?, phone_verified = 1, phone_verified_at = ?, updated_at = ?
                WHERE account_id = ?
                """,
                (clean_phone, now_str, now_str, account_id),
            )
            conn.commit()

        return True, "Phone number successfully verified."



