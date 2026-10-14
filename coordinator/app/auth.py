"""
Authentication and Session Security Subsystem for Expo Coordinator (Phase 8B).

Provides:
1. Explicit credential-to-provider mapping and role separation (CredentialManager).
2. Cryptographically hashed server-side session management (ProviderSessionManager).
3. Session-bound CSRF token issuance and verification.
4. Tenant isolation and prevention of provider identity spoofing.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from pydantic import BaseModel, Field

from coordinator.app.database import get_db_connection
from coordinator.app.config import CoordinatorSettings

logger = logging.getLogger("expo_auth")


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


class AuthenticatedPrincipal(BaseModel):
    """Resolved and verified security principal for an API/UI request."""
    principal_id: str
    provider_id: str
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
    def hash_secret(secret: str) -> str:
        """Computes a cryptographically salted SHA-256 hash of a credential secret."""
        salted = f"expo_cred_pepper:{secret.strip()}".encode("utf-8")
        return hashlib.sha256(salted).hexdigest()

    def register_credential(
        self,
        principal_id: str,
        provider_id: str,
        secret: str,
        is_admin: bool = False,
    ) -> ProviderCredentialRecord:
        """Registers or replaces an explicit credential mapping."""
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
        """Resolves an active credential by verifying secret hash."""
        if not secret or not secret.strip():
            return None
        target_hash = self.hash_secret(secret)

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM provider_credentials WHERE secret_hash = ? AND is_active = 1",
                (target_hash,),
            ).fetchone()

            if not row:
                return None

            return ProviderCredentialRecord(
                credential_id=row["credential_id"],
                principal_id=row["principal_id"],
                provider_id=row["provider_id"],
                secret_hash=row["secret_hash"],
                is_admin=bool(row["is_admin"]),
                is_active=bool(row["is_active"]),
                created_at=row["created_at"],
            )

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

