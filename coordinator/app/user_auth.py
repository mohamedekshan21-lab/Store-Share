"""
Secure JWT-Based Human User Authentication and Role-Based Access Control (RBAC).

Features:
- Three human account roles: ADMIN, PROVIDER, CONSUMER.
- Argon2id cryptographic password hashing with salting.
- Signed PyJWT token generation with strict claim validation (sub, iss, aud, iat, exp, jti, role_version).
- SQLite persistence for user accounts and immediate token revocation blacklist.
- Reusable FastAPI dependencies for authentication and role authorization.
- Cookie (HttpOnly, SameSite, Secure) and Bearer header token support with CSRF protection.
"""

from __future__ import annotations

import enum
import logging
import re
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional, Sequence, Tuple, Union

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.database import get_db_connection

logger = logging.getLogger("expo_user_auth")

# Argon2id password hasher configuration (OWASP recommended parameters)
_argon2_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    type=Type.ID,
)


class Role(str, enum.Enum):
    ADMIN = "admin"
    PROVIDER = "provider"
    CONSUMER = "consumer"


VALID_ROLES = {Role.ADMIN.value, Role.PROVIDER.value, Role.CONSUMER.value}

_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,32}$")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    return _argon2_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    if not password or not password_hash:
        return False
    try:
        return _argon2_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception as exc:
        logger.warning("Unexpected error during Argon2 password verification: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class UserRecord(BaseModel):
    """Authoritative user record stored in database (excluding password hash)."""
    user_id: str
    username: str
    email: str
    role: str
    is_active: bool = True
    provider_id: Optional[str] = None
    role_version: int = 1
    created_at: str
    updated_at: str


class UserCreate(BaseModel):
    """Public registration request model. Self-assignment of admin or provider is prohibited."""
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip()
        if not _USERNAME_REGEX.match(clean):
            raise ValueError(
                "Username must be 3-32 characters and contain only alphanumeric, underscores, hyphens, or dots."
            )
        return clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if len(v) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        return v


class UserLogin(BaseModel):
    """User login request model accepting username or email."""
    username_or_email: str
    password: str


class TokenResponse(BaseModel):
    """JWT Login response with token metadata and CSRF token."""
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    csrf_token: str
    user: UserRecord


class RoleUpdateRequest(BaseModel):
    """Admin-only role change request model."""
    role: str
    provider_id: Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in VALID_ROLES:
            raise ValueError(f"Invalid role '{clean}'. Must be one of: {', '.join(VALID_ROLES)}")
        return clean


class StatusUpdateRequest(BaseModel):
    """Admin-only account activation/deactivation request model."""
    is_active: bool


class UserListResponse(BaseModel):
    users: List[UserRecord]
    count: int


# ---------------------------------------------------------------------------
# JWT Operations
# ---------------------------------------------------------------------------

def create_access_token(
    user: UserRecord,
    settings: CoordinatorSettings,
    expires_delta: Optional[timedelta] = None,
    return_full: bool = False,
) -> Union[str, Tuple[str, str, datetime]]:
    """
    Creates a signed PyJWT token with standard claims:
    sub, username, email, role, provider_id, role_version, iss, aud, iat, exp, jti.
    Returns raw token string by default, or (token, jti, expires_at) if return_full=True.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expires_at = now + expires_delta
    else:
        expires_at = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    jti = secrets.token_hex(16)

    payload = {
        "sub": user.user_id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "provider_id": user.provider_id,
        "role_version": user.role_version,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": jti,
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    if return_full:
        return token, jti, expires_at
    return token


def decode_access_token(token: str, settings: CoordinatorSettings) -> Dict[str, Any]:
    """
    Validates signature, algorithm, expiration, issuer, audience, and required claims.
    Raises jwt.PyJWTError on any validation failure.
    """
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        options={
            "require": ["sub", "iss", "aud", "exp", "iat", "jti", "role"],
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
        },
    )


# ---------------------------------------------------------------------------
# User & Session Persistence Manager
# ---------------------------------------------------------------------------

class UserManager:
    """Manages persistent human user accounts, role versions, and JWT revocation."""

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = Role.CONSUMER.value,
        provider_id: Optional[str] = None,
        is_active: bool = True,
    ) -> UserRecord:
        """Creates a new human user account. Role must be in VALID_ROLES."""
        clean_user = username.strip().lower()
        clean_email = email.strip().lower()
        clean_role = role.strip().lower()
        if clean_role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{clean_role}'. Must be one of {VALID_ROLES}")

        pwd_hash = hash_password(password)
        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        now_str = self._now()

        with get_db_connection(self.db_path) as conn:
            # Check unique username and email
            existing = conn.execute(
                "SELECT username, email FROM users WHERE username = ? OR email = ?",
                (clean_user, clean_email),
            ).fetchone()
            if existing:
                if existing["username"] == clean_user:
                    raise ValueError(f"Username '{clean_user}' is already registered.")
                else:
                    raise ValueError(f"Email '{clean_email}' is already registered.")

            conn.execute(
                """
                INSERT INTO users (
                    user_id, username, email, password_hash, role,
                    is_active, provider_id, role_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    user_id,
                    clean_user,
                    clean_email,
                    pwd_hash,
                    clean_role,
                    1 if is_active else 0,
                    provider_id.strip() if provider_id else None,
                    now_str,
                    now_str,
                ),
            )
            conn.commit()

        return UserRecord(
            user_id=user_id,
            username=clean_user,
            email=clean_email,
            role=clean_role,
            is_active=is_active,
            provider_id=provider_id.strip() if provider_id else None,
            role_version=1,
            created_at=now_str,
            updated_at=now_str,
        )

    def authenticate_user(self, username_or_email: str, password: str) -> Optional[UserRecord]:
        """Verifies credentials with Argon2id and returns UserRecord if valid and active."""
        clean = username_or_email.strip().lower()
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (clean, clean),
            ).fetchone()
            if not row:
                return None

            if not verify_password(password, row["password_hash"]):
                return None

            return UserRecord(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                role=row["role"],
                is_active=bool(row["is_active"]),
                provider_id=row["provider_id"],
                role_version=int(row["role_version"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        """Looks up user by user_id."""
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id.strip(),)).fetchone()
            if not row:
                return None
            return UserRecord(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                role=row["role"],
                is_active=bool(row["is_active"]),
                provider_id=row["provider_id"],
                role_version=int(row["role_version"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def get_user_by_username(self, username: str) -> Optional[UserRecord]:
        """Looks up user by username."""
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),)).fetchone()
            if not row:
                return None
            return UserRecord(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                role=row["role"],
                is_active=bool(row["is_active"]),
                provider_id=row["provider_id"],
                role_version=int(row["role_version"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_users(self) -> List[UserRecord]:
        """Lists all user accounts."""
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
            return [
                UserRecord(
                    user_id=r["user_id"],
                    username=r["username"],
                    email=r["email"],
                    role=r["role"],
                    is_active=bool(r["is_active"]),
                    provider_id=r["provider_id"],
                    role_version=int(r["role_version"]),
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ]

    def update_user_role(
        self,
        user_id: str,
        new_role: str,
        provider_id: Optional[str] = None,
    ) -> UserRecord:
        """
        Updates user role and increments role_version to immediately invalidate older JWTs.
        """
        clean_role = new_role.strip().lower()
        if clean_role not in VALID_ROLES:
            raise ValueError(f"Invalid role '{clean_role}'. Must be one of {VALID_ROLES}")

        now_str = self._now()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE users SET
                    role = ?,
                    provider_id = ?,
                    role_version = role_version + 1,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    clean_role,
                    provider_id.strip() if provider_id else None,
                    now_str,
                    user_id.strip(),
                ),
            )
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError(f"User with ID '{user_id}' not found.")

        return self.get_user_by_id(user_id)

    def update_user_status(self, user_id: str, is_active: bool) -> UserRecord:
        """Activates or deactivates an account and increments role_version."""
        now_str = self._now()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE users SET
                    is_active = ?,
                    role_version = role_version + 1,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (1 if is_active else 0, now_str, user_id.strip()),
            )
            conn.commit()
            if cursor.rowcount == 0:
                raise ValueError(f"User with ID '{user_id}' not found.")

        return self.get_user_by_id(user_id)

    set_user_active_status = update_user_status

    def revoke_token(
        self,
        jti: str,
        user_id: str,
        expires_at: str,
        reason: str = "logout",
    ) -> None:
        """Records a token's jti in the revoked_tokens blacklist."""
        now_str = self._now()
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO revoked_tokens (
                    jti, user_id, expires_at, revoked_at, reason
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (jti.strip(), user_id.strip(), expires_at, now_str, reason),
            )
            conn.commit()

    def is_token_revoked(self, jti: str) -> bool:
        """Checks if a jti has been revoked."""
        if not jti or not jti.strip():
            return True
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT jti FROM revoked_tokens WHERE jti = ?",
                (jti.strip(),),
            ).fetchone()
            return bool(row)

    def clean_expired_revocations(self) -> int:
        """Housekeeping to remove expired tokens from the blacklist."""
        now_str = self._now()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_str,))
            conn.commit()
            return cursor.rowcount


# ---------------------------------------------------------------------------
# FastAPI Authentication & Authorization Dependencies
# ---------------------------------------------------------------------------

def get_user_manager(request: Request) -> UserManager:
    """Dependency providing a configured UserManager."""
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    if not hasattr(request.app.state, "user_manager") or getattr(request.app.state.user_manager, "db_path", None) != settings.db_path:
        request.app.state.user_manager = UserManager(settings)
    return request.app.state.user_manager


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    expo_jwt_cookie: Optional[str] = Cookie(None, alias="expo_jwt"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
    expo_csrf_cookie: Optional[str] = Cookie(None, alias="expo_csrf"),
) -> UserRecord:
    """
    Resolves and verifies the authenticated user from a signed JWT.
    Supports Authorization: Bearer <token> or HttpOnly Cookie expo_jwt.
    Validates CSRF token on state-changing requests when authenticated via cookie.
    Validates token signature, expiration, issuer, audience, revocation, active account, and role_version.
    """
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    user_manager = get_user_manager(request)

    auth_header = authorization if isinstance(authorization, str) else request.headers.get("authorization")
    jwt_cookie = expo_jwt_cookie if isinstance(expo_jwt_cookie, str) else request.cookies.get("expo_jwt")
    csrf_hdr = x_csrf_token if isinstance(x_csrf_token, str) else request.headers.get("x-csrf-token")
    csrf_ck = expo_csrf_cookie if isinstance(expo_csrf_cookie, str) else request.cookies.get("expo_csrf")

    token = None
    is_cookie_auth = False

    if auth_header and auth_header.strip().lower().startswith("bearer "):
        token = auth_header.strip()[7:].strip()
    elif jwt_cookie and jwt_cookie.strip():
        token = jwt_cookie.strip()
        is_cookie_auth = True

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # CSRF protection for cookie-based state mutations
    if is_cookie_auth and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if not csrf_hdr or not csrf_ck or csrf_hdr.strip() != csrf_ck.strip():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Invalid or missing CSRF token for browser session.",
            )

    # Decode and verify JWT
    try:
        payload = decode_access_token(token, settings)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid token issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid token audience.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized: Invalid token ({str(exc)}).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    user_id = payload.get("sub")
    token_role_version = payload.get("role_version", 1)

    # Check revocation blacklist
    if user_manager.is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify user exists in SQLite and check active state and role_version
    user = user_manager.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Account has been deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.role_version != token_role_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Account privileges or role have changed. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_optional_user(
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    expo_jwt_cookie: Optional[str] = Cookie(None, alias="expo_jwt"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
    expo_csrf_cookie: Optional[str] = Cookie(None, alias="expo_csrf"),
) -> Optional[UserRecord]:
    """Gracefully resolves authenticated user if valid token present, otherwise None."""
    if hasattr(request.state, "current_user") and request.state.current_user:
        return request.state.current_user
    try:
        user = get_current_user(
            request=request,
            authorization=authorization,
            expo_jwt_cookie=expo_jwt_cookie,
            x_csrf_token=x_csrf_token,
            expo_csrf_cookie=expo_csrf_cookie,
        )
        request.state.current_user = user
        return user
    except Exception:
        return None


def require_roles(*allowed_roles: str):
    """
    Factory creating a FastAPI dependency that verifies the authenticated user possesses
    one of the allowed roles. Returns 403 Forbidden on role mismatch.
    """
    clean_allowed = {r.strip().lower() for r in allowed_roles}

    def role_checker(current_user: UserRecord = Depends(get_current_user)) -> UserRecord:
        if current_user.role not in clean_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Account role '{current_user.role}' lacks permission for this operation. Required: {', '.join(sorted(clean_allowed))}.",
            )
        return current_user

    return role_checker


# Convenient role-specific dependencies
require_admin = require_roles(Role.ADMIN.value)
require_provider = require_roles(Role.PROVIDER.value)
require_consumer = require_roles(Role.CONSUMER.value)
require_provider_or_admin = require_roles(Role.PROVIDER.value, Role.ADMIN.value)
require_consumer_or_admin = require_roles(Role.CONSUMER.value, Role.ADMIN.value)


# ---------------------------------------------------------------------------
# Resource Ownership Authorization Helpers
# ---------------------------------------------------------------------------

def check_file_ownership(user: UserRecord, file_owner_id: str) -> None:
    """
    Ensures that a consumer can only access/delete/download their own files.
    Administrators are permitted to inspect metadata for cluster auditing,
    but cannot view plaintext contents or encryption keys.
    """
    if user.role == Role.ADMIN.value:
        return
    if user.role == Role.CONSUMER.value:
        if user.user_id != file_owner_id and user.username != file_owner_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You do not have permission to access files owned by another user.",
            )
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: Providers are not authorized to access consumer files.",
    )


def check_provider_ownership(user: UserRecord, target_provider_id: str) -> None:
    """
    Ensures that a provider user can only manage their own storage nodes and telemetry.
    Administrators have cluster-wide operational access.
    """
    if user.role == Role.ADMIN.value:
        return

    if user.role == Role.PROVIDER.value:
        if not user.provider_id or user.provider_id.strip() != target_provider_id.strip():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: You are not authorized to manage resources for provider '{target_provider_id}'.",
            )
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: Consumer accounts cannot manage storage provider infrastructure.",
    )
