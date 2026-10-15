"""
FastAPI Router for Human User Authentication & RBAC Management (/auth).

Endpoints:
- POST /auth/register: Public consumer registration.
- POST /auth/login: User login, Argon2id verification, JWT issuance, and secure cookie setting.
- GET  /auth/me: Retrieve current authenticated user profile and role.
- POST /auth/logout: Revoke current JWT (jti blacklist) and clear cookies.
- GET  /auth/admin/users: [ADMIN] List all registered user accounts.
- POST /auth/admin/users/{user_id}/role: [ADMIN] Update user role & provider mapping (role version incremented).
- POST /auth/admin/users/{user_id}/status: [ADMIN] Activate or deactivate user account.
"""

from __future__ import annotations

import secrets
from typing import Annotated, Dict, List, Optional
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.user_auth import (
    Role,
    UserRecord,
    UserCreate,
    UserLogin,
    TokenResponse,
    RoleUpdateRequest,
    StatusUpdateRequest,
    UserListResponse,
    UserManager,
    get_user_manager,
    get_current_user,
    require_admin,
    create_access_token,
    decode_access_token,
)

auth_router = APIRouter(prefix="/auth", tags=["User Authentication & RBAC"])


@auth_router.post(
    "/register",
    response_model=UserRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Register Consumer Account",
    description="Public registration for human consumer accounts. Assigns 'consumer' role by default.",
)
def register(
    data: UserCreate,
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
) -> UserRecord:
    try:
        # Public registration is strictly restricted to consumer role
        user = user_manager.create_user(
            username=data.username,
            email=data.email,
            password=data.password,
            role=Role.CONSUMER.value,
            provider_id=None,
            is_active=True,
        )
        return user
    except ValueError as exc:
        err_msg = str(exc)
        if "already registered" in err_msg.lower() or "already exists" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=err_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg,
        )


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login & Obtain JWT",
    description="Authenticates with username/email and password, returning a signed JWT access token and setting HttpOnly cookie.",
)
def login(
    data: UserLogin,
    response: Response,
    request: Request,
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
) -> TokenResponse:
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )

    user = user_manager.authenticate_user(data.username_or_email, data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username, email, or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account has been deactivated. Please contact an administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Issue JWT access token
    token, jti, exp_datetime = create_access_token(user, settings, return_full=True)
    csrf_token = secrets.token_urlsafe(32)
    expires_in_seconds = int(settings.jwt_access_token_expire_minutes * 60)

    # Set secure HttpOnly cookie
    response.set_cookie(
        key="expo_jwt",
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=expires_in_seconds,
        path="/",
    )

    # Set client-readable CSRF cookie
    response.set_cookie(
        key="expo_csrf",
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=expires_in_seconds,
        path="/",
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=expires_in_seconds,
        csrf_token=csrf_token,
        user=user,
    )


@auth_router.get(
    "/me",
    response_model=UserRecord,
    summary="Get Current User Profile",
    description="Returns the profile and verified role of the currently authenticated human user.",
)
def get_me(
    current_user: Annotated[UserRecord, Depends(get_current_user)],
) -> UserRecord:
    return current_user


@auth_router.post(
    "/logout",
    summary="Logout & Revoke JWT",
    description="Revokes the current JWT via immediate jti blacklisting and clears authentication cookies.",
)
def logout(
    response: Response,
    request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    expo_jwt_cookie: Optional[str] = Cookie(None, alias="expo_jwt"),
    user_manager: UserManager = Depends(get_user_manager),
) -> Dict[str, str]:
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )

    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif expo_jwt_cookie and expo_jwt_cookie.strip():
        token = expo_jwt_cookie.strip()

    if token:
        try:
            payload = decode_access_token(token, settings)
            jti = payload.get("jti")
            user_id = payload.get("sub")
            exp = payload.get("exp")
            if jti and user_id and exp:
                from datetime import datetime, timezone
                exp_str = datetime.fromtimestamp(exp, timezone.utc).isoformat()
                user_manager.revoke_token(jti, user_id, exp_str, reason="user_logout")
        except Exception as exc:
            logger.debug("Non-fatal token parse error during logout: %s", exc)

    # Clear cookies
    response.delete_cookie(key="expo_jwt", path="/")
    response.delete_cookie(key="expo_csrf", path="/")

    return {"status": "logged_out", "message": "Session invalidated successfully."}


# ---------------------------------------------------------------------------
# Admin Management Endpoints
# ---------------------------------------------------------------------------

@auth_router.get(
    "/admin/users",
    response_model=UserListResponse,
    dependencies=[Depends(require_admin)],
    summary="[Admin] List All User Accounts",
)
def admin_list_users(
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
) -> UserListResponse:
    users = user_manager.list_users()
    return UserListResponse(users=users, count=len(users))


@auth_router.post(
    "/admin/users/{user_id}/role",
    response_model=UserRecord,
    dependencies=[Depends(require_admin)],
    summary="[Admin] Update User Role & Provider Binding",
)
def admin_update_user_role(
    user_id: str,
    data: RoleUpdateRequest,
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
) -> UserRecord:
    try:
        updated = user_manager.update_user_role(
            user_id=user_id,
            new_role=data.role,
            provider_id=data.provider_id,
        )
        return updated
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@auth_router.post(
    "/admin/users/{user_id}/status",
    response_model=UserRecord,
    dependencies=[Depends(require_admin)],
    summary="[Admin] Activate or Deactivate Account",
)
def admin_update_user_status(
    user_id: str,
    data: StatusUpdateRequest,
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
) -> UserRecord:
    try:
        updated = user_manager.update_user_status(
            user_id=user_id,
            is_active=data.is_active,
        )
        return updated
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
