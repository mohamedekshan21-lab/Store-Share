"""
Authentication, Account Identity, and Session Management Router (Phase 10A).

Provides:
- User registration with Argon2id password hashing (/auth/register).
- Secure login and server-side session issuance (/auth/login).
- Session revocation and logout (/auth/logout).
- Current authenticated account profile retrieval (/auth/me).
"""

from __future__ import annotations

import logging
from typing import Optional, Annotated
from fastapi import APIRouter, Depends, HTTPException, Header, Cookie, Query, Request, Response, status

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.main import get_settings
from coordinator.app.models import (
    RegisterAccountRequest,
    LoginAccountRequest,
    AccountResponse,
    LoginSuccessResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
    ResendVerificationRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    SendSmsCodeRequest,
    VerifySmsCodeRequest,
    ActionStatusResponse,
)
from coordinator.app.auth import (
    AccountManager,
    AccountRecord,
    AccountSessionRecord,
    RateLimitExceededError,
)

logger = logging.getLogger("expo_auth_router")

auth_router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])


def get_client_ip(request: Request) -> Optional[str]:
    """Resolves client IP for rate limiting and audit logging."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_account_manager(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> AccountManager:
    """Dependency provider for AccountManager."""
    if not hasattr(request.app.state, "account_manager") or getattr(request.app.state.account_manager, "db_path", None) != settings.db_path:
        request.app.state.account_manager = AccountManager(settings)
    return request.app.state.account_manager


def get_current_account_session(
    request: Request,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
) -> AccountSessionRecord:
    """
    Dependency that resolves the active user account session from Bearer token,
    X-Auth-Token header, or secure HTTP-only browser cookie.
    Validates CSRF tokens on mutating requests authenticated via cookies.
    """
    token = None
    is_cookie = False

    if x_auth_token and x_auth_token.strip():
        token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif session_cookie and session_cookie.strip():
        token = session_cookie.strip()
        is_cookie = True

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session = account_manager.get_session(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or expired session.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # CSRF validation for cookie-authenticated mutating requests
    if is_cookie and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if not x_csrf_token or x_csrf_token.strip() != session.csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Invalid or missing CSRF token.",
            )

    return session


def get_current_account(
    session: Annotated[AccountSessionRecord, Depends(get_current_account_session)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
) -> AccountRecord:
    """Dependency that resolves the authenticated AccountRecord."""
    account = account_manager.get_account(session.account_id)
    if not account or account.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Account is inactive or not found.",
        )
    return account


def require_verified_account(
    account: Annotated[AccountRecord, Depends(get_current_account)],
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> AccountRecord:
    """
    Dependency enforcing the documented account verification policy.
    Blocks unverified accounts from mutating/quota/provider operations when require_email_verification is active.
    """
    if getattr(settings, "require_email_verification", False):
        if not account.email_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email verification required. Please verify your email address to perform this action.",
            )
    return account


def build_account_response(account: AccountRecord) -> AccountResponse:
    """Constructs a public AccountResponse payload."""
    return AccountResponse(
        account_id=account.account_id,
        email=account.email,
        role=account.role,
        capabilities=account.capabilities,
        status=account.status,
        provider_id=account.provider_id,
        email_verified=account.email_verified,
        email_verified_at=account.email_verified_at,
        phone_number=account.phone_number,
        phone_verified=account.phone_verified,
        phone_verified_at=account.phone_verified_at,
        created_at=account.created_at,
        updated_at=account.updated_at,
    )


@auth_router.post(
    "/register",
    response_model=AccountResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a New Account",
)
def register_account(
    req: RegisterAccountRequest,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Registers a new consumer or provider account with Argon2id password hashing.
    Prevents public registration of administrator accounts.
    Resists enumeration attacks by returning generic error if account already exists.
    """
    requested_role = getattr(req, "role", None)
    target_role = "provider" if requested_role and str(requested_role).strip().lower() == "provider" else "consumer"
    try:
        acc = account_manager.register_account(
            email=req.email,
            password=req.password,
            role=target_role,
            provider_id=req.provider_id,
        )
        return build_account_response(acc)
    except ValueError as e:
        err_msg = str(e)
        if "already exists" in err_msg.lower():
            err_msg = "Unable to register account with the provided details."
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg,
        )


@auth_router.get(
    "/csrf",
    summary="Get Active Session CSRF Token",
)
def get_session_csrf(
    session: Annotated[AccountSessionRecord, Depends(get_current_account_session)],
):
    """Returns the CSRF token associated with the active browser session."""
    return {"csrf_token": session.csrf_token, "account_id": session.account_id}


@auth_router.post(
    "/login",
    response_model=LoginSuccessResponse,
    summary="Authenticate Account and Issue Session",
)
def login_account(
    req: LoginAccountRequest,
    response: Response,
    request: Request,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Authenticates account credentials against stored Argon2id password hashes.
    Issues a server-side session hash and returns an opaque session token and CSRF token.
    Sets secure HTTP-only session cookie for web clients.
    """
    account = account_manager.authenticate(req.email, req.password)
    if not account:
        # Generic error message to prevent email enumeration or credential oracle
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if account.status in ("suspended", "disabled", "inactive"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Account is {account.status}. Access denied.",
        )

    session = account_manager.create_session(account)

    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    cookie_secure = settings.cookie_secure or (settings.environment == "production")

    response.set_cookie(
        key="expo_session",
        value=session.session_id,
        httponly=True,
        samesite="lax",
        secure=cookie_secure,
        path="/",
        max_age=86400,
    )

    return LoginSuccessResponse(
        account=build_account_response(account),
        token=session.session_id,
        csrf_token=session.csrf_token,
        expires_at=session.expires_at,
    )


@auth_router.post(
    "/logout",
    summary="Revoke Session and Logout",
)
def logout_account(
    response: Response,
    session: Annotated[AccountSessionRecord, Depends(get_current_account_session)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """Revokes the active session and clears the browser session cookie."""
    account_manager.revoke_session(session.session_id)
    response.delete_cookie(key="expo_session", path="/")
    return {"detail": "Logged out successfully."}


@auth_router.get(
    "/me",
    response_model=AccountResponse,
    summary="Get Current Authenticated Account",
)
def get_me(
    account: Annotated[AccountRecord, Depends(get_current_account)],
):
    """Returns profile metadata and role for the currently authenticated account."""
    return build_account_response(account)


# =============================================================================
# Phase 10E: Email Verification Endpoints
# =============================================================================

@auth_router.post(
    "/verify-email",
    response_model=VerifyEmailResponse,
    summary="Redeem Email Verification Token (POST)",
)
def verify_email_post(
    req: VerifyEmailRequest,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Redeems an email verification token submitted in the request body.
    Enforces single-use, non-expired, and updates account verification status.
    """
    success, message, acc = account_manager.verify_email_token(req.token)
    if not success or not acc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return VerifyEmailResponse(
        detail=message,
        email_verified=True,
        email=acc.email,
        account_id=acc.account_id,
    )


@auth_router.get(
    "/verify-email",
    response_model=VerifyEmailResponse,
    summary="Redeem Email Verification Token (GET)",
)
def verify_email_get(
    token: Annotated[str, Query(..., min_length=16, description="Email verification token")],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """Redeems an email verification token provided in query parameters."""
    success, message, acc = account_manager.verify_email_token(token)
    if not success or not acc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return VerifyEmailResponse(
        detail=message,
        email_verified=True,
        email=acc.email,
        account_id=acc.account_id,
    )


@auth_router.post(
    "/resend-verification",
    response_model=ActionStatusResponse,
    summary="Resend Email Verification Link",
)
def resend_verification(
    req: ResendVerificationRequest,
    request: Request,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Requests a fresh email verification link with cooldown and rate-limit enforcement.
    Avoids account enumeration by returning identical success responses.
    """
    client_ip = get_client_ip(request)
    try:
        account_manager.request_email_verification(req.email, client_ip)
        return ActionStatusResponse(
            detail="If an unverified account exists for this email address, a verification link has been sent.",
            success=True,
        )
    except RateLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers={"Retry-After": str(e.retry_after_seconds)},
        )


# =============================================================================
# Phase 10E: Password Reset and Account Recovery Endpoints
# =============================================================================

@auth_router.post(
    "/password-reset/request",
    response_model=ActionStatusResponse,
    summary="Request Password Reset Link",
)
@auth_router.post(
    "/forgot-password",
    response_model=ActionStatusResponse,
    summary="Request Password Reset Link (Alias)",
)
def request_password_reset(
    req: ForgotPasswordRequest,
    request: Request,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Initiates a password reset request.
    Does not disclose whether the account exists, preventing account enumeration.
    Enforces cooldown and hourly rate limits.
    """
    client_ip = get_client_ip(request)
    try:
        account_manager.request_password_reset(req.email, client_ip)
        return ActionStatusResponse(
            detail="If an account exists with this email address, password reset instructions have been sent.",
            success=True,
        )
    except RateLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers={"Retry-After": str(e.retry_after_seconds)},
        )


@auth_router.post(
    "/password-reset/confirm",
    response_model=ActionStatusResponse,
    summary="Confirm Password Reset",
)
@auth_router.post(
    "/reset-password",
    response_model=ActionStatusResponse,
    summary="Confirm Password Reset (Alias)",
)
def confirm_password_reset(
    req: ResetPasswordRequest,
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Updates the account password using Argon2id and revokes all active sessions.
    Validates single-use token and rejects expired, reused, or malformed tokens.
    """
    success, message, _ = account_manager.confirm_password_reset(req.token, req.new_password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return ActionStatusResponse(detail=message, success=True)


# =============================================================================
# Phase 10E: SMS Verification Endpoints
# =============================================================================

@auth_router.post(
    "/sms/send-code",
    response_model=ActionStatusResponse,
    summary="Send SMS Verification Code",
)
def send_sms_code(
    req: SendSmsCodeRequest,
    request: Request,
    account: Annotated[AccountRecord, Depends(get_current_account)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Issues a short-lived, single-use 6-digit SMS verification code to an authenticated user.
    Fails safely when SMS provider credentials are not configured.
    """
    client_ip = get_client_ip(request)
    try:
        success, message, _ = account_manager.request_phone_verification(
            account_id=account.account_id,
            phone_number=req.phone_number,
            ip_address=client_ip,
        )
        if not success:
            # Safe failure when provider credentials are not configured
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=message,
            )
        return ActionStatusResponse(detail=message, success=True)
    except RateLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers={"Retry-After": str(e.retry_after_seconds)},
        )


@auth_router.post(
    "/sms/verify-code",
    response_model=ActionStatusResponse,
    summary="Verify SMS Verification Code",
)
def verify_sms_code(
    req: VerifySmsCodeRequest,
    account: Annotated[AccountRecord, Depends(get_current_account)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
):
    """
    Validates the 6-digit SMS code. Enforces attempt limits and burns code on exhaustion.
    """
    success, message = account_manager.verify_phone_code(
        account_id=account.account_id,
        phone_number=req.phone_number,
        raw_code=req.code,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    return ActionStatusResponse(detail=message, success=True)

