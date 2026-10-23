"""
FastAPI application for Expo Coordinator Service (Phase 2B).
Provides Node Registry management, heartbeat tracking, capacity monitoring,
smart node selection, and Internet connectivity node discovery.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any, Dict, List, Optional
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Header,
    Query,
    Request,
    BackgroundTasks,
    Cookie,
    status,
)
from fastapi.responses import JSONResponse

from coordinator.app import __version__
from coordinator.app.config import get_coordinator_settings, CoordinatorSettings
from coordinator.app.models import (
    HealthResponse,
    NodeRegisterRequest,
    NodeHeartbeatRequest,
    NodeRecord,
    NodeListResponse,
    NodeSelectionRequest,
    NodeConnectivityResponse,
    RepairJobRecord,
    RepairJobListResponse,
    RegisterFileRequest,
    FileCatalogRecord,
    FileCatalogListResponse,
    RequestUploadCapabilitiesRequest,
    RequestUploadCapabilitiesResponse,
    RequestDownloadCapabilitiesRequest,
    RequestDownloadCapabilitiesResponse,
    AccountQuotaResponse,
    ReserveQuotaRequest,
    ReserveQuotaResponse,
    ReleaseQuotaRequest,
    ReleaseQuotaResponse,
    UpdateAccountQuotaRequest,
    UpdateAccountQuotaResponse,
    FileStorageStatusResponse,
)
from coordinator.app.node_registry import (
    NodeRegistry,
    NodeNotFoundError,
    InvalidCapacityError,
)
from coordinator.app.file_catalog import (
    FileCatalog,
    FileCatalogError,
    FileNotFoundError as CatalogFileNotFoundError,
)
from coordinator.app.quota_manager import (
    QuotaManager,
    QuotaError,
    QuotaExceededError,
)
from coordinator.app.auth import AccountManager
from coordinator.app.reconciliation import ReconciliationService
from coordinator.app.database import get_db_connection

app = FastAPI(
    title="Expo Coordinator API",
    version=__version__,
    description="Control and management service for Expo distributed storage node registry and discovery.",
)

# CORS Middleware (allows decoupled frontend development on ports 3000, 5173, etc.)
from starlette.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforces strict security headers against clickjacking, sniffing, and XSS."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if "Content-Security-Policy" not in response.headers:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
    return response


def get_settings(request: Request) -> CoordinatorSettings:
    """Dependency provider for CoordinatorSettings instance."""
    if hasattr(request.app.state, "settings"):
        return request.app.state.settings
    return get_coordinator_settings()


def get_registry(request: Request) -> NodeRegistry:
    """Dependency provider for NodeRegistry instance."""
    settings = get_settings(request)
    if not hasattr(request.app.state, "registry") or getattr(request.app.state.registry, "db_path", None) != settings.db_path:
        request.app.state.registry = NodeRegistry(settings)
    return request.app.state.registry


def get_settings_from_state(app_state: Any) -> CoordinatorSettings:
    """Resolves CoordinatorSettings directly from app state (for non-Request contexts, e.g. WebSocket)."""
    if hasattr(app_state, "settings"):
        return app_state.settings
    return get_coordinator_settings()


def get_registry_from_state(app_state: Any) -> NodeRegistry:
    """Resolves the NodeRegistry directly from app state (for non-Request contexts, e.g. WebSocket)."""
    settings = app_state.settings if hasattr(app_state, "settings") else get_coordinator_settings()
    if not hasattr(app_state, "registry") or getattr(app_state.registry, "db_path", None) != settings.db_path:
        app_state.registry = NodeRegistry(settings)
    return app_state.registry


def get_catalog(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)]
) -> FileCatalog:
    """Dependency provider for FileCatalog instance."""
    if not hasattr(request.app.state, "catalog") or getattr(request.app.state.catalog, "db_path", None) != settings.db_path:
        request.app.state.catalog = FileCatalog(settings)
    return request.app.state.catalog


def get_quota_manager(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)]
) -> QuotaManager:
    """Dependency provider for QuotaManager instance."""
    if not hasattr(request.app.state, "quota_manager") or getattr(request.app.state.quota_manager, "db_path", None) != settings.db_path:
        request.app.state.quota_manager = QuotaManager(settings)
        request.app.state.quota_manager.recover_durable_reservations()
    return request.app.state.quota_manager


def get_reconciliation_service(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)]
) -> ReconciliationService:
    """Dependency provider for ReconciliationService."""
    if not hasattr(request.app.state, "reconciliation_service") or getattr(request.app.state.reconciliation_service, "db_path", None) != settings.db_path:
        request.app.state.reconciliation_service = ReconciliationService(settings)
    return request.app.state.reconciliation_service


def get_metering_service(
    request: Request,
) -> MeteringService:
    """Dependency provider for MeteringService."""
    from coordinator.app.metering import MeteringService
    settings = get_settings(request)
    if not hasattr(request.app.state, "metering_service") or getattr(request.app.state.metering_service, "db_path", None) != settings.db_path:
        request.app.state.metering_service = MeteringService(settings)
    return request.app.state.metering_service


def get_metering_service_from_state(app_state: Any) -> MeteringService:
    """Resolves MeteringService from app state directly."""
    from coordinator.app.metering import MeteringService
    settings = get_settings_from_state(app_state)
    if not hasattr(app_state, "metering_service") or getattr(app_state.metering_service, "db_path", None) != settings.db_path:
        app_state.metering_service = MeteringService(settings)
    return app_state.metering_service




def get_account_manager(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> AccountManager:
    """Dependency provider for AccountManager instance."""
    if not hasattr(request.app.state, "account_manager") or getattr(request.app.state.account_manager, "db_path", None) != settings.db_path:
        request.app.state.account_manager = AccountManager(settings)
        if settings.admin_email and settings.admin_password:
            try:
                request.app.state.account_manager.bootstrap_admin(settings.admin_email, settings.admin_password)
            except Exception as e:
                logger.error("Failed to bootstrap administrator: %s", e)
    return request.app.state.account_manager


def verify_coordinator_auth(
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    valid_tokens = [t.strip() for t in (settings.auth_token, settings.admin_auth_token) if t and t.strip()]
    if not valid_tokens:
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Production coordinator authentication is not configured.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return "default_user"

    client_token = None
    if x_auth_token:
        client_token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        client_token = authorization[7:].strip()

    if not client_token or client_token not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing coordinator authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return client_token


def verify_registration_auth(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
) -> tuple[str, Optional[str], bool]:
    """
    Validates authentication for Storage Node registration.
    Supports coordinator tokens, administrative tokens, and authenticated provider sessions.
    Returns: (principal_id, bound_provider_id, is_admin)
    """
    token = None
    if x_auth_token and x_auth_token.strip():
        token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif session_cookie and session_cookie.strip():
        token = session_cookie.strip()

    valid_admin = settings.admin_auth_token.strip() if settings.admin_auth_token else None
    valid_coord = settings.auth_token.strip() if settings.auth_token else None

    # 1. Admin auth token check
    if valid_admin and token == valid_admin:
        return ("admin", None, True)

    # 2. Coordinator auth token check
    if valid_coord and token == valid_coord:
        return ("coordinator", None, False)

    # 3. Account session check
    if token:
        sess = account_manager.get_session(token)
        if sess:
            act = account_manager.get_account(sess.account_id)
            if not act or act.status in ("suspended", "disabled", "inactive"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account '{sess.account_id}' is inactive or suspended. Registration denied.",
                )
            if not sess.is_admin:
                with get_db_connection(settings.db_path) as conn:
                    onb = conn.execute(
                        "SELECT is_verified, status FROM provider_onboarding WHERE account_id = ? OR provider_id = ?",
                        (sess.account_id, sess.provider_id or ""),
                    ).fetchone()
                    if not onb or not onb["is_verified"] or onb["status"] != "active":
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Provider onboarding and terms agreement required before registering storage nodes.",
                        )
            prov_id = sess.provider_id or (f"provider-{sess.account_id}" if not sess.is_admin else "admin_provider")
            return (sess.account_id, prov_id, sess.is_admin)

        # 4. Credential manager check
        from coordinator.app.auth import CredentialManager
        cred_mgr = CredentialManager(settings)
        cred = cred_mgr.verify_credential(token)
        if cred:
            return (cred.principal_id, cred.provider_id, cred.is_admin)

    # If auth_token or admin_auth_token is configured on coordinator,
    # any missing or non-matching token must raise 401:
    if valid_coord or valid_admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing coordinator authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # If NO auth tokens are configured:
    if not token:
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Missing authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return ("default_user", None, False)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid coordinator or provider authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_authenticated_consumer(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
) -> str:
    """
    Resolves the authenticated consumer account UUID for catalog and file operations.
    Enforces that consumer file ownership is strictly bound to account UUIDs.
    Never accepts arbitrary user-supplied owner IDs.
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

    if token:
        # 1. Check account session (Account UUID)
        acc_session = account_manager.get_session(token)
        if acc_session:
            if is_cookie and request.method in ("POST", "PUT", "DELETE", "PATCH"):
                if not x_csrf_token or x_csrf_token.strip() != acc_session.csrf_token:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Forbidden: Invalid or missing CSRF token.",
                    )
            if getattr(settings, "require_email_verification", False) and request.method in ("POST", "PUT", "DELETE", "PATCH"):
                acc = account_manager.get_account(acc_session.account_id)
                if acc and not acc.email_verified:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Email verification required. Please verify your email address to perform this action.",
                    )
            return acc_session.account_id

        # 2. Check legacy coordinator token in non-production
        valid_tokens = [t.strip() for t in (settings.auth_token, settings.admin_auth_token) if t and t.strip()]
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Consumer file operations require an authenticated account session.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not valid_tokens or token in valid_tokens:
            return token

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid coordinator authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # No token provided
    if settings.environment == "production" or request.url.path.startswith("/consumer"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in to access consumer file management." if request.url.path.startswith("/consumer") else "Unauthorized: Production coordinator authentication is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    valid_tokens = [t.strip() for t in (settings.auth_token, settings.admin_auth_token) if t and t.strip()]
    if not valid_tokens:
        return "default_user"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid or missing coordinator authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_admin_auth(
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    account_manager: Annotated[AccountManager, Depends(get_account_manager)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
) -> str:
    """Verifies that the caller has explicit administrator privileges."""
    token = None
    if x_auth_token and x_auth_token.strip():
        token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    elif session_cookie and session_cookie.strip():
        token = session_cookie.strip()

    valid_admin = settings.admin_auth_token.strip() if settings.admin_auth_token else None
    if valid_admin and token == valid_admin:
        return "admin"

    if token:
        sess = account_manager.get_session(token)
        if sess and sess.is_admin:
            return sess.account_id

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden: Explicit administrator privileges required.",
    )


# Custom Exception Handlers
@app.exception_handler(NodeNotFoundError)
async def node_not_found_handler(request: Request, exc: NodeNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidCapacityError)
async def invalid_capacity_handler(request: Request, exc: InvalidCapacityError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(FileCatalogError)
async def file_catalog_error_handler(request: Request, exc: FileCatalogError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


# Endpoints
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Coordinator Health Liveness Check",
)
def health() -> HealthResponse:
    """Returns the operational status of the Coordinator Service (Public endpoint)."""
    return HealthResponse(status="online")


@app.post(
    "/nodes/register",
    response_model=NodeRecord,
    status_code=status.HTTP_200_OK,
    tags=["Registry"],
    summary="Register or Update a Storage Node",
)
def register_node(
    data: NodeRegisterRequest,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    auth_info: tuple[str, Optional[str], bool] = Depends(verify_registration_auth),
) -> NodeRecord:
    """Registers a new Storage Node or updates an existing registered node (Idempotent)."""
    principal_id, bound_provider_id, is_admin = auth_info

    # If bound to a provider account, prevent spoofing
    if bound_provider_id and not is_admin:
        setattr(data, "_from_account_session", True)
        if data.provider_id and data.provider_id.strip() and data.provider_id.strip() != bound_provider_id and data.provider_id != "default_provider":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Cannot register node for another provider '{data.provider_id}'.",
            )
        data.provider_id = bound_provider_id
    elif bound_provider_id and is_admin:
        setattr(data, "_from_account_session", True)
    elif not bound_provider_id and data.provider_id and data.provider_id != "default_provider":
        # Check that provider account is not suspended/disabled
        with get_db_connection(settings.db_path) as conn:
            act = conn.execute(
                "SELECT status FROM accounts WHERE provider_id = ? OR account_id = ?",
                (data.provider_id, data.provider_id),
            ).fetchone()
            if act and act["status"] in ("suspended", "disabled", "inactive"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Provider account '{data.provider_id}' is {act['status']}. Registration denied.",
                )

    # Check ownership of existing node to prevent claiming another provider's node identity
    clean_nid = data.node_id.strip() if data.node_id else ""
    if clean_nid and not is_admin:
        existing_node = registry.get_node(clean_nid)
        if existing_node and existing_node.provider_id and existing_node.provider_id != "default_provider":
            effective_caller_provider = bound_provider_id or data.provider_id
            if effective_caller_provider and existing_node.provider_id != effective_caller_provider:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied: Node '{clean_nid}' is already registered to provider '{existing_node.provider_id}'.",
                )

    try:
        return registry.register_node(data)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@app.get(
    "/nodes",
    response_model=NodeListResponse,
    tags=["Discovery"],
    summary="List Registered Storage Nodes",
)
def list_nodes(
    status_param: Optional[str] = Query(None, alias="status", description="Filter nodes by status ('online', 'offline', etc.)"),
    connectivity_mode: Optional[str] = Query(None, alias="connectivity_mode", description="Filter by connectivity capability ('LAN', 'DIRECT', 'RELAY')"),
    min_available_bytes: Optional[int] = Query(None, alias="min_available_bytes", description="Filter by minimum available capacity in bytes"),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeListResponse:
    """Returns registered Storage Nodes, evaluating offline timeout status and applying filters."""
    nodes = registry.list_nodes(
        status_filter=status_param,
        connectivity_mode_filter=connectivity_mode,
        min_available_bytes=min_available_bytes,
    )
    return NodeListResponse(nodes=nodes, count=len(nodes))


@app.get(
    "/nodes/select",
    response_model=NodeRecord,
    tags=["Selection"],
    summary="Smart Storage Node Selection (GET)",
)

def select_node_get(
    required_bytes: Optional[int] = Query(None, description="Minimum required available capacity in bytes"),
    min_bytes: Optional[int] = Query(None, description="Alternative alias for required_bytes"),
    online_only: bool = Query(True, description="Require online nodes only"),
    preferred_connectivity: Optional[str] = Query(None, description="Preferred connectivity mode ('LAN', 'DIRECT', 'RELAY')"),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeRecord:
    """Selects the best eligible Storage Node based on available capacity and connectivity."""
    target_bytes = required_bytes if required_bytes is not None else (min_bytes if min_bytes is not None else 0)
    selected = registry.select_node(
        required_bytes=target_bytes,
        online_only=online_only,
        preferred_connectivity=preferred_connectivity,
    )
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No eligible storage node available matching criteria ({required_bytes} bytes).",
        )
    return selected


@app.post(
    "/nodes/select",
    response_model=NodeRecord,
    tags=["Selection"],
    summary="Smart Storage Node Selection (POST)",
)
def select_node_post(
    data: NodeSelectionRequest,
    registry: NodeRegistry = Depends(get_registry),
) -> NodeRecord:
    """Selects the best eligible Storage Node based on available capacity and connectivity."""
    selected = registry.select_node(
        required_bytes=data.required_bytes,
        online_only=data.online_only,
        preferred_connectivity=data.preferred_connectivity,
    )
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No eligible storage node available matching criteria ({data.required_bytes} bytes).",
        )
    return selected


@app.get(
    "/nodes/{node_id}",
    response_model=NodeRecord,
    tags=["Discovery"],
    summary="Get Information for a Specific Node",
)
def get_node(
    node_id: str,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
) -> NodeRecord:
    """Retrieves record and status for a specific node_id. Returns 404 if not found."""
    record = registry.get_node(node_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with ID '{node_id}' not found.",
        )
    return record


@app.get(
    "/nodes/{node_id}/connectivity",
    response_model=NodeConnectivityResponse,
    tags=["Discovery"],
    summary="Get Node Connectivity & Diagnostic Info",
)
def get_node_connectivity(
    node_id: str,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
) -> NodeConnectivityResponse:
    """Returns diagnostic connectivity information for a specific Storage Node."""
    record = registry.get_node(node_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with ID '{node_id}' not found.",
        )
    return NodeConnectivityResponse(
        node_id=record.node_id,
        status=record.status,
        connectivity_mode=record.connectivity_mode,
        endpoint=record.endpoint,
        advertised_endpoint=record.advertised_endpoint or record.endpoint,
        reachability="UNKNOWN",
        last_seen=record.last_seen,
        available_capacity_bytes=record.available_capacity_bytes,
        total_capacity_bytes=record.total_capacity_bytes,
        used_capacity_bytes=record.used_capacity_bytes,
        protocol_version=record.protocol_version,
    )


@app.post(
    "/nodes/{node_id}/heartbeat",
    response_model=NodeRecord,
    dependencies=[Depends(verify_coordinator_auth)],
    tags=["Heartbeat"],
    summary="Storage Node Heartbeat Liveness Update",
)
def node_heartbeat(
    node_id: str,
    data: NodeHeartbeatRequest,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
) -> NodeRecord:
    """Updates last_seen timestamp, liveness status, and optional capacity for a registered node."""
    return registry.heartbeat(node_id, data)


@app.delete(
    "/nodes/{node_id}",
    dependencies=[Depends(verify_coordinator_auth)],
    tags=["Registry"],
    summary="Deregister / Remove Storage Node",
)
def delete_node(
    node_id: str,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
):
    """Deletes a node record from the Coordinator registry."""
    success = registry.delete_node(node_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with ID '{node_id}' not found.",
        )
    return {"status": "deleted", "node_id": node_id}


# Phase 4B Repair Job Endpoints
_coordinator_repair_jobs: Dict[str, Dict[str, Any]] = {}


@app.get(
    "/repair/jobs",
    response_model=RepairJobListResponse,
    tags=["Repair"],
    summary="List Coordinator Repair Jobs",
)
def list_repair_jobs(
    state: Optional[str] = Query(None, description="Filter jobs by state ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', etc.)"),
    file_id: Optional[str] = Query(None, description="Filter jobs by target file_id"),
) -> RepairJobListResponse:
    """Retrieves repair jobs tracked by the Coordinator."""
    results = list(_coordinator_repair_jobs.values())
    if state:
        results = [j for j in results if j.get("state") == state]
    if file_id:
        results = [j for j in results if j.get("file_id") == file_id]
    return RepairJobListResponse(jobs=results, count=len(results))


@app.post(
    "/repair/jobs",
    response_model=RepairJobRecord,
    status_code=status.HTTP_201_CREATED,
    tags=["Repair"],
    summary="Create or Update a Coordinator Repair Job",
)
def create_repair_job(
    job_data: RepairJobRecord,
    request: Request,
) -> RepairJobRecord:
    """Registers or updates a repair job on the Coordinator."""
    _coordinator_repair_jobs[job_data.job_id] = job_data.model_dump()
    if job_data.state.upper() in ("SUCCEEDED", "COMPLETED", "REPAIRED"):
        try:
            metering = get_metering_service(request)
            metering.record_operation_event(
                operation_type="repair",
                target_node_id=job_data.destination_node_id or "unknown",
                payload_bytes=0,
                source_node_id=job_data.source_node_id,
                chunk_id=job_data.chunk_id,
                status="completed",
                completed_at=job_data.completed_at or job_data.updated_at,
                idempotency_key=f"repair-{job_data.job_id}",
            )
        except Exception:
            pass
    return job_data


@app.get(
    "/repair/jobs/{job_id}",
    response_model=RepairJobRecord,
    tags=["Repair"],
    summary="Get Specific Repair Job Details",
)
def get_repair_job(job_id: str) -> RepairJobRecord:
    """Retrieves specific repair job record by job_id."""
    if job_id not in _coordinator_repair_jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repair job with ID '{job_id}' not found.",
        )
    return RepairJobRecord(**_coordinator_repair_jobs[job_id])


# Phase 5A: Unified Storage Metadata and File Catalog

@app.post(
    "/catalog/files",
    response_model=FileCatalogRecord,
    status_code=status.HTTP_201_CREATED,
    tags=["Catalog"],
    summary="Register a Logical File"
)
def register_file(
    request: RegisterFileRequest,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
):
    """Registers a newly uploaded file using its manifest, validating size and committing quota."""
    try:
        return catalog.register_file(owner_id, request.manifest, quota_mgr=quota_mgr)
    except QuotaExceededError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except FileCatalogError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get(
    "/catalog/files",
    response_model=FileCatalogListResponse,
    tags=["Catalog"],
    summary="List Logical Files"
)
def list_files(
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog)
):
    """Lists files owned by the authenticated user."""
    files = catalog.list_files(owner_id)
    return FileCatalogListResponse(files=files)


@app.get(
    "/catalog/files/{file_id}",
    response_model=FileCatalogRecord,
    tags=["Catalog"],
    summary="Get Logical File Metadata"
)
def get_file(
    file_id: str,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    settings: CoordinatorSettings = Depends(get_settings),
):
    """Retrieves file catalog metadata by ID, enriching chunk placements with signed download capabilities."""
    try:
        raw_rec = catalog.get_file(file_id, owner_id)
        rec = dict(raw_rec)
        raw_manifest = rec.get("manifest_json")
        if raw_manifest and settings and settings.effective_capability_secret:
            try:
                manifest_dict = json.loads(raw_manifest)
                from coordinator.app.capability import issue_download_capability
                # Enrich replication chunks
                for chunk in manifest_dict.get("chunks", []):
                    c_id = chunk.get("chunk_id")
                    c_sha = chunk.get("sha256")
                    for p in chunk.get("placements", []):
                        n_id = p.get("node_id") or "NODE-LOCAL"
                        p_cid = p.get("chunk_id") or c_id
                        if n_id and p_cid:
                            try:
                                p["capability"] = issue_download_capability(
                                    settings=settings,
                                    node_id=n_id,
                                    chunk_id=p_cid,
                                    account_id=owner_id,
                                    expected_sha256=c_sha,
                                )
                            except Exception:
                                pass
                    # Enrich erasure shards
                    for shard in chunk.get("shards", []):
                        s_id = shard.get("shard_id")
                        s_sha = shard.get("sha256")
                        n_id = shard.get("node_id") or "NODE-LOCAL"
                        if n_id and s_id:
                            try:
                                shard["capability"] = issue_download_capability(
                                    settings=settings,
                                    node_id=n_id,
                                    chunk_id=s_id,
                                    account_id=owner_id,
                                    expected_sha256=s_sha,
                                )
                            except Exception:
                                pass
                rec["manifest_json"] = json.dumps(manifest_dict)
            except Exception:
                pass
        return rec
    except CatalogFileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.get(
    "/catalog/files/{file_id}/status",
    response_model=FileStorageStatusResponse,
    tags=["Catalog"],
    summary="Get Logical File Storage and Degradation Status",
)
def get_file_storage_status_endpoint(
    file_id: str,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    registry: NodeRegistry = Depends(get_registry),
):
    """Retrieves file storage health, checking chunk/shard placement availability on storage nodes."""
    try:
        return catalog.get_file_storage_status(file_id, owner_id, registry)
    except CatalogFileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# Phase 10D: Account Storage Quotas

@app.get(
    "/catalog/quota",
    response_model=AccountQuotaResponse,
    tags=["Catalog"],
    summary="Get Authenticated Account Storage Quota",
)
def get_account_quota_endpoint(
    owner_id: str = Depends(get_authenticated_consumer),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
):
    """Retrieves configured storage limit, committed usage, active reservations, and remaining quota."""
    return quota_mgr.get_account_quota(owner_id)


@app.post(
    "/catalog/quota/reserve",
    response_model=ReserveQuotaResponse,
    tags=["Catalog"],
    summary="Atomically Reserve Storage Quota",
)
def reserve_quota_endpoint(
    data: ReserveQuotaRequest,
    owner_id: str = Depends(get_authenticated_consumer),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
):
    """Atomically reserves account storage quota before beginning file transfers."""
    try:
        res_id = quota_mgr.reserve_quota(
            account_id=owner_id,
            requested_bytes=data.expected_bytes,
            file_id=data.file_id,
            ttl_seconds=data.ttl_seconds,
        )
        now = quota_mgr._now_utc()
        ttl = data.ttl_seconds or getattr(quota_mgr.settings, "account_reservation_ttl_seconds", 300)
        from datetime import timedelta
        expires_at = (now + timedelta(seconds=ttl)).isoformat()
        return ReserveQuotaResponse(
            reservation_id=res_id,
            account_id=owner_id,
            reserved_bytes=data.expected_bytes,
            expires_at=expires_at,
            status="active",
        )
    except QuotaExceededError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@app.post(
    "/catalog/quota/release",
    response_model=ReleaseQuotaResponse,
    tags=["Catalog"],
    summary="Release Storage Quota Reservation",
)
def release_quota_endpoint(
    data: ReleaseQuotaRequest,
    owner_id: str = Depends(get_authenticated_consumer),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
):
    """Releases an active reservation upon failed upload or transfer abort."""
    count = quota_mgr.release_reservation(
        reservation_id=data.reservation_id,
        account_id=owner_id,
        file_id=data.file_id,
    )
    return ReleaseQuotaResponse(status="released", released_count=count)


@app.put(
    "/auth/accounts/{account_id}/quota",
    response_model=UpdateAccountQuotaResponse,
    tags=["Authentication & Identity"],
    summary="Update Account Storage Quota (Administrator only)",
)
def update_account_quota_endpoint(
    account_id: str,
    data: UpdateAccountQuotaRequest,
    admin_auth: str = Depends(verify_admin_auth),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
):
    """Administratively updates the configured storage quota for an account."""
    success = quota_mgr.update_account_quota(account_id, data.quota_bytes)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Account '{account_id}' not found.")
    return UpdateAccountQuotaResponse(
        account_id=account_id,
        quota_bytes=data.quota_bytes,
        message="Account storage quota updated successfully.",
    )


@app.post(
    "/catalog/capabilities/upload",
    response_model=RequestUploadCapabilitiesResponse,
    tags=["Catalog"],
    summary="Issue Upload Capabilities for Chunks",
)
def request_upload_capabilities(
    data: RequestUploadCapabilitiesRequest,
    owner_id: str = Depends(get_authenticated_consumer),
    settings: CoordinatorSettings = Depends(get_settings),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
) -> RequestUploadCapabilitiesResponse:
    """Issues signed, narrowly scoped upload capabilities for chunks and storage nodes after atomic quota reservation."""
    # 1. Atomically reserve quota for upload
    needed_bytes = data.original_size
    if needed_bytes is None:
        needed_bytes = sum(item.size or 0 for item in data.chunks)

    if needed_bytes > 0:
        try:
            quota_mgr.reserve_quota(
                account_id=owner_id,
                requested_bytes=needed_bytes,
                file_id=data.file_id,
            )
        except QuotaExceededError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))

    from coordinator.app.capability import issue_upload_capability
    result: Dict[str, Dict[str, str]] = {}
    for item in data.chunks:
        c_id = item.chunk_id
        result[c_id] = {}
        for n_id in item.node_ids:
            cap_token = issue_upload_capability(
                settings=settings,
                node_id=n_id,
                chunk_id=c_id,
                account_id=owner_id,
                expected_size=item.size,
                expected_sha256=item.sha256,
            )
            result[c_id][n_id] = cap_token

    return RequestUploadCapabilitiesResponse(capabilities=result)


@app.post(
    "/catalog/capabilities/download",
    response_model=RequestDownloadCapabilitiesResponse,
    tags=["Catalog"],
    summary="Issue Download Capabilities for File Chunks",
)
def request_download_capabilities(
    data: RequestDownloadCapabilitiesRequest,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    settings: CoordinatorSettings = Depends(get_settings),
) -> RequestDownloadCapabilitiesResponse:
    """Issues signed download capabilities for authorized chunks of an owned file."""
    try:
        rec = catalog.get_file(data.file_id, owner_id)
    except CatalogFileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    raw_manifest = rec.get("manifest_json")
    if not raw_manifest:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File manifest is missing.")

    manifest_dict = json.loads(raw_manifest)
    from coordinator.app.capability import issue_download_capability

    requested_chunks = set(data.chunk_ids) if data.chunk_ids else None
    result: Dict[str, Dict[str, str]] = {}

    for chunk in manifest_dict.get("chunks", []):
        c_id = chunk.get("chunk_id")
        c_sha = chunk.get("sha256")
        if requested_chunks and c_id not in requested_chunks:
            has_matching_shard = any(s.get("shard_id") in requested_chunks for s in chunk.get("shards", []))
            if not has_matching_shard:
                continue

        for p in chunk.get("placements", []):
            n_id = p.get("node_id") or "NODE-LOCAL"
            p_cid = p.get("chunk_id") or c_id
            if requested_chunks and p_cid not in requested_chunks:
                continue
            if p_cid not in result:
                result[p_cid] = {}
            result[p_cid][n_id] = issue_download_capability(
                settings=settings,
                node_id=n_id,
                chunk_id=p_cid,
                account_id=owner_id,
                expected_sha256=c_sha,
            )

        for shard in chunk.get("shards", []):
            s_id = shard.get("shard_id")
            s_sha = shard.get("sha256")
            n_id = shard.get("node_id") or "NODE-LOCAL"
            if requested_chunks and s_id not in requested_chunks:
                continue
            if s_id not in result:
                result[s_id] = {}
            result[s_id][n_id] = issue_download_capability(
                settings=settings,
                node_id=n_id,
                chunk_id=s_id,
                account_id=owner_id,
                expected_sha256=s_sha,
            )

    return RequestDownloadCapabilitiesResponse(file_id=data.file_id, capabilities=result)


@app.delete(
    "/catalog/files/{file_id}",
    response_model=FileCatalogRecord,
    tags=["Catalog"],
    summary="Mark Logical File for Deletion"
)
def mark_file_deleting(
    file_id: str,
    background_tasks: BackgroundTasks,
    finalize: bool = False,
    sync_cleanup: bool = False,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    recon: ReconciliationService = Depends(get_reconciliation_service)
):
    """Marks a file as 'deleting' or fully 'deleted', scheduling durable cleanup."""
    try:
        if finalize:
            return catalog.mark_deleted(file_id, owner_id)
        
        file_record = catalog.get_file(file_id, owner_id)
        if file_record["status"] not in ("deleting", "deleted"):
            job_id = recon.create_deletion_job(file_id, owner_id, file_record["manifest_json"])
            if sync_cleanup:
                recon.process_deletion_job_bg(job_id)
            else:
                background_tasks.add_task(recon.process_deletion_job_bg, job_id)
        return catalog.get_file(file_id, owner_id)
    except CatalogFileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


from coordinator.app.models import ReconciliationReport

@app.post(
    "/catalog/reconcile",
    response_model=ReconciliationReport,
    tags=["Catalog"],
    summary="Run Reconciliation Service"
)
def reconcile_catalog(
    dry_run: bool = True,
    owner_id: str = Depends(verify_coordinator_auth),
    recon: ReconciliationService = Depends(get_reconciliation_service)
):
    """Run reconciliation to find orphaned objects, missing objects, and process stalled deletions."""
    return recon.run_reconciliation(dry_run=dry_run)


# Mount Authenticated Relay Router (Phase 6B)
from coordinator.app.relay import relay_router
app.include_router(relay_router)

# Mount Metering Router (Phase 7A)
from coordinator.app.metering_router import metering_router
app.include_router(metering_router)

# Mount Contribution Credits, Reputation, and Accounting Routers (Phase 7B)
from coordinator.app.accounting_router import (
    credits_router,
    reputation_router,
    accounting_router,
)
app.include_router(credits_router)
app.include_router(reputation_router)
app.include_router(accounting_router)

# Mount Provider Monitoring and Management Router (Phase 8A)
from pathlib import Path
from starlette.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from coordinator.app.provider_router import provider_router, serve_provider_dashboard
app.include_router(provider_router)

# Mount Authentication and Multi-Tenant Account Identity Router (Phase 10A)
from coordinator.app.auth_router import auth_router
app.include_router(auth_router)

# Mount Observability and Health Router & Middleware (Phase 10F)
from coordinator.app.observability import CorrelationAndMetricsMiddleware, observability_router
app.add_middleware(CorrelationAndMetricsMiddleware)
app.include_router(observability_router)

# Mount Administrative Control Router (Phase 10F)
from coordinator.app.admin_router import admin_router
app.include_router(admin_router)

# Mount Consumer Application File Management Router (Phase 10F)
from coordinator.app.consumer_router import consumer_router
app.include_router(consumer_router)

# Mount root dashboard endpoints and static assets
@app.get("/", response_class=HTMLResponse, tags=["Application Portal"], summary="Unified Integrated Application UI")
@app.get("/app", response_class=HTMLResponse, tags=["Application Portal"], summary="Integrated Application Portal UI")
@app.get("/dashboard", response_class=HTMLResponse, tags=["Application Portal"], summary="Application Portal UI")
def root_dashboard() -> HTMLResponse:
    return serve_provider_dashboard()

# Check dedicated frontend folder first, fallback to coordinator/app/static
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
static_dir = frontend_dir if frontend_dir.exists() else (Path(__file__).parent / "static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")



