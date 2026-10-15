"""
FastAPI application for Expo Coordinator Service (Phase 2B).
Provides Node Registry management, heartbeat tracking, capacity monitoring,
smart node selection, and Internet connectivity node discovery.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Dict, List, Optional
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Header,
    Query,
    Cookie,
    status,
    Request,
    BackgroundTasks,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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
)
from coordinator.app.node_registry import (
    NodeRegistry,
    NodeNotFoundError,
    InvalidCapacityError,
)
from coordinator.app.file_catalog import (
    FileCatalog,
    FileNotFoundError as CatalogFileNotFoundError,
)
from coordinator.app.reconciliation import ReconciliationService
from coordinator.app.user_auth import get_optional_user

logger = logging.getLogger("expo_coordinator")

def resolve_user_from_request(req: Request):
    """Safely extracts UserRecord from request state or resolves from headers/cookies if present."""
    if not req:
        return None
    return getattr(req.state, "current_user", None) or get_optional_user(req)

app = FastAPI(
    title="Expo Coordinator API",
    version=__version__,
    description="Control and management service for Expo distributed storage node registry and discovery.",
)

# Configure CORS for explicitly trusted frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
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
    if not hasattr(request.app.state, "registry"):
        settings = get_settings(request)
        request.app.state.registry = NodeRegistry(settings)
    return request.app.state.registry


def get_settings_from_state(app_state: Any) -> CoordinatorSettings:
    """Resolves CoordinatorSettings directly from app state (for non-Request contexts, e.g. WebSocket)."""
    if hasattr(app_state, "settings"):
        return app_state.settings
    return get_coordinator_settings()


def get_registry_from_state(app_state: Any) -> NodeRegistry:
    """Resolves the NodeRegistry directly from app state (for non-Request contexts, e.g. WebSocket)."""
    if not hasattr(app_state, "registry"):
        settings = app_state.settings if hasattr(app_state, "settings") else get_coordinator_settings()
        app_state.registry = NodeRegistry(settings)
    return app_state.registry


def get_catalog(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)]
) -> FileCatalog:
    """Dependency provider for FileCatalog instance."""
    if not hasattr(request.app.state, "catalog"):
        request.app.state.catalog = FileCatalog(settings)
    return request.app.state.catalog


def get_reconciliation_service(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)]
) -> ReconciliationService:
    """Dependency provider for ReconciliationService."""
    if not hasattr(request.app.state, "reconciliation_service"):
        request.app.state.reconciliation_service = ReconciliationService(settings)
    return request.app.state.reconciliation_service


def get_metering_service(
    request: Request,
) -> MeteringService:
    """Dependency provider for MeteringService."""
    from coordinator.app.metering import MeteringService
    if not hasattr(request.app.state, "metering_service"):
        settings = get_settings(request)
        request.app.state.metering_service = MeteringService(settings)
    return request.app.state.metering_service


def get_metering_service_from_state(app_state: Any) -> MeteringService:
    """Resolves MeteringService from app state directly."""
    from coordinator.app.metering import MeteringService
    if not hasattr(app_state, "metering_service"):
        settings = get_settings_from_state(app_state)
        app_state.metering_service = MeteringService(settings)
    return app_state.metering_service


def verify_coordinator_auth(
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    expo_jwt_cookie: Optional[str] = Cookie(None, alias="expo_jwt"),
) -> str:
    token = None
    if isinstance(x_auth_token, str) and x_auth_token.strip():
        token = x_auth_token.strip()
    elif isinstance(authorization, str) and authorization.strip().lower().startswith("bearer "):
        token = authorization.strip()[7:].strip()
    elif isinstance(expo_jwt_cookie, str) and expo_jwt_cookie.strip():
        token = expo_jwt_cookie.strip()

    # 1. If token is a signed JWT (human user authentication)
    if token and token.count(".") == 2:
        from coordinator.app.user_auth import decode_access_token, UserManager
        user_manager = UserManager(settings)

        try:
            payload = decode_access_token(token, settings)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unauthorized: Invalid JWT token ({str(exc)}).",
                headers={"WWW-Authenticate": "Bearer"},
            )
        jti = payload.get("jti")
        user_id = payload.get("sub")
        if user_manager.is_token_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Token has been revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = user_manager.get_user_by_id(user_id)
        if not user or not user.is_active or user.role_version != payload.get("role_version", 1):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: User account inactive or privileges revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user.username

    # 2. Machine token check for storage nodes / legacy SDK
    valid_tokens = [t.strip() for t in (settings.auth_token, settings.admin_auth_token) if t and t.strip()]
    if not valid_tokens:
        return "default_user"

    if not token or token not in valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing coordinator authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


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
    dependencies=[Depends(verify_coordinator_auth)],
    tags=["Registry"],
    summary="Register or Update a Storage Node",
)
def register_node(
    request: Request,
    data: NodeRegisterRequest,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
) -> NodeRecord:
    """Registers a new Storage Node or updates an existing registered node (Idempotent)."""
    user = resolve_user_from_request(request)
    if user:
        if user.role == "consumer":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Consumer accounts cannot register storage nodes.",
            )
        if user.role == "provider":
            if data.provider_id and data.provider_id.strip() != (user.provider_id or "").strip():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: You are not authorized to register nodes for provider '{data.provider_id}'.",
                )
            data.provider_id = user.provider_id or "default_provider"

    return registry.register_node(data)


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
    request: Request,
    node_id: str,
    registry: Annotated[NodeRegistry, Depends(get_registry)],
):
    """Deletes a node record from the Coordinator registry."""
    user = resolve_user_from_request(request)
    if user:
        if user.role == "consumer":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Consumer accounts cannot deregister storage nodes.",
            )
        if user.role == "provider":
            node = registry.get_node(node_id)
            if not node:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Node with ID '{node_id}' not found.",
                )
            if node.provider_id and node.provider_id != user.provider_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: You are not authorized to deregister node belonging to provider '{node.provider_id}'.",
                )

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
    request: Request,
    state: Optional[str] = Query(None, description="Filter jobs by state ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', etc.)"),
    file_id: Optional[str] = Query(None, description="Filter jobs by target file_id"),
    catalog: FileCatalog = Depends(get_catalog),
) -> RepairJobListResponse:
    """Retrieves repair jobs tracked by the Coordinator."""
    results = list(_coordinator_repair_jobs.values())
    user = resolve_user_from_request(request)
    if user:
        if user.role == "consumer":
            user_files = {f["file_id"] for f in catalog.list_files(user.username)}
            results = [j for j in results if j.get("file_id") in user_files]
        elif user.role == "provider":
            results = [j for j in results if j.get("source_node_id") == user.provider_id or j.get("destination_node_id") == user.provider_id]

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
    request_http: Request,
    request: RegisterFileRequest,
    owner_id: str = Depends(verify_coordinator_auth),
    catalog: FileCatalog = Depends(get_catalog)
):
    """Registers a newly uploaded file using its manifest."""
    user = resolve_user_from_request(request_http)
    if user:
        if user.role == "provider":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Provider accounts cannot register consumer files.",
            )
        owner_id = user.username
    try:
        return catalog.register_file(owner_id, request.manifest)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get(
    "/catalog/files",
    response_model=FileCatalogListResponse,
    tags=["Catalog"],
    summary="List Logical Files"
)
def list_files(
    request_http: Request,
    owner_id: str = Depends(verify_coordinator_auth),
    catalog: FileCatalog = Depends(get_catalog)
):
    """Lists files owned by the authenticated user."""
    user = resolve_user_from_request(request_http)
    if user:
        if user.role == "provider":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Provider accounts cannot access consumer file catalogs.",
            )
        if user.role == "admin":
            files = catalog.list_files(None)
            return FileCatalogListResponse(files=files)
        owner_id = user.username

    files = catalog.list_files(owner_id)
    return FileCatalogListResponse(files=files)


@app.get(
    "/catalog/files/{file_id}",
    response_model=FileCatalogRecord,
    tags=["Catalog"],
    summary="Get Logical File Metadata"
)
def get_file(
    request_http: Request,
    file_id: str,
    owner_id: str = Depends(verify_coordinator_auth),
    catalog: FileCatalog = Depends(get_catalog)
):
    """Retrieves file catalog metadata by ID."""
    is_admin = False
    user = resolve_user_from_request(request_http)
    if user:
        if user.role == "provider":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Provider accounts cannot inspect consumer file metadata.",
            )
        if user.role == "admin":
            is_admin = True
        else:
            owner_id = user.username

    try:
        file_rec = catalog.get_file(file_id, None if is_admin else owner_id)
        if user:
            if user.role == "consumer" and file_rec["owner_id"] not in (user.user_id, user.username):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: You do not have permission to access files owned by another user.",
                )
        return file_rec
    except CatalogFileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.delete(
    "/catalog/files/{file_id}",
    response_model=FileCatalogRecord,
    tags=["Catalog"],
    summary="Mark Logical File for Deletion"
)
def mark_file_deleting(
    request_http: Request,
    file_id: str,
    background_tasks: BackgroundTasks,
    finalize: bool = False,
    owner_id: str = Depends(verify_coordinator_auth),
    catalog: FileCatalog = Depends(get_catalog),
    recon: ReconciliationService = Depends(get_reconciliation_service)
):
    """Marks a file as 'deleting' or fully 'deleted', scheduling durable cleanup."""
    is_admin = False
    user = resolve_user_from_request(request_http)
    if user:
        if user.role == "provider":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Provider accounts cannot delete consumer files.",
            )
        if user.role == "admin":
            is_admin = True
        else:
            owner_id = user.username

    try:
        if user:
            file_rec = catalog.get_file(file_id, None if is_admin else owner_id)
            if user.role == "consumer" and file_rec["owner_id"] not in (user.user_id, user.username):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: You do not have permission to delete files owned by another user.",
                )
            target_owner = file_rec["owner_id"]
        else:
            target_owner = owner_id

        if finalize:
            return catalog.mark_deleted(file_id, target_owner)
        
        file_record = catalog.get_file(file_id, target_owner)
        if file_record["status"] not in ("deleting", "deleted"):
            job_id = recon.create_deletion_job(file_id, target_owner, file_record["manifest_json"])
            background_tasks.add_task(recon.process_deletion_job_bg, job_id)
        return catalog.get_file(file_id, target_owner)
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
    request: Request,
    dry_run: bool = True,
    owner_id: str = Depends(verify_coordinator_auth),
    recon: ReconciliationService = Depends(get_reconciliation_service)
):
    """Run reconciliation to find orphaned objects, missing objects, and process stalled deletions."""
    user = resolve_user_from_request(request)
    if user:
        if user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Only administrators can trigger reconciliation runs.",
            )
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

# Mount root dashboard endpoint and static assets
@app.get("/dashboard", response_class=HTMLResponse, tags=["Provider Management"], summary="Provider Dashboard UI")
def root_dashboard() -> HTMLResponse:
    return serve_provider_dashboard()

# Mount User Authentication & RBAC Router
from coordinator.app.auth_router import auth_router
app.include_router(auth_router)

static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


