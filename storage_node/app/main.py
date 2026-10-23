"""
FastAPI application for Expo Storage Node (Phase 1B).
Provides storage node liveness, persistent node identity, storage quota, authenticated file upload,
listing, download (with SHA-256 verification), and deletion endpoints.
"""

from __future__ import annotations

import logging
from typing import List, Annotated, Optional
from fastapi import (
    FastAPI,
    File,
    UploadFile,
    HTTPException,
    Depends,
    Header,
    Query,
    status,
    Request,
    Response,
)
from fastapi.responses import FileResponse, JSONResponse

from storage_node.app import __version__
from storage_node.app.config import get_settings, Settings
from storage_node.app.models import (
    HealthResponse,
    StorageInfoResponse,
    NodeInfoResponse,
    FileMetadata,
    FileListResponse,
)
from storage_node.app.storage_manager import (
    StorageManager,
    QuotaExceededError,
    SecurityError,
    StorageFileNotFoundError,
    ChecksumMismatchError,
)
from storage_node.app.capability import (
    CapabilityToken,
    CapabilityError,
    InvalidCapabilitySignatureError,
    ExpiredCapabilityError,
    ScopeMismatchCapabilityError,
    MalformedCapabilityError,
    verify_capability,
    extract_capability_from_request,
)
from storage_node.app.coordinator_integration import CoordinatorNotifier, RelayTunnelClient

logger = logging.getLogger("expo_storage_node")

import asyncio
from contextlib import asynccontextmanager
import random

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for starting background heartbeat tasks and outbound relay tunnels."""
    settings = get_settings()
    bg_tasks = []
    tunnel_client = None
    if settings.coordinator_enabled and settings.resolved_coordinator_url:
        manager = StorageManager(settings)
        notifier = CoordinatorNotifier(settings, manager)
        
        async def heartbeat_loop():
            backoff = 1.0
            max_backoff = min(60.0, float(settings.heartbeat_interval_seconds))
            
            while True:
                try:
                    res = await asyncio.to_thread(notifier.heartbeat)
                    if res:
                        backoff = 1.0
                        await asyncio.sleep(settings.heartbeat_interval_seconds)
                    else:
                        jitter = random.uniform(0.5, 1.5)
                        sleep_time = min(max_backoff, backoff * jitter)
                        backoff = min(max_backoff, backoff * 2)
                        await asyncio.sleep(sleep_time)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("Unexpected error in heartbeat loop: %s", exc)
                    await asyncio.sleep(backoff)
                    
        # Initial registration attempt
        try:
            await asyncio.to_thread(notifier.register)
        except Exception:
            pass
            
        bg_tasks.append(asyncio.create_task(heartbeat_loop()))

        # Start persistent outbound reverse tunnel
        node_info = manager.get_node_info()
        tunnel_client = RelayTunnelClient(
            node_id=node_info.node_id,
            coordinator_url=settings.resolved_coordinator_url,
            local_port=settings.port,
            auth_token=settings.coordinator_auth_token,
            verify_tls=settings.coordinator_verify_tls,
        )
        bg_tasks.append(asyncio.create_task(tunnel_client.start()))
        
    yield
    
    for task in bg_tasks:
        task.cancel()
    if tunnel_client:
        tunnel_client.stop()

app = FastAPI(
    title="Expo Storage Node API",
    version=__version__,
    description="LAN-accessible storage node daemon for Expo distributed storage network.",
    lifespan=lifespan,
)


def get_app_settings(request: Request) -> Settings:
    """Dependency provider for Settings instance."""
    if hasattr(request.app.state, "settings"):
        return request.app.state.settings
    return get_settings()


def get_manager(request: Request) -> StorageManager:
    """Dependency provider for StorageManager instance."""
    if not hasattr(request.app.state, "storage_manager"):
        settings = get_app_settings(request)
        request.app.state.storage_manager = StorageManager(settings)
    return request.app.state.storage_manager


def verify_authentication(
    request: Request,
    settings: Annotated[Settings, Depends(get_app_settings)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> None:
    """Verifies development authentication token if configured on the storage node."""
    configured_token = settings.auth_token

    # If no auth token is configured in environment, permit local/unauthenticated access
    if not configured_token or not configured_token.strip():
        return

    # Extract token from X-Auth-Token or Authorization: Bearer <token>
    client_token = None
    if x_auth_token:
        client_token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        client_token = authorization[7:].strip()

    if not client_token or client_token != configured_token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing node authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Custom exception handlers
@app.exception_handler(QuotaExceededError)
async def quota_exceeded_handler(request: Request, exc: QuotaExceededError):
    return JSONResponse(
        status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
        content={"detail": str(exc)},
    )


@app.exception_handler(SecurityError)
async def security_error_handler(request: Request, exc: SecurityError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": f"Security Exception: {str(exc)}"},
    )


@app.exception_handler(ChecksumMismatchError)
async def checksum_error_handler(request: Request, exc: ChecksumMismatchError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


@app.exception_handler(StorageFileNotFoundError)
async def file_not_found_handler(request: Request, exc: StorageFileNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
    )


@app.exception_handler(InvalidCapabilitySignatureError)
async def invalid_cap_sig_handler(request: Request, exc: InvalidCapabilitySignatureError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


@app.exception_handler(ExpiredCapabilityError)
async def expired_cap_handler(request: Request, exc: ExpiredCapabilityError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
        headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"token has expired\""},
    )


@app.exception_handler(ScopeMismatchCapabilityError)
async def scope_mismatch_handler(request: Request, exc: ScopeMismatchCapabilityError):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


@app.exception_handler(MalformedCapabilityError)
async def malformed_cap_handler(request: Request, exc: MalformedCapabilityError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": str(exc)},
    )


def authorize_chunk_operation(
    request: Request,
    op: str,
    file_id: Optional[str],
    settings: Settings,
    manager: StorageManager,
    x_capability_token: Optional[str] = None,
    x_auth_token: Optional[str] = None,
    authorization: Optional[str] = None,
    cap_query: Optional[str] = None,
) -> Optional[CapabilityToken]:
    """
    Validates per-chunk capability authorization for Storage Node chunk operations.
    If a capability token is supplied, enforces signature, node scope, chunk scope, operation,
    expiration, and replay prevention.
    If no capability token is supplied, checks for internal coordinator or node authentication.
    Fails closed in production if neither valid capability nor internal credentials exist.
    """
    token_str = extract_capability_from_request(
        request,
        x_capability_token=x_capability_token,
        authorization=authorization,
        cap_query=cap_query,
    )

    if token_str:
        secret = settings.effective_capability_secret
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Capability secret is not configured on storage node.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Constant-time signature & scope verification
        cap = verify_capability(
            token_str=token_str,
            secret=secret,
            expected_node_id=manager.node_id,
            expected_chunk_id=file_id,
            expected_op=op,
        )

        # Enforce replay protection on upload atomically before data write
        if op == "upload":
            if not manager.claim_upload_capability(cap.jti, cap.chunk_id, "upload", cap.exp):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Conflict: Capability token '{cap.jti}' has already been consumed / replayed.",
                )

        return cap

    # No capability token presented: production strictly requires valid capability token
    if settings.environment == "production":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Production storage operations require a valid capability token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # In non-production development mode, check internal coordinator / node authentication
    client_token = None
    if x_auth_token:
        client_token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        client_token = authorization[7:].strip()

    valid_internal_tokens = [
        t.strip() for t in (settings.auth_token, settings.coordinator_auth_token) if t and t.strip()
    ]

    if client_token and valid_internal_tokens and client_token in valid_internal_tokens:
        return None

    if not valid_internal_tokens:
        # In non-production unconfigured development mode, allow unauthenticated access for legacy test fixtures
        return None

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Missing or invalid capability token or node authentication credential.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/health", response_model=HealthResponse, response_model_exclude_none=True, tags=["Health"], summary="Storage Node Liveness Check")
def health(
    settings: Annotated[Settings, Depends(get_app_settings)],
    manager: Annotated[StorageManager, Depends(get_manager)],
    verbose: bool = Query(False, description="Include detailed node_id and protocol_version"),
) -> HealthResponse:
    """Returns the operational status of the Storage Node (Public endpoint)."""
    if verbose:
        return HealthResponse(
            status="online",
            node_id=manager.node_id,
            protocol_version=settings.protocol_version,
        )
    return HealthResponse(status="online")


@app.get("/node", response_model=NodeInfoResponse, tags=["Node"], summary="Node Identity & Status")
def get_node_info(
    manager: Annotated[StorageManager, Depends(get_manager)]
) -> NodeInfoResponse:
    """Returns stable persistent Node ID, operational status, and capacity (Public endpoint)."""
    return manager.get_node_info()


@app.get(
    "/storage",
    response_model=StorageInfoResponse,
    dependencies=[Depends(verify_authentication)],
    tags=["Storage"],
    summary="Storage Quota & Usage",
)
def get_storage_info(
    manager: Annotated[StorageManager, Depends(get_manager)]
) -> StorageInfoResponse:
    """Returns total configured quota, currently consumed bytes, and remaining available bytes."""
    return manager.get_storage_info()


@app.post(
    "/files",
    response_model=FileMetadata,
    status_code=status.HTTP_201_CREATED,
    tags=["Files"],
    summary="Upload a File to Storage Node",
)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    x_sha256_checksum: Optional[str] = Header(None, alias="X-SHA256-Checksum"),
    x_capability_token: Optional[str] = Header(None, alias="X-Capability-Token"),
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    cap_query: Optional[str] = Query(None, alias="cap"),
    settings: Annotated[Settings, Depends(get_app_settings)] = None,
    manager: Annotated[StorageManager, Depends(get_manager)] = None,
) -> FileMetadata:
    """Accepts a file upload, verifies upload capability, checks quota atomically, verifies SHA-256 checksum, and safely stores it."""
    cap = authorize_chunk_operation(
        request=request,
        op="upload",
        file_id=None,
        settings=settings,
        manager=manager,
        x_capability_token=x_capability_token,
        x_auth_token=x_auth_token,
        authorization=authorization,
        cap_query=cap_query,
    )

    target_file_id = cap.chunk_id if cap else None
    expected_size = cap.expected_size if cap else None
    expected_sha256 = cap.expected_sha256 if (cap and cap.expected_sha256) else x_sha256_checksum

    try:
        metadata = manager.save_file(
            file_obj=file.file,
            original_filename=file.filename,
            content_type=file.content_type,
            expected_sha256=expected_sha256,
            file_id=target_file_id,
            expected_size=expected_size,
        )

        if cap:
            manager.record_consumed_capability(cap.jti, metadata.file_id, "upload", cap.exp)

        return metadata
    except Exception:
        if cap:
            manager.release_consumed_capability(cap.jti)
        raise
    finally:
        await file.close()


@app.get(
    "/files",
    response_model=List[FileMetadata],
    tags=["Files"],
    summary="List Stored Files",
)
def list_files(
    request: Request,
    settings: Annotated[Settings, Depends(get_app_settings)],
    manager: Annotated[StorageManager, Depends(get_manager)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_capability_token: Optional[str] = Header(None, alias="X-Capability-Token"),
) -> List[FileMetadata]:
    """
    Returns metadata for all files stored in the node's sandbox.
    Strictly restricted to internal coordinator/node administration.
    Ordinary capability tokens cannot enumerate stored chunks.
    """
    if x_capability_token or request.headers.get("X-Capability-Token"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Capability tokens do not authorize chunk enumeration.",
        )

    client_token = None
    if x_auth_token:
        client_token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        client_token = authorization[7:].strip()

    valid_internal_tokens = [
        t.strip() for t in (settings.auth_token, settings.coordinator_auth_token) if t and t.strip()
    ]

    if client_token and valid_internal_tokens and client_token in valid_internal_tokens:
        file_list = manager.list_files()
        return file_list.files

    if not valid_internal_tokens:
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Production storage enumeration is restricted.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        file_list = manager.list_files()
        return file_list.files

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Chunk listing requires internal administrator or coordinator credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get(
    "/files/{file_id}",
    tags=["Files"],
    summary="Download / Retrieve Stored File",
)
def get_file(
    file_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_app_settings)],
    manager: Annotated[StorageManager, Depends(get_manager)],
    x_capability_token: Optional[str] = Header(None, alias="X-Capability-Token"),
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    cap_query: Optional[str] = Query(None, alias="cap"),
):
    """Retrieves a stored file by file_id after verifying download capability or coordinator auth."""
    authorize_chunk_operation(
        request=request,
        op="download",
        file_id=file_id,
        settings=settings,
        manager=manager,
        x_capability_token=x_capability_token,
        x_auth_token=x_auth_token,
        authorization=authorization,
        cap_query=cap_query,
    )

    metadata, file_path = manager.get_file(file_id)
    headers = {}
    if metadata.sha256:
        headers["X-SHA256-Checksum"] = metadata.sha256

    return FileResponse(
        path=str(file_path),
        filename=metadata.original_filename,
        media_type=metadata.content_type,
        headers=headers,
    )


@app.delete(
    "/files/{file_id}",
    tags=["Files"],
    summary="Delete Stored File",
)
def delete_file(
    file_id: str,
    request: Request,
    settings: Annotated[Settings, Depends(get_app_settings)],
    manager: Annotated[StorageManager, Depends(get_manager)],
    x_capability_token: Optional[str] = Header(None, alias="X-Capability-Token"),
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    cap_query: Optional[str] = Query(None, alias="cap"),
):
    """Deletes a stored file and its metadata from the storage node after verifying delete capability."""
    authorize_chunk_operation(
        request=request,
        op="delete",
        file_id=file_id,
        settings=settings,
        manager=manager,
        x_capability_token=x_capability_token,
        x_auth_token=x_auth_token,
        authorization=authorization,
        cap_query=cap_query,
    )

    manager.delete_file(file_id)
    return {"status": "deleted", "file_id": file_id}
