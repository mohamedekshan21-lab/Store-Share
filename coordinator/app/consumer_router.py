"""
Phase 10F: Consumer Application File Management and Quota Router.

Provides:
- Web-friendly consumer file upload with quota verification, chunking, and capability-signed node placement.
- Consumer file listing, metadata inspection, and quota utilization.
- Direct file download with chunk retrieval, integrity verification, and reassembly.
- File deletion with background reconciliation job dispatch.
- Strict server-side ownership enforcement (Consumer A cannot access Consumer B's files).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Annotated

import httpx
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Header,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse

from client.crypto import AESGCMCrypto
from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
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
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.reconciliation import ReconciliationService
from coordinator.app.capability import (
    issue_upload_capability,
    issue_download_capability,
    issue_delete_capability,
)
from coordinator.app.models import (
    ConsumerFileItem,
    ConsumerFileListResponse,
    AccountQuotaResponse,
    ActionStatusResponse,
)
from coordinator.app.main import (
    get_settings,
    get_catalog,
    get_quota_manager,
    get_registry,
    get_reconciliation_service,
    get_authenticated_consumer,
)

logger = logging.getLogger("expo_consumer_router")

consumer_router = APIRouter(prefix="/consumer", tags=["Consumer File Management"])

# Fallback in-memory chunk storage for offline testing environments
_TEST_CHUNK_STORE: Dict[str, bytes] = {}


def split_bytes_into_chunks(data: bytes, chunk_size: int = 64 * 1024) -> List[Tuple[str, bytes, str]]:
    """Splits payload into chunks, returning (chunk_id, chunk_bytes, sha256_hex)."""
    chunks = []
    if len(data) == 0:
        c_id = str(uuid.uuid4())
        chunks.append((c_id, b"", hashlib.sha256(b"").hexdigest()))
        return chunks

    offset = 0
    while offset < len(data):
        chunk_data = data[offset : offset + chunk_size]
        c_id = str(uuid.uuid4())
        sha = hashlib.sha256(chunk_data).hexdigest()
        chunks.append((c_id, chunk_data, sha))
        offset += chunk_size
    return chunks


# =============================================================================
# 1. File Listing & Quota Overview
# =============================================================================

@consumer_router.get(
    "/files",
    response_model=ConsumerFileListResponse,
    summary="List Owned Files and Quota Status",
)
def list_consumer_files(
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
) -> ConsumerFileListResponse:
    """Lists files owned strictly by the authenticated consumer, enriched with quota statistics."""
    files = catalog.list_files(owner_id)
    quota = quota_mgr.get_account_quota(owner_id)

    file_items = []
    total_bytes = 0
    for f in files:
        st = f.get("status", "available")
        if st != "deleted":
            size = f.get("original_size", 0)
            total_bytes += size
            raw_m = f.get("manifest_json")
            chunk_cnt = 0
            if raw_m:
                try:
                    chunk_cnt = len(json.loads(raw_m).get("chunks", []))
                except Exception:
                    pass
            file_items.append(
                ConsumerFileItem(
                    file_id=f["file_id"],
                    original_filename=f.get("original_filename", "unknown"),
                    original_size=size,
                    status=st,
                    redundancy_mode=f.get("redundancy_mode", "replication"),
                    chunk_count=chunk_cnt,
                    created_at=f.get("created_at", ""),
                    updated_at=f.get("updated_at", ""),
                )
            )

    return ConsumerFileListResponse(
        files=file_items,
        total_files=len(file_items),
        total_bytes=total_bytes,
        quota_bytes=quota["quota_bytes"],
        used_bytes=quota["used_bytes"],
        available_bytes=quota["available_bytes"],
    )


@consumer_router.get(
    "/quota",
    response_model=AccountQuotaResponse,
    summary="Get Consumer Quota Overview",
)
def get_consumer_quota(
    owner_id: str = Depends(get_authenticated_consumer),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
) -> AccountQuotaResponse:
    """Returns the authenticated consumer's current quota, usage, and reservations."""
    q = quota_mgr.get_account_quota(owner_id)
    return AccountQuotaResponse(**q)


# =============================================================================
# 2. File Upload API
# =============================================================================

@consumer_router.post(
    "/files/upload",
    response_model=ConsumerFileItem,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a File to Expo Distributed Storage",
)
async def upload_consumer_file(
    file: UploadFile = File(...),
    owner_id: str = Depends(get_authenticated_consumer),
    settings: CoordinatorSettings = Depends(get_settings),
    catalog: FileCatalog = Depends(get_catalog),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
    registry: NodeRegistry = Depends(get_registry),
) -> ConsumerFileItem:
    """
    Accepts multipart file upload, verifies account quota, distributes chunks across
    active storage nodes using signed capabilities, and commits file metadata to the catalog.
    """
    filename = file.filename or "untitled_file"
    file_bytes = await file.read()
    file_size = len(file_bytes)
    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_id = str(uuid.uuid4())

    # 1. Check and reserve quota atomically
    res_id = None
    try:
        res_id = quota_mgr.reserve_quota(owner_id, file_size, file_id=file_id)
    except QuotaExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Upload rejected: {str(exc)}",
        )

    # 2. Select online/probation storage nodes
    all_registered = registry.list_nodes()
    online_nodes = [
        n for n in all_registered
        if n.is_schedulable and n.status in ("online", "probation") and n.lifecycle_state in ("online", "probation")
    ]
    if not online_nodes:
        # Fallback to status_filter="online" or all registered nodes if non-production
        online_nodes = registry.list_nodes(status_filter="online")
        if not online_nodes and settings.environment != "production":
            online_nodes = all_registered

    if not online_nodes and settings.environment == "production":
        if res_id:
            quota_mgr.release_reservation(reservation_id=res_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No online storage nodes available to accept chunk placements.",
        )

    # 3. Encrypt and Chunk payload (AES-256-GCM authenticated encryption)
    # Derive DEK deterministically from coordinator capability secret + owner + file_id
    file_enc_key = hashlib.sha256(f"{settings.capability_secret}:{owner_id}:{file_id}".encode()).digest()
    file_nonce = AESGCMCrypto.generate_nonce()
    encrypted_bytes, _ = AESGCMCrypto.encrypt(file_bytes, file_enc_key, nonce=file_nonce)

    chunks_data = split_bytes_into_chunks(encrypted_bytes)
    placed_chunks = []

    try:
        for seq, (c_id, c_data, c_sha) in enumerate(chunks_data):
            # Select target node (round robin / available)
            target_node = online_nodes[seq % len(online_nodes)] if online_nodes else None
            node_id = target_node.node_id if target_node else "local_fallback_node"
            node_endpoint = (target_node.advertised_endpoint or target_node.endpoint) if target_node else "http://127.0.0.1:8000"

            # Issue upload capability
            cap_token = issue_upload_capability(
                settings=settings,
                chunk_id=c_id,
                node_id=node_id,
                account_id=owner_id,
                expected_size=len(c_data),
                expected_sha256=c_sha,
            )

            # Transmit chunk to storage node
            stored_remotely = False
            if target_node:
                try:
                    chunk_url = f"{node_endpoint.rstrip('/')}/files"
                    files_payload = {"file": (f"{c_id}.chunk", c_data, "application/octet-stream")}
                    headers = {"X-Capability-Token": cap_token}
                    with httpx.Client(timeout=10.0) as http_client:
                        resp = http_client.post(chunk_url, files=files_payload, headers=headers)
                        if resp.status_code == 201:
                            stored_remotely = True
                except Exception as net_exc:
                    logger.debug("Failed remote chunk upload to %s: %s", node_endpoint, net_exc)

            if not stored_remotely:
                # If remote node unavailable in non-production, store in memory fallback
                if settings.environment != "production":
                    _TEST_CHUNK_STORE[c_id] = c_data
                else:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=f"Failed to place chunk '{c_id}' on node '{node_id}'.",
                    )

            placed_chunks.append(
                {
                    "chunk_id": c_id,
                    "sequence": seq,
                    "sha256": c_sha,
                    "size": len(c_data),
                    "node_id": node_id,
                    "node_endpoint": node_endpoint,
                    "placements": [
                        {
                            "node_id": node_id,
                            "node_endpoint": node_endpoint,
                            "role": "PRIMARY",
                            "chunk_id": c_id,
                        }
                    ],
                    "shards": [],
                }
            )

        # 4. Assemble Manifest
        now_iso = datetime.now(timezone.utc).isoformat()
        manifest = {
            "file_id": file_id,
            "original_filename": filename,
            "original_size": file_size,
            "original_sha256": file_sha256,
            "encrypted_size": len(encrypted_bytes),
            "chunk_size": 64 * 1024,
            "chunk_count": len(placed_chunks),
            "replication_factor": 1,
            "redundancy_mode": "replication",
            "manifest_version": 2,
            "nonce_hex": file_nonce.hex(),
            "created_at": now_iso,
            "chunks": placed_chunks,
        }

        # 5. Register in catalog and commit quota
        record = catalog.register_file(owner_id, manifest, quota_mgr=quota_mgr)
        return ConsumerFileItem(
            file_id=record["file_id"],
            original_filename=record.get("original_filename", filename),
            original_size=record.get("original_size", file_size),
            status=record.get("status", "available"),
            redundancy_mode=record.get("redundancy_mode", "replication"),
            chunk_count=len(placed_chunks),
            created_at=record.get("created_at", now_iso),
            updated_at=record.get("updated_at", now_iso),
        )

    except Exception:
        # Cleanup quota reservation on catastrophic failure
        if res_id:
            quota_mgr.release_reservation(reservation_id=res_id)
        raise


# =============================================================================
# 3. File Download API
# =============================================================================

@consumer_router.get(
    "/files/{file_id}/download",
    summary="Download and Reassemble an Owned File",
)
def download_consumer_file(
    file_id: str,
    owner_id: str = Depends(get_authenticated_consumer),
    settings: CoordinatorSettings = Depends(get_settings),
    catalog: FileCatalog = Depends(get_catalog),
    registry: NodeRegistry = Depends(get_registry),
) -> Response:
    """
    Downloads, reassembles, and streams an owned file back to the browser.
    Verifies ownership, fetches chunks using signed capabilities, and checks integrity.
    """
    clean_fid = file_id.strip()
    try:
        raw_rec = catalog.get_file(clean_fid, owner_id)
    except CatalogFileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{clean_fid}' not found.",
        )

    rec = dict(raw_rec)
    if rec.get("status") in ("deleting", "deleted"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{clean_fid}' has been deleted.",
        )

    raw_manifest = rec.get("manifest_json")
    if not raw_manifest:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File manifest metadata is missing.",
        )

    manifest = json.loads(raw_manifest)
    chunks = sorted(manifest.get("chunks", []), key=lambda c: c.get("sequence", 0))

    assembled_bytes = bytearray()
    for chunk in chunks:
        c_id = chunk.get("chunk_id")
        placements = chunk.get("placements", [])
        primary_endpoint = chunk.get("node_endpoint")
        node_id = chunk.get("node_id")

        if placements:
            primary_endpoint = placements[0].get("node_endpoint", primary_endpoint)
            node_id = placements[0].get("node_id", node_id)

        # Refresh endpoint from live registry if possible
        if primary_endpoint and node_id:
            try:
                target_node_rec = registry.get_node(node_id)
                if target_node_rec:
                    primary_endpoint = target_node_rec.advertised_endpoint or target_node_rec.endpoint or primary_endpoint
            except Exception:
                pass

        # Issue download capability
        cap_token = issue_download_capability(
            settings=settings,
            chunk_id=c_id,
            node_id=node_id or "default_node",
            account_id=owner_id,
        )

        chunk_data = None
        # Attempt download from remote node
        if primary_endpoint:
            try:
                chunk_url = f"{primary_endpoint.rstrip('/')}/files/{c_id}"
                headers = {"X-Capability-Token": cap_token}
                with httpx.Client(timeout=10.0) as http_client:
                    resp = http_client.get(chunk_url, headers=headers)
                    if resp.status_code == 200:
                        chunk_data = resp.content
            except Exception as net_exc:
                logger.debug("Failed remote chunk download for %s: %s", c_id, net_exc)

        # Fallback to test store
        if chunk_data is None and c_id in _TEST_CHUNK_STORE:
            chunk_data = _TEST_CHUNK_STORE[c_id]

        if chunk_data is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to retrieve chunk '{c_id}' from storage node.",
            )

        # Verify chunk sha256
        expected_sha = chunk.get("sha256")
        if expected_sha and hashlib.sha256(chunk_data).hexdigest() != expected_sha:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Integrity check failed for chunk '{c_id}'.",
            )

        assembled_bytes.extend(chunk_data)

    raw_nonce = manifest.get("nonce_hex")
    if raw_nonce and raw_nonce != ("00" * 12):
        try:
            file_enc_key = hashlib.sha256(f"{settings.capability_secret}:{owner_id}:{clean_fid}".encode()).digest()
            file_nonce = bytes.fromhex(raw_nonce)
            decrypted_payload = AESGCMCrypto.decrypt(bytes(assembled_bytes), file_enc_key, nonce=file_nonce)
        except Exception as dec_err:
            logger.error("Decryption failed for file %s: %s", clean_fid, dec_err)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt file payload. Integrity verification failed.",
            )
    else:
        decrypted_payload = bytes(assembled_bytes)

    filename = rec.get("original_filename", f"{clean_fid}.bin")
    # Sanitize filename for Content-Disposition header
    safe_filename = filename.replace('"', '\\"')

    return Response(
        content=decrypted_payload,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-SHA256-Checksum": hashlib.sha256(decrypted_payload).hexdigest(),
        },
    )


# =============================================================================
# 4. File Deletion API
# =============================================================================

@consumer_router.delete(
    "/files/{file_id}",
    response_model=ActionStatusResponse,
    summary="Delete an Owned File",
)
def delete_consumer_file(
    file_id: str,
    owner_id: str = Depends(get_authenticated_consumer),
    catalog: FileCatalog = Depends(get_catalog),
    quota_mgr: QuotaManager = Depends(get_quota_manager),
    recon: ReconciliationService = Depends(get_reconciliation_service),
) -> ActionStatusResponse:
    """Deletes an owned file, creates a background deletion job, and recovers quota."""
    clean_fid = file_id.strip()
    try:
        raw_rec = catalog.get_file(clean_fid, owner_id)
    except CatalogFileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{clean_fid}' not found.",
        )

    file_rec = dict(raw_rec)
    if file_rec.get("status") not in ("deleting", "deleted"):
        job_id = recon.create_deletion_job(clean_fid, owner_id, file_rec.get("manifest_json"))
        # Execute deletion job immediately or in background
        recon.process_deletion_job_bg(job_id)

    return ActionStatusResponse(
        detail=f"File '{clean_fid}' marked for deletion and storage quota recovered.",
        success=True,
    )
