"""
Expo Phase 10B: Coordinator Capability Generation and Issuance Service.
Issues cryptographically signed HMAC-SHA-256 capability tokens for consumer file
operations (upload, download, delete) and internal replication/repair/drain tasks.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from coordinator.app.config import CoordinatorSettings
from storage_node.app.capability import (
    CapabilityToken,
    CapabilityError,
    InvalidCapabilitySignatureError,
    ExpiredCapabilityError,
    ScopeMismatchCapabilityError,
    MalformedCapabilityError,
    create_capability,
    verify_capability,
    extract_capability_from_request,
)


def get_capability_secret(settings: CoordinatorSettings) -> str:
    """Resolves capability signing secret from coordinator settings."""
    secret = settings.effective_capability_secret
    if not secret:
        raise ValueError("Capability signing secret is not configured on Coordinator.")
    return secret


def issue_upload_capability(
    settings: CoordinatorSettings,
    node_id: str,
    chunk_id: str,
    account_id: str,
    expected_size: Optional[int] = None,
    expected_sha256: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    token_id: Optional[str] = None,
) -> str:
    """Generates an upload capability token for a specific chunk and storage node."""
    secret = get_capability_secret(settings)
    ttl = ttl_seconds if ttl_seconds is not None else settings.capability_ttl_seconds
    return create_capability(
        secret=secret,
        node_id=node_id,
        chunk_id=chunk_id,
        op="upload",
        account_id=account_id,
        ttl_seconds=ttl,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        token_id=token_id,
    )


def issue_download_capability(
    settings: CoordinatorSettings,
    node_id: str,
    chunk_id: str,
    account_id: str,
    expected_sha256: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> str:
    """Generates a download capability token for a specific chunk and storage node."""
    secret = get_capability_secret(settings)
    ttl = ttl_seconds if ttl_seconds is not None else settings.capability_ttl_seconds
    return create_capability(
        secret=secret,
        node_id=node_id,
        chunk_id=chunk_id,
        op="download",
        account_id=account_id,
        ttl_seconds=ttl,
        expected_sha256=expected_sha256,
    )


def issue_delete_capability(
    settings: CoordinatorSettings,
    node_id: str,
    chunk_id: str,
    account_id: str = "system:coordinator",
    ttl_seconds: Optional[int] = None,
) -> str:
    """Generates a delete capability token for a specific chunk and storage node."""
    secret = get_capability_secret(settings)
    ttl = ttl_seconds if ttl_seconds is not None else settings.capability_ttl_seconds
    return create_capability(
        secret=secret,
        node_id=node_id,
        chunk_id=chunk_id,
        op="delete",
        account_id=account_id,
        ttl_seconds=ttl,
    )
