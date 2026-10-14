"""
Pydantic data models for Expo Storage Node API (Phase 1B).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Liveness health check response."""
    status: str = Field(default="online", json_schema_extra={"example": "online"})
    node_id: Optional[str] = Field(default=None, description="Persistent node identity")
    protocol_version: Optional[str] = Field(default=None, description="Supported protocol version")


class StorageInfoResponse(BaseModel):
    """Storage quota and usage statistics."""
    quota_bytes: int = Field(..., description="Total allowed storage quota in bytes")
    used_bytes: int = Field(..., description="Storage consumed by Expo sandbox in bytes")
    available_bytes: int = Field(..., description="Remaining available quota in bytes")


class NodeInfoResponse(BaseModel):
    """Storage Node identity and status response."""
    node_id: str = Field(..., description="Stable persistent Node ID (e.g. NODE-<UUID>)")
    status: str = Field(default="online", description="Operational status of the node")
    last_seen: str = Field(..., description="ISO 8601 timestamp of node status check")
    storage: Optional[StorageInfoResponse] = Field(default=None, description="Optional storage stats")


class FileMetadata(BaseModel):
    """Metadata for a file stored in the node."""
    file_id: str = Field(..., description="Unique secure UUID identifier for the stored file")
    original_filename: str = Field(..., description="Sanitized original filename")
    stored_filename: str = Field(..., description="Internal safe stored filename")
    size: int = Field(..., description="File size in bytes")
    sha256: Optional[str] = Field(default=None, description="HEX SHA-256 integrity checksum")
    content_type: Optional[str] = Field(default="application/octet-stream", description="MIME type")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")


class FileListResponse(BaseModel):
    """Response containing list of stored files."""
    files: List[FileMetadata] = Field(default_factory=list)
    count: int = Field(..., description="Total number of stored files")
