"""
StorageManager for Expo Storage Node (Phase 1B).
Handles sandbox directory isolation, path security validation, quota enforcement,
persistent node identity, SHA-256 integrity verification, and SQLite metadata persistence.
"""

from __future__ import annotations

import os
import re
import hashlib
import sqlite3
import uuid
import shutil
from datetime import datetime, timezone
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import BinaryIO, List, Tuple, Optional

from storage_node.app.config import Settings
from storage_node.app.models import FileMetadata, StorageInfoResponse, FileListResponse, NodeInfoResponse


class StorageNodeException(Exception):
    """Base exception for Storage Node errors."""


class QuotaExceededError(StorageNodeException):
    """Raised when file storage operation exceeds the configured quota."""


class SecurityError(StorageNodeException):
    """Raised when path traversal or unsafe file access is detected."""


class StorageFileNotFoundError(StorageNodeException):
    """Raised when a requested file is not found in the storage node."""


class ChecksumMismatchError(StorageNodeException):
    """Raised when uploaded file SHA-256 does not match expected checksum."""


# UUID4 format pattern
UUID4_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def sanitize_filename(filename: str | None) -> str:
    """Strips path components, control characters, and leading/trailing dots/spaces."""
    if not filename:
        return "unnamed_file"
    
    # Strip any directory separators from both POSIX and Windows paths
    name = PureWindowsPath(PurePosixPath(filename).name).name
    # Strip control characters
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    name = name.strip(".")
    return name[:255] if name else "unnamed_file"


class StorageManager:
    """Manages files within a strict sandbox root with quota enforcement and SHA-256 verification."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.storage_root = settings.resolve_sandbox_path()
        self.files_dir = (self.storage_root / "files").resolve()
        self.temp_dir = (self.storage_root / "temp").resolve()
        self.metadata_dir = (self.storage_root / "metadata").resolve()
        
        # Ensure sandbox subdirectories exist
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.metadata_dir / "node_metadata.db"
        self._init_db()
        self.node_id = self._get_or_create_node_id()

    def _get_db_connection(self) -> sqlite3.Connection:
        """Returns SQLite database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes the metadata SQLite database schema."""
        with self._get_db_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS node_info (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_metadata (
                    file_id TEXT PRIMARY KEY,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT,
                    content_type TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            # Add sha256 column if migrating from Phase 1A schema
            cursor = conn.execute("PRAGMA table_info(file_metadata)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "sha256" not in columns:
                conn.execute("ALTER TABLE file_metadata ADD COLUMN sha256 TEXT")
            conn.commit()

    def _get_or_create_node_id(self) -> str:
        """Retrieves persistent Node ID from SQLite database or generates a new one."""
        with self._get_db_connection() as conn:
            cursor = conn.execute("SELECT value FROM node_info WHERE key = 'node_id'")
            row = cursor.fetchone()
            if row:
                return row["value"]
            
            new_id = f"NODE-{uuid.uuid4()}"
            conn.execute("INSERT INTO node_info (key, value) VALUES ('node_id', ?)", (new_id,))
            conn.commit()
            return new_id

    def _validate_file_id(self, file_id: str) -> None:
        """Validates that file_id is a valid UUID4 and contains no path separators."""
        if not file_id or not isinstance(file_id, str):
            raise SecurityError("Invalid file ID: must be a non-empty string.")
        
        # Check for path traversal characters or drive indicators
        if any(char in file_id for char in ("/", "\\", "..", ":", "\x00")):
            raise SecurityError(f"Path traversal characters detected in file ID: '{file_id}'.")
        
        if not UUID4_PATTERN.match(file_id.strip()):
            raise SecurityError(f"Invalid file ID format: '{file_id}'. Must be a valid UUID4.")

    def _resolve_and_verify_sandbox_path(self, relative_filename: str) -> Path:
        """Resolves target path and strictly verifies it remains inside files_dir sandbox."""
        if not relative_filename or not isinstance(relative_filename, str):
            raise SecurityError("Invalid filename provided.")

        if any(char in relative_filename for char in ("/", "\\", "..", ":", "\x00")):
            raise SecurityError(f"Path traversal detected in filename: '{relative_filename}'.")

        # Resolve candidate path
        candidate_path = (self.files_dir / relative_filename).resolve()
        
        # Verify strict containment inside files_dir
        try:
            candidate_path.relative_to(self.files_dir)
        except ValueError:
            raise SecurityError(
                f"Path traversal detected: Resolved path '{candidate_path}' is outside sandbox '{self.files_dir}'."
            )
            
        return candidate_path

    def get_used_bytes(self) -> int:
        """Calculates total bytes consumed by files in the sandbox."""
        total_size = 0
        if self.files_dir.exists():
            for entry in os.scandir(self.files_dir):
                if entry.is_file(follow_symlinks=False):
                    total_size += entry.stat().st_size
        return total_size

    def get_storage_info(self) -> StorageInfoResponse:
        """Calculates quota, used, and available bytes."""
        quota_bytes = self.settings.storage_quota_bytes
        used_bytes = self.get_used_bytes()
        available_bytes = max(0, quota_bytes - used_bytes)
        return StorageInfoResponse(
            quota_bytes=quota_bytes,
            used_bytes=used_bytes,
            available_bytes=available_bytes,
        )

    def get_node_info(self) -> NodeInfoResponse:
        """Returns stable Node identity, operational status, and capacity."""
        return NodeInfoResponse(
            node_id=self.node_id,
            status="online",
            last_seen=datetime.now(timezone.utc).isoformat(),
            storage=self.get_storage_info(),
        )

    def save_file(
        self,
        file_obj: BinaryIO,
        original_filename: str | None,
        content_type: str | None = None,
        expected_sha256: str | None = None,
    ) -> FileMetadata:
        """Saves incoming stream to sandbox file with quota enforcement and SHA-256 verification."""
        clean_original_name = sanitize_filename(original_filename)
        file_id = str(uuid.uuid4())
        stored_filename = f"{file_id}.dat"
        
        target_path = self._resolve_and_verify_sandbox_path(stored_filename)
        temp_path = (self.temp_dir / f"{file_id}.tmp").resolve()
        
        # Calculate available capacity before write
        current_used = self.get_used_bytes()
        quota_bytes = self.settings.storage_quota_bytes
        
        if current_used >= quota_bytes:
            raise QuotaExceededError(
                f"Insufficient storage: Current node storage ({current_used} bytes) has reached quota ({quota_bytes} bytes)."
            )

        bytes_written = 0
        chunk_size = 64 * 1024  # 64 KB chunks
        hasher = hashlib.sha256()
        
        try:
            with open(temp_path, "wb") as f_out:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break
                    
                    bytes_written += len(chunk)
                    if current_used + bytes_written > quota_bytes:
                        raise QuotaExceededError(
                            f"Quota exceeded: Storing file of size > {bytes_written} bytes would exceed quota ({quota_bytes} bytes)."
                        )
                    hasher.update(chunk)
                    f_out.write(chunk)

            computed_sha256 = hasher.hexdigest().lower()
            
            # Verify SHA-256 checksum if provided by client
            if expected_sha256 and expected_sha256.strip():
                clean_expected = expected_sha256.strip().lower()
                if clean_expected != computed_sha256:
                    raise ChecksumMismatchError(
                        f"SHA-256 checksum mismatch: Expected '{clean_expected}', but calculated '{computed_sha256}'."
                    )
            
            # Atomically move temporary file to final target destination inside sandbox
            shutil.move(temp_path, target_path)
            
        except Exception:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise

        created_at = datetime.now(timezone.utc).isoformat()
        metadata = FileMetadata(
            file_id=file_id,
            original_filename=clean_original_name,
            stored_filename=stored_filename,
            size=bytes_written,
            sha256=computed_sha256,
            content_type=content_type or "application/octet-stream",
            created_at=created_at,
        )

        try:
            with self._get_db_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO file_metadata (file_id, original_filename, stored_filename, size, sha256, content_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        metadata.file_id,
                        metadata.original_filename,
                        metadata.stored_filename,
                        metadata.size,
                        metadata.sha256,
                        metadata.content_type,
                        metadata.created_at,
                    ),
                )
                conn.commit()
        except Exception:
            if target_path.exists():
                target_path.unlink(missing_ok=True)
            raise

        return metadata

    def list_files(self) -> FileListResponse:
        """Lists metadata for all stored files."""
        files: List[FileMetadata] = []
        with self._get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT file_id, original_filename, stored_filename, size, sha256, content_type, created_at FROM file_metadata ORDER BY created_at DESC"
            )
            for row in cursor.fetchall():
                files.append(
                    FileMetadata(
                        file_id=row["file_id"],
                        original_filename=row["original_filename"],
                        stored_filename=row["stored_filename"],
                        size=row["size"],
                        sha256=row["sha256"],
                        content_type=row["content_type"],
                        created_at=row["created_at"],
                    )
                )
        return FileListResponse(files=files, count=len(files))

    def get_file(self, file_id: str) -> Tuple[FileMetadata, Path]:
        """Retrieves metadata and verified file path for a stored file."""
        self._validate_file_id(file_id)

        with self._get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT file_id, original_filename, stored_filename, size, sha256, content_type, created_at FROM file_metadata WHERE file_id = ?",
                (file_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise StorageFileNotFoundError(f"File with ID '{file_id}' not found.")
            
            metadata = FileMetadata(
                file_id=row["file_id"],
                original_filename=row["original_filename"],
                stored_filename=row["stored_filename"],
                size=row["size"],
                sha256=row["sha256"],
                content_type=row["content_type"],
                created_at=row["created_at"],
            )

        target_path = self._resolve_and_verify_sandbox_path(metadata.stored_filename)
        if not target_path.is_file():
            raise StorageFileNotFoundError(f"Stored file for ID '{file_id}' is missing on disk.")

        return metadata, target_path

    def delete_file(self, file_id: str) -> bool:
        """Deletes stored file and its metadata record."""
        self._validate_file_id(file_id)

        with self._get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT stored_filename FROM file_metadata WHERE file_id = ?",
                (file_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise StorageFileNotFoundError(f"File with ID '{file_id}' not found.")
            
            stored_filename = row["stored_filename"]
            
            # Remove from DB first
            conn.execute("DELETE FROM file_metadata WHERE file_id = ?", (file_id,))
            conn.commit()

        target_path = self._resolve_and_verify_sandbox_path(stored_filename)
        if target_path.exists():
            target_path.unlink(missing_ok=True)

        return True
