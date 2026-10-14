"""
Phase 5A: Unified Storage Metadata and File Catalog.
Provides service-layer operations for tracking logical files independently of physical storage locations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from coordinator.app.database import get_db_connection
from coordinator.app.config import CoordinatorSettings


class FileCatalogError(Exception):
    """Base exception for File Catalog operations."""


class FileNotFoundError(FileCatalogError):
    """Raised when a file cannot be found or the user is unauthorized."""


class FileCatalog:
    """Service layer for unified file metadata and catalog."""

    def __init__(self, settings: CoordinatorSettings):
        self.settings = settings
        self.db_path = settings.db_path

    def register_file(self, owner_id: str, manifest: Dict[str, Any], status: str = "available") -> Dict[str, Any]:
        """
        Registers a logical file after upload or updates an existing one idempotently.
        """
        file_id = manifest.get("file_id")
        if not file_id:
            raise ValueError("Manifest must contain a valid file_id.")

        original_filename = manifest.get("original_filename", "unknown")
        original_size = manifest.get("original_size", 0)
        redundancy_mode = manifest.get("redundancy_mode", "replication")
        manifest_version = manifest.get("manifest_version", 2)
        manifest_json = json.dumps(manifest)
        now = datetime.now(timezone.utc).isoformat()

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO files (
                    file_id, owner_id, original_filename, original_size, status,
                    redundancy_mode, manifest_version, manifest_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id) DO UPDATE SET
                    manifest_json=excluded.manifest_json,
                    status=excluded.status,
                    updated_at=excluded.updated_at
                """,
                (
                    file_id, owner_id, original_filename, original_size, status,
                    redundancy_mode, manifest_version, manifest_json, now, now
                )
            )
            conn.commit()

        return self.get_file(file_id, owner_id)

    def get_file(self, file_id: str, owner_id: str) -> Dict[str, Any]:
        """Retrieves logical file metadata for an authenticated user."""
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM files WHERE file_id = ? AND owner_id = ?",
                (file_id, owner_id)
            ).fetchone()

            if not row:
                raise FileNotFoundError(f"File {file_id} not found or unauthorized.")
            return dict(row)

    def list_files(self, owner_id: str) -> List[Dict[str, Any]]:
        """Lists all active files in the user's namespace."""
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM files WHERE owner_id = ? AND status NOT IN ('deleted', 'deleting') ORDER BY created_at DESC",
                (owner_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_deleting(self, file_id: str, owner_id: str) -> Dict[str, Any]:
        """Marks a file for deletion safely."""
        now = datetime.now(timezone.utc).isoformat()
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT status FROM files WHERE file_id = ? AND owner_id = ?",
                (file_id, owner_id)
            ).fetchone()

            if not row:
                raise FileNotFoundError(f"File {file_id} not found or unauthorized.")

            if row["status"] == "deleting":
                # Idempotent
                return self.get_file(file_id, owner_id)

            conn.execute(
                "UPDATE files SET status = 'deleting', updated_at = ? WHERE file_id = ? AND owner_id = ?",
                (now, file_id, owner_id)
            )
            conn.commit()
            
        return self.get_file(file_id, owner_id)

    def mark_deleted(self, file_id: str, owner_id: str) -> Dict[str, Any]:
        """Marks a file as fully deleted after physical GC."""
        now = datetime.now(timezone.utc).isoformat()
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT status FROM files WHERE file_id = ? AND owner_id = ?",
                (file_id, owner_id)
            ).fetchone()

            if not row:
                raise FileNotFoundError(f"File {file_id} not found or unauthorized.")

            conn.execute(
                "UPDATE files SET status = 'deleted', updated_at = ? WHERE file_id = ? AND owner_id = ?",
                (now, file_id, owner_id)
            )
            conn.commit()
            
        return self.get_file(file_id, owner_id)

    def update_manifest_internal(self, file_id: str, manifest: Dict[str, Any]) -> None:
        """
        Updates the manifest references safely without needing the owner_id.
        Used primarily by internal systems like the Repair Engine.
        """
        now = datetime.now(timezone.utc).isoformat()
        manifest_json = json.dumps(manifest)
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                "UPDATE files SET manifest_json = ?, updated_at = ? WHERE file_id = ?",
                (manifest_json, now, file_id)
            )
            conn.commit()
