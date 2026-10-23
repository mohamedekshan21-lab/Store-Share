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

    def register_file(
        self,
        owner_id: str,
        manifest: Dict[str, Any],
        status: str = "available",
        quota_mgr: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Registers a logical file after upload or updates an existing one idempotently.
        Enforces that an existing file owned by another account cannot be overwritten or hijacked.
        Validates manifest data consistency and commits account quota atomically.
        """
        file_id = manifest.get("file_id")
        if not file_id or not str(file_id).strip():
            raise ValueError("Manifest must contain a valid, non-empty file_id.")

        original_filename = manifest.get("original_filename", "unknown")
        original_size = manifest.get("original_size", 0)
        if not isinstance(original_size, int) or original_size < 0:
            raise ValueError("Manifest original_size must be a non-negative integer.")

        encrypted_size = manifest.get("encrypted_size", original_size)
        if isinstance(encrypted_size, int) and encrypted_size < original_size:
            raise ValueError("Manifest encrypted_size cannot be smaller than original_size.")

        redundancy_mode = manifest.get("redundancy_mode", "replication")
        manifest_version = manifest.get("manifest_version", 2)
        manifest_json = json.dumps(manifest)
        now = datetime.now(timezone.utc).isoformat()

        chunks = manifest.get("chunks", [])
        if not isinstance(chunks, list):
            raise ValueError("Manifest chunks must be a list.")

        with get_db_connection(self.db_path) as conn:
            # Check for existing file ownership to prevent cross-user hijacking
            existing = conn.execute(
                "SELECT owner_id FROM files WHERE file_id = ?",
                (file_id,)
            ).fetchone()
            if existing and existing["owner_id"] != owner_id:
                raise FileCatalogError(f"Access denied: file '{file_id}' is owned by another account.")

            # Atomically commit quota reservation or verify available quota
            if quota_mgr is not None:
                quota_mgr.commit_reservation(
                    account_id=owner_id,
                    file_id=file_id,
                    actual_size=original_size,
                    conn=conn,
                )

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

    def get_file_storage_status(
        self,
        file_id: str,
        owner_id: str,
        node_registry: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves file metadata and calculates physical storage health and degradation status.
        Enforces strict account ownership isolation (fails closed with 404).
        """
        file_rec = self.get_file(file_id, owner_id)
        raw_manifest = file_rec.get("manifest_json")
        manifest = json.loads(raw_manifest) if raw_manifest else {}

        chunks = manifest.get("chunks", [])
        redundancy_mode = file_rec.get("redundancy_mode", "replication")
        current_status = file_rec.get("status", "available")

        if current_status in ("deleted", "deleting"):
            return {
                "file_id": file_id,
                "owner_id": owner_id,
                "original_filename": file_rec.get("original_filename", "unknown"),
                "original_size": file_rec.get("original_size", 0),
                "status": current_status,
                "redundancy_mode": redundancy_mode,
                "total_chunks": len(chunks),
                "total_placements_or_shards": 0,
                "available_nodes_count": 0,
                "health": current_status,
                "details": {"status_note": f"File is currently in '{current_status}' state."},
                "created_at": file_rec.get("created_at", ""),
                "updated_at": file_rec.get("updated_at", ""),
            }

        # Query node states
        online_nodes = set()
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT node_id, status FROM nodes").fetchall()
            for r in rows:
                if r["status"] == "online":
                    online_nodes.add(r["node_id"])

        total_placements = 0
        total_online_placements = 0
        chunk_health_list = []
        is_degraded = False
        is_incomplete = False

        if redundancy_mode == "erasure":
            data_shards = manifest.get("data_shards", 4)
            parity_shards = manifest.get("parity_shards", 2)
            for c in chunks:
                shards = c.get("shards", [])
                total_placements += len(shards)
                online_shards = 0
                for s in shards:
                    n_id = s.get("node_id")
                    if n_id in online_nodes or n_id == "NODE-LOCAL":
                        online_shards += 1
                        total_online_placements += 1
                if online_shards < data_shards:
                    is_incomplete = True
                elif online_shards < (data_shards + parity_shards):
                    is_degraded = True
                chunk_health_list.append({
                    "chunk_id": c.get("chunk_id"),
                    "online_shards": online_shards,
                    "required_shards": data_shards,
                    "total_shards": len(shards),
                })
        else:
            rep_factor = manifest.get("replication_factor", 2)
            for c in chunks:
                placements = c.get("placements", [])
                if not placements and c.get("node_id"):
                    placements = [{"node_id": c.get("node_id")}]
                total_placements += len(placements)
                online_replicas = 0
                for p in placements:
                    n_id = p.get("node_id")
                    if n_id in online_nodes or n_id == "NODE-LOCAL":
                        online_replicas += 1
                        total_online_placements += 1
                if online_replicas == 0:
                    is_incomplete = True
                elif online_replicas < rep_factor:
                    is_degraded = True
                chunk_health_list.append({
                    "chunk_id": c.get("chunk_id"),
                    "online_replicas": online_replicas,
                    "target_replicas": rep_factor,
                })

        overall_health = "healthy"
        if is_incomplete:
            overall_health = "incomplete"
        elif is_degraded:
            overall_health = "degraded"

        return {
            "file_id": file_id,
            "owner_id": owner_id,
            "original_filename": file_rec.get("original_filename", "unknown"),
            "original_size": file_rec.get("original_size", 0),
            "status": current_status,
            "redundancy_mode": redundancy_mode,
            "total_chunks": len(chunks),
            "total_placements_or_shards": total_placements,
            "available_nodes_count": total_online_placements,
            "health": overall_health,
            "details": {
                "chunks_evaluated": len(chunks),
                "redundancy_mode": redundancy_mode,
                "chunk_status": chunk_health_list,
            },
            "created_at": file_rec.get("created_at", ""),
            "updated_at": file_rec.get("updated_at", ""),
        }

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
