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
import threading
import time
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


def is_pid_alive(pid: int | None) -> bool:
    """Checks if an OS process ID is currently running on the system."""
    if pid is None or pid <= 0:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        pass

    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x0400, False, pid)
            if handle:
                exit_code = ctypes.c_ulong()
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                kernel32.CloseHandle(handle)
                return exit_code.value == 259
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def is_file_locked(lock_path: Path) -> bool:
    """Checks non-blockingly whether an active process holds a writer lock on lock_path."""
    if not lock_path.exists():
        return False
    try:
        f = open(lock_path, "r+b")
    except (OSError, IOError, PermissionError):
        # File is locked exclusively by another process (e.g., Windows sharing violation)
        return True

    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            f.close()
            return False
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()
            return False
    except (OSError, IOError, PermissionError):
        try:
            f.close()
        except Exception:
            pass
        return True


class WriterLock:
    """Context manager for acquiring and holding a kernel-managed lock file during upload."""

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self._f = None

    def __enter__(self):
        try:
            self._f = open(self.lock_path, "a+b")
            self._f.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            if self._f:
                try:
                    self._f.close()
                except Exception:
                    pass
                self._f = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._f:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._f.seek(0)
                    msvcrt.locking(self._f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self._f.close()
            except Exception:
                pass
            self._f = None
        try:
            self.lock_path.unlink(missing_ok=True)
        except Exception:
            pass


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
        self._reservation_lock = threading.Lock()
        self._init_db()
        self._cleanup_stale_temp_files()
        self.node_id = self._get_or_create_node_id()

    def _get_db_connection(self) -> sqlite3.Connection:
        """Returns SQLite database connection with row factory and cross-process timeout."""
        conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _cleanup_stale_temp_files(self) -> None:
        """Cleans up orphaned temporary files and stale reservations belonging to dead processes."""
        try:
            live_temp_files = set()
            with self._get_db_connection() as conn:
                cursor = conn.execute("SELECT reservation_id, owner_pid, temp_filename FROM quota_reservations")
                rows = cursor.fetchall()
                stale_res_ids = []
                current_pid = os.getpid()

                for r in rows:
                    res_id = r["reservation_id"]
                    pid = r["owner_pid"]
                    t_name = r["temp_filename"]

                    is_active = False
                    if t_name:
                        lock_name = t_name.replace(".tmp", "") + ".lock"
                        lock_path = self.temp_dir / lock_name
                        if is_file_locked(lock_path):
                            is_active = True

                    # If not locked, check if owner process is active in another process
                    if not is_active and pid is not None and pid != current_pid and is_pid_alive(pid):
                        is_active = True

                    if is_active:
                        if t_name:
                            live_temp_files.add(t_name)
                            live_temp_files.add(t_name.replace(".tmp", "") + ".lock")
                    else:
                        stale_res_ids.append(res_id)
                        if t_name:
                            (self.temp_dir / t_name).unlink(missing_ok=True)
                            (self.temp_dir / (t_name.replace(".tmp", "") + ".lock")).unlink(missing_ok=True)

                if stale_res_ids:
                    placeholders = ",".join("?" for _ in stale_res_ids)
                    conn.execute(f"DELETE FROM quota_reservations WHERE reservation_id IN ({placeholders})", stale_res_ids)

            # Clean any untracked or orphaned files in temp_dir that are not active
            if self.temp_dir.exists():
                for entry in os.scandir(self.temp_dir):
                    if entry.is_file(follow_symlinks=False):
                        if entry.name not in live_temp_files:
                            # If it's a lock file and currently locked, do not delete it!
                            if entry.name.endswith(".lock") and is_file_locked(Path(entry.path)):
                                continue
                            # If it's a .tmp file whose corresponding .lock is currently locked, do not delete it!
                            if entry.name.endswith(".tmp"):
                                corresponding_lock = Path(entry.path).with_suffix(".lock")
                                if is_file_locked(corresponding_lock):
                                    continue
                            try:
                                os.unlink(entry.path)
                            except Exception:
                                pass
        except Exception:
            pass

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

            # Phase 10B: Track consumed capability tokens to prevent replay attacks
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_capabilities (
                    jti TEXT PRIMARY KEY,
                    chunk_id TEXT NOT NULL,
                    op TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    exp INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_consumed_capabilities_exp
                ON consumed_capabilities(exp)
                """
            )

            # Phase 10B: Atomic Quota Reservations to prevent concurrent race oversubscription
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quota_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    expected_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    owner_pid INTEGER,
                    temp_filename TEXT
                )
                """
            )
            # Add owner_pid and temp_filename columns if migrating from earlier schema
            cursor = conn.execute("PRAGMA table_info(quota_reservations)")
            q_cols = [row["name"] for row in cursor.fetchall()]
            if "owner_pid" not in q_cols:
                conn.execute("ALTER TABLE quota_reservations ADD COLUMN owner_pid INTEGER")
            if "temp_filename" not in q_cols:
                conn.execute("ALTER TABLE quota_reservations ADD COLUMN temp_filename TEXT")

    def _get_or_create_node_id(self) -> str:
        """Retrieves persistent Node ID from SQLite database or generates a new one."""
        with self._get_db_connection() as conn:
            cursor = conn.execute("SELECT value FROM node_info WHERE key = 'node_id'")
            row = cursor.fetchone()
            if row:
                return row["value"]
            
            configured_id = getattr(self.settings, "node_id", None)
            clean_id = configured_id.strip() if (configured_id and isinstance(configured_id, str) and configured_id.strip()) else None
            new_id = clean_id or f"NODE-{uuid.uuid4()}"
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

    def get_committed_used_bytes(self) -> int:
        """Calculates total bytes consumed by committed files in the sandbox."""
        total_size = 0
        if self.files_dir.exists():
            for entry in os.scandir(self.files_dir):
                if entry.is_file(follow_symlinks=False):
                    total_size += entry.stat().st_size
        return total_size

    def get_active_reserved_bytes(self) -> int:
        """Returns total bytes currently held by active upload reservations."""
        with self._reservation_lock:
            with self._get_db_connection() as conn:
                row = conn.execute("SELECT COALESCE(SUM(expected_bytes), 0) AS total FROM quota_reservations").fetchone()
                return int(row["total"]) if row else 0

    def reserve_quota(self, expected_bytes: int, temp_filename: Optional[str] = None) -> str:
        """
        Atomically reserves storage capacity for an in-flight upload.
        Guarantees concurrent uploads across threads and processes cannot exceed configured quota.
        """
        expected_bytes = max(0, int(expected_bytes))
        reservation_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()
        quota_bytes = self.settings.storage_quota_bytes
        current_pid = os.getpid()

        with self._reservation_lock:
            with self._get_db_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    used_committed = self.get_committed_used_bytes()
                    row = conn.execute("SELECT COALESCE(SUM(expected_bytes), 0) AS total FROM quota_reservations").fetchone()
                    current_reserved = int(row["total"]) if row else 0

                    if used_committed + current_reserved + expected_bytes > quota_bytes:
                        conn.execute("ROLLBACK")
                        raise QuotaExceededError(
                            f"Insufficient storage: Reserving {expected_bytes} bytes exceeds quota ({quota_bytes} bytes). "
                            f"Current used: {used_committed} bytes, Active reservations: {current_reserved} bytes."
                        )

                    conn.execute(
                        "INSERT INTO quota_reservations (reservation_id, expected_bytes, created_at, owner_pid, temp_filename) VALUES (?, ?, ?, ?, ?)",
                        (reservation_id, expected_bytes, now_str, current_pid, temp_filename)
                    )
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise

        return reservation_id

    def update_reservation(self, reservation_id: str, new_bytes: int) -> None:
        """Incrementally increases reservation during streaming if upload exceeds initial reservation."""
        quota_bytes = self.settings.storage_quota_bytes
        new_bytes = max(0, int(new_bytes))

        with self._reservation_lock:
            with self._get_db_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    used_committed = self.get_committed_used_bytes()
                    row = conn.execute(
                        "SELECT expected_bytes FROM quota_reservations WHERE reservation_id = ?",
                        (reservation_id,)
                    ).fetchone()
                    current_item_reserved = int(row["expected_bytes"]) if row else 0

                    delta = new_bytes - current_item_reserved
                    if delta <= 0:
                        conn.execute("COMMIT")
                        return

                    total_row = conn.execute(
                        "SELECT COALESCE(SUM(expected_bytes), 0) AS total FROM quota_reservations WHERE reservation_id != ?",
                        (reservation_id,)
                    ).fetchone()
                    other_reserved = int(total_row["total"]) if total_row else 0

                    if used_committed + other_reserved + new_bytes > quota_bytes:
                        conn.execute("ROLLBACK")
                        raise QuotaExceededError(
                            f"Quota exceeded: Streaming upload reached {new_bytes} bytes, exceeding available capacity "
                            f"({quota_bytes} bytes quota, {used_committed} used, {other_reserved} other reservations)."
                        )

                    if row:
                        conn.execute(
                            "UPDATE quota_reservations SET expected_bytes = ? WHERE reservation_id = ?",
                            (new_bytes, reservation_id)
                        )
                    else:
                        now_str = datetime.now(timezone.utc).isoformat()
                        conn.execute(
                            "INSERT INTO quota_reservations (reservation_id, expected_bytes, created_at, owner_pid) VALUES (?, ?, ?, ?)",
                            (reservation_id, new_bytes, now_str, os.getpid())
                        )
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise

    def release_reservation(self, reservation_id: Optional[str]) -> None:
        """Releases a quota reservation after commit or on abort/failure."""
        if not reservation_id:
            return
        with self._reservation_lock:
            with self._get_db_connection() as conn:
                conn.execute("DELETE FROM quota_reservations WHERE reservation_id = ?", (reservation_id,))

    def is_capability_consumed(self, jti: str) -> bool:
        """Checks if capability token ID has already been consumed."""
        with self._get_db_connection() as conn:
            row = conn.execute("SELECT 1 FROM consumed_capabilities WHERE jti = ?", (jti,)).fetchone()
            return row is not None

    def claim_upload_capability(self, jti: str, chunk_id: str, op: str, exp: int) -> bool:
        """
        Atomically claims an upload capability token ID in SQLite to prevent concurrent replay attacks.
        Returns True if successfully claimed, False if already claimed or consumed.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        try:
            with self._get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO consumed_capabilities (jti, chunk_id, op, consumed_at, exp) VALUES (?, ?, ?, ?, ?)",
                    (jti, chunk_id, op, now_str, int(exp))
                )
                return True
        except sqlite3.IntegrityError:
            return False

    def release_consumed_capability(self, jti: str) -> None:
        """Releases a claimed capability if upload fails before committing."""
        try:
            with self._get_db_connection() as conn:
                conn.execute("DELETE FROM consumed_capabilities WHERE jti = ?", (jti,))
        except Exception:
            pass

    def record_consumed_capability(self, jti: str, chunk_id: str, op: str, exp: int) -> None:
        """Persists consumed capability token ID to prevent replay attacks across restarts."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_db_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO consumed_capabilities (jti, chunk_id, op, consumed_at, exp) VALUES (?, ?, ?, ?, ?)",
                (jti, chunk_id, op, now_str, int(exp))
            )

    def purge_expired_consumed_capabilities(self, current_time: Optional[float] = None) -> int:
        """Cleans up expired consumed capability records."""
        now = int(current_time if current_time is not None else time.time())
        with self._get_db_connection() as conn:
            cur = conn.execute("DELETE FROM consumed_capabilities WHERE exp < ?", (now,))
            conn.commit()
            return cur.rowcount

    def get_used_bytes(self) -> int:
        """Calculates total bytes counting against quota (committed files + active reservations)."""
        committed = self.get_committed_used_bytes()
        reserved = self.get_active_reserved_bytes()
        return committed + reserved

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
        file_id: Optional[str] = None,
        expected_size: Optional[int] = None,
        reservation_id: Optional[str] = None,
    ) -> FileMetadata:
        """Saves incoming stream to sandbox file with atomic quota reservation and SHA-256 verification."""
        clean_original_name = sanitize_filename(original_filename)
        if file_id:
            self._validate_file_id(file_id)
            target_file_id = file_id.strip()
        else:
            target_file_id = str(uuid.uuid4())

        stored_filename = f"{target_file_id}.dat"
        target_path = self._resolve_and_verify_sandbox_path(stored_filename)
        temp_path = (self.temp_dir / f"{target_file_id}.tmp").resolve()
        lock_path = (self.temp_dir / f"{target_file_id}.lock").resolve()

        # Atomic Quota Reservation
        active_res_id = reservation_id
        own_reservation = False
        if not active_res_id:
            initial_reserve = expected_size if expected_size is not None else 0
            active_res_id = self.reserve_quota(initial_reserve, temp_filename=f"{target_file_id}.tmp")
            own_reservation = True

        bytes_written = 0
        chunk_size = 64 * 1024  # 64 KB chunks
        hasher = hashlib.sha256()

        with WriterLock(lock_path):
            try:
                with open(temp_path, "wb") as f_out:
                    while True:
                        chunk = file_obj.read(chunk_size)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        # Incrementally update reservation if stream exceeds initially reserved bytes
                        self.update_reservation(active_res_id, bytes_written)
                        hasher.update(chunk)
                        f_out.write(chunk)

                computed_sha256 = hasher.hexdigest().lower()

                # Verify SHA-256 checksum if provided by client or capability
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
                if own_reservation:
                    self.release_reservation(active_res_id)
                raise

        created_at = datetime.now(timezone.utc).isoformat()
        metadata = FileMetadata(
            file_id=target_file_id,
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
                    INSERT OR REPLACE INTO file_metadata (file_id, original_filename, stored_filename, size, sha256, content_type, created_at)
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
            if own_reservation:
                self.release_reservation(active_res_id)
            raise

        # Successful commit -> release reservation (now counted in committed files)
        if own_reservation:
            self.release_reservation(active_res_id)

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
