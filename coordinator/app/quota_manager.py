"""
Phase 10D: Account Storage Quotas and Concurrency-Safe Reservations.
Provides atomic per-account quota enforcement, durable reservation recovery,
cross-process race protection via SQLite BEGIN IMMEDIATE, and consistent
logical/physical accounting policies.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

from coordinator.app.database import get_db_connection
from coordinator.app.config import CoordinatorSettings

logger = logging.getLogger("expo_quota")


class QuotaError(Exception):
    """Base exception for account quota operations."""


class QuotaExceededError(QuotaError):
    """Raised when an upload reservation or file registration exceeds account quota."""


class QuotaReservationNotFoundError(QuotaError):
    """Raised when an expected reservation cannot be found."""


class QuotaManager:
    """Manages per-account storage quotas, atomic reservations, and crash recovery."""

    def __init__(self, settings: CoordinatorSettings):
        self.settings = settings
        self.db_path = settings.db_path

    def _now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def _now_str(self) -> str:
        return self._now_utc().isoformat()

    def recover_durable_reservations(self) -> int:
        """
        Durable crash recovery: scans active reservations across all accounts
        and marks expired reservations as 'expired'. Called at coordinator startup
        and during reconciliation.
        """
        now_str = self._now_str()
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.execute(
                    "UPDATE account_quota_reservations SET status = 'expired' WHERE status = 'active' AND expires_at < ?",
                    (now_str,)
                )
                conn.commit()
                recovered = cursor.rowcount
                if recovered > 0:
                    logger.info("Recovered %d expired quota reservations", recovered)
                return recovered
        except sqlite3.OperationalError:
            return 0

    def get_account_quota(self, account_id: str, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        """
        Retrieves accurate used, reserved, available, and total quota figures for an account.
        """
        now_str = self._now_str()
        default_quota = getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024)
        policy = getattr(self.settings, "account_quota_policy", "logical").lower()

        def _query(c: sqlite3.Connection) -> Dict[str, Any]:
            # Recover expired reservations for this account on access
            c.execute(
                "UPDATE account_quota_reservations SET status = 'expired' WHERE account_id = ? AND status = 'active' AND expires_at < ?",
                (account_id, now_str)
            )

            # 1. Total configured quota limit
            quota_bytes = default_quota
            acc_row = c.execute(
                "SELECT quota_bytes FROM accounts WHERE account_id = ?",
                (account_id,)
            ).fetchone()
            if acc_row and "quota_bytes" in acc_row.keys() and acc_row["quota_bytes"] is not None:
                quota_bytes = int(acc_row["quota_bytes"])

            # 2. Used bytes from committed active files
            # Note: files in 'deleting' remain counted until physical cleanup completes ('deleted')
            if policy == "physical":
                file_rows = c.execute(
                    "SELECT manifest_json FROM files WHERE owner_id = ? AND status NOT IN ('deleted')",
                    (account_id,)
                ).fetchall()
                used_bytes = 0
                file_count = len(file_rows)
                for f_row in file_rows:
                    raw_m = f_row["manifest_json"]
                    if raw_m:
                        try:
                            m = json.loads(raw_m)
                            for chunk in m.get("chunks", []):
                                c_size = chunk.get("size_bytes", chunk.get("size", 0))
                                placements = chunk.get("placements", [])
                                if placements:
                                    used_bytes += c_size * len(placements)
                                else:
                                    shards = chunk.get("shards", [])
                                    if shards:
                                        for s in shards:
                                            used_bytes += s.get("size_bytes", c_size)
                                    else:
                                        used_bytes += c_size
                        except Exception:
                            pass
            else:
                # Default logical accounting policy
                row_used = c.execute(
                    "SELECT COALESCE(SUM(original_size), 0) AS total_used, COUNT(*) AS file_count FROM files WHERE owner_id = ? AND status NOT IN ('deleted')",
                    (account_id,)
                ).fetchone()
                used_bytes = int(row_used["total_used"]) if row_used else 0
                file_count = int(row_used["file_count"]) if row_used else 0

            # 3. Active unexpired reservations
            row_res = c.execute(
                "SELECT COALESCE(SUM(reserved_bytes), 0) AS total_reserved FROM account_quota_reservations WHERE account_id = ? AND status = 'active' AND expires_at >= ?",
                (account_id, now_str)
            ).fetchone()
            reserved_bytes = int(row_res["total_reserved"]) if row_res else 0

            available_bytes = max(0, quota_bytes - used_bytes - reserved_bytes)

            return {
                "account_id": account_id,
                "quota_bytes": quota_bytes,
                "used_bytes": used_bytes,
                "reserved_bytes": reserved_bytes,
                "available_bytes": available_bytes,
                "file_count": file_count,
                "policy": policy,
            }

        if conn is not None:
            return _query(conn)
        with get_db_connection(self.db_path) as conn_owned:
            return _query(conn_owned)

    def reserve_quota(
        self,
        account_id: str,
        requested_bytes: int,
        file_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """
        Atomically reserves storage capacity for an in-flight upload.
        Guarantees that concurrent requests across multiple threads and processes
        cannot exceed the configured account quota using SQLite BEGIN IMMEDIATE.
        """
        requested_bytes = max(0, int(requested_bytes))
        reservation_id = str(uuid.uuid4())
        ttl = ttl_seconds or getattr(self.settings, "account_reservation_ttl_seconds", 300)
        now = self._now_utc()
        now_str = now.isoformat()
        expires_str = (now + timedelta(seconds=ttl)).isoformat()
        default_quota = getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024)

        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # 1. Recover expired reservations for this account
                conn.execute(
                    "UPDATE account_quota_reservations SET status = 'expired' WHERE account_id = ? AND status = 'active' AND expires_at < ?",
                    (account_id, now_str)
                )

                # 2. Get account limit
                quota_bytes = default_quota
                acc_row = conn.execute(
                    "SELECT quota_bytes FROM accounts WHERE account_id = ?",
                    (account_id,)
                ).fetchone()
                if acc_row and "quota_bytes" in acc_row.keys() and acc_row["quota_bytes"] is not None:
                    quota_bytes = int(acc_row["quota_bytes"])

                # 3. Get committed used bytes
                row_used = conn.execute(
                    "SELECT COALESCE(SUM(original_size), 0) AS total_used FROM files WHERE owner_id = ? AND status NOT IN ('deleted')",
                    (account_id,)
                ).fetchone()
                used_bytes = int(row_used["total_used"]) if row_used else 0

                # 4. Get active reservations excluding any previous reservation for this exact file_id (for retries)
                if file_id:
                    row_res = conn.execute(
                        "SELECT COALESCE(SUM(reserved_bytes), 0) AS total_reserved FROM account_quota_reservations WHERE account_id = ? AND file_id != ? AND status = 'active' AND expires_at >= ?",
                        (account_id, file_id, now_str)
                    ).fetchone()
                else:
                    row_res = conn.execute(
                        "SELECT COALESCE(SUM(reserved_bytes), 0) AS total_reserved FROM account_quota_reservations WHERE account_id = ? AND status = 'active' AND expires_at >= ?",
                        (account_id, now_str)
                    ).fetchone()
                reserved_bytes = int(row_res["total_reserved"]) if row_res else 0

                # 5. Check quota limit
                if used_bytes + reserved_bytes + requested_bytes > quota_bytes:
                    avail = max(0, quota_bytes - used_bytes - reserved_bytes)
                    conn.execute("ROLLBACK")
                    raise QuotaExceededError(
                        f"Account quota exceeded: requested {requested_bytes} bytes, "
                        f"but only {avail} bytes available (Quota: {quota_bytes}, Used: {used_bytes}, Reserved: {reserved_bytes})."
                    )

                # 6. If re-reserving for the same file_id, release prior active reservation
                if file_id:
                    conn.execute(
                        "UPDATE account_quota_reservations SET status = 'released' WHERE account_id = ? AND file_id = ? AND status = 'active'",
                        (account_id, file_id)
                    )

                # 7. Insert new active reservation
                conn.execute(
                    """
                    INSERT INTO account_quota_reservations (
                        reservation_id, account_id, file_id, reserved_bytes, created_at, expires_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, 'active')
                    """,
                    (reservation_id, account_id, file_id, requested_bytes, now_str, expires_str)
                )

                conn.execute("COMMIT")
                return reservation_id

            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def commit_reservation(
        self,
        account_id: str,
        file_id: str,
        actual_size: int,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        """
        Commits an upload reservation upon successful catalog manifest registration.
        If no reservation was held, verifies that registering the file does not exceed quota.
        """
        now_str = self._now_str()
        default_quota = getattr(self.settings, "default_account_quota_bytes", 10 * 1024 * 1024 * 1024)

        def _do_commit(c: sqlite3.Connection):
            # Find active reservation for this file
            row = c.execute(
                "SELECT reservation_id, reserved_bytes FROM account_quota_reservations WHERE account_id = ? AND file_id = ? AND status = 'active' AND expires_at >= ?",
                (account_id, file_id, now_str)
            ).fetchone()

            if row:
                # Mark as committed
                c.execute(
                    "UPDATE account_quota_reservations SET status = 'committed' WHERE reservation_id = ?",
                    (row["reservation_id"],)
                )
            else:
                # No active reservation: verify account limit directly
                quota_bytes = default_quota
                acc_row = c.execute(
                    "SELECT quota_bytes FROM accounts WHERE account_id = ?",
                    (account_id,)
                ).fetchone()
                if acc_row and "quota_bytes" in acc_row.keys() and acc_row["quota_bytes"] is not None:
                    quota_bytes = int(acc_row["quota_bytes"])

                row_used = c.execute(
                    "SELECT COALESCE(SUM(original_size), 0) AS total_used FROM files WHERE owner_id = ? AND status NOT IN ('deleted')",
                    (account_id,)
                ).fetchone()
                used_bytes = int(row_used["total_used"]) if row_used else 0

                row_res = c.execute(
                    "SELECT COALESCE(SUM(reserved_bytes), 0) AS total_reserved FROM account_quota_reservations WHERE account_id = ? AND status = 'active' AND expires_at >= ?",
                    (account_id, now_str)
                ).fetchone()
                reserved_bytes = int(row_res["total_reserved"]) if row_res else 0

                if used_bytes + reserved_bytes + actual_size > quota_bytes:
                    avail = max(0, quota_bytes - used_bytes - reserved_bytes)
                    raise QuotaExceededError(
                        f"Account quota exceeded: registering {actual_size} bytes exceeds available quota ({avail} bytes)."
                    )

        if conn is not None:
            _do_commit(conn)
        else:
            with get_db_connection(self.db_path) as conn_owned:
                conn_owned.execute("BEGIN IMMEDIATE")
                try:
                    _do_commit(conn_owned)
                    conn_owned.execute("COMMIT")
                except Exception:
                    try:
                        conn_owned.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise

    def release_reservation(
        self,
        reservation_id: Optional[str] = None,
        account_id: Optional[str] = None,
        file_id: Optional[str] = None,
    ) -> int:
        """
        Releases an active quota reservation upon upload failure or client abort.
        """
        if not reservation_id and not (account_id and file_id):
            return 0

        with get_db_connection(self.db_path) as conn:
            if reservation_id:
                cursor = conn.execute(
                    "UPDATE account_quota_reservations SET status = 'released' WHERE reservation_id = ? AND status = 'active'",
                    (reservation_id,)
                )
            else:
                cursor = conn.execute(
                    "UPDATE account_quota_reservations SET status = 'released' WHERE account_id = ? AND file_id = ? AND status = 'active'",
                    (account_id, file_id)
                )
            conn.commit()
            return cursor.rowcount

    def update_account_quota(self, account_id: str, new_quota_bytes: int) -> bool:
        """Updates the total storage quota limit configured for an account."""
        now_str = self._now_str()
        new_quota_bytes = max(0, int(new_quota_bytes))
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE accounts SET quota_bytes = ?, updated_at = ? WHERE account_id = ?",
                (new_quota_bytes, now_str, account_id.strip())
            )
            conn.commit()
            return cursor.rowcount > 0
