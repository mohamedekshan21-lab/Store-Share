"""
Phase 7A: Bandwidth and Capacity Metering Service for Expo Coordinator.
Provides reliable, persistent, auditable accounting of storage capacity,
data volume, bandwidth transfers, node uptime, and self-healing operations.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.models import (
    CapacitySnapshotRecord,
    TransferEventRecord,
    TransferEventCreateRequest,
    HeartbeatObservationRecord,
    OperationEventRecord,
    OperationEventCreateRequest,
    NodeUptimeSummary,
    NodeContributionSummary,
    ClusterMeteringSummary,
)

logger = logging.getLogger("expo_metering")


class MeteringService:
    """Core metering engine for tracking capacity, transfers, uptime, and recovery contributions."""

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path
        init_db(self.db_path)

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _parse_iso(self, ts_str: str) -> datetime:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Capacity Snapshots
    # -------------------------------------------------------------------------

    def record_capacity_snapshot(
        self,
        node_id: str,
        total_quota_bytes: int,
        used_bytes: int,
        remaining_quota_bytes: Optional[int] = None,
        physical_total_bytes: Optional[int] = None,
        physical_free_bytes: Optional[int] = None,
        source: str = "heartbeat",
        is_valid: bool = True,
        timestamp: Optional[str] = None,
    ) -> CapacitySnapshotRecord:
        """
        Records an auditable point-in-time capacity snapshot.
        Configured Expo quota is strictly separated from physical host disk capacity.
        """
        snap_id = f"snap-{uuid.uuid4().hex[:12]}"
        measured_at = timestamp or self._now_iso()
        remaining = (
            remaining_quota_bytes
            if remaining_quota_bytes is not None
            else max(0, total_quota_bytes - used_bytes)
        )

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO node_capacity_snapshots (
                    snapshot_id, node_id, total_quota_bytes, used_bytes,
                    remaining_quota_bytes, physical_total_bytes, physical_free_bytes,
                    measured_at, source, is_valid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snap_id,
                    node_id,
                    total_quota_bytes,
                    used_bytes,
                    remaining,
                    physical_total_bytes,
                    physical_free_bytes,
                    measured_at,
                    source,
                    1 if is_valid else 0,
                ),
            )
            conn.commit()

        return CapacitySnapshotRecord(
            snapshot_id=snap_id,
            node_id=node_id,
            total_quota_bytes=total_quota_bytes,
            used_bytes=used_bytes,
            remaining_quota_bytes=remaining,
            physical_total_bytes=physical_total_bytes,
            physical_free_bytes=physical_free_bytes,
            measured_at=measured_at,
            source=source,
            is_valid=is_valid,
        )

    def get_capacity_snapshots(
        self, node_id: Optional[str] = None, limit: int = 100
    ) -> List[CapacitySnapshotRecord]:
        """Retrieves capacity snapshots, optionally filtered by node_id."""
        with get_db_connection(self.db_path) as conn:
            if node_id:
                cursor = conn.execute(
                    """
                    SELECT * FROM node_capacity_snapshots
                    WHERE node_id = ?
                    ORDER BY measured_at DESC LIMIT ?
                    """,
                    (node_id, limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM node_capacity_snapshots
                    ORDER BY measured_at DESC LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()

        return [
            CapacitySnapshotRecord(
                snapshot_id=r["snapshot_id"],
                node_id=r["node_id"],
                total_quota_bytes=r["total_quota_bytes"],
                used_bytes=r["used_bytes"],
                remaining_quota_bytes=r["remaining_quota_bytes"],
                physical_total_bytes=r["physical_total_bytes"],
                physical_free_bytes=r["physical_free_bytes"],
                measured_at=r["measured_at"],
                source=r["source"],
                is_valid=bool(r["is_valid"]),
            )
            for r in rows
        ]

    # -------------------------------------------------------------------------
    # 2. Transfer Events (Bandwidth Ingress / Egress)
    # -------------------------------------------------------------------------

    def record_transfer_event(
        self,
        node_id: str,
        direction: str,
        operation_type: str,
        payload_bytes: int,
        chunk_id: Optional[str] = None,
        file_id: Optional[str] = None,
        status: str = "success",
        idempotency_key: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> TransferEventRecord:
        """
        Records a completed bandwidth transfer event.
        Guarantees idempotency: duplicate events with the same idempotency_key
        are returned without duplicate accounting or raising an error.
        """
        if payload_bytes < 0:
            raise ValueError("Payload bytes cannot be negative")

        clean_dir = direction.lower().strip()
        if clean_dir not in ("upload", "download"):
            clean_dir = "upload" if "up" in clean_dir or "in" in clean_dir else "download"

        clean_status = status.lower().strip()
        if clean_status not in ("success", "failed", "cancelled"):
            clean_status = "success"

        ts = timestamp or self._now_iso()
        idem_key = (
            idempotency_key.strip()
            if idempotency_key and idempotency_key.strip()
            else f"tx-{uuid.uuid4().hex}"
        )

        with get_db_connection(self.db_path) as conn:
            # Check for existing event by idempotency key
            existing = conn.execute(
                "SELECT * FROM metering_transfer_events WHERE idempotency_key = ?",
                (idem_key,),
            ).fetchone()

            if existing:
                return TransferEventRecord(
                    event_id=existing["event_id"],
                    node_id=existing["node_id"],
                    direction=existing["direction"],
                    operation_type=existing["operation_type"],
                    payload_bytes=existing["payload_bytes"],
                    chunk_id=existing["chunk_id"],
                    file_id=existing["file_id"],
                    status=existing["status"],
                    timestamp=existing["timestamp"],
                    idempotency_key=existing["idempotency_key"],
                )

            event_id = f"evt-{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO metering_transfer_events (
                    event_id, node_id, direction, operation_type,
                    payload_bytes, chunk_id, file_id, status,
                    timestamp, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    node_id,
                    clean_dir,
                    operation_type,
                    payload_bytes,
                    chunk_id,
                    file_id,
                    clean_status,
                    ts,
                    idem_key,
                ),
            )
            conn.commit()

        return TransferEventRecord(
            event_id=event_id,
            node_id=node_id,
            direction=clean_dir,
            operation_type=operation_type,
            payload_bytes=payload_bytes,
            chunk_id=chunk_id,
            file_id=file_id,
            status=clean_status,
            timestamp=ts,
            idempotency_key=idem_key,
        )

    def get_transfer_events(
        self,
        node_id: Optional[str] = None,
        direction: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
    ) -> List[TransferEventRecord]:
        """Queries transfer events with optional filtering."""
        query = "SELECT * FROM metering_transfer_events WHERE 1=1"
        params: List[Any] = []

        if node_id:
            query += " AND node_id = ?"
            params.append(node_id)
        if direction:
            query += " AND direction = ?"
            params.append(direction.lower().strip())
        if status:
            query += " AND status = ?"
            params.append(status.lower().strip())
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        return [
            TransferEventRecord(
                event_id=r["event_id"],
                node_id=r["node_id"],
                direction=r["direction"],
                operation_type=r["operation_type"],
                payload_bytes=r["payload_bytes"],
                chunk_id=r["chunk_id"],
                file_id=r["file_id"],
                status=r["status"],
                timestamp=r["timestamp"],
                idempotency_key=r["idempotency_key"],
            )
            for r in rows
        ]

    # -------------------------------------------------------------------------
    # 3. Heartbeat Observations & Uptime Calculation
    # -------------------------------------------------------------------------

    def record_heartbeat_observation(
        self,
        node_id: str,
        reported_status: str = "online",
        response_time_ms: Optional[float] = None,
        observed_at: Optional[str] = None,
    ) -> HeartbeatObservationRecord:
        """Records a timestamped liveness heartbeat observation."""
        obs_id = f"hb-{uuid.uuid4().hex[:12]}"
        ts = observed_at or self._now_iso()

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO node_heartbeat_observations (
                    observation_id, node_id, observed_at, reported_status, response_time_ms
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (obs_id, node_id, ts, reported_status.lower(), response_time_ms),
            )
            conn.commit()

        return HeartbeatObservationRecord(
            observation_id=obs_id,
            node_id=node_id,
            observed_at=ts,
            reported_status=reported_status.lower(),
            response_time_ms=response_time_ms,
        )

    def calculate_node_uptime(
        self,
        node_id: str,
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
    ) -> NodeUptimeSummary:
        """
        Calculates observed online duration, offline duration, and availability percentage
        over the evaluated time window based on heartbeat intervals and registration time.
        """
        now = datetime.now(timezone.utc)
        w_end_dt = self._parse_iso(window_end) if window_end else now
        w_start_dt = self._parse_iso(window_start) if window_start else (w_end_dt - timedelta(hours=24))

        if w_start_dt >= w_end_dt:
            w_start_dt = w_end_dt - timedelta(hours=1)

        total_window_seconds = max(1.0, (w_end_dt - w_start_dt).total_seconds())
        timeout_seconds = float(self.settings.heartbeat_timeout_seconds)

        with get_db_connection(self.db_path) as conn:
            # Check node registration time
            node_row = conn.execute(
                "SELECT registered_at, last_seen, status FROM nodes WHERE node_id = ?",
                (node_id,),
            ).fetchone()

            if not node_row:
                return NodeUptimeSummary(
                    node_id=node_id,
                    window_start=w_start_dt.isoformat(),
                    window_end=w_end_dt.isoformat(),
                    observed_online_seconds=0.0,
                    observed_offline_seconds=total_window_seconds,
                    observed_unknown_seconds=0.0,
                    availability_percentage=0.0,
                    last_successful_heartbeat=None,
                    total_heartbeats_count=0,
                )

            reg_dt = self._parse_iso(node_row["registered_at"])

            # Query observations in window (plus one observation before window if exists)
            obs_rows = conn.execute(
                """
                SELECT observed_at, reported_status FROM node_heartbeat_observations
                WHERE node_id = ? AND observed_at <= ?
                ORDER BY observed_at ASC
                """,
                (node_id, w_end_dt.isoformat()),
            ).fetchall()

            # Effective node creation time is min of registered_at and earliest observation
            earliest_obs = self._parse_iso(obs_rows[0]["observed_at"]) if obs_rows else reg_dt
            node_birth = min(reg_dt, earliest_obs)

            effective_start = max(w_start_dt, node_birth)
            unknown_seconds = max(0.0, (effective_start - w_start_dt).total_seconds())

        if not obs_rows:
            # No observations in DB, use current node status and last_seen
            last_seen_dt = self._parse_iso(node_row["last_seen"])
            elapsed = (w_end_dt - last_seen_dt).total_seconds()
            is_online = elapsed <= timeout_seconds and node_row["status"].lower() == "online"

            eval_seconds = max(0.0, total_window_seconds - unknown_seconds)
            online_sec = eval_seconds if is_online else 0.0
            offline_sec = eval_seconds if not is_online else 0.0
            avail = (online_sec / max(1.0, online_sec + offline_sec)) * 100.0

            return NodeUptimeSummary(
                node_id=node_id,
                window_start=w_start_dt.isoformat(),
                window_end=w_end_dt.isoformat(),
                observed_online_seconds=round(online_sec, 2),
                observed_offline_seconds=round(offline_sec, 2),
                observed_unknown_seconds=round(unknown_seconds, 2),
                availability_percentage=round(avail, 2),
                last_successful_heartbeat=node_row["last_seen"],
                total_heartbeats_count=0,
            )

        # Parse observations that fall within or bound the window
        timestamps = [self._parse_iso(r["observed_at"]) for r in obs_rows]
        last_hb_str = timestamps[-1].isoformat()

        online_seconds = 0.0
        offline_seconds = 0.0

        # Process interval from effective_start to first observation
        first_obs = timestamps[0]
        if first_obs > effective_start:
            gap = (first_obs - effective_start).total_seconds()
            if gap <= timeout_seconds:
                online_seconds += gap
            else:
                online_seconds += timeout_seconds
                offline_seconds += (gap - timeout_seconds)

        # Process successive observations
        for i in range(len(timestamps) - 1):
            t1 = timestamps[i]
            t2 = timestamps[i + 1]

            # Clip interval to [effective_start, w_end_dt]
            seg_start = max(effective_start, t1)
            seg_end = min(w_end_dt, t2)
            if seg_end > seg_start:
                interval = (t2 - t1).total_seconds()
                overlap = (seg_end - seg_start).total_seconds()
                if interval <= timeout_seconds:
                    online_seconds += overlap
                else:
                    # Heartbeat timed out during this gap
                    online_fraction = min(overlap, timeout_seconds)
                    online_seconds += online_fraction
                    offline_seconds += max(0.0, overlap - online_fraction)

        # Process tail from last observation to w_end_dt
        last_obs = timestamps[-1]
        if last_obs < w_end_dt:
            tail_gap = (w_end_dt - last_obs).total_seconds()
            if tail_gap <= timeout_seconds:
                online_seconds += tail_gap
            else:
                online_seconds += timeout_seconds
                offline_seconds += (tail_gap - timeout_seconds)

        eval_total = online_seconds + offline_seconds
        if eval_total <= 0:
            avail_pct = 100.0 if node_row["status"].lower() == "online" else 0.0
        else:
            avail_pct = (online_seconds / eval_total) * 100.0

        return NodeUptimeSummary(
            node_id=node_id,
            window_start=w_start_dt.isoformat(),
            window_end=w_end_dt.isoformat(),
            observed_online_seconds=round(online_seconds, 2),
            observed_offline_seconds=round(offline_seconds, 2),
            observed_unknown_seconds=round(unknown_seconds, 2),
            availability_percentage=round(min(100.0, max(0.0, avail_pct)), 2),
            last_successful_heartbeat=last_hb_str,
            total_heartbeats_count=len(timestamps),
        )

    # -------------------------------------------------------------------------
    # 4. Repair & Replication Operations
    # -------------------------------------------------------------------------

    def record_operation_event(
        self,
        operation_type: str,
        target_node_id: str,
        payload_bytes: int,
        source_node_id: Optional[str] = None,
        chunk_id: Optional[str] = None,
        status: str = "completed",
        completed_at: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> OperationEventRecord:
        """
        Records a completed replication or repair event.
        Guarantees idempotency via idempotency_key.
        Only 'completed' operations contribute to successful recovery totals.
        """
        if payload_bytes < 0:
            raise ValueError("Payload bytes cannot be negative")

        clean_op = operation_type.lower().strip()
        clean_status = status.lower().strip()
        ts = completed_at or self._now_iso()
        idem_key = (
            idempotency_key.strip()
            if idempotency_key and idempotency_key.strip()
            else f"op-{uuid.uuid4().hex}"
        )

        with get_db_connection(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM metering_operation_events WHERE idempotency_key = ?",
                (idem_key,),
            ).fetchone()

            if existing:
                return OperationEventRecord(
                    operation_id=existing["operation_id"],
                    operation_type=existing["operation_type"],
                    source_node_id=existing["source_node_id"],
                    target_node_id=existing["target_node_id"],
                    chunk_id=existing["chunk_id"],
                    payload_bytes=existing["payload_bytes"],
                    status=existing["status"],
                    completed_at=existing["completed_at"],
                    duration_seconds=existing["duration_seconds"],
                    idempotency_key=existing["idempotency_key"],
                )

            op_id = f"op-{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO metering_operation_events (
                    operation_id, operation_type, source_node_id, target_node_id,
                    chunk_id, payload_bytes, status, completed_at, duration_seconds, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    op_id,
                    clean_op,
                    source_node_id,
                    target_node_id,
                    chunk_id,
                    payload_bytes,
                    clean_status,
                    ts,
                    duration_seconds,
                    idem_key,
                ),
            )
            conn.commit()

        return OperationEventRecord(
            operation_id=op_id,
            operation_type=clean_op,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            chunk_id=chunk_id,
            payload_bytes=payload_bytes,
            status=clean_status,
            completed_at=ts,
            duration_seconds=duration_seconds,
            idempotency_key=idem_key,
        )

    def get_operation_events(
        self,
        node_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[OperationEventRecord]:
        """Queries replication and repair operations."""
        query = "SELECT * FROM metering_operation_events WHERE 1=1"
        params: List[Any] = []

        if node_id:
            query += " AND (target_node_id = ? OR source_node_id = ?)"
            params.extend([node_id, node_id])
        if operation_type:
            query += " AND operation_type = ?"
            params.append(operation_type.lower().strip())
        if status:
            query += " AND status = ?"
            params.append(status.lower().strip())

        query += " ORDER BY completed_at DESC LIMIT ?"
        params.append(limit)

        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        return [
            OperationEventRecord(
                operation_id=r["operation_id"],
                operation_type=r["operation_type"],
                source_node_id=r["source_node_id"],
                target_node_id=r["target_node_id"],
                chunk_id=r["chunk_id"],
                payload_bytes=r["payload_bytes"],
                status=r["status"],
                completed_at=r["completed_at"],
                duration_seconds=r["duration_seconds"],
                idempotency_key=r["idempotency_key"],
            )
            for r in rows
        ]

    # -------------------------------------------------------------------------
    # 5. Authoritative Storage & Contribution Summaries
    # -------------------------------------------------------------------------

    def calculate_authoritative_stored_bytes(self, node_id: str) -> int:
        """
        Calculates authoritative storage used by parsing active manifests in the catalog.
        Aggregates DISTINCT chunks/shards assigned to this node, avoiding double counting.
        """
        total_stored = 0
        counted_chunks = set()

        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT manifest_json FROM files WHERE status NOT IN ('deleted')"
            )
            rows = cursor.fetchall()

        for r in rows:
            raw_manifest = r["manifest_json"]
            if not raw_manifest:
                continue
            try:
                manifest = json.loads(raw_manifest)
            except Exception:
                continue

            for chunk in manifest.get("chunks", []):
                chunk_size = chunk.get("size_bytes", 0)
                # Replicated chunk placements
                for placement in chunk.get("placements", []):
                    if placement.get("node_id") == node_id:
                        cid = placement.get("chunk_id") or chunk.get("chunk_id")
                        if cid and (node_id, cid) not in counted_chunks:
                            counted_chunks.add((node_id, cid))
                            total_stored += chunk_size

                # Erasure-coded shards
                for shard in chunk.get("shards", []):
                    if shard.get("node_id") == node_id:
                        sid = shard.get("shard_id")
                        shard_size = shard.get("size_bytes", chunk_size)
                        if sid and (node_id, sid) not in counted_chunks:
                            counted_chunks.add((node_id, sid))
                            total_stored += shard_size

        return total_stored

    def get_node_summary(
        self, node_id: str, window_hours: float = 24.0
    ) -> NodeContributionSummary:
        """
        Aggregates a complete contribution summary for a single storage node:
        - Configured Expo quota vs physical host disk
        - Current used bytes (authoritative catalog placements or snapshot)
        - Lifetime transfer totals (ingress / egress)
        - Uptime percentage
        - Completed replication/repair operations
        """
        with get_db_connection(self.db_path) as conn:
            node_row = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?", (node_id,)
            ).fetchone()

        if not node_row:
            raise KeyError(f"Storage Node '{node_id}' not found in registry.")

        # Latest capacity snapshot
        snapshots = self.get_capacity_snapshots(node_id, limit=1)
        latest_snap = snapshots[0] if snapshots else None

        quota = (
            latest_snap.total_quota_bytes
            if latest_snap
            else node_row["total_capacity_bytes"]
        )
        phys_total = latest_snap.physical_total_bytes if latest_snap else None
        phys_free = latest_snap.physical_free_bytes if latest_snap else None

        # Authoritative catalog storage usage
        authoritative_used = self.calculate_authoritative_stored_bytes(node_id)
        # If no files in catalog yet, fall back to snapshot or node reported used
        current_used = (
            authoritative_used
            if authoritative_used > 0
            else (latest_snap.used_bytes if latest_snap else node_row["used_capacity_bytes"])
        )
        remaining = max(0, quota - current_used)

        # Lifetime transfers
        with get_db_connection(self.db_path) as conn:
            tx_stats = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN direction = 'upload' AND status = 'success' THEN payload_bytes ELSE 0 END) AS ingress,
                    SUM(CASE WHEN direction = 'download' AND status = 'success' THEN payload_bytes ELSE 0 END) AS egress
                FROM metering_transfer_events
                WHERE node_id = ?
                """,
                (node_id,),
            ).fetchone()

            ingress_bytes = int(tx_stats["ingress"] or 0)
            egress_bytes = int(tx_stats["egress"] or 0)

            # Successful operations
            op_stats = conn.execute(
                """
                SELECT
                    COUNT(*) AS op_count,
                    COALESCE(SUM(payload_bytes), 0) AS op_bytes
                FROM metering_operation_events
                WHERE (target_node_id = ? OR source_node_id = ?) AND status = 'completed'
                """,
                (node_id, node_id),
            ).fetchone()

            op_count = int(op_stats["op_count"] or 0)
            op_bytes = int(op_stats["op_bytes"] or 0)

        # Uptime over window
        w_end = datetime.now(timezone.utc)
        w_start = w_end - timedelta(hours=window_hours)
        uptime_summary = self.calculate_node_uptime(
            node_id,
            window_start=w_start.isoformat(),
            window_end=w_end.isoformat(),
        )

        return NodeContributionSummary(
            node_id=node_id,
            configured_quota_bytes=quota,
            current_used_bytes=current_used,
            remaining_quota_bytes=remaining,
            physical_disk_total_bytes=phys_total,
            physical_disk_free_bytes=phys_free,
            lifetime_ingress_bytes=ingress_bytes,
            lifetime_egress_bytes=egress_bytes,
            lifetime_transfer_bytes=ingress_bytes + egress_bytes,
            availability_percentage=uptime_summary.availability_percentage,
            uptime_window_start=w_start.isoformat(),
            uptime_window_end=w_end.isoformat(),
            successful_operations_count=op_count,
            successful_operations_bytes=op_bytes,
            last_seen=node_row["last_seen"],
            status=node_row["status"],
        )

    def get_cluster_summary(self, window_hours: float = 24.0) -> ClusterMeteringSummary:
        """Aggregates cluster-wide capacity, bandwidth, recovery, and availability totals."""
        with get_db_connection(self.db_path) as conn:
            nodes = conn.execute("SELECT node_id, status FROM nodes").fetchall()

            total_nodes = len(nodes)
            timeout = self.settings.heartbeat_timeout_seconds
            now = datetime.now(timezone.utc)

            online_nodes = 0
            for n in nodes:
                st = n["status"].lower()
                if st == "online":
                    online_nodes += 1

            # Cumulative transfers across all nodes
            tx_totals = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN direction = 'upload' AND status = 'success' THEN payload_bytes ELSE 0 END) AS ingress,
                    SUM(CASE WHEN direction = 'download' AND status = 'success' THEN payload_bytes ELSE 0 END) AS egress
                FROM metering_transfer_events
                """
            ).fetchone()
            total_ingress = int(tx_totals["ingress"] or 0)
            total_egress = int(tx_totals["egress"] or 0)

            # Cumulative operations
            op_totals = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN operation_type = 'replication' AND status = 'completed' THEN 1 ELSE 0 END) AS reps,
                    SUM(CASE WHEN operation_type = 'repair' AND status = 'completed' THEN 1 ELSE 0 END) AS reps_repair
                FROM metering_operation_events
                """
            ).fetchone()
            replications_count = int(op_totals["reps"] or 0)
            repairs_count = int(op_totals["reps_repair"] or 0)

        # Quota and used storage
        total_quota = 0
        total_used = 0
        avail_list: List[float] = []

        w_end = datetime.now(timezone.utc)
        w_start = w_end - timedelta(hours=window_hours)

        for n in nodes:
            nid = n["node_id"]
            try:
                summary = self.get_node_summary(nid, window_hours=window_hours)
                total_quota += summary.configured_quota_bytes
                total_used += summary.current_used_bytes
                avail_list.append(summary.availability_percentage)
            except Exception:
                continue

        avg_avail = sum(avail_list) / len(avail_list) if avail_list else 100.0
        remaining_quota = max(0, total_quota - total_used)

        return ClusterMeteringSummary(
            total_nodes_count=total_nodes,
            online_nodes_count=online_nodes,
            total_contributed_quota_bytes=total_quota,
            total_used_bytes=total_used,
            total_remaining_quota_bytes=remaining_quota,
            total_ingress_bytes=total_ingress,
            total_egress_bytes=total_egress,
            total_transfer_bytes=total_ingress + total_egress,
            total_replications_completed=replications_count,
            total_repairs_completed=repairs_count,
            average_availability_percentage=round(avg_avail, 2),
        )
