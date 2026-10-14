"""
NodeRegistry service for Expo Coordinator (Phase 2B).
Handles Storage Node registration, heartbeat processing, capacity validation,
offline status detection, connectivity capabilities, protocol versioning,
and smart node selection algorithms.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from urllib.parse import urlparse

from coordinator.app.config import CoordinatorSettings
from coordinator.app.database import get_db_connection, init_db
from coordinator.app.models import (
    NodeRegisterRequest,
    NodeHeartbeatRequest,
    NodeRecord,
)


def validate_port(port: int, field_name: str = "port") -> int:
    """Validates that a port is an integer in the valid TCP port range [1, 65535]."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Invalid {field_name}: {port}. Port must be an integer between 1 and 65535.")
    return port


def validate_endpoint_url(url: str, field_name: str = "endpoint") -> str:
    """
    Validates URL syntax for an endpoint:
    - Must not be empty
    - Must have http or https scheme
    - Must have a netloc with a non-empty hostname
    - Must have a valid port in [1, 65535] if a port is present in the netloc
    - Rejects malformed URLs and unsupported schemes
    Returns clean normalized URL (without trailing slash).
    """
    clean_url = (url or "").strip()
    if not clean_url:
        raise ValueError(f"{field_name} cannot be empty.")

    try:
        parsed = urlparse(clean_url)
    except Exception as exc:
        raise ValueError(f"Malformed URL in {field_name} '{clean_url}': {exc}") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Invalid scheme in {field_name} '{clean_url}': scheme must be 'http' or 'https'."
        )

    if not parsed.netloc:
        raise ValueError(f"Invalid {field_name} '{clean_url}': missing host or netloc.")

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name} '{clean_url}': {exc}") from exc

    if not hostname:
        raise ValueError(f"Invalid {field_name} '{clean_url}': missing valid hostname or IP address.")

    if port is not None:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port in {field_name} '{clean_url}': port must be between 1 and 65535.")

    return clean_url.rstrip("/")


class NodeRegistryError(Exception):
    """Base exception for NodeRegistry errors."""


class NodeNotFoundError(NodeRegistryError):
    """Raised when a specified node_id is not found in the registry."""


class InvalidCapacityError(NodeRegistryError, ValueError):
    """Raised when provided capacity values are invalid or impossible."""


VALID_CONNECTIVITY_MODES = {"LAN", "DIRECT", "RELAY", "UNKNOWN"}
VALID_STATUSES = {
    "online",
    "offline",
    "connecting",
    "degraded",
    "disabled",
    "draining",
    "drain_blocked",
    "drained",
}


class NodeRegistry:
    """Manages node registration, heartbeats, status tracking, and node selection in SQLite."""

    def __init__(self, settings: CoordinatorSettings) -> None:
        self.settings = settings
        self.db_path = settings.db_path
        init_db(self.db_path)

    def _parse_iso_datetime(self, timestamp_str: str) -> datetime:
        """Parses an ISO 8601 timestamp string to a timezone-aware UTC datetime."""
        try:
            dt = datetime.fromisoformat(timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def _compute_node_status(self, raw_status: str, last_seen_str: str) -> str:
        """Calculates current node status based on configured heartbeat timeout."""
        clean_status = raw_status.lower() if raw_status else "online"
        last_seen_dt = self._parse_iso_datetime(last_seen_str)
        now_dt = datetime.now(timezone.utc)
        elapsed = (now_dt - last_seen_dt).total_seconds()

        if elapsed > self.settings.heartbeat_timeout_seconds:
            return "offline"
        return clean_status if clean_status in VALID_STATUSES else "online"

    def _validate_and_normalize_capacity(
        self,
        total: Optional[int],
        used: Optional[int],
        available: Optional[int],
        existing_total: Optional[int] = None,
    ) -> tuple[int, int, int]:
        """Validates and calculates total, used, and available capacity in bytes."""
        if total is not None:
            if total <= 0:
                raise InvalidCapacityError("Invalid capacity values: total_capacity_bytes must be greater than 0.")
            total_val = total
        elif existing_total is not None and existing_total > 0:
            total_val = existing_total
        else:
            # Default to 10 GB if unspecified
            total_val = 10 * 1024 * 1024 * 1024

        used_val = used if used is not None else 0

        # Calculate available capacity
        if available is not None:
            available_val = available
        else:
            available_val = total_val - used_val

        # Capacity validation rules:
        if total_val <= 0 or used_val < 0 or available_val < 0:
            raise InvalidCapacityError(
                "Invalid capacity values: total, used, and available capacity must be non-negative."
            )

        if used_val > total_val:
            raise InvalidCapacityError(
                f"Invalid capacity values: used capacity ({used_val}) cannot exceed total capacity ({total_val})."
            )

        calculated_available = max(0, total_val - used_val)

        return total_val, used_val, calculated_available

    def register_node(
        self,
        data: Optional[Any] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs
    ) -> NodeRecord:
        """Registers or updates a Storage Node in the registry (Idempotent)."""
        if isinstance(data, str):
            kwargs["node_id"] = data
            data = None
        if host is not None:
            kwargs["host"] = host
        if port is not None:
            kwargs["port"] = port
        if data is None:
            data = NodeRegisterRequest(**kwargs)

        node_id = data.node_id.strip()
        if not node_id:
            raise ValueError("node_id cannot be empty.")


        host = data.host.strip()
        if not host:
            raise ValueError("host cannot be empty.")
        port = validate_port(data.port, "port")

        raw_endpoint = data.endpoint.strip() if data.endpoint else f"http://{host}:{port}"
        endpoint = validate_endpoint_url(raw_endpoint, "endpoint")

        raw_adv_endpoint = data.advertised_endpoint.strip() if data.advertised_endpoint else endpoint
        adv_endpoint = validate_endpoint_url(raw_adv_endpoint, "advertised_endpoint")

        connectivity = (data.connectivity_mode or "LAN").strip().upper()
        if connectivity not in VALID_CONNECTIVITY_MODES:
            connectivity = "UNKNOWN"

        protocol = (data.protocol_version or "2B").strip()

        raw_total = data.total_capacity_bytes if data.total_capacity_bytes is not None else data.storage_capacity_bytes
        raw_used = data.used_capacity_bytes
        raw_available = data.available_capacity_bytes

        now_str = datetime.now(timezone.utc).isoformat()

        provider_id = (getattr(data, "provider_id", None) or kwargs.get("provider_id") or "default_provider").strip()
        is_schedulable = 1 if (getattr(data, "is_schedulable", True) if getattr(data, "is_schedulable", None) is not None else kwargs.get("is_schedulable", True)) else 0

        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT node_id, registered_at, total_capacity_bytes, provider_id, is_schedulable FROM nodes WHERE node_id = ?",
                (node_id,),
            )
            existing = cursor.fetchone()

            existing_total = existing["total_capacity_bytes"] if existing else None
            total_bytes, used_bytes, avail_bytes = self._validate_and_normalize_capacity(
                total=raw_total,
                used=raw_used,
                available=raw_available,
                existing_total=existing_total,
            )

            if existing:
                registered_at = existing["registered_at"]
                node_provider = existing["provider_id"] or provider_id
                node_sched = existing["is_schedulable"] if existing["is_schedulable"] is not None else is_schedulable
                conn.execute(
                    """
                    UPDATE nodes
                    SET host = ?,
                        port = ?,
                        endpoint = ?,
                        advertised_endpoint = ?,
                        status = 'online',
                        connectivity_mode = ?,
                        protocol_version = ?,
                        total_capacity_bytes = ?,
                        used_capacity_bytes = ?,
                        available_capacity_bytes = ?,
                        last_seen = ?,
                        provider_id = ?,
                        is_schedulable = ?
                    WHERE node_id = ?
                    """,
                    (
                        host,
                        port,
                        endpoint,
                        adv_endpoint,
                        connectivity,
                        protocol,
                        total_bytes,
                        used_bytes,
                        avail_bytes,
                        now_str,
                        node_provider,
                        node_sched,
                        node_id,
                    ),
                )
            else:
                registered_at = now_str
                node_provider = provider_id
                node_sched = is_schedulable
                conn.execute(
                    """
                    INSERT INTO nodes (
                        node_id, host, port, endpoint, advertised_endpoint, status,
                        connectivity_mode, protocol_version,
                        total_capacity_bytes, used_capacity_bytes, available_capacity_bytes,
                        last_seen, registered_at, provider_id, is_schedulable
                    ) VALUES (?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        host,
                        port,
                        endpoint,
                        adv_endpoint,
                        connectivity,
                        protocol,
                        total_bytes,
                        used_bytes,
                        avail_bytes,
                        now_str,
                        registered_at,
                        node_provider,
                        node_sched,
                    ),
                )

            conn.commit()

        # Phase 7A: Record initial heartbeat observation and capacity snapshot
        try:
            from coordinator.app.metering import MeteringService
            metering = MeteringService(self.settings)
            metering.record_heartbeat_observation(
                node_id=node_id,
                reported_status="online",
                observed_at=now_str,
            )
            metering.record_capacity_snapshot(
                node_id=node_id,
                total_quota_bytes=total_bytes,
                used_bytes=used_bytes,
                remaining_quota_bytes=avail_bytes,
                physical_total_bytes=getattr(data, "physical_total_bytes", None),
                physical_free_bytes=getattr(data, "physical_free_bytes", None),
                source="registration",
                timestamp=now_str,
            )
        except Exception:
            pass

        return NodeRecord(
            node_id=node_id,
            host=host,
            port=port,
            endpoint=endpoint,
            advertised_endpoint=adv_endpoint,
            status="online",
            connectivity_mode=connectivity,
            protocol_version=protocol,
            total_capacity_bytes=total_bytes,
            used_capacity_bytes=used_bytes,
            available_capacity_bytes=avail_bytes,
            last_seen=now_str,
            registered_at=registered_at,
            provider_id=node_provider,
            is_schedulable=bool(node_sched),
            drain_status="none",
        )

    def heartbeat(self, node_id: str, data: NodeHeartbeatRequest) -> NodeRecord:
        """Processes a liveness heartbeat and optional capacity/connectivity updates for a registered node."""
        clean_node_id = node_id.strip()
        now_str = datetime.now(timezone.utc).isoformat()
        heartbeat_timestamp = data.timestamp.strip() if data.timestamp else now_str

        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (clean_node_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise NodeNotFoundError(f"Node with ID '{clean_node_id}' is not registered.")

            existing_total = row["total_capacity_bytes"]
            
            raw_used = data.used_capacity_bytes if data.used_capacity_bytes is not None else data.used_bytes
            raw_avail = data.available_capacity_bytes if data.available_capacity_bytes is not None else data.available_bytes

            if raw_used is not None or raw_avail is not None:
                new_total, new_used, new_avail = self._validate_and_normalize_capacity(
                    total=existing_total,
                    used=raw_used if raw_used is not None else row["used_capacity_bytes"],
                    available=raw_avail,
                    existing_total=existing_total,
                )
            else:
                new_total = row["total_capacity_bytes"]
                new_used = row["used_capacity_bytes"]
                new_avail = row["available_capacity_bytes"]

            new_status = (data.status.lower() if data.status else "online")
            if new_status not in VALID_STATUSES:
                new_status = "online"

            new_connectivity = (data.connectivity_mode.strip().upper() if data.connectivity_mode else row["connectivity_mode"])
            if new_connectivity not in VALID_CONNECTIVITY_MODES:
                new_connectivity = row["connectivity_mode"]

            new_protocol = (data.protocol_version.strip() if data.protocol_version else row["protocol_version"])

            if data.endpoint and data.endpoint.strip():
                new_endpoint = validate_endpoint_url(data.endpoint.strip(), "endpoint")
            else:
                new_endpoint = row["endpoint"]

            if data.advertised_endpoint and data.advertised_endpoint.strip():
                new_adv_endpoint = validate_endpoint_url(data.advertised_endpoint.strip(), "advertised_endpoint")
            else:
                new_adv_endpoint = (row["advertised_endpoint"] or new_endpoint)

            conn.execute(
                """
                UPDATE nodes
                SET status = ?,
                    connectivity_mode = ?,
                    protocol_version = ?,
                    used_capacity_bytes = ?,
                    available_capacity_bytes = ?,
                    endpoint = ?,
                    advertised_endpoint = ?,
                    last_seen = ?
                WHERE node_id = ?
                """,
                (new_status, new_connectivity, new_protocol, new_used, new_avail, new_endpoint, new_adv_endpoint, heartbeat_timestamp, clean_node_id),
            )
            conn.commit()

        # Phase 7A: Record heartbeat observation and capacity snapshot
        try:
            from coordinator.app.metering import MeteringService
            metering = MeteringService(self.settings)
            metering.record_heartbeat_observation(
                node_id=clean_node_id,
                reported_status=new_status,
                observed_at=heartbeat_timestamp,
            )
            metering.record_capacity_snapshot(
                node_id=clean_node_id,
                total_quota_bytes=new_total,
                used_bytes=new_used,
                remaining_quota_bytes=new_avail,
                physical_total_bytes=getattr(data, "physical_total_bytes", None),
                physical_free_bytes=getattr(data, "physical_free_bytes", None),
                source="heartbeat",
                timestamp=heartbeat_timestamp,
            )
        except Exception:
            pass

        return NodeRecord(
                node_id=clean_node_id,
                host=row["host"],
                port=row["port"],
                endpoint=new_endpoint,
                advertised_endpoint=new_adv_endpoint,
                status=new_status,
                connectivity_mode=new_connectivity,
                protocol_version=new_protocol,
                total_capacity_bytes=new_total,
                used_capacity_bytes=new_used,
                available_capacity_bytes=new_avail,
                last_seen=heartbeat_timestamp,
                registered_at=row["registered_at"],
                provider_id=row["provider_id"] if "provider_id" in row.keys() and row["provider_id"] else "default_provider",
                is_schedulable=bool(row["is_schedulable"]) if "is_schedulable" in row.keys() and row["is_schedulable"] is not None else True,
            )

    def get_node(self, node_id: str) -> Optional[NodeRecord]:
        """Retrieves record for a specific node with evaluated heartbeat status."""
        clean_node_id = node_id.strip()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT * FROM nodes WHERE node_id = ?",
                (clean_node_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            computed_status = self._compute_node_status(row["status"], row["last_seen"])
            
            if computed_status != row["status"]:
                conn.execute(
                    "UPDATE nodes SET status = ? WHERE node_id = ?",
                    (computed_status, clean_node_id),
                )
                conn.commit()

            return NodeRecord(
                node_id=row["node_id"],
                host=row["host"],
                port=row["port"],
                endpoint=row["endpoint"],
                advertised_endpoint=row["advertised_endpoint"] or row["endpoint"],
                status=computed_status,
                connectivity_mode=row["connectivity_mode"] or "LAN",
                protocol_version=row["protocol_version"] or "2B",
                total_capacity_bytes=row["total_capacity_bytes"],
                used_capacity_bytes=row["used_capacity_bytes"],
                available_capacity_bytes=row["available_capacity_bytes"],
                last_seen=row["last_seen"],
                registered_at=row["registered_at"],
                provider_id=row["provider_id"] if "provider_id" in row.keys() and row["provider_id"] else "default_provider",
                is_schedulable=bool(row["is_schedulable"]) if "is_schedulable" in row.keys() and row["is_schedulable"] is not None else True,
                drain_status=row["drain_status"] if "drain_status" in row.keys() and row["drain_status"] else "none",
            )

    def list_nodes(
        self,
        status_filter: Optional[str] = None,
        connectivity_mode_filter: Optional[str] = None,
        min_available_bytes: Optional[int] = None,
    ) -> List[NodeRecord]:
        """Lists registered nodes with evaluated heartbeat status and advanced filtering."""
        results: List[NodeRecord] = []
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM nodes ORDER BY registered_at DESC")
            rows = cursor.fetchall()
            
            for row in rows:
                computed_status = self._compute_node_status(row["status"], row["last_seen"])
                
                if computed_status != row["status"]:
                    conn.execute(
                        "UPDATE nodes SET status = ? WHERE node_id = ?",
                        (computed_status, row["node_id"]),
                    )

                if status_filter:
                    clean_filter = status_filter.strip().lower()
                    if computed_status.lower() != clean_filter:
                        continue

                conn_mode = (row["connectivity_mode"] or "LAN").upper()
                if connectivity_mode_filter:
                    clean_conn_filter = connectivity_mode_filter.strip().upper()
                    if conn_mode != clean_conn_filter:
                        continue

                avail_bytes = row["available_capacity_bytes"]
                if min_available_bytes is not None and min_available_bytes > 0:
                    if avail_bytes < min_available_bytes:
                        continue

                results.append(
                    NodeRecord(
                        node_id=row["node_id"],
                        host=row["host"],
                        port=row["port"],
                        endpoint=row["endpoint"],
                        advertised_endpoint=row["advertised_endpoint"] or row["endpoint"],
                        status=computed_status,
                        connectivity_mode=conn_mode,
                        protocol_version=row["protocol_version"] or "2B",
                        total_capacity_bytes=row["total_capacity_bytes"],
                        used_capacity_bytes=row["used_capacity_bytes"],
                        available_capacity_bytes=avail_bytes,
                        last_seen=row["last_seen"],
                        registered_at=row["registered_at"],
                        provider_id=row["provider_id"] if "provider_id" in row.keys() and row["provider_id"] else "default_provider",
                        is_schedulable=bool(row["is_schedulable"]) if "is_schedulable" in row.keys() and row["is_schedulable"] is not None else True,
                        drain_status=row["drain_status"] if "drain_status" in row.keys() and row["drain_status"] else "none",
                    )
                )

            conn.commit()
            return results

    def select_node(
        self,
        required_bytes: int,
        online_only: bool = True,
        preferred_connectivity: Optional[str] = None,
    ) -> Optional[NodeRecord]:
        """Smart node selection algorithm: selects best eligible node based on capacity and connectivity."""
        status_filter = "online" if online_only else None
        candidates = self.list_nodes(
            status_filter=status_filter,
            min_available_bytes=required_bytes,
        )

        if not candidates:
            return None

        # Filter out nodes that have scheduling disabled or are draining/disabled
        schedulable_candidates = [c for c in candidates if c.is_schedulable and c.status == "online"]
        if not schedulable_candidates:
            return None

        pref = preferred_connectivity.strip().upper() if preferred_connectivity else None

        def selection_score(n: NodeRecord) -> tuple[int, int]:
            connectivity_match = 1 if (pref and n.connectivity_mode == pref) else 0
            return (connectivity_match, n.available_capacity_bytes)

        schedulable_candidates.sort(key=selection_score, reverse=True)
        return schedulable_candidates[0]

    def delete_node(self, node_id: str) -> bool:
        """Deletes a node record from the registry."""
        clean_node_id = node_id.strip()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM nodes WHERE node_id = ?", (clean_node_id,))
            conn.commit()
            return cursor.rowcount > 0

    def list_nodes_by_provider(self, provider_id: str) -> List[NodeRecord]:
        """Lists all registered nodes belonging to a specific provider."""
        all_nodes = self.list_nodes()
        clean_pid = provider_id.strip()
        return [n for n in all_nodes if n.provider_id == clean_pid]

    def set_node_scheduling(self, node_id: str, enabled: bool) -> NodeRecord:
        """Enables or disables future scheduling on a node."""
        clean_node_id = node_id.strip()
        val = 1 if enabled else 0
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE nodes SET is_schedulable = ? WHERE node_id = ?",
                (val, clean_node_id),
            )
            if cursor.rowcount == 0:
                raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
            conn.commit()
        node = self.get_node(clean_node_id)
        if not node:
            raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
        return node

    def set_node_status(self, node_id: str, new_status: str) -> NodeRecord:
        """Updates operational status for a node."""
        clean_node_id = node_id.strip()
        clean_status = new_status.strip().lower()
        if clean_status not in VALID_STATUSES:
            raise ValueError(f"Invalid node status '{clean_status}'.")
        sched = 0 if clean_status in ("disabled", "draining", "offline") else 1
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE nodes SET status = ?, is_schedulable = ? WHERE node_id = ?",
                (clean_status, sched, clean_node_id),
            )
            if cursor.rowcount == 0:
                raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
            conn.commit()
        node = self.get_node(clean_node_id)
        if not node:
            raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
        return node

    def set_node_drain_status(self, node_id: str, drain_status: str) -> NodeRecord:
        """Sets the durable drain lifecycle status of a node ('none', 'draining', 'drain_blocked', 'drained')."""
        clean_node_id = node_id.strip()
        clean_drain = drain_status.strip().lower()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE nodes SET drain_status = ? WHERE node_id = ?",
                (clean_drain, clean_node_id),
            )
            if cursor.rowcount == 0:
                raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
            conn.commit()
        node = self.get_node(clean_node_id)
        if not node:
            raise NodeNotFoundError(f"Node '{clean_node_id}' not found.")
        return node

