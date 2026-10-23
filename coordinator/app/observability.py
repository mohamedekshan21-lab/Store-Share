"""
Phase 10F: Observability, Metrics, Structured Logging, and Health Checking Subsystem.

Provides:
- Liveness (/health/live) and Readiness (/health/ready) checks with deep dependency inspection.
- Request correlation ID generation and propagation (X-Correlation-ID / X-Request-ID).
- Comprehensive operational metrics (/observability/metrics, /metrics).
- Exception handling and logging with zero credential/token leakage.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.database import get_db_connection
from coordinator.app.main import get_settings
from coordinator.app.models import (
    LivenessResponse,
    ReadinessResponse,
    ObservabilityMetricsResponse,
)

logger = logging.getLogger("expo_observability")

observability_router = APIRouter(tags=["Observability & Health"])


class ObservabilityMetricsTracker:
    """Thread-safe operational metrics collector for the Coordinator service."""

    def __init__(self) -> None:
        self.requests_total: int = 0
        self.requests_2xx: int = 0
        self.requests_3xx: int = 0
        self.requests_4xx: int = 0
        self.requests_5xx: int = 0
        self.total_duration_ms: float = 0.0
        self.quota_rejections_total: int = 0
        self.start_time: float = time.time()

    def record_request(self, status_code: int, duration_ms: float) -> None:
        self.requests_total += 1
        self.total_duration_ms += duration_ms

        if 200 <= status_code < 300:
            self.requests_2xx += 1
        elif 300 <= status_code < 400:
            self.requests_3xx += 1
        elif 400 <= status_code < 500:
            self.requests_4xx += 1
            if status_code == 403:
                # Potential quota or policy rejection
                pass
        elif status_code >= 500:
            self.requests_5xx += 1

    def record_quota_rejection(self) -> None:
        self.quota_rejections_total += 1

    def get_avg_latency_ms(self) -> float:
        if self.requests_total == 0:
            return 0.0
        return round(self.total_duration_ms / self.requests_total, 2)


# Global metrics tracker instance
metrics_tracker = ObservabilityMetricsTracker()


def get_metrics_tracker() -> ObservabilityMetricsTracker:
    return metrics_tracker


class CorrelationAndMetricsMiddleware(BaseHTTPMiddleware):
    """
    HTTP middleware that:
    1. Extracts or generates a UUID correlation ID (X-Correlation-ID / X-Request-ID).
    2. Attaches the correlation ID to request state and response headers.
    3. Records request counts and latency without logging sensitive data (tokens, passwords).
    """

    async def dispatch(self, request: Request, call_next):
        corr_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        request.state.correlation_id = corr_id

        start_time = time.perf_counter()
        status_code = 500

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Correlation-ID"] = corr_id
            response.headers["X-Request-ID"] = corr_id
            return response
        except Exception as exc:
            # Safe structured logging without logging request bodies/tokens
            logger.error(
                "Unhandled request exception [corr_id=%s, method=%s, path=%s]: %s",
                corr_id,
                request.method,
                request.url.path,
                type(exc).__name__,
            )
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            metrics_tracker.record_request(status_code, elapsed_ms)


def resolve_settings(request: Request) -> CoordinatorSettings:
    if hasattr(request.app.state, "settings"):
        return request.app.state.settings
    return get_coordinator_settings()


# =============================================================================
# Liveness & Readiness Check Endpoints
# =============================================================================

@observability_router.get(
    "/health/live",
    response_model=LivenessResponse,
    summary="Coordinator Liveness Probe",
)
def liveness_check() -> LivenessResponse:
    """
    Liveness check indicating whether the Coordinator process is running and responsive.
    Does not verify external dependencies. Returns 200 OK.
    """
    now_str = datetime.now(timezone.utc).isoformat()
    return LivenessResponse(
        status="online",
        service="coordinator",
        timestamp=now_str,
    )


@observability_router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Coordinator Readiness Probe",
)
def readiness_check(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> ReadinessResponse:
    """
    Readiness check verifying that critical dependencies are operational:
    1. SQLite Database read/write connectivity.
    2. Active storage nodes availability.
    3. Pending/stalled background job queue health.

    Returns HTTP 200 OK when ready to serve traffic.
    Returns HTTP 503 Service Unavailable if database is unreachable or critical checks fail.
    """
    now_str = datetime.now(timezone.utc).isoformat()
    checks: Dict[str, Any] = {}
    is_ready = True
    failure_reasons = []

    # 1. Database Connectivity Check
    try:
        with get_db_connection(settings.db_path) as conn:
            cursor = conn.execute("SELECT 1 AS ping")
            ping_row = cursor.fetchone()
            if not ping_row or ping_row["ping"] != 1:
                raise RuntimeError("Database ping returned invalid result")
            checks["database"] = {
                "status": "healthy",
                "engine": "sqlite3",
                "path": str(settings.db_path.name),
            }
    except Exception as exc:
        is_ready = False
        failure_reasons.append("database_unreachable")
        checks["database"] = {
            "status": "failed",
            "error": type(exc).__name__,
        }
        logger.error("Readiness check: Database verification failed: %s", exc)

    # 2. Storage Node Connectivity Check
    if is_ready:
        try:
            with get_db_connection(settings.db_path) as conn:
                node_stats = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_nodes,
                        SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online_nodes,
                        SUM(CASE WHEN lifecycle_state = 'probation' THEN 1 ELSE 0 END) AS probation_nodes,
                        SUM(CASE WHEN status = 'unhealthy' THEN 1 ELSE 0 END) AS unhealthy_nodes
                    FROM nodes
                    """
                ).fetchone()
                total = int(node_stats["total_nodes"] or 0)
                online = int(node_stats["online_nodes"] or 0)
                probation = int(node_stats["probation_nodes"] or 0)
                unhealthy = int(node_stats["unhealthy_nodes"] or 0)

                checks["storage_nodes"] = {
                    "total": total,
                    "online": online,
                    "probation": probation,
                    "unhealthy": unhealthy,
                    "status": "healthy" if (online > 0 or settings.environment != "production") else "degraded",
                }

                # In strict production, require at least one online storage node
                if settings.environment == "production" and online == 0 and total > 0:
                    is_ready = False
                    failure_reasons.append("no_online_storage_nodes")
        except Exception as exc:
            checks["storage_nodes"] = {"status": "error", "error": type(exc).__name__}

    # 3. Background Jobs Health Check
    if is_ready:
        try:
            with get_db_connection(settings.db_path) as conn:
                pending_del = conn.execute(
                    "SELECT COUNT(*) AS c FROM deletion_jobs WHERE status IN ('pending', 'running')"
                ).fetchone()["c"]
                checks["background_jobs"] = {
                    "pending_or_running_deletions": int(pending_del or 0),
                    "status": "healthy",
                }
        except Exception:
            checks["background_jobs"] = {"status": "unknown"}

    if not is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "failures": failure_reasons,
                "checks": checks,
                "timestamp": now_str,
            },
        )

    return ReadinessResponse(
        status="ready",
        checks=checks,
        timestamp=now_str,
    )


# =============================================================================
# Observability Metrics Endpoints
# =============================================================================

@observability_router.get(
    "/observability/metrics",
    response_model=ObservabilityMetricsResponse,
    summary="Get Detailed Observability Metrics",
)
@observability_router.get(
    "/metrics",
    response_model=ObservabilityMetricsResponse,
    summary="Get Operational Metrics",
)
def get_metrics(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> ObservabilityMetricsResponse:
    """
    Returns comprehensive metrics for request volume, status codes, latency,
    storage nodes, capacity utilization, quota rejections, and background jobs.
    """
    now_str = datetime.now(timezone.utc).isoformat()
    req_stats = {
        "total": metrics_tracker.requests_total,
        "2xx": metrics_tracker.requests_2xx,
        "3xx": metrics_tracker.requests_3xx,
        "4xx": metrics_tracker.requests_4xx,
        "5xx": metrics_tracker.requests_5xx,
        "avg_latency_ms": metrics_tracker.get_avg_latency_ms(),
    }

    node_counts = {
        "total": 0,
        "online": 0,
        "offline": 0,
        "probation": 0,
        "unhealthy": 0,
        "draining": 0,
    }
    storage_bytes = {
        "total_capacity_bytes": 0,
        "used_capacity_bytes": 0,
        "available_capacity_bytes": 0,
        "verified_stored_bytes": 0,
    }
    job_counts = {
        "pending_deletions": 0,
        "repair_completed": 0,
        "repair_failed": 0,
        "repair_pending": 0,
    }
    active_sessions = 0

    try:
        with get_db_connection(settings.db_path) as conn:
            # Nodes
            rows = conn.execute("SELECT status, lifecycle_state, total_capacity_bytes, used_capacity_bytes, available_capacity_bytes FROM nodes").fetchall()
            node_counts["total"] = len(rows)
            for r in rows:
                st = (r["status"] or "offline").lower()
                lc = (r["lifecycle_state"] or "registered").lower()
                if st == "online":
                    node_counts["online"] += 1
                elif st == "unhealthy":
                    node_counts["unhealthy"] += 1
                elif st in ("draining", "drain_blocked", "drained"):
                    node_counts["draining"] += 1
                else:
                    node_counts["offline"] += 1

                if lc == "probation":
                    node_counts["probation"] += 1

                storage_bytes["total_capacity_bytes"] += int(r["total_capacity_bytes"] or 0)
                storage_bytes["used_capacity_bytes"] += int(r["used_capacity_bytes"] or 0)
                storage_bytes["available_capacity_bytes"] += int(r["available_capacity_bytes"] or 0)

            # Files / Verified Stored
            file_sum = conn.execute("SELECT COUNT(*) AS c, SUM(original_size) AS s FROM files WHERE status = 'active'").fetchone()
            storage_bytes["verified_stored_bytes"] = int(file_sum["s"] or 0)

            # Active Sessions
            now_iso = datetime.now(timezone.utc).isoformat()
            sess_row = conn.execute("SELECT COUNT(*) AS c FROM account_sessions WHERE expires_at > ?", (now_iso,)).fetchone()
            active_sessions = int(sess_row["c"] or 0)

            # Deletion Jobs
            del_row = conn.execute("SELECT COUNT(*) AS c FROM deletion_jobs WHERE status IN ('pending', 'running')").fetchone()
            job_counts["pending_deletions"] = int(del_row["c"] or 0)

            # Repair Jobs (in-memory registry)
            try:
                from coordinator.app.main import _coordinator_repair_jobs
                for job in _coordinator_repair_jobs.values():
                    s = (job.get("status") or "").lower()
                    if s == "completed":
                        job_counts["repair_completed"] += 1
                    elif s == "failed":
                        job_counts["repair_failed"] += 1
                    elif s in ("pending", "in_progress"):
                        job_counts["repair_pending"] += 1
            except Exception:
                pass
    except Exception as exc:
        logger.warning("Error computing metrics from SQLite: %s", exc)

    return ObservabilityMetricsResponse(
        requests=req_stats,
        storage_nodes=node_counts,
        storage_bytes=storage_bytes,
        quota={
            "rejections_total": metrics_tracker.quota_rejections_total,
        },
        jobs=job_counts,
        active_sessions=active_sessions,
        timestamp=now_str,
    )
