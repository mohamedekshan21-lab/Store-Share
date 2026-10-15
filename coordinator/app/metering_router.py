"""
FastAPI router for Expo Metering API (Phase 7A).
Provides REST endpoints for querying and recording storage capacity snapshots,
bandwidth transfers, uptime, and recovery operation events.
"""

from __future__ import annotations

import logging
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from coordinator.app.main import verify_coordinator_auth, get_registry
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.metering import MeteringService
from coordinator.app.user_auth import get_optional_user, Role
from coordinator.app.models import (
    CapacitySnapshotRecord,
    CapacitySnapshotListResponse,
    TransferEventRecord,
    TransferEventCreateRequest,
    TransferEventListResponse,
    HeartbeatObservationRecord,
    OperationEventRecord,
    OperationEventCreateRequest,
    OperationEventListResponse,
    NodeUptimeSummary,
    NodeContributionSummary,
    ClusterMeteringSummary,
)

logger = logging.getLogger("expo_metering_router")

metering_router = APIRouter(prefix="/metering", tags=["Metering"])


def get_metering_service(request: Request) -> MeteringService:
    """Dependency provider for MeteringService instance."""
    if not hasattr(request.app.state, "metering_service"):
        settings = (
            request.app.state.settings
            if hasattr(request.app.state, "settings")
            else get_coordinator_settings()
        )
        request.app.state.metering_service = MeteringService(settings)
    return request.app.state.metering_service


def check_metering_node_access(request: Request, node_id: Optional[str], registry: NodeRegistry) -> None:
    """Verifies that the caller has permission to view node metering details."""
    user = get_optional_user(request)
    if not user:
        return
    if user.role == Role.CONSUMER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Consumer accounts cannot inspect node metering or telemetry.",
        )
    if user.role == Role.PROVIDER.value and node_id:
        node = registry.get_node(node_id)
        if node and node.provider_id and node.provider_id != user.provider_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: You are not authorized to inspect metering for node '{node_id}' belonging to another provider.",
            )


@metering_router.post(
    "/transfers",
    response_model=TransferEventRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Record a Bandwidth Transfer Event",
)
def record_transfer_event(
    req: TransferEventCreateRequest,
    service: MeteringService = Depends(get_metering_service),
) -> TransferEventRecord:
    """Records a completed bandwidth transfer event with idempotency protection."""
    if req.payload_bytes < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="payload_bytes cannot be negative")
    return service.record_transfer_event(
        node_id=req.node_id,
        direction=req.direction,
        operation_type=req.operation_type,
        payload_bytes=req.payload_bytes,
        chunk_id=req.chunk_id,
        file_id=req.file_id,
        status=req.status,
        idempotency_key=req.idempotency_key,
        timestamp=req.timestamp,
    )


@metering_router.get(
    "/transfers",
    response_model=TransferEventListResponse,
    summary="List Bandwidth Transfer Events",
)
def list_transfer_events(
    request: Request,
    node_id: Optional[str] = Query(None, description="Filter by node ID"),
    direction: Optional[str] = Query(None, description="Filter by direction ('upload' or 'download')"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status ('success', 'failed')"),
    start_time: Optional[str] = Query(None, description="ISO start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO end timestamp"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    service: MeteringService = Depends(get_metering_service),
    registry: NodeRegistry = Depends(get_registry),
) -> TransferEventListResponse:
    """Queries bandwidth transfer events."""
    check_metering_node_access(request, node_id, registry)
    events = service.get_transfer_events(
        node_id=node_id,
        direction=direction,
        status=status_filter,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )
    total_bytes = sum(e.payload_bytes for e in events if e.status == "success")
    return TransferEventListResponse(events=events, count=len(events), total_bytes=total_bytes)


@metering_router.get(
    "/snapshots",
    response_model=CapacitySnapshotListResponse,
    summary="List Storage Capacity Snapshots",
)
def list_capacity_snapshots(
    request: Request,
    node_id: Optional[str] = Query(None, description="Filter by node ID"),
    limit: int = Query(100, ge=1, le=1000),
    service: MeteringService = Depends(get_metering_service),
    registry: NodeRegistry = Depends(get_registry),
) -> CapacitySnapshotListResponse:
    """Queries historical capacity snapshots."""
    check_metering_node_access(request, node_id, registry)
    snaps = service.get_capacity_snapshots(node_id=node_id, limit=limit)
    return CapacitySnapshotListResponse(snapshots=snaps, count=len(snaps))


@metering_router.post(
    "/operations",
    response_model=OperationEventRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Record a Replication/Repair Operation",
)
def record_operation_event(
    req: OperationEventCreateRequest,
    service: MeteringService = Depends(get_metering_service),
) -> OperationEventRecord:
    """Records a completed self-healing replication or repair operation."""
    if req.payload_bytes < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="payload_bytes cannot be negative")
    return service.record_operation_event(
        operation_type=req.operation_type,
        target_node_id=req.target_node_id,
        payload_bytes=req.payload_bytes,
        source_node_id=req.source_node_id,
        chunk_id=req.chunk_id,
        status=req.status,
        completed_at=req.completed_at,
        duration_seconds=req.duration_seconds,
        idempotency_key=req.idempotency_key,
    )


@metering_router.get(
    "/operations",
    response_model=OperationEventListResponse,
    summary="List Replication/Repair Operations",
)
def list_operation_events(
    request: Request,
    node_id: Optional[str] = Query(None, description="Filter by node ID"),
    operation_type: Optional[str] = Query(None, description="Filter by operation type ('replication', 'repair')"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status ('completed', 'failed')"),
    limit: int = Query(100, ge=1, le=1000),
    service: MeteringService = Depends(get_metering_service),
    registry: NodeRegistry = Depends(get_registry),
) -> OperationEventListResponse:
    """Queries recorded self-healing and replication operations."""
    check_metering_node_access(request, node_id, registry)
    ops = service.get_operation_events(
        node_id=node_id,
        operation_type=operation_type,
        status=status_filter,
        limit=limit,
    )
    return OperationEventListResponse(operations=ops, count=len(ops))


@metering_router.get(
    "/nodes/{node_id}/summary",
    response_model=NodeContributionSummary,
    summary="Get Node Contribution Summary",
)
def get_node_contribution_summary(
    request: Request,
    node_id: str,
    window_hours: float = Query(24.0, ge=0.1, le=8760.0, description="Uptime evaluation window in hours"),
    service: MeteringService = Depends(get_metering_service),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeContributionSummary:
    """Retrieves an aggregated contribution summary for a specific storage node."""
    check_metering_node_access(request, node_id, registry)
    try:
        return service.get_node_summary(node_id, window_hours=window_hours)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@metering_router.get(
    "/nodes/{node_id}/uptime",
    response_model=NodeUptimeSummary,
    summary="Get Node Uptime & Availability",
)
def get_node_uptime(
    request: Request,
    node_id: str,
    window_start: Optional[str] = Query(None, description="ISO window start timestamp"),
    window_end: Optional[str] = Query(None, description="ISO window end timestamp"),
    service: MeteringService = Depends(get_metering_service),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeUptimeSummary:
    """Calculates node uptime and availability over an evaluated time window."""
    check_metering_node_access(request, node_id, registry)
    return service.calculate_node_uptime(
        node_id=node_id, window_start=window_start, window_end=window_end
    )


@metering_router.get(
    "/cluster/summary",
    response_model=ClusterMeteringSummary,
    summary="Get Cluster Metering Summary",
)
def get_cluster_metering_summary(
    request: Request,
    window_hours: float = Query(24.0, ge=0.1, le=8760.0),
    service: MeteringService = Depends(get_metering_service),
) -> ClusterMeteringSummary:
    """Calculates cluster-wide capacity, transfer volume, and recovery statistics."""
    user = get_optional_user(request)
    if user and user.role == Role.CONSUMER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Consumer accounts cannot inspect cluster metering.",
        )
    return service.get_cluster_summary(window_hours=window_hours)
