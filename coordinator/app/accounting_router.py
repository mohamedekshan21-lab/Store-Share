"""
FastAPI routers for Expo Contribution Credits (ECC), Reputation, and Accounting APIs (Phase 7B).
Provides REST endpoints for inspecting credit balances, paginated ledgers, reputation scoring,
policy inspection, and administrative credit reconciliation/reversals.
"""

from __future__ import annotations

import logging
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from coordinator.app.main import verify_coordinator_auth, get_registry
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.accounting import AccountingService
from coordinator.app.user_auth import get_optional_user, Role
from coordinator.app.models import (
    CreditLedgerEntryRecord,
    CreditBalanceRecord,
    CreditLedgerListResponse,
    NodeCreditSummary,
    AccountingPolicyConfig,
    NodeReputationRecord,
    NodeReputationListResponse,
    ClusterAccountingSummary,
    CreditReversalRequest,
    CreditCalculationRequest,
)

logger = logging.getLogger("expo_accounting_router")

credits_router = APIRouter(prefix="/credits", tags=["Credits"])
reputation_router = APIRouter(prefix="/reputation", tags=["Reputation"])
accounting_router = APIRouter(prefix="/accounting", tags=["Accounting"])


def get_accounting_service(request: Request) -> AccountingService:
    """Dependency provider for AccountingService instance."""
    if not hasattr(request.app.state, "accounting_service"):
        settings = (
            request.app.state.settings
            if hasattr(request.app.state, "settings")
            else get_coordinator_settings()
        )
        request.app.state.accounting_service = AccountingService(settings)
    return request.app.state.accounting_service


def check_node_accounting_access(request: Request, node_id: str, registry: NodeRegistry) -> None:
    """Verifies that the caller has permission to view node accounting details."""
    user = get_optional_user(request)
    if not user:
        return
    if user.role == Role.CONSUMER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Consumer accounts cannot inspect storage provider accounting or credit ledgers.",
        )
    if user.role == Role.PROVIDER.value:
        node = registry.get_node(node_id)
        if node and node.provider_id and node.provider_id != user.provider_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: You are not authorized to inspect accounting for node '{node_id}' belonging to another provider.",
            )


def check_admin_access(request: Request) -> None:
    """Verifies that the caller has admin permissions for configuration or reconciliation actions."""
    user = get_optional_user(request)
    if user and user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Action requires '{Role.ADMIN.value}' privileges.",
        )


# =============================================================================
# 1. Credits Endpoints
# =============================================================================

@credits_router.get(
    "/nodes/{node_id}/balance",
    response_model=CreditBalanceRecord,
    summary="Get Node Credit Balance",
)
def get_node_credit_balance(
    request: Request,
    node_id: str,
    service: AccountingService = Depends(get_accounting_service),
    registry: NodeRegistry = Depends(get_registry),
) -> CreditBalanceRecord:
    """Retrieves the current reconciled ECC balance and lifetime metrics for a storage node."""
    check_node_accounting_access(request, node_id, registry)
    return service.get_node_balance(node_id)


@credits_router.get(
    "/nodes/{node_id}/ledger",
    response_model=CreditLedgerListResponse,
    summary="Get Paginated Node Credit Ledger",
)
def get_node_credit_ledger(
    request: Request,
    node_id: str,
    category: Optional[str] = Query(None, description="Filter by category ('storage', 'transfer_upload', 'transfer_download', 'replication', 'repair', 'reversal')"),
    start_time: Optional[str] = Query(None, description="ISO start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO end timestamp"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    service: AccountingService = Depends(get_accounting_service),
    registry: NodeRegistry = Depends(get_registry),
) -> CreditLedgerListResponse:
    """Retrieves paginated, immutable credit ledger entries for a storage node."""
    check_node_accounting_access(request, node_id, registry)
    entries = service.get_ledger_entries(
        node_id=node_id,
        category=category,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )
    total_in_page = round(sum(e.credit_delta for e in entries), 4)
    return CreditLedgerListResponse(
        node_id=node_id,
        entries=entries,
        count=len(entries),
        total_credits_in_page=total_in_page,
        limit=limit,
        offset=offset,
    )


@credits_router.get(
    "/nodes/{node_id}/summary",
    response_model=NodeCreditSummary,
    summary="Get Node Credit Summary",
)
def get_node_credit_summary(
    request: Request,
    node_id: str,
    service: AccountingService = Depends(get_accounting_service),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeCreditSummary:
    """Retrieves a comprehensive categorized credit breakdown for a storage node."""
    check_node_accounting_access(request, node_id, registry)
    return service.get_node_credit_summary(node_id)


# =============================================================================
# 2. Reputation Endpoints
# =============================================================================

@reputation_router.get(
    "/nodes/{node_id}",
    response_model=NodeReputationRecord,
    summary="Get Node Reputation & Trust Score",
)
def get_node_reputation(
    request: Request,
    node_id: str,
    window_hours: float = Query(168.0, ge=1.0, le=8760.0, description="Evaluation window in hours"),
    service: AccountingService = Depends(get_accounting_service),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeReputationRecord:
    """Calculates and returns an objective reputation score (0 to 100) with confidence indicator."""
    check_node_accounting_access(request, node_id, registry)
    try:
        return service.calculate_node_reputation(node_id, window_hours=window_hours)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@reputation_router.get(
    "/nodes",
    response_model=NodeReputationListResponse,
    summary="List Cluster Node Reputations",
)
def list_node_reputations(
    request: Request,
    window_hours: float = Query(168.0, ge=1.0, le=8760.0),
    service: AccountingService = Depends(get_accounting_service),
) -> NodeReputationListResponse:
    """Calculates and lists reputation scores for all registered storage nodes."""
    user = get_optional_user(request)
    if user and user.role == Role.CONSUMER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Consumer accounts cannot inspect cluster node reputations.",
        )
    records = service.list_node_reputations(window_hours=window_hours)
    return NodeReputationListResponse(nodes=records, count=len(records))


# =============================================================================
# 3. Accounting & Policy Endpoints
# =============================================================================

@accounting_router.get(
    "/policy",
    response_model=AccountingPolicyConfig,
    summary="Get Active Accounting Policy",
)
def get_accounting_policy(
    service: AccountingService = Depends(get_accounting_service),
) -> AccountingPolicyConfig:
    """Retrieves the active credit and reputation policy weights, formulas, and version."""
    return service.get_policy()


@accounting_router.put(
    "/policy",
    response_model=AccountingPolicyConfig,
    dependencies=[Depends(verify_coordinator_auth)],
    summary="Update Accounting Policy (Admin)",
)
def update_accounting_policy(
    request: Request,
    new_policy: AccountingPolicyConfig,
    service: AccountingService = Depends(get_accounting_service),
) -> AccountingPolicyConfig:
    """Updates the active accounting policy parameters and logs an audit trail."""
    check_admin_access(request)
    return service.update_policy(new_policy, actor="admin")


@accounting_router.get(
    "/cluster/summary",
    response_model=ClusterAccountingSummary,
    summary="Get Cluster Accounting Summary",
)
def get_cluster_accounting_summary(
    request: Request,
    service: AccountingService = Depends(get_accounting_service),
) -> ClusterAccountingSummary:
    """Returns cluster-wide aggregated credits issued, reversed, net, and reputation metrics."""
    user = get_optional_user(request)
    if user and user.role == Role.CONSUMER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Consumer accounts cannot inspect cluster accounting summaries.",
        )
    return service.get_cluster_accounting_summary()


@accounting_router.post(
    "/credits/calculate",
    dependencies=[Depends(verify_coordinator_auth)],
    summary="Trigger Contribution Accounting Calculation (Admin)",
)
def trigger_credit_calculation(
    request: Request,
    req: CreditCalculationRequest,
    service: AccountingService = Depends(get_accounting_service),
) -> dict:
    """Triggers on-demand calculation and finalization of contribution credits."""
    check_admin_access(request)
    return service.process_contribution_accounting(
        node_id=req.node_id,
        window_hours=req.window_hours,
        include_storage=req.include_storage,
        include_transfers=req.include_transfers,
        include_operations=req.include_operations,
    )


@accounting_router.post(
    "/credits/reverse",
    response_model=CreditLedgerEntryRecord,
    dependencies=[Depends(verify_coordinator_auth)],
    summary="Reverse Credit Ledger Entry (Admin)",
)
def reverse_credit_entry(
    request: Request,
    req: CreditReversalRequest,
    service: AccountingService = Depends(get_accounting_service),
) -> CreditLedgerEntryRecord:
    """Creates an explicit compensating reversal ledger entry for an erroneous award."""
    check_admin_access(request)
    try:
        return service.reverse_ledger_entry(
            req.entry_id,
            reason=req.reason,
            actor="admin",
            amount=req.amount,
            idempotency_key=req.idempotency_key,
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
