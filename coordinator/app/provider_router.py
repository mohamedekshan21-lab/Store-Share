"""
FastAPI router for Provider Monitoring and Management (Phase 8A).
Provides authorized provider overview, node health inspection, quota vs verified usage diagnostics,
scheduling control, graceful node drain/shutdown, and responsive provider dashboard integration.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.database import get_db_connection
from coordinator.app.main import (
    get_settings,
    get_registry,
    get_metering_service,
    verify_coordinator_auth,
)
from coordinator.app.node_registry import NodeRegistry, NodeNotFoundError
from coordinator.app.metering import MeteringService
from coordinator.app.accounting import AccountingService
from coordinator.app.auth import ProviderSessionManager, AuthenticatedPrincipal, CredentialManager, AccountManager
from coordinator.app.drain_service import NodeDrainService, DrainStatus
from coordinator.app.node_validation import NodeValidator
from coordinator.app.models import (
    NodeRecord,
    ProviderOverview,
    ProviderNodeSummary,
    ProviderNodeDetail,
    NodeSchedulingRequest,
    NodeShutdownRequest,
    NodeManagementActionResponse,
    SessionLoginRequest,
    SessionLoginResponse,
    SessionStatusResponse,
    NodeDrainRequest,
    NodeDrainResponse,
    NodeDrainMigrationRecord,
    NodeDrainMigrationListResponse,
    DrainWorkerStatusResponse,
    ProviderOnboardRequest,
    ProviderOnboardResponse,
    NodeValidationCheckItem,
    NodeValidationResponse,
    NodeProbationStatusResponse,
    ProviderNodeValidationHistoryResponse,
)

logger = logging.getLogger("expo_provider_router")

provider_router = APIRouter(prefix="/provider", tags=["Provider Management"])


def get_accounting_service(request: Request) -> AccountingService:
    """Dependency provider for AccountingService."""
    if not hasattr(request.app.state, "accounting_service"):
        settings = (
            request.app.state.settings
            if hasattr(request.app.state, "settings")
            else get_coordinator_settings()
        )
        request.app.state.accounting_service = AccountingService(settings)
    return request.app.state.accounting_service


def get_session_manager(request: Request) -> ProviderSessionManager:
    """Dependency provider for ProviderSessionManager."""
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    if not hasattr(request.app.state, "session_manager") or getattr(request.app.state.session_manager, "db_path", None) != settings.db_path:
        request.app.state.session_manager = ProviderSessionManager(settings)
    return request.app.state.session_manager


def get_drain_service(request: Request) -> NodeDrainService:
    """Dependency provider for NodeDrainService."""
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    if not hasattr(request.app.state, "drain_service") or getattr(request.app.state.drain_service, "db_path", None) != settings.db_path:
        ds = NodeDrainService(settings)
        ds.recover_in_flight_migrations()
        request.app.state.drain_service = ds

    ds = request.app.state.drain_service
    if ds.worker is None:
        from coordinator.app.drain_service import NodeDrainMigrationWorker
        reg = request.app.state.registry if hasattr(request.app.state, "registry") else NodeRegistry(settings)
        ds.worker = NodeDrainMigrationWorker(ds, reg)
        try:
            ds.worker.start()
        except Exception:
            pass

    return ds



def get_credential_manager(request: Request) -> CredentialManager:
    """Dependency provider for CredentialManager."""
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    if not hasattr(request.app.state, "credential_manager") or getattr(request.app.state.credential_manager, "db_path", None) != settings.db_path:
        request.app.state.credential_manager = CredentialManager(settings)
    return request.app.state.credential_manager


def get_account_manager(request: Request) -> AccountManager:
    """Dependency provider for AccountManager."""
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    if not hasattr(request.app.state, "account_manager") or getattr(request.app.state.account_manager, "db_path", None) != settings.db_path:
        request.app.state.account_manager = AccountManager(settings)
    return request.app.state.account_manager


def get_current_principal(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_provider_id: Optional[str] = Header(None, alias="X-Provider-Id"),
    x_admin_override: Optional[str] = Header(None, alias="X-Admin-Override"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
) -> AuthenticatedPrincipal:
    """
    Resolves and verifies the security principal from Bearer tokens or browser session cookies.
    Prevents untrusted X-Provider-Id spoofing:
    - Master/Admin token is authorized to specify provider context.
    - Non-admin principals can only access their own provider identity.
    - Explicit X-Admin-Override is required for cross-provider node mutations.
    - Session-authenticated state mutations require a valid CSRF token.
    """
    session_manager = get_session_manager(request)
    credential_manager = get_credential_manager(request)
    account_manager = get_account_manager(request)
    configured_token = settings.auth_token
    admin_configured_token = settings.admin_auth_token
    admin_override_requested = bool(x_admin_override and x_admin_override.strip().lower() == "true")

    # 1. Bearer / X-Auth-Token Header Check (CLI, SDK, Direct API)
    token = None
    if x_auth_token and x_auth_token.strip():
        token = x_auth_token.strip()
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

    if token:
        # 1a. Explicit database credential check
        cred = credential_manager.verify_credential(token)
        if cred:
            if x_provider_id and x_provider_id.strip():
                req_prov = x_provider_id.strip()
                if not cred.is_admin and req_prov != cred.provider_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied: Principal '{cred.principal_id}' is not authorized to act as provider '{req_prov}'.",
                    )
                target_provider = req_prov
            else:
                target_provider = cred.provider_id

            return AuthenticatedPrincipal(
                principal_id=cred.principal_id,
                provider_id=target_provider,
                is_admin=cred.is_admin,
                admin_override=cred.is_admin and admin_override_requested,
                auth_method="token",
            )

        # 1b. Explicit Administrative token check
        if admin_configured_token and admin_configured_token.strip() and token == admin_configured_token.strip():
            target_provider = x_provider_id.strip() if x_provider_id and x_provider_id.strip() else "default_provider"
            return AuthenticatedPrincipal(
                principal_id="admin_token",
                provider_id=target_provider,
                is_admin=True,
                admin_override=admin_override_requested,
                auth_method="token",
            )

        # 1c. Provider-bound token check (e.g. provider:<id>)
        if token.startswith("provider:"):
            bound_provider = token.split(":", 1)[1].strip()
            if x_provider_id and x_provider_id.strip() and x_provider_id.strip() != bound_provider:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied: Principal '{bound_provider}' is not authorized to act as provider '{x_provider_id.strip()}'.",
                )
            return AuthenticatedPrincipal(
                principal_id=bound_provider,
                provider_id=bound_provider,
                is_admin=False,
                admin_override=False,
                auth_method="token",
            )

        # 1d. Account session check (from token)
        account_session = account_manager.get_session(token)
        if account_session:
            if x_provider_id and x_provider_id.strip():
                req_prov = x_provider_id.strip()
                if not account_session.is_admin and account_session.provider_id != req_prov:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied: Principal '{account_session.account_id}' is not authorized to act as provider '{req_prov}'.",
                    )
                target_provider = req_prov
            else:
                target_provider = account_session.provider_id or "default_provider"

            return AuthenticatedPrincipal(
                principal_id=account_session.account_id,
                provider_id=target_provider,
                account_id=account_session.account_id,
                is_admin=account_session.is_admin,
                admin_override=account_session.is_admin and admin_override_requested,
                auth_method="token",
                csrf_token=account_session.csrf_token,
            )

        # 1e. Coordinator token check
        if configured_token and configured_token.strip():
            if token == configured_token.strip():
                # Shared coordinator token NEVER grants administrator access (Phase 10A)
                is_admin = False
                target_provider = x_provider_id.strip() if x_provider_id and x_provider_id.strip() else "default_provider"
                return AuthenticatedPrincipal(
                    principal_id="coordinator_token",
                    provider_id=target_provider,
                    is_admin=False,
                    admin_override=False,
                    auth_method="token",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unauthorized: Invalid coordinator authentication token.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        else:
            # Missing configuration check
            if settings.environment == "production":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unauthorized: Production coordinator authentication is not configured.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Dev mode (testing/local only)
            target_provider = x_provider_id.strip() if x_provider_id and x_provider_id.strip() else "default_provider"
            return AuthenticatedPrincipal(
                principal_id="dev_user",
                provider_id=target_provider,
                is_admin=False,
                admin_override=False,
                auth_method="token",
            )

    # 2. Browser Session Cookie Check
    if session_cookie and session_cookie.strip():
        # First check provider sessions
        session = session_manager.get_session(session_cookie.strip())
        if session:
            # CSRF defense on state-changing browser requests
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                if not x_csrf_token or x_csrf_token.strip() != session.csrf_token:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Forbidden: Invalid or missing CSRF token.",
                    )

            if x_provider_id and x_provider_id.strip():
                requested_id = x_provider_id.strip()
                if not session.is_admin and requested_id != session.provider_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied: Principal '{session.provider_id}' is not authorized to act as provider '{requested_id}'.",
                    )
                target_provider = requested_id
            else:
                target_provider = session.provider_id

            return AuthenticatedPrincipal(
                principal_id=session.provider_id,
                provider_id=target_provider,
                is_admin=session.is_admin,
                admin_override=session.is_admin and admin_override_requested,
                auth_method="session",
                csrf_token=session.csrf_token,
            )

        # Then check account sessions
        acc_session = account_manager.get_session(session_cookie.strip())
        if acc_session:
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                if not x_csrf_token or x_csrf_token.strip() != acc_session.csrf_token:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Forbidden: Invalid or missing CSRF token.",
                    )

            if x_provider_id and x_provider_id.strip():
                requested_id = x_provider_id.strip()
                if not acc_session.is_admin and requested_id != acc_session.provider_id:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Access denied: Account '{acc_session.account_id}' is not authorized to act as provider '{requested_id}'.",
                    )
                target_provider = requested_id
            else:
                target_provider = acc_session.provider_id or "default_provider"

            return AuthenticatedPrincipal(
                principal_id=acc_session.account_id,
                provider_id=target_provider,
                account_id=acc_session.account_id,
                is_admin=acc_session.is_admin,
                admin_override=acc_session.is_admin and admin_override_requested,
                auth_method="session",
                csrf_token=acc_session.csrf_token,
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Session expired or invalid.",
        )

    # 3. No credentials provided: check configuration
    if not configured_token or not configured_token.strip():
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Production coordinator authentication is not configured.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        target_provider = x_provider_id.strip() if x_provider_id and x_provider_id.strip() else "default_provider"
        return AuthenticatedPrincipal(
            principal_id="dev_user",
            provider_id=target_provider,
            is_admin=False,
            admin_override=False,
            auth_method="token",
        )

    # 4. No valid credentials supplied
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid or missing coordinator authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_optional_principal(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
    x_auth_token: Optional[str] = Header(None, alias="X-Auth-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_provider_id: Optional[str] = Header(None, alias="X-Provider-Id"),
    x_admin_override: Optional[str] = Header(None, alias="X-Admin-Override"),
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
    x_csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
) -> Optional[AuthenticatedPrincipal]:
    """Gracefully resolves principal if authenticated, otherwise returns None without throwing."""
    try:
        return get_current_principal(
            request=request,
            settings=settings,
            x_auth_token=x_auth_token,
            authorization=authorization,
            x_provider_id=x_provider_id,
            x_admin_override=x_admin_override,
            session_cookie=session_cookie,
            x_csrf_token=x_csrf_token,
        )
    except HTTPException:
        return None


def resolve_provider_identity(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> str:
    """Returns the verified provider identity bound to the authenticated principal."""
    return principal.provider_id


def verify_node_ownership(
    node_id: str,
    principal_or_id: Any,
    registry: NodeRegistry,
) -> NodeRecord:
    """
    Asserts that the target node belongs to the authenticated provider.
    Rejects unauthorized access with 403 Forbidden or 404 Not Found.
    Never exposes another provider's private node info.
    Cross-provider access requires explicit, authorized administrative permission.
    """
    clean_id = node_id.strip()
    node = registry.get_node(clean_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Storage Node '{clean_id}' not found.",
        )

    admin_override = False
    allowed_providers = set()
    if isinstance(principal_or_id, AuthenticatedPrincipal):
        admin_override = principal_or_id.is_admin and principal_or_id.admin_override
        caller_provider = principal_or_id.provider_id or (f"provider-{principal_or_id.account_id}" if principal_or_id.account_id else "unknown")
        if principal_or_id.provider_id:
            allowed_providers.add(principal_or_id.provider_id)
        if principal_or_id.account_id:
            allowed_providers.add(principal_or_id.account_id)
            allowed_providers.add(f"provider-{principal_or_id.account_id}")
    else:
        caller_provider = str(principal_or_id)
        allowed_providers.add(caller_provider)
        allowed_providers.add(f"provider-{caller_provider}")

    # Scoped provider check: caller cannot view or modify another provider's node without explicit admin override
    if not admin_override and node.provider_id and node.provider_id not in allowed_providers and node.provider_id != "default_provider":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Node '{clean_id}' does not belong to provider '{caller_provider}'.",
        )

    return node



# =============================================================================
# 1. Provider Overview & Nodes List
# =============================================================================

@provider_router.get(
    "/overview",
    response_model=ProviderOverview,
    summary="Get Provider Overview Summary",
)
def get_provider_overview(
    window_hours: float = Query(24.0, ge=1.0, le=8760.0, description="Evaluation window in hours"),
    provider_id: str = Depends(resolve_provider_identity),
    registry: NodeRegistry = Depends(get_registry),
    metering: MeteringService = Depends(get_metering_service),
    accounting: AccountingService = Depends(get_accounting_service),
) -> ProviderOverview:
    """
    Aggregates high-level capacity, traffic, credits, reputation, and repair stats
    across all Storage Nodes owned by the authenticated provider.
    Distinguishes configured quota, verified stored data, and host physical disk.
    """
    nodes = registry.list_nodes_by_provider(provider_id)
    now = datetime.now(timezone.utc)
    w_start = (now - timedelta(hours=window_hours)).isoformat()
    w_end = now.isoformat()

    total_quota = 0
    total_verified = 0
    total_remaining = 0
    total_phys_disk: Optional[int] = None
    total_phys_free: Optional[int] = None
    total_ingress = 0
    total_egress = 0
    total_credits = 0.0
    rep_scores: List[float] = []
    online_count = 0
    sched_count = 0

    node_summaries: List[ProviderNodeSummary] = []

    for n in nodes:
        total_quota += n.total_capacity_bytes
        if n.status == "online":
            online_count += 1
        if n.is_schedulable:
            sched_count += 1

        # Verified stored bytes from active manifest chunks
        verified_bytes = metering.calculate_authoritative_stored_bytes(n.node_id)
        if verified_bytes <= 0:
            snaps = metering.get_capacity_snapshots(n.node_id, limit=1)
            verified_bytes = snaps[0].used_bytes if snaps and snaps[0].is_valid else 0

        rem_bytes = max(0, n.total_capacity_bytes - verified_bytes)
        total_verified += verified_bytes
        total_remaining += rem_bytes

        # Physical disk capacity from latest valid snapshot
        latest_snaps = metering.get_capacity_snapshots(n.node_id, limit=1)
        p_total = None
        p_free = None
        if latest_snaps and latest_snaps[0].physical_total_bytes is not None:
            p_total = latest_snaps[0].physical_total_bytes
            p_free = latest_snaps[0].physical_free_bytes
            total_phys_disk = (total_phys_disk or 0) + p_total
            if p_free is not None:
                total_phys_free = (total_phys_free or 0) + p_free

        # Heartbeat elapsed time
        last_seen_dt = registry._parse_iso_datetime(n.last_seen)
        hb_elapsed = max(0.0, (now - last_seen_dt).total_seconds())

        # Observed availability over window
        uptime = metering.calculate_node_uptime(n.node_id, window_start=w_start, window_end=w_end)
        avail_pct = uptime.availability_percentage

        # ECC Credit balance
        bal = accounting.get_node_balance(n.node_id)
        total_credits += bal.total_credits

        # Reputation score
        rep = accounting.calculate_node_reputation(n.node_id, window_hours=168.0)
        rep_scores.append(rep.reputation_score)

        node_summaries.append(
            ProviderNodeSummary(
                node_id=n.node_id,
                host=n.host,
                port=n.port,
                endpoint=n.endpoint,
                status=n.status,
                is_schedulable=n.is_schedulable,
                connectivity_mode=n.connectivity_mode,
                total_configured_quota_bytes=n.total_capacity_bytes,
                verified_stored_bytes=verified_bytes,
                remaining_quota_bytes=rem_bytes,
                physical_disk_total_bytes=p_total,
                physical_disk_free_bytes=p_free,
                last_seen=n.last_seen,
                last_heartbeat_elapsed_seconds=round(hb_elapsed, 1),
                observed_availability_percentage=round(avail_pct, 2),
                credit_balance=bal.total_credits,
                reputation_score=rep.reputation_score,
                confidence_indicator=rep.confidence_indicator,
                data_sufficiency_status=rep.data_sufficiency_status,
                drain_status=n.drain_status,
            )
        )

    # Traffic and repair stats across provider's nodes
    node_ids = [n.node_id for n in nodes]
    recent_succ_repairs = 0
    recent_fail_repairs = 0

    if node_ids:
        placeholders = ",".join(["?"] * len(node_ids))
        with get_db_connection(registry.db_path) as conn:
            # Transfer traffic
            tx_rows = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN direction = 'upload' AND status = 'success' THEN payload_bytes ELSE 0 END) AS ingress,
                    SUM(CASE WHEN direction = 'download' AND status = 'success' THEN payload_bytes ELSE 0 END) AS egress
                FROM metering_transfer_events
                WHERE node_id IN ({placeholders}) AND timestamp >= ?
                """,
                (*node_ids, w_start),
            ).fetchone()

            total_ingress = int(tx_rows["ingress"] or 0)
            total_egress = int(tx_rows["egress"] or 0)

            # Repair stats
            rep_rows = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_rep,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_rep
                FROM metering_operation_events
                WHERE operation_type = 'repair' AND (target_node_id IN ({placeholders}) OR source_node_id IN ({placeholders}))
                  AND completed_at >= ?
                """,
                (*node_ids, *node_ids, w_start),
            ).fetchone()

            recent_succ_repairs = int(rep_rows["completed_rep"] or 0)
            recent_fail_repairs = int(rep_rows["failed_rep"] or 0)

    avg_rep = round(sum(rep_scores) / len(rep_scores), 2) if rep_scores else 50.0

    return ProviderOverview(
        provider_id=provider_id,
        total_nodes_count=len(nodes),
        online_nodes_count=online_count,
        schedulable_nodes_count=sched_count,
        total_configured_quota_bytes=total_quota,
        total_verified_stored_bytes=total_verified,
        total_remaining_quota_bytes=total_remaining,
        total_physical_disk_bytes=total_phys_disk,
        total_physical_free_bytes=total_phys_free,
        total_ingress_bytes=total_ingress,
        total_egress_bytes=total_egress,
        total_traffic_bytes=total_ingress + total_egress,
        total_credit_balance=round(total_credits, 6),
        average_reputation_score=avg_rep,
        recent_successful_repairs=recent_succ_repairs,
        recent_failed_repairs=recent_fail_repairs,
        evaluation_window_hours=window_hours,
        nodes=node_summaries,
    )


@provider_router.get(
    "/nodes",
    response_model=List[ProviderNodeSummary],
    summary="List Provider's Storage Nodes",
)
def list_provider_nodes(
    provider_id: str = Depends(resolve_provider_identity),
    registry: NodeRegistry = Depends(get_registry),
    metering: MeteringService = Depends(get_metering_service),
    accounting: AccountingService = Depends(get_accounting_service),
) -> List[ProviderNodeSummary]:
    """Lists summary cards for all Storage Nodes owned by the provider."""
    overview = get_provider_overview(
        window_hours=24.0,
        provider_id=provider_id,
        registry=registry,
        metering=metering,
        accounting=accounting,
    )
    return overview.nodes


# =============================================================================
# 2. Node Detail & Diagnostics
# =============================================================================

@provider_router.get(
    "/nodes/{node_id}/detail",
    response_model=ProviderNodeDetail,
    summary="Get Node Detail & Diagnostics",
)
def get_provider_node_detail(
    node_id: str,
    window_hours: float = Query(24.0, ge=1.0, le=8760.0),
    provider_id: str = Depends(resolve_provider_identity),
    registry: NodeRegistry = Depends(get_registry),
    metering: MeteringService = Depends(get_metering_service),
    accounting: AccountingService = Depends(get_accounting_service),
) -> ProviderNodeDetail:
    """
    Fetches comprehensive diagnostics, historical snapshots, traffic stats, and activity
    for a specific node. Enforces ownership: unauthorized cross-provider access is rejected.
    """
    node = verify_node_ownership(node_id, provider_id, registry)
    now = datetime.now(timezone.utc)
    w_start = (now - timedelta(hours=window_hours)).isoformat()
    w_end = now.isoformat()

    # 1. Capacity metrics
    verified_bytes = metering.calculate_authoritative_stored_bytes(node.node_id)
    if verified_bytes <= 0:
        snaps = metering.get_capacity_snapshots(node.node_id, limit=1)
        verified_bytes = snaps[0].used_bytes if snaps and snaps[0].is_valid else 0
    rem_bytes = max(0, node.total_capacity_bytes - verified_bytes)

    latest_snaps = metering.get_capacity_snapshots(node.node_id, limit=10)
    p_total = None
    p_free = None
    if latest_snaps and latest_snaps[0].physical_total_bytes is not None:
        p_total = latest_snaps[0].physical_total_bytes
        p_free = latest_snaps[0].physical_free_bytes

    snap_dicts = [
        {
            "snapshot_id": s.snapshot_id,
            "used_bytes": s.used_bytes,
            "total_quota_bytes": s.total_quota_bytes,
            "remaining_quota_bytes": s.remaining_quota_bytes,
            "physical_total_bytes": s.physical_total_bytes,
            "physical_free_bytes": s.physical_free_bytes,
            "source": s.source,
            "timestamp": s.measured_at,
        }
        for s in latest_snaps
    ]

    # 2. Liveness & Availability
    last_seen_dt = registry._parse_iso_datetime(node.last_seen)
    hb_elapsed = max(0.0, (now - last_seen_dt).total_seconds())
    uptime = metering.calculate_node_uptime(node.node_id, window_start=w_start, window_end=w_end)

    # 3. Credits & Reversals
    bal = accounting.get_node_balance(node.node_id)

    # 4. Reputation
    rep = accounting.calculate_node_reputation(node.node_id, window_hours=168.0)

    # 5. Traffic & Operations
    with get_db_connection(registry.db_path) as conn:
        tx_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN direction = 'upload' AND status = 'success' THEN payload_bytes ELSE 0 END) AS ingress,
                SUM(CASE WHEN direction = 'download' AND status = 'success' THEN payload_bytes ELSE 0 END) AS egress,
                COUNT(*) AS total_tx
            FROM metering_transfer_events
            WHERE node_id = ? AND timestamp >= ?
            """,
            (node.node_id, w_start),
        ).fetchone()

        total_ingress = int(tx_row["ingress"] or 0)
        total_egress = int(tx_row["egress"] or 0)
        total_tx = int(tx_row["total_tx"] or 0)

        op_row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS succ_ops,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS fail_ops
            FROM metering_operation_events
            WHERE operation_type = 'repair' AND (target_node_id = ? OR source_node_id = ?)
              AND completed_at >= ?
            """,
            (node.node_id, node.node_id, w_start),
        ).fetchone()

        succ_ops = int(op_row["succ_ops"] or 0)
        fail_ops = int(op_row["fail_ops"] or 0)

        # 6. Recent Activity Log (transfers, operations, ledger entries)
        activity: List[Dict[str, Any]] = []

        recent_tx = conn.execute(
            """
            SELECT event_id, direction, payload_bytes, status, timestamp
            FROM metering_transfer_events
            WHERE node_id = ?
            ORDER BY timestamp DESC LIMIT 10
            """,
            (node.node_id,),
        ).fetchall()
        for r in recent_tx:
            activity.append({
                "type": "transfer",
                "id": r["event_id"],
                "summary": f"{r['direction'].capitalize()} ({r['payload_bytes']} bytes) - {r['status']}",
                "status": r["status"],
                "timestamp": r["timestamp"],
            })

        recent_ops = conn.execute(
            """
            SELECT operation_id, operation_type, payload_bytes, status, completed_at
            FROM metering_operation_events
            WHERE target_node_id = ? OR source_node_id = ?
            ORDER BY completed_at DESC LIMIT 10
            """,
            (node.node_id, node.node_id),
        ).fetchall()
        for r in recent_ops:
            activity.append({
                "type": "operation",
                "id": r["operation_id"],
                "summary": f"{r['operation_type'].capitalize()} ({r['payload_bytes']} bytes) - {r['status']}",
                "status": r["status"],
                "timestamp": r["completed_at"],
            })

        recent_cle = conn.execute(
            """
            SELECT entry_id, category, credit_delta, reason, timestamp
            FROM credit_ledger_entries
            WHERE node_id = ?
            ORDER BY timestamp DESC LIMIT 10
            """,
            (node.node_id,),
        ).fetchall()
        for r in recent_cle:
            activity.append({
                "type": "credit",
                "id": r["entry_id"],
                "summary": f"Ledger {r['category']}: {r['credit_delta']:+.4f} ECC ({r['reason'][:40]})",
                "status": "success",
                "timestamp": r["timestamp"],
            })

        # Sort combined activity chronologically descending
        activity.sort(key=lambda x: x["timestamp"], reverse=True)
        activity = activity[:20]

    return ProviderNodeDetail(
        node_id=node.node_id,
        provider_id=node.provider_id or provider_id,
        host=node.host,
        port=node.port,
        endpoint=node.endpoint,
        status=node.status,
        is_schedulable=node.is_schedulable,
        drain_status=node.drain_status,
        connectivity_mode=node.connectivity_mode,
        protocol_version=node.protocol_version,
        total_configured_quota_bytes=node.total_capacity_bytes,
        verified_stored_bytes=verified_bytes,
        remaining_quota_bytes=rem_bytes,
        physical_disk_total_bytes=p_total,
        physical_disk_free_bytes=p_free,
        last_seen=node.last_seen,
        registered_at=node.registered_at,
        last_heartbeat_elapsed_seconds=round(hb_elapsed, 1),
        observed_availability_percentage=round(uptime.availability_percentage, 2),
        observed_online_seconds=round(uptime.observed_online_seconds, 1),
        total_ingress_bytes=total_ingress,
        total_egress_bytes=total_egress,
        credit_balance=bal.total_credits,
        lifetime_credits_earned=bal.lifetime_earned,
        lifetime_credits_reversed=bal.lifetime_reversed,
        reputation_score=rep.reputation_score,
        availability_score=rep.availability_score,
        integrity_score=rep.integrity_score,
        recovery_score=rep.recovery_score,
        confidence_indicator=rep.confidence_indicator,
        data_sufficiency_status=rep.data_sufficiency_status,
        recent_transfers_count=total_tx,
        recent_repairs_count=succ_ops,
        recent_failed_repairs_count=fail_ops,
        recent_snapshots=snap_dicts,
        recent_activity=activity,
    )


# =============================================================================
# 3. Provider Session Authentication (Browser Dashboard)
# =============================================================================

@provider_router.post(
    "/session/login",
    response_model=SessionLoginResponse,
    summary="Login to establish a secure browser dashboard session",
)
def session_login(
    req: SessionLoginRequest,
    response: Response,
    request: Request,
    session_manager: ProviderSessionManager = Depends(get_session_manager),
    credential_manager: CredentialManager = Depends(get_credential_manager),
) -> SessionLoginResponse:
    """
    Authenticates a provider or administrator for dashboard access.
    Sets a secure, HttpOnly, SameSite=Lax session cookie and returns a CSRF token.
    Production requirement: HTTPS deployment with Secure cookie flag enabled.
    Development exception: Local non-HTTPS testing permits Secure=False.
    """
    settings = (
        request.app.state.settings
        if hasattr(request.app.state, "settings")
        else get_coordinator_settings()
    )
    configured_token = settings.auth_token
    admin_configured_token = settings.admin_auth_token

    is_admin = False
    clean_provider = (req.provider_id or "default_provider").strip()
    provided_secret = req.get_token()

    if not provided_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token or secret is required.",
        )

    # 1. Check database credentials
    cred = credential_manager.verify_credential(provided_secret)
    if cred:
        if req.provider_id and req.provider_id.strip() and not cred.is_admin:
            if req.provider_id.strip() != cred.provider_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid provider authentication credentials.",
                )
        clean_provider = cred.provider_id
        is_admin = cred.is_admin
    elif provided_secret.startswith("provider:"):
        bound = provided_secret.split(":", 1)[1].strip()
        if req.provider_id and req.provider_id.strip() and req.provider_id.strip() != bound:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid provider authentication credentials.",
            )
        clean_provider = bound
        is_admin = False
    elif (
        (admin_configured_token and admin_configured_token.strip() and provided_secret == admin_configured_token.strip())
        or (configured_token and configured_token.strip() and provided_secret == configured_token.strip())
    ):
        if (clean_provider == "admin" or not req.provider_id) and admin_configured_token and provided_secret == admin_configured_token.strip():
            is_admin = True
            clean_provider = "admin"
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid provider credentials: the shared Coordinator token cannot be used for ordinary provider dashboard sessions.",
            )
    elif not configured_token:
        # Dev mode (no coordinator token configured)
        if settings.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Production coordinator authentication is not configured.",
            )
        is_admin = False
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid provider authentication credentials.",
        )

    session = session_manager.create_session(
        provider_id=clean_provider,
        is_admin=is_admin,
    )

    # Issue secure session cookie
    # Production deployments require HTTPS; local development / tests allow Secure=False.
    cookie_secure = settings.cookie_secure or (settings.environment == "production")
    response.set_cookie(
        key="expo_session",
        value=session.session_id,
        httponly=True,
        samesite="lax",
        secure=cookie_secure,
        path="/",
    )

    logger.info(f"Dashboard session created for provider '{clean_provider}' (admin={is_admin}, secure={cookie_secure})")
    return SessionLoginResponse(
        session_id=session.session_id,
        provider_id=session.provider_id,
        csrf_token=session.csrf_token,
        expires_at=session.expires_at,
        is_admin=session.is_admin,
    )


@provider_router.post(
    "/session/logout",
    summary="Logout browser session",
)
def session_logout(
    response: Response,
    session_cookie: Optional[str] = Cookie(None, alias="expo_session"),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    session_manager: ProviderSessionManager = Depends(get_session_manager),
) -> Dict[str, str]:
    """Terminates active browser session and clears the session cookie."""
    if session_cookie:
        session_manager.delete_session(session_cookie)
    response.delete_cookie(key="expo_session", path="/")
    logger.info(f"Dashboard session terminated for provider '{principal.provider_id}'")
    return {"status": "logged_out", "provider_id": principal.provider_id}


@provider_router.get(
    "/session/status",
    response_model=SessionStatusResponse,
    summary="Check current browser session status",
)
def session_status(
    principal: Optional[AuthenticatedPrincipal] = Depends(get_optional_principal),
) -> SessionStatusResponse:
    """Returns whether the caller has an active authenticated session/token and its CSRF token."""
    if not principal:
        return SessionStatusResponse(authenticated=False)
    return SessionStatusResponse(
        authenticated=True,
        provider_id=principal.provider_id,
        is_admin=principal.is_admin,
        csrf_token=principal.csrf_token,
    )


# =============================================================================
# 4. Node Management: Scheduling & Safe Draining
# =============================================================================

@provider_router.post(
    "/nodes/{node_id}/scheduling",
    response_model=NodeManagementActionResponse,
    summary="Toggle Node Scheduling (Enable/Disable)",
)
def set_node_scheduling(
    node_id: str,
    req: NodeSchedulingRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
) -> NodeManagementActionResponse:
    """
    Enables or disables future chunk placement scheduling on a provider's Storage Node.
    When disabled, smart node selection immediately excludes this node from allocation.
    """
    verify_node_ownership(node_id, principal, registry)
    enabled = req.get_enabled_state()
    updated_node = registry.set_node_scheduling(node_id, enabled=enabled)
    logger.info(f"Node {node_id} scheduling set to {enabled} by provider {principal.provider_id} (reason: {req.reason})")
    return NodeManagementActionResponse(
        node_id=updated_node.node_id,
        status=updated_node.status,
        is_schedulable=updated_node.is_schedulable,
        reason=req.reason,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@provider_router.post(
    "/nodes/{node_id}/shutdown",
    response_model=NodeManagementActionResponse,
    summary="Initiate Graceful Node Drain & Shutdown",
)
def initiate_node_shutdown(
    node_id: str,
    req: NodeShutdownRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeManagementActionResponse:
    """
    Initiates safe graceful shutdown by disabling scheduling and evaluating drain safety.
    Existing chunks remain readable; no new chunk placements will be assigned.
    """
    node = verify_node_ownership(node_id, principal, registry)
    drain_job = drain_service.initiate_drain(
        node_id=node_id,
        provider_id=principal.provider_id,
        registry=registry,
        reason=req.reason,
    )
    registry.set_node_status(node_id, "draining")
    logger.info(
        f"Node {node_id} drain initiated for shutdown by provider {principal.provider_id} "
        f"(status: {drain_job.status}, reason: {req.reason})"
    )
    return NodeManagementActionResponse(
        node_id=drain_job.node_id,
        status="draining",
        drain_status=drain_job.status,
        is_schedulable=False,
        reason=drain_job.reason,
        updated_at=drain_job.updated_at,
    )



@provider_router.post(
    "/nodes/{node_id}/drain",
    response_model=NodeDrainResponse,
    summary="Initiate Safe Node Draining",
)
def initiate_node_drain(
    node_id: str,
    req: Optional[NodeDrainRequest] = None,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainResponse:
    """
    Explicitly initiates safe node draining.
    Inspects dependent chunks, evaluates cluster redundancy, and sets truthful status.
    """
    verify_node_ownership(node_id, principal, registry)
    drain_req = req or NodeDrainRequest()
    if drain_service.worker and not drain_service.worker.is_running():
        try:
            drain_service.worker.start()
        except Exception:
            pass
    drain_job = drain_service.initiate_drain(
        node_id=node_id,
        provider_id=principal.provider_id,
        registry=registry,
        reason=drain_req.reason,
        force=drain_req.force,
    )
    return NodeDrainResponse(
        drain_id=drain_job.drain_id,
        node_id=drain_job.node_id,
        provider_id=drain_job.provider_id,
        status=drain_job.status,
        total_chunks=drain_job.total_chunks,
        migrated_chunks=drain_job.migrated_chunks,
        remaining_chunks=drain_job.remaining_chunks,
        failed_chunks=drain_job.failed_chunks,
        reason=drain_job.reason,
        started_at=drain_job.started_at,
        updated_at=drain_job.updated_at,
        completed_at=drain_job.completed_at,
        blocked_details=drain_job.blocked_details or [],
    )


@provider_router.get(
    "/nodes/{node_id}/drain",
    response_model=NodeDrainResponse,
    summary="Get Node Drain Job Status",
)
def get_node_drain(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainResponse:
    """Retrieves current durable status and progress for a node's drain workflow."""
    verify_node_ownership(node_id, principal, registry)
    drain_job = drain_service.get_drain_job(node_id)
    if not drain_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No drain job found for node '{node_id}'.",
        )
    return NodeDrainResponse(
        drain_id=drain_job.drain_id,
        node_id=drain_job.node_id,
        provider_id=drain_job.provider_id,
        status=drain_job.status,
        total_chunks=drain_job.total_chunks,
        migrated_chunks=drain_job.migrated_chunks,
        remaining_chunks=drain_job.remaining_chunks,
        failed_chunks=drain_job.failed_chunks,
        reason=drain_job.reason,
        started_at=drain_job.started_at,
        updated_at=drain_job.updated_at,
        completed_at=drain_job.completed_at,
        blocked_details=drain_job.blocked_details or [],
    )


@provider_router.post(
    "/nodes/{node_id}/drain/retry",
    response_model=NodeDrainResponse,
    summary="Retry a Blocked or Interrupted Node Drain",
)
def retry_node_drain(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainResponse:
    """Re-evaluates a blocked drain job when additional nodes or capacity have been added."""
    verify_node_ownership(node_id, principal, registry)
    drain_job = drain_service.retry_drain(
        node_id=node_id,
        provider_id=principal.provider_id,
        registry=registry,
    )
    return NodeDrainResponse(
        drain_id=drain_job.drain_id,
        node_id=drain_job.node_id,
        provider_id=drain_job.provider_id,
        status=drain_job.status,
        total_chunks=drain_job.total_chunks,
        migrated_chunks=drain_job.migrated_chunks,
        remaining_chunks=drain_job.remaining_chunks,
        failed_chunks=drain_job.failed_chunks,
        reason=drain_job.reason,
        started_at=drain_job.started_at,
        updated_at=drain_job.updated_at,
        completed_at=drain_job.completed_at,
        blocked_details=drain_job.blocked_details or [],
    )


@provider_router.get(
    "/nodes/{node_id}/drain/migrations",
    response_model=NodeDrainMigrationListResponse,
    summary="List Granular Migration Jobs for Node Drain",
)
def list_node_drain_migrations(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainMigrationListResponse:
    """Retrieves all tracked chunk and shard migration records for a node's drain workflow."""
    verify_node_ownership(node_id, principal, registry)
    job = drain_service.get_drain_job(node_id)
    drain_id = job.drain_id if job else ""
    migrations = drain_service.list_migrations(node_id=node_id)
    return NodeDrainMigrationListResponse(
        node_id=node_id,
        drain_id=drain_id,
        migrations=migrations,
        count=len(migrations),
    )


@provider_router.get(
    "/drain/worker/status",
    response_model=DrainWorkerStatusResponse,
    summary="Get Background Drain Migration Worker Status",
)
def get_drain_worker_status(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> DrainWorkerStatusResponse:
    """Returns the operational status, queue metrics, and active count of the migration worker."""
    with get_db_connection(drain_service.db_path) as conn:
        rows = conn.execute(
            "SELECT status, count(*) as cnt FROM node_drain_migrations GROUP BY status"
        ).fetchall()
    counts = {r["status"]: r["cnt"] for r in rows}
    is_running = drain_service.worker.is_running() if drain_service.worker else False
    in_flight = len(drain_service.worker._in_flight_migrations) if drain_service.worker else 0
    return DrainWorkerStatusResponse(
        is_running=is_running,
        active_workers=in_flight,
        pending_migrations=counts.get("pending", 0),
        in_flight_migrations=counts.get("transferring", 0) + counts.get("verifying", 0),
        completed_migrations=counts.get("completed", 0),
        failed_migrations=counts.get("retryable_failure", 0),
        blocked_migrations=counts.get("blocked", 0),
    )


@provider_router.post(
    "/nodes/{node_id}/drain/complete",
    response_model=NodeDrainResponse,
    summary="Complete a Node Drain After Redundancy Verification",
)
def complete_node_drain(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainResponse:
    """
    Marks a node safely removable ('drained') if redundancy verification passes.
    Returns 409 Conflict if required redundancy is missing.
    """
    verify_node_ownership(node_id, principal, registry)
    try:
        drain_job = drain_service.complete_drain(
            node_id=node_id,
            provider_id=principal.provider_id,
            registry=registry,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    return NodeDrainResponse(
        drain_id=drain_job.drain_id,
        node_id=drain_job.node_id,
        provider_id=drain_job.provider_id,
        status=drain_job.status,
        total_chunks=drain_job.total_chunks,
        migrated_chunks=drain_job.migrated_chunks,
        remaining_chunks=drain_job.remaining_chunks,
        failed_chunks=drain_job.failed_chunks,
        reason=drain_job.reason,
        started_at=drain_job.started_at,
        updated_at=drain_job.updated_at,
        completed_at=drain_job.completed_at,
        blocked_details=drain_job.blocked_details or [],
    )


@provider_router.post(
    "/nodes/{node_id}/drain/cancel",
    response_model=NodeDrainResponse,
    summary="Cancel an In-Progress or Blocked Node Drain",
)
def cancel_node_drain(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    drain_service: NodeDrainService = Depends(get_drain_service),
) -> NodeDrainResponse:
    """Cancels a drain workflow and restores node status to 'disabled'."""
    verify_node_ownership(node_id, principal, registry)
    try:
        drain_job = drain_service.cancel_drain(
            node_id=node_id,
            provider_id=principal.provider_id,
            registry=registry,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    return NodeDrainResponse(
        drain_id=drain_job.drain_id,
        node_id=drain_job.node_id,
        provider_id=drain_job.provider_id,
        status=drain_job.status,
        total_chunks=drain_job.total_chunks,
        migrated_chunks=drain_job.migrated_chunks,
        remaining_chunks=drain_job.remaining_chunks,
        failed_chunks=drain_job.failed_chunks,
        reason=drain_job.reason,
        started_at=drain_job.started_at,
        updated_at=drain_job.updated_at,
        completed_at=drain_job.completed_at,
        blocked_details=drain_job.blocked_details or [],
    )


# =============================================================================
# 5. Phase 10C: Provider Onboarding, Node Validation and Probation
# =============================================================================

@provider_router.post(
    "/onboard",
    response_model=ProviderOnboardResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete Provider Onboarding and Terms Acceptance",
)
def onboard_provider(
    data: ProviderOnboardRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    account_manager: AccountManager = Depends(get_account_manager),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ProviderOnboardResponse:
    """Records formal provider terms consent and verifies provider capabilities."""
    if not data.accept_terms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Terms and conditions must be explicitly accepted to onboard as a provider.",
        )

    # Verify that account exists and is active if authenticated via account
    account = None
    if principal.account_id:
        account = account_manager.get_account(principal.account_id)
        if not account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Account '{principal.account_id}' not found.",
            )
        if account.status in ("suspended", "disabled", "inactive"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account '{principal.account_id}' is {account.status}. Onboarding rejected.",
            )
        if getattr(settings, "require_email_verification", False) and not account.email_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email verification required. Please verify your email address to onboard as a provider.",
            )

    # Determine stable provider identity:
    # If client passed provider_id, ensure non-admin cannot spoof another provider
    if data.provider_id and data.provider_id.strip():
        req_provider = data.provider_id.strip()
        if not principal.is_admin and principal.provider_id != "default_provider" and req_provider != principal.provider_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Not authorized to onboard as provider '{req_provider}'.",
            )
        provider_id = req_provider
    elif principal.provider_id and principal.provider_id != "default_provider":
        provider_id = principal.provider_id
    elif principal.account_id:
        provider_id = account.provider_id if (account and account.provider_id) else f"provider-{principal.account_id}"
    else:
        provider_id = "default_provider"

    # Add 'provider' capability to the account if account exists
    if account and "provider" not in account.capabilities:
        new_caps = list(account.capabilities) + ["provider"]
        account_manager.update_account_capabilities(account.account_id, new_caps)

    now_str = datetime.now(timezone.utc).isoformat()
    terms_ver = data.terms_version.strip() if (data.terms_version and data.terms_version.strip()) else settings.terms_version

    # Persist consent and onboarding status in provider_onboarding
    with get_db_connection(settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO provider_onboarding (
                provider_id, account_id, terms_version, terms_accepted_at, accepted_at, is_verified, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?)
            ON CONFLICT(provider_id) DO UPDATE SET
                account_id = excluded.account_id,
                terms_version = excluded.terms_version,
                terms_accepted_at = excluded.terms_accepted_at,
                accepted_at = excluded.accepted_at,
                is_verified = 1,
                status = 'active',
                updated_at = excluded.updated_at
            """,
            (provider_id, principal.account_id, terms_ver, now_str, now_str, now_str, now_str),
        )
        if principal.account_id:
            conn.execute(
                "UPDATE accounts SET provider_id = ?, updated_at = ? WHERE account_id = ?",
                (provider_id, now_str, principal.account_id),
            )
            conn.execute(
                "UPDATE account_sessions SET provider_id = ? WHERE account_id = ?",
                (provider_id, principal.account_id),
            )
        conn.commit()

    return ProviderOnboardResponse(
        provider_id=provider_id,
        account_id=principal.account_id,
        is_verified=True,
        terms_version=terms_ver,
        terms_accepted_at=now_str,
        accepted_at=now_str,
        status="active",
        message="Provider onboarding and terms agreement completed successfully.",
    )


@provider_router.get(
    "/onboarding",
    response_model=ProviderOnboardResponse,
    summary="Get Provider Onboarding Status",
)
def get_onboarding_status(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ProviderOnboardResponse:
    """Returns onboarding status and agreed terms version for the authenticated provider."""
    provider_id = principal.provider_id
    with get_db_connection(settings.db_path) as conn:
        row = conn.execute(
            "SELECT * FROM provider_onboarding WHERE provider_id = ? OR account_id = ?",
            (provider_id, principal.account_id or ""),
        ).fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Onboarding record not found for provider '{provider_id}'.",
            )
        acc_time = row["terms_accepted_at"] if ("terms_accepted_at" in row.keys() and row["terms_accepted_at"]) else (row["accepted_at"] if "accepted_at" in row.keys() else "")
        verified = bool(row["is_verified"]) if "is_verified" in row.keys() else True
        return ProviderOnboardResponse(
            provider_id=row["provider_id"],
            account_id=row["account_id"],
            is_verified=verified,
            terms_version=row["terms_version"],
            terms_accepted_at=acc_time,
            accepted_at=acc_time,
            status=row["status"],
            message="Provider onboarding is active.",
        )


@provider_router.post(
    "/nodes/{node_id}/validate",
    response_model=NodeValidationResponse,
    summary="Run Storage Node Health and Integrity Validation",
)
def validate_node(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    settings: CoordinatorSettings = Depends(get_settings),
) -> NodeValidationResponse:
    """Executes non-destructive health, sandbox write/read, and cleanup checks on the target node."""
    verify_node_ownership(node_id, principal, registry)
    from coordinator.app.node_validation import NodeValidator
    validator = NodeValidator(settings)
    try:
        result = validator.validate_node(node_id=node_id)
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation error: {exc}",
        )


@provider_router.get(
    "/nodes/{node_id}/validation",
    response_model=ProviderNodeValidationHistoryResponse,
    summary="Get Node Health Validation History",
)
def get_node_validation_history(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ProviderNodeValidationHistoryResponse:
    """Retrieves full validation history and current probation status for a node."""
    node = verify_node_ownership(node_id, principal, registry)
    validator = NodeValidator(settings)
    with get_db_connection(settings.db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM node_validation_records WHERE node_id = ? ORDER BY performed_at DESC LIMIT 50",
            (node_id,),
        ).fetchall()
        records: List[NodeValidationResponse] = []
        for r in rows:
            checks_list = []
            try:
                raw_checks = json.loads(r["checks_performed"]) if r["checks_performed"] else []
                for c in raw_checks:
                    checks_list.append(NodeValidationCheckItem(**c))
            except Exception:
                pass
            score = 0.0
            try:
                if r["details_json"]:
                    dj = json.loads(r["details_json"])
                    score = float(dj.get("reliability_score", node.reliability_score))
            except Exception:
                score = float(node.reliability_score)

            records.append(
                NodeValidationResponse(
                    validation_id=r["validation_id"],
                    node_id=r["node_id"],
                    provider_id=r["provider_id"],
                    status=r["status"],
                    lifecycle_state=node.lifecycle_state,
                    overall_status=r["status"],
                    resulting_lifecycle_state=node.lifecycle_state,
                    failure_reason=r["failure_reason"],
                    reliability_score=score,
                    checks=checks_list,
                    performed_at=r["performed_at"],
                    duration_ms=r["duration_ms"] or 0.0,
                )
            )

    probation_status = validator.get_probation_status(node_id)
    return ProviderNodeValidationHistoryResponse(
        node_id=node.node_id,
        probation_status=probation_status,
        validations=records,
        count=len(records),
    )


@provider_router.get(
    "/nodes/{node_id}/probation",
    response_model=NodeProbationStatusResponse,
    summary="Get Node Probation Lifecycle Status",
)
def get_node_probation_status(
    node_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    registry: NodeRegistry = Depends(get_registry),
    settings: CoordinatorSettings = Depends(get_settings),
) -> NodeProbationStatusResponse:
    """Returns real-time probation metrics and promotion eligibility for a node."""
    verify_node_ownership(node_id, principal, registry)
    validator = NodeValidator(settings)
    return validator.get_probation_status(node_id)


# =============================================================================
# 6. Interactive Provider Dashboard (HTML5 SPA)
# =============================================================================

@provider_router.get(
    "/dashboard",
    response_class=HTMLResponse,
    summary="Serve Provider Dashboard Web UI",
)
def serve_provider_dashboard() -> HTMLResponse:
    """Serves the rich, responsive, accessible Provider Monitoring & Management Dashboard."""
    from pathlib import Path
    frontend_html = Path(__file__).resolve().parent.parent.parent / "frontend" / "index.html"
    html_path = frontend_html if frontend_html.exists() else (Path(__file__).parent / "static" / "index.html")
    if html_path.exists():
        content = html_path.read_text(encoding="utf-8")
    else:
        content = "<h1>Expo Provider Dashboard</h1><p>UI assets not found.</p>"
    return HTMLResponse(content=content)
