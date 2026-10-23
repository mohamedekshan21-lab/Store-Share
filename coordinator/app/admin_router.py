"""
Phase 10F: Role-Protected Administrative API Router.

Provides:
- Account inspection, filtering, and safe administrative suspension/restoration.
- Storage Node lifecycle inspection and administrative drain controls.
- Aggregate system-wide capacity, storage, and health statistics.
- Failed background jobs inspection (stalled deletions, failed repairs) and reconciliation triggers.
- Paginated, bounded audit event logging with zero sensitive credential leakage.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from coordinator.app.config import CoordinatorSettings, get_coordinator_settings
from coordinator.app.database import get_db_connection, record_audit_event, get_audit_events
from coordinator.app.main import get_settings
from coordinator.app.auth import AccountManager, AccountRecord
from coordinator.app.auth_router import (
    get_account_manager,
    get_current_account,
    get_client_ip,
    build_account_response,
)
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.reconciliation import ReconciliationService
from coordinator.app.models import (
    AccountResponse,
    NodeRecord,
    AdminAccountListResponse,
    AdminUpdateAccountStatusRequest,
    AdminDrainNodeRequest,
    AdminNodeListResponse,
    AdminStatsOverviewResponse,
    AdminAuditLogEntry,
    AdminAuditLogListResponse,
    ActionStatusResponse,
    ReconciliationReport,
)

logger = logging.getLogger("expo_admin_router")

admin_router = APIRouter(prefix="/admin", tags=["Administrative Control"])


def resolve_settings(request: Request) -> CoordinatorSettings:
    if hasattr(request.app.state, "settings"):
        return request.app.state.settings
    return get_coordinator_settings()


def require_admin_account(
    account: Annotated[AccountRecord, Depends(get_current_account)],
) -> AccountRecord:
    """
    Enforces server-side administrator role verification on every admin route.
    Rejects any non-admin account (Consumer, Provider) with HTTP 403 Forbidden.
    Never trusts client-supplied headers or role claims.
    """
    if not account.is_admin():
        logger.warning(
            "Access denied to admin API for non-admin account [account_id=%s, role=%s]",
            account.account_id,
            account.role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Explicit administrative privileges required.",
        )
    return account


def get_admin_registry(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> NodeRegistry:
    if not hasattr(request.app.state, "registry") or getattr(request.app.state.registry, "db_path", None) != settings.db_path:
        request.app.state.registry = NodeRegistry(settings)
    return request.app.state.registry


def get_admin_recon(
    request: Request,
    settings: Annotated[CoordinatorSettings, Depends(get_settings)],
) -> ReconciliationService:
    if not hasattr(request.app.state, "reconciliation_service"):
        request.app.state.reconciliation_service = ReconciliationService(settings)
    return request.app.state.reconciliation_service


# =============================================================================
# 1. Account Status & Inspection APIs
# =============================================================================

@admin_router.get(
    "/accounts",
    response_model=AdminAccountListResponse,
    summary="List and Inspect User Accounts (Admin Only)",
)
def list_accounts(
    request: Request,
    limit: int = Query(50, ge=1, description="Page limit (max 100)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    search: Optional[str] = Query(None, description="Search email or account ID substring"),
    role: Optional[str] = Query(None, description="Filter by role ('consumer', 'provider', 'admin')"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status ('active', 'suspended', 'disabled')"),
    admin: AccountRecord = Depends(require_admin_account),
    settings: CoordinatorSettings = Depends(get_settings),
) -> AdminAccountListResponse:
    """
    Returns bounded and paginated account records for administrative review.
    Sanitizes all sensitive secrets, password hashes, and tokens.
    """
    safe_limit = max(1, min(100, int(limit)))
    safe_offset = max(0, int(offset))

    where_clauses = []
    params: List[Any] = []

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        where_clauses.append("(LOWER(email) LIKE ? OR LOWER(account_id) LIKE ?)")
        params.extend([term, term])

    if role and role.strip():
        where_clauses.append("role = ?")
        params.append(role.strip().lower())

    if status_filter and status_filter.strip():
        where_clauses.append("status = ?")
        params.append(status_filter.strip().lower())

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with get_db_connection(settings.db_path) as conn:
        count_row = conn.execute(
            f"SELECT COUNT(*) AS total FROM accounts {where_sql}",
            params,
        ).fetchone()
        total = count_row["total"] if count_row else 0

        query_sql = f"""
            SELECT * FROM accounts
            {where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query_sql, params + [safe_limit, safe_offset]).fetchall()

        sanitized_accounts: List[AccountResponse] = []
        for r in rows:
            capabilities_list = []
            if r["capabilities"]:
                try:
                    capabilities_list = json.loads(r["capabilities"])
                except Exception:
                    capabilities_list = []

            sanitized_accounts.append(
                AccountResponse(
                    account_id=r["account_id"],
                    email=r["email"],
                    role=r["role"],
                    capabilities=capabilities_list,
                    status=r["status"],
                    provider_id=r["provider_id"],
                    email_verified=bool(r["email_verified"]),
                    email_verified_at=r["email_verified_at"] if "email_verified_at" in r.keys() else None,
                    phone_number=r["phone_number"] if "phone_number" in r.keys() else None,
                    phone_verified=bool(r["phone_verified"]) if "phone_verified" in r.keys() else False,
                    phone_verified_at=r["phone_verified_at"] if "phone_verified_at" in r.keys() else None,
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
            )

    return AdminAccountListResponse(
        total=total,
        limit=safe_limit,
        offset=safe_offset,
        accounts=sanitized_accounts,
    )


@admin_router.post(
    "/accounts/{account_id}/status",
    response_model=ActionStatusResponse,
    summary="Update Account Status (Suspend/Restore under Safe Policy)",
)
def update_account_status(
    account_id: str,
    req: AdminUpdateAccountStatusRequest,
    request: Request,
    admin: AccountRecord = Depends(require_admin_account),
    account_manager: AccountManager = Depends(get_account_manager),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ActionStatusResponse:
    """
    Administratively updates an account's operational status ('active', 'suspended', 'disabled').
    Enforces safe policy:
    1. Caller cannot suspend or disable their own account.
    2. Cannot suspend or disable the last active administrator.
    3. Suspension or disabling immediately revokes all active sessions for that account.
    4. Audits the action in the administrative audit log.
    """
    clean_target_id = account_id.strip()
    target_status = req.status.strip().lower()

    if target_status not in ("active", "suspended", "disabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{req.status}'. Must be one of: 'active', 'suspended', 'disabled'.",
        )

    target_acc = account_manager.get_account(clean_target_id)
    if not target_acc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Account '{clean_target_id}' not found.",
        )

    # Policy 1: Cannot suspend self
    if target_acc.account_id == admin.account_id and target_status in ("suspended", "disabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Forbidden: Administrators cannot suspend or disable their own account.",
        )

    # Policy 2: Cannot suspend last active admin
    if target_acc.is_admin() and target_status in ("suspended", "disabled"):
        with get_db_connection(settings.db_path) as conn:
            active_admin_count = conn.execute(
                "SELECT COUNT(*) AS c FROM accounts WHERE role = 'admin' AND status = 'active'"
            ).fetchone()["c"]
            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot suspend the last remaining active administrator account.",
                )

    old_status = target_acc.status
    now_str = datetime.now(timezone.utc).isoformat()

    with get_db_connection(settings.db_path) as conn:
        conn.execute(
            "UPDATE accounts SET status = ?, updated_at = ? WHERE account_id = ?",
            (target_status, now_str, clean_target_id),
        )
        conn.commit()

    # Policy 3: Revoke all active sessions on suspension or disabling
    revoked_sessions = 0
    if target_status in ("suspended", "disabled"):
        revoked_sessions = account_manager.revoke_account_sessions(clean_target_id)

    # Policy 4: Audit sensitive administrative action
    client_ip = get_client_ip(request)
    record_audit_event(
        db_path=settings.db_path,
        admin_account_id=admin.account_id,
        admin_email=admin.email,
        action="account_status_update",
        target_type="account",
        target_id=clean_target_id,
        details={
            "old_status": old_status,
            "new_status": target_status,
            "reason": req.reason,
            "revoked_sessions": revoked_sessions,
        },
        ip_address=client_ip,
    )

    logger.info(
        "Admin '%s' changed status of account '%s' from '%s' to '%s' (revoked %d sessions)",
        admin.email,
        clean_target_id,
        old_status,
        target_status,
        revoked_sessions,
    )

    return ActionStatusResponse(
        detail=f"Account '{clean_target_id}' status updated to '{target_status}'.",
        success=True,
    )


# =============================================================================
# 2. Storage Node Health & Lifecycle Inspection APIs
# =============================================================================

@admin_router.get(
    "/nodes",
    response_model=AdminNodeListResponse,
    summary="List Storage Nodes with Lifecycle & Reliability Stats (Admin Only)",
)
def list_admin_nodes(
    limit: int = Query(50, ge=1, description="Page limit (max 100)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by operational status"),
    lifecycle_state: Optional[str] = Query(None, description="Filter by lifecycle state ('probation', 'online', etc.)"),
    provider_id: Optional[str] = Query(None, description="Filter by provider ID"),
    admin: AccountRecord = Depends(require_admin_account),
    registry: NodeRegistry = Depends(get_admin_registry),
    settings: CoordinatorSettings = Depends(get_settings),
) -> AdminNodeListResponse:
    """
    Returns paginated storage node records enriched with health, probation,
    and reliability metrics. Bounded to a maximum limit of 100.
    """
    safe_limit = max(1, min(100, int(limit)))
    safe_offset = max(0, int(offset))

    all_nodes = registry.list_nodes(
        status_filter=status_filter,
    )

    if provider_id and provider_id.strip():
        req_prov = provider_id.strip()
        all_nodes = [n for n in all_nodes if n.provider_id == req_prov]

    if lifecycle_state and lifecycle_state.strip():
        target_lc = lifecycle_state.strip().lower()
        all_nodes = [n for n in all_nodes if (n.lifecycle_state or "").lower() == target_lc]

    total = len(all_nodes)
    paginated_nodes = all_nodes[safe_offset : safe_offset + safe_limit]

    return AdminNodeListResponse(
        total=total,
        limit=safe_limit,
        offset=safe_offset,
        nodes=paginated_nodes,
    )


@admin_router.post(
    "/nodes/{node_id}/drain",
    response_model=ActionStatusResponse,
    summary="Initiate Graceful Drain for a Storage Node (Admin Only)",
)
def admin_drain_node(
    node_id: str,
    req: AdminDrainNodeRequest,
    request: Request,
    admin: AccountRecord = Depends(require_admin_account),
    registry: NodeRegistry = Depends(get_admin_registry),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ActionStatusResponse:
    """Administratively marks a node as draining and disables future placements."""
    clean_nid = node_id.strip()
    node = registry.get_node(clean_nid)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Storage node '{clean_nid}' not found.",
        )

    registry.set_node_status(clean_nid, "draining")
    registry.set_node_scheduling(clean_nid, False)

    with get_db_connection(settings.db_path) as conn:
        conn.execute(
            "UPDATE nodes SET drain_status = 'draining', lifecycle_state = 'draining' WHERE node_id = ?",
            (clean_nid,),
        )
        conn.commit()

    client_ip = get_client_ip(request)
    record_audit_event(
        db_path=settings.db_path,
        admin_account_id=admin.account_id,
        admin_email=admin.email,
        action="node_drain_initiated",
        target_type="storage_node",
        target_id=clean_nid,
        details={"reason": req.reason, "node_endpoint": node.endpoint},
        ip_address=client_ip,
    )

    logger.info("Admin '%s' initiated drain on node '%s'", admin.email, clean_nid)
    return ActionStatusResponse(
        detail=f"Node '{clean_nid}' marked as draining. Placements disabled.",
        success=True,
    )


# =============================================================================
# 3. Aggregate Storage & Health Statistics
# =============================================================================

@admin_router.get(
    "/stats/overview",
    response_model=AdminStatsOverviewResponse,
    summary="Get System-Wide Aggregate Statistics (Admin Only)",
)
def get_stats_overview(
    admin: AccountRecord = Depends(require_admin_account),
    settings: CoordinatorSettings = Depends(get_settings),
) -> AdminStatsOverviewResponse:
    """Returns system-wide aggregated counts, capacity, placement, and job statistics."""
    now_str = datetime.now(timezone.utc).isoformat()
    acc_stats = {"total": 0, "active": 0, "suspended": 0, "providers": 0, "admins": 0}
    node_stats = {"total": 0, "online": 0, "offline": 0, "probation": 0, "unhealthy": 0, "draining": 0}
    storage_stats = {
        "total_capacity_bytes": 0,
        "used_capacity_bytes": 0,
        "available_capacity_bytes": 0,
        "total_files": 0,
        "total_file_bytes": 0,
        "allocated_quota_bytes": 0,
    }
    job_stats = {"pending_deletions": 0, "failed_repairs": 0, "active_reservations": 0}

    with get_db_connection(settings.db_path) as conn:
        # Accounts
        acc_rows = conn.execute("SELECT role, status, quota_bytes FROM accounts").fetchall()
        acc_stats["total"] = len(acc_rows)
        for r in acc_rows:
            st = (r["status"] or "active").lower()
            rl = (r["role"] or "consumer").lower()
            if st == "active":
                acc_stats["active"] += 1
            elif st in ("suspended", "disabled"):
                acc_stats["suspended"] += 1

            if rl == "provider":
                acc_stats["providers"] += 1
            elif rl == "admin":
                acc_stats["admins"] += 1

            storage_stats["allocated_quota_bytes"] += int(r["quota_bytes"] or 0)

        # Nodes
        node_rows = conn.execute("SELECT status, lifecycle_state, total_capacity_bytes, used_capacity_bytes, available_capacity_bytes FROM nodes").fetchall()
        node_stats["total"] = len(node_rows)
        for r in node_rows:
            st = (r["status"] or "offline").lower()
            lc = (r["lifecycle_state"] or "registered").lower()
            if st == "online":
                node_stats["online"] += 1
            elif st == "unhealthy":
                node_stats["unhealthy"] += 1
            elif st in ("draining", "drain_blocked", "drained"):
                node_stats["draining"] += 1
            else:
                node_stats["offline"] += 1

            if lc == "probation":
                node_stats["probation"] += 1

            storage_stats["total_capacity_bytes"] += int(r["total_capacity_bytes"] or 0)
            storage_stats["used_capacity_bytes"] += int(r["used_capacity_bytes"] or 0)
            storage_stats["available_capacity_bytes"] += int(r["available_capacity_bytes"] or 0)

        # Files
        file_row = conn.execute("SELECT COUNT(*) AS c, SUM(original_size) AS s FROM files WHERE status = 'active'").fetchone()
        storage_stats["total_files"] = int(file_row["c"] or 0)
        storage_stats["total_file_bytes"] = int(file_row["s"] or 0)

        # Background Jobs
        del_row = conn.execute("SELECT COUNT(*) AS c FROM deletion_jobs WHERE status IN ('pending', 'running')").fetchone()
        job_stats["pending_deletions"] = int(del_row["c"] or 0)

        try:
            from coordinator.app.main import _coordinator_repair_jobs
            job_stats["failed_repairs"] = sum(1 for j in _coordinator_repair_jobs.values() if (j.get("status") or "").lower() == "failed")
        except Exception:
            job_stats["failed_repairs"] = 0

        res_row = conn.execute("SELECT COUNT(*) AS c FROM account_quota_reservations WHERE status = 'active'").fetchone()
        job_stats["active_reservations"] = int(res_row["c"] or 0)

    return AdminStatsOverviewResponse(
        accounts=acc_stats,
        nodes=node_stats,
        storage=storage_stats,
        jobs=job_stats,
        timestamp=now_str,
    )


# =============================================================================
# 4. Failed Jobs & Reconciliation Management
# =============================================================================

@admin_router.get(
    "/operations/failures",
    summary="Inspect Failed or Stalled Background Operations (Admin Only)",
)
def inspect_operational_failures(
    admin: AccountRecord = Depends(require_admin_account),
    settings: CoordinatorSettings = Depends(get_settings),
) -> Dict[str, Any]:
    """Returns stalled deletions, failed repairs, and orphaned reservations."""
    with get_db_connection(settings.db_path) as conn:
        failed_deletions = conn.execute(
            "SELECT * FROM deletion_jobs WHERE status = 'failed' ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()

        failed_repairs = []
        try:
            from coordinator.app.main import _coordinator_repair_jobs
            failed_repairs = [j for j in _coordinator_repair_jobs.values() if (j.get("status") or "").lower() == "failed"][:50]
        except Exception:
            pass

        expired_reservations = conn.execute(
            "SELECT * FROM account_quota_reservations WHERE status = 'active' AND expires_at < ? LIMIT 50",
            (datetime.now(timezone.utc).isoformat(),),
        ).fetchall()

        return {
            "failed_deletions": [dict(r) for r in failed_deletions],
            "failed_repairs": failed_repairs,
            "expired_stuck_reservations": [dict(r) for r in expired_reservations],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@admin_router.post(
    "/operations/reconcile",
    response_model=ReconciliationReport,
    summary="Trigger Catalog Reconciliation Service (Admin Only)",
)
def trigger_admin_reconciliation(
    request: Request,
    dry_run: bool = Query(True, description="Dry run mode without mutating objects"),
    admin: AccountRecord = Depends(require_admin_account),
    recon: ReconciliationService = Depends(get_admin_recon),
    settings: CoordinatorSettings = Depends(get_settings),
) -> ReconciliationReport:
    """Manually triggers catalog reconciliation across storage nodes and files."""
    report = recon.run_reconciliation(dry_run=dry_run)

    client_ip = get_client_ip(request)
    record_audit_event(
        db_path=settings.db_path,
        admin_account_id=admin.account_id,
        admin_email=admin.email,
        action="catalog_reconciliation_executed",
        target_type="catalog",
        target_id="system",
        details={
            "dry_run": dry_run,
            "orphaned_objects_detected": report.orphaned_objects_detected,
            "orphaned_objects_cleaned": report.orphaned_objects_cleaned,
            "missing_objects_detected": report.missing_objects_detected,
            "stalled_deletions_resumed": report.stalled_deletions_resumed,
        },
        ip_address=client_ip,
    )

    return report


# =============================================================================
# 5. Audit Log Inspection API
# =============================================================================

@admin_router.get(
    "/audit-logs",
    response_model=AdminAuditLogListResponse,
    summary="Retrieve Administrative Audit Logs (Admin Only)",
)
def list_audit_logs(
    limit: int = Query(50, ge=1, description="Page limit (max 100)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    admin_id: Optional[str] = Query(None, description="Filter by admin account ID or email"),
    admin: AccountRecord = Depends(require_admin_account),
    settings: CoordinatorSettings = Depends(get_settings),
) -> AdminAuditLogListResponse:
    """Retrieves paginated and bounded administrative audit logs."""
    total, raw_events = get_audit_events(
        db_path=settings.db_path,
        limit=limit,
        offset=offset,
        action=action,
        admin_id=admin_id,
    )

    log_entries = [
        AdminAuditLogEntry(
            audit_id=e["audit_id"],
            timestamp=e["timestamp"],
            admin_account_id=e["admin_account_id"],
            admin_email=e["admin_email"],
            action=e["action"],
            target_type=e["target_type"],
            target_id=e["target_id"],
            details=e["details"],
            ip_address=e["ip_address"],
        )
        for e in raw_events
    ]

    return AdminAuditLogListResponse(
        total=total,
        limit=max(1, min(100, int(limit))),
        offset=max(0, int(offset)),
        logs=log_entries,
    )
