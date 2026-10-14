"""
Pydantic data models for Expo Coordinator API (Phase 2B).
Supports internet connectivity metadata, connectivity modes, protocol versioning,
and smart node selection.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Coordinator liveness health check response."""
    status: str = Field(default="online", json_schema_extra={"example": "online"})


class NodeRegisterRequest(BaseModel):
    """Registration request sent by a Storage Node to the Coordinator."""
    node_id: str = Field(..., description="Stable persistent Node ID (e.g. NODE-<UUID>)")
    host: str = Field(..., description="Storage Node IP address or hostname")
    port: int = Field(..., description="Storage Node port number")
    endpoint: Optional[str] = Field(None, description="Optional full HTTP/HTTPS endpoint URL")
    advertised_endpoint: Optional[str] = Field(None, description="Publicly advertised endpoint URL")
    connectivity_mode: Optional[str] = Field("LAN", description="Connectivity capability ('LAN', 'DIRECT', 'RELAY', 'UNKNOWN')")
    protocol_version: Optional[str] = Field("2B", description="Supported protocol version")
    total_capacity_bytes: Optional[int] = Field(None, description="Total storage capacity in bytes")
    storage_capacity_bytes: Optional[int] = Field(None, description="Alias for total_capacity_bytes")
    used_capacity_bytes: Optional[int] = Field(0, description="Currently used capacity in bytes")
    available_capacity_bytes: Optional[int] = Field(None, description="Remaining available capacity in bytes")
    physical_total_bytes: Optional[int] = Field(None, description="Physical host disk total capacity in bytes")
    physical_free_bytes: Optional[int] = Field(None, description="Physical host disk free capacity in bytes")
    provider_id: Optional[str] = Field("default_provider", description="Provider account/owner identity")
    is_schedulable: Optional[bool] = Field(True, description="Whether node accepts new chunk allocations")


class NodeHeartbeatRequest(BaseModel):
    """Heartbeat request sent by a Storage Node to report liveness and capacity updates."""
    node_id: Optional[str] = Field(None, description="Node ID sending heartbeat")
    status: Optional[str] = Field("online", description="Reported operational status")
    endpoint: Optional[str] = Field(None, description="Updated endpoint URL")
    advertised_endpoint: Optional[str] = Field(None, description="Updated advertised endpoint URL")
    used_capacity_bytes: Optional[int] = Field(None, description="Updated used capacity in bytes")
    used_bytes: Optional[int] = Field(None, description="Alias for used_capacity_bytes")
    available_capacity_bytes: Optional[int] = Field(None, description="Updated available capacity in bytes")
    available_bytes: Optional[int] = Field(None, description="Alias for available_capacity_bytes")
    physical_total_bytes: Optional[int] = Field(None, description="Physical host disk total capacity in bytes")
    physical_free_bytes: Optional[int] = Field(None, description="Physical host disk free capacity in bytes")
    connectivity_mode: Optional[str] = Field(None, description="Updated connectivity capability")
    protocol_version: Optional[str] = Field(None, description="Updated protocol version")
    timestamp: Optional[str] = Field(None, description="Optional timestamp of heartbeat creation")


class NodeRecord(BaseModel):
    """Registered Storage Node record stored in Node Registry."""
    node_id: str = Field(..., description="Stable persistent Node ID")
    host: str = Field(..., description="Storage Node IP or hostname")
    port: int = Field(..., description="Storage Node listening port")
    endpoint: str = Field(..., description="Full endpoint URL for access")
    advertised_endpoint: Optional[str] = Field(None, description="Publicly advertised endpoint URL")
    status: str = Field(..., description="Operational status ('online', 'offline', 'connecting', 'degraded')")
    connectivity_mode: str = Field(default="LAN", description="Connectivity mode ('LAN', 'DIRECT', 'RELAY', 'UNKNOWN')")
    protocol_version: str = Field(default="2B", description="Protocol version string")
    total_capacity_bytes: int = Field(..., description="Total storage capacity in bytes")
    used_capacity_bytes: int = Field(..., description="Used capacity in bytes")
    available_capacity_bytes: int = Field(..., description="Available capacity in bytes")
    last_seen: str = Field(..., description="ISO 8601 timestamp of last received heartbeat or registration")
    registered_at: str = Field(..., description="ISO 8601 timestamp of initial node registration")
    provider_id: Optional[str] = Field("default_provider", description="Provider account/owner identity")
    is_schedulable: Optional[bool] = Field(True, description="Whether node accepts new chunk allocations")
    drain_status: Optional[str] = Field("none", description="Durable drain status ('none', 'draining', 'drain_blocked', 'drained', 'decommissioned')")


class NodeListResponse(BaseModel):
    """Response model for node discovery requests."""
    nodes: List[NodeRecord] = Field(default_factory=list)
    count: int = Field(..., description="Total count of matching registered nodes")


class NodeSelectionRequest(BaseModel):
    """Request model for smart node selection."""
    required_bytes: int = Field(..., description="Minimum required available storage in bytes")
    online_only: bool = Field(default=True, description="Filter for online nodes only")
    preferred_connectivity: Optional[str] = Field(None, description="Preferred connectivity mode ('LAN', 'DIRECT', 'RELAY')")
    require_reachable: bool = Field(default=False, description="Filter for verified reachable nodes")


class NodeConnectivityResponse(BaseModel):
    """Diagnostic response model for node connectivity status."""
    node_id: str = Field(..., description="Stable persistent Node ID")
    status: str = Field(..., description="Coordinator liveness status ('online', 'offline')")
    connectivity_mode: str = Field(default="LAN", description="Connectivity mode ('LAN', 'DIRECT', 'RELAY', 'UNKNOWN')")
    endpoint: str = Field(..., description="Registered local endpoint URL")
    advertised_endpoint: str = Field(..., description="Publicly advertised endpoint URL")
    reachability: str = Field(default="UNKNOWN", description="Consumer reachability status ('REACHABLE', 'UNREACHABLE', 'UNKNOWN')")
    last_seen: str = Field(..., description="ISO 8601 timestamp of last liveness update")
    available_capacity_bytes: int = Field(..., description="Available capacity in bytes")
    total_capacity_bytes: int = Field(..., description="Total capacity in bytes")
    used_capacity_bytes: int = Field(..., description="Used capacity in bytes")
    protocol_version: str = Field(default="3C", description="Protocol version string")


class RepairJobRecord(BaseModel):
    """Coordinator repair job status response model."""
    job_id: str = Field(..., description="Unique repair job UUID")
    file_id: str = Field(..., description="Target file UUID")
    chunk_id: str = Field(..., description="Target chunk UUID")
    sequence: int = Field(default=0, description="Chunk sequence index")
    required_replication_factor: int = Field(default=2, description="Target replication factor")
    source_node_id: Optional[str] = Field(None, description="Healthy source node ID")
    source_node_endpoint: Optional[str] = Field(None, description="Source node endpoint")
    destination_node_id: Optional[str] = Field(None, description="Replacement node ID")
    destination_node_endpoint: Optional[str] = Field(None, description="Replacement node endpoint")
    state: str = Field(..., description="Repair job state ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'RETRY_WAIT', 'UNRECOVERABLE')")
    attempt_count: int = Field(default=0, description="Attempt count")
    max_attempts: int = Field(default=3, description="Max allowed attempts")
    last_error: Optional[str] = Field(None, description="Last failure error detail")
    created_at: str = Field(..., description="Creation ISO timestamp")
    updated_at: str = Field(..., description="Update ISO timestamp")
    completed_at: Optional[str] = Field(None, description="Completion ISO timestamp")


class RepairJobListResponse(BaseModel):
    """Response list for Coordinator repair jobs query."""
    jobs: List[RepairJobRecord] = Field(default_factory=list)
    count: int = Field(..., description="Total matching jobs count")


class RegisterFileRequest(BaseModel):
    """Request to register a newly uploaded file."""
    manifest: dict = Field(..., description="The FileManifest representation")


class FileCatalogRecord(BaseModel):
    """Record of a logical file tracked by the Coordinator."""
    file_id: str
    owner_id: str
    original_filename: str
    original_size: int
    status: str
    redundancy_mode: str
    manifest_version: int
    manifest_json: str
    created_at: str
    updated_at: str


class FileCatalogListResponse(BaseModel):
    """Response list for file catalog query."""
    files: List[FileCatalogRecord] = Field(default_factory=list)


class DeletionJobRecord(BaseModel):
    """Phase 5C: Durable deletion job record."""
    job_id: str
    file_id: str
    owner_id: str
    status: str
    target_chunks: str
    attempt_count: int
    created_at: str
    updated_at: str


class ReconciliationReport(BaseModel):
    """Phase 5C: Reconciliation report output."""
    status: str = Field(..., description="'dry_run' or 'executed'")
    incomplete_uploads_cleaned: int = Field(default=0)
    stalled_deletions_resumed: int = Field(default=0)
    missing_objects_detected: int = Field(default=0)
    stale_placements_removed: int = Field(default=0)
    orphaned_objects_detected: int = Field(default=0)
    orphaned_objects_cleaned: int = Field(default=0)
    capacity_discrepancies_fixed: int = Field(default=0)
    details: List[str] = Field(default_factory=list)


# Phase 7A: Bandwidth and Capacity Metering Models

class CapacitySnapshotRecord(BaseModel):
    """Point-in-time storage capacity snapshot for a storage node."""
    snapshot_id: str
    node_id: str
    total_quota_bytes: int
    used_bytes: int
    remaining_quota_bytes: int
    physical_total_bytes: Optional[int] = None
    physical_free_bytes: Optional[int] = None
    measured_at: str
    source: str = "heartbeat"
    is_valid: bool = True


class CapacitySnapshotListResponse(BaseModel):
    """List of capacity snapshots."""
    snapshots: List[CapacitySnapshotRecord] = Field(default_factory=list)
    count: int = 0


class TransferEventRecord(BaseModel):
    """Recorded bandwidth transfer event for a storage node."""
    event_id: str
    node_id: str
    direction: str = Field(..., description="'upload' (ingress) or 'download' (egress)")
    operation_type: str = Field(..., description="'client_upload', 'client_download', 'replication', 'repair', 'relay'")
    payload_bytes: int = Field(..., description="Actual successfully transferred payload bytes")
    chunk_id: Optional[str] = None
    file_id: Optional[str] = None
    status: str = Field(default="success", description="'success', 'failed', 'cancelled'")
    timestamp: str
    idempotency_key: str


class TransferEventCreateRequest(BaseModel):
    """Request payload to record a transfer event."""
    node_id: str
    direction: str = Field(..., description="'upload' or 'download'")
    operation_type: str = Field(..., description="'client_upload', 'client_download', 'replication', 'repair', 'relay'")
    payload_bytes: int
    chunk_id: Optional[str] = None
    file_id: Optional[str] = None
    status: str = "success"
    timestamp: Optional[str] = None
    idempotency_key: Optional[str] = None


class TransferEventListResponse(BaseModel):
    """List of transfer events."""
    events: List[TransferEventRecord] = Field(default_factory=list)
    count: int = 0
    total_bytes: int = 0


class HeartbeatObservationRecord(BaseModel):
    """Recorded liveness heartbeat observation."""
    observation_id: str
    node_id: str
    observed_at: str
    reported_status: str
    response_time_ms: Optional[float] = None


class OperationEventRecord(BaseModel):
    """Replication or repair operation event."""
    operation_id: str
    operation_type: str = Field(..., description="'replication', 'repair', 'rebalance'")
    source_node_id: Optional[str] = None
    target_node_id: str
    chunk_id: Optional[str] = None
    payload_bytes: int
    status: str = "completed"
    completed_at: str
    duration_seconds: Optional[float] = None
    idempotency_key: str


class OperationEventCreateRequest(BaseModel):
    """Request to record a replication/repair operation."""
    operation_type: str = Field(..., description="'replication', 'repair', 'rebalance'")
    source_node_id: Optional[str] = None
    target_node_id: str
    chunk_id: Optional[str] = None
    payload_bytes: int
    status: str = "completed"
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    idempotency_key: Optional[str] = None


class OperationEventListResponse(BaseModel):
    """List of operation events."""
    operations: List[OperationEventRecord] = Field(default_factory=list)
    count: int = 0


class NodeUptimeSummary(BaseModel):
    """Calculated availability and uptime for a node over an evaluated time window."""
    node_id: str
    window_start: str
    window_end: str
    observed_online_seconds: float
    observed_offline_seconds: float
    observed_unknown_seconds: float
    availability_percentage: float
    last_successful_heartbeat: Optional[str] = None
    total_heartbeats_count: int


class NodeContributionSummary(BaseModel):
    """Comprehensive historical and point-in-time contribution summary for a storage node."""
    node_id: str
    configured_quota_bytes: int
    current_used_bytes: int
    remaining_quota_bytes: int
    physical_disk_total_bytes: Optional[int] = None
    physical_disk_free_bytes: Optional[int] = None
    lifetime_ingress_bytes: int
    lifetime_egress_bytes: int
    lifetime_transfer_bytes: int
    availability_percentage: float
    uptime_window_start: Optional[str] = None
    uptime_window_end: Optional[str] = None
    successful_operations_count: int
    successful_operations_bytes: int
    last_seen: Optional[str] = None
    status: str


class ClusterMeteringSummary(BaseModel):
    """Cluster-wide aggregated capacity, transfer, and contribution totals."""
    total_nodes_count: int
    online_nodes_count: int
    total_contributed_quota_bytes: int
    total_used_bytes: int
    total_remaining_quota_bytes: int
    total_ingress_bytes: int
    total_egress_bytes: int
    total_transfer_bytes: int
    total_replications_completed: int
    total_repairs_completed: int
    average_availability_percentage: float


# =============================================================================
# Phase 7B: Contribution Credits (ECC), Node Reputation and Trust Scoring
# =============================================================================

class CreditLedgerEntryRecord(BaseModel):
    """Immutable audit record representing an Expo Contribution Credit (ECC) ledger entry."""
    entry_id: str
    node_id: str
    category: str
    credit_delta: float
    credit_micro_units: Optional[int] = None
    event_id: Optional[str] = None
    policy_version: str
    timestamp: str
    idempotency_key: str
    reason: str
    audit_metadata: Optional[Dict[str, Any]] = None
    reversal_ref: Optional[str] = None
    window_start: Optional[str] = None
    window_end: Optional[str] = None


class CreditBalanceRecord(BaseModel):
    """Reconciled point-in-time balance for a storage node provider."""
    node_id: str
    total_credits: float
    total_micro_units: Optional[int] = None
    lifetime_earned: float
    lifetime_earned_micro: Optional[int] = None
    lifetime_reversed: float
    lifetime_reversed_micro: Optional[int] = None
    last_reconciled_at: str


class CreditLedgerListResponse(BaseModel):
    """Paginated list response for credit ledger entries."""
    node_id: str
    entries: List[CreditLedgerEntryRecord]
    count: int
    total_credits_in_page: float
    limit: int
    offset: int


class NodeCreditSummary(BaseModel):
    """Detailed category breakdown of credits earned by a specific node."""
    node_id: str
    current_balance: float
    storage_credits: float
    upload_credits: float
    download_credits: float
    replication_credits: float
    repair_credits: float
    reversal_credits: float
    entry_count: int
    last_updated: Optional[str] = None


class AccountingPolicyConfig(BaseModel):
    """Configurable, versioned parameters for ECC credit and reputation calculation."""
    policy_version: str = "7B-v1.0"
    storage_weight_per_gb_day: float = 1.0
    upload_weight_per_gb: float = 1.0
    download_weight_per_gb: float = 1.5
    replication_op_weight: float = 0.5
    replication_weight_per_gb: float = 0.5
    repair_op_weight: float = 2.0
    repair_weight_per_gb: float = 1.0
    availability_multiplier_min: float = 0.5
    availability_multiplier_max: float = 1.0
    availability_weight: float = 0.40
    integrity_weight: float = 0.35
    recovery_weight: float = 0.25
    min_observations_for_confidence: int = 10
    min_transfers_for_confidence: int = 5


class NodeReputationRecord(BaseModel):
    """Evaluated trust and reputation score (0.0 to 100.0) with confidence indicator."""
    node_id: str
    reputation_score: float
    availability_score: float
    integrity_score: float
    recovery_score: float
    confidence_indicator: float
    data_sufficiency_status: str
    policy_version: str
    calculated_at: str
    metrics_summary: Optional[Dict[str, Any]] = None


class NodeReputationListResponse(BaseModel):
    """List response for cluster-wide node reputations."""
    nodes: List[NodeReputationRecord]
    count: int


class ClusterAccountingSummary(BaseModel):
    """Cluster-wide aggregated credit issuance and reputation summary."""
    total_nodes_evaluated: int
    total_credits_issued: float
    total_credits_reversed: float
    net_cluster_credits: float
    average_reputation_score: float
    high_confidence_nodes_count: int
    policy_version: str


class CreditReversalRequest(BaseModel):
    """Request payload for an administrative credit reversal."""
    entry_id: str
    reason: str
    amount: Optional[float] = None
    idempotency_key: Optional[str] = None


class CreditCalculationRequest(BaseModel):
    """Request payload for on-demand credit calculation."""
    node_id: Optional[str] = None
    window_hours: float = 24.0
    include_storage: bool = True
    include_transfers: bool = True
    include_operations: bool = True


# =============================================================================
# Phase 8A: Provider Monitoring and Management Models
# =============================================================================

class ProviderNodeSummary(BaseModel):
    """Concise health and capacity summary of a provider's Storage Node."""
    node_id: str
    host: str
    port: int
    endpoint: str
    status: str
    is_schedulable: bool
    connectivity_mode: str
    total_configured_quota_bytes: int
    verified_stored_bytes: int
    remaining_quota_bytes: int
    physical_disk_total_bytes: Optional[int] = None
    physical_disk_free_bytes: Optional[int] = None
    last_seen: str
    last_heartbeat_elapsed_seconds: float
    observed_availability_percentage: float
    credit_balance: float
    reputation_score: float
    confidence_indicator: float
    data_sufficiency_status: str
    drain_status: Optional[str] = "none"


class ProviderOverview(BaseModel):
    """Comprehensive provider-level resource, traffic, credit, and health overview."""
    provider_id: str
    total_nodes_count: int
    online_nodes_count: int
    schedulable_nodes_count: int
    total_configured_quota_bytes: int
    total_verified_stored_bytes: int
    total_remaining_quota_bytes: int
    total_physical_disk_bytes: Optional[int] = None
    total_physical_free_bytes: Optional[int] = None
    total_ingress_bytes: int
    total_egress_bytes: int
    total_traffic_bytes: int
    total_credit_balance: float
    average_reputation_score: float
    recent_successful_repairs: int
    recent_failed_repairs: int
    evaluation_window_hours: float
    nodes: List[ProviderNodeSummary]


class ProviderNodeDetail(BaseModel):
    """In-depth diagnostics, historical stats, and activity for a specific node."""
    node_id: str
    provider_id: str
    host: str
    port: int
    endpoint: str
    status: str
    is_schedulable: bool
    drain_status: Optional[str] = "none"
    connectivity_mode: str
    protocol_version: str
    total_configured_quota_bytes: int
    verified_stored_bytes: int
    remaining_quota_bytes: int
    physical_disk_total_bytes: Optional[int] = None
    physical_disk_free_bytes: Optional[int] = None
    last_seen: str
    registered_at: str
    last_heartbeat_elapsed_seconds: float
    observed_availability_percentage: float
    observed_online_seconds: float
    total_ingress_bytes: int
    total_egress_bytes: int
    credit_balance: float
    lifetime_credits_earned: float
    lifetime_credits_reversed: float
    reputation_score: float
    availability_score: float
    integrity_score: float
    recovery_score: float
    confidence_indicator: float
    data_sufficiency_status: str
    recent_transfers_count: int
    recent_repairs_count: int
    recent_failed_repairs_count: int
    recent_snapshots: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]


class NodeSchedulingRequest(BaseModel):
    """Payload to enable or disable future scheduling on a node."""
    enabled: Optional[bool] = Field(None, description="True to enable scheduling, False to disable/drain")
    is_schedulable: Optional[bool] = Field(None, description="Alternative alias for enabled")
    reason: Optional[str] = Field(None, description="Optional administrative reason")

    def get_enabled_state(self) -> bool:
        if self.enabled is not None:
            return self.enabled
        if self.is_schedulable is not None:
            return self.is_schedulable
        return True


class NodeShutdownRequest(BaseModel):
    """Payload to initiate graceful shutdown on a node."""
    reason: Optional[str] = Field("Provider initiated shutdown", description="Shutdown reason")


class NodeManagementActionResponse(BaseModel):
    """Response returned upon altering node scheduling or initiating shutdown."""
    node_id: str
    status: str
    is_schedulable: bool
    drain_status: Optional[str] = "none"
    reason: Optional[str] = None
    updated_at: str


# =============================================================================
# Phase 8B: Provider Security and Safe Node Lifecycle Hardening Models
# =============================================================================

class SessionLoginRequest(BaseModel):
    """Request to authenticate and establish a browser session."""
    token: Optional[str] = Field(None, description="Coordinator authentication token")
    secret_or_token: Optional[str] = Field(None, description="Provider secret or token")
    provider_id: Optional[str] = Field(None, description="Optional provider identifier")

    def get_token(self) -> str:
        return (self.token or self.secret_or_token or "").strip()


class SessionLoginResponse(BaseModel):
    """Response payload upon successful session login."""
    session_id: str
    provider_id: str
    csrf_token: str
    expires_at: str
    is_admin: bool = False


class SessionStatusResponse(BaseModel):
    """Response reflecting active browser session or principal status."""
    authenticated: bool
    provider_id: Optional[str] = None
    is_admin: bool = False
    auth_method: Optional[str] = None
    csrf_token: Optional[str] = None


class NodeDrainRequest(BaseModel):
    """Request to initiate or re-evaluate safe node draining."""
    reason: Optional[str] = Field(None, description="Administrative drain reason")
    force: bool = Field(False, description="Attempt force drain if supported")


class NodeDrainResponse(BaseModel):
    """Response reflecting current durable drain status and progress."""
    drain_id: str
    node_id: str
    provider_id: str
    status: str
    total_chunks: int = 0
    migrated_chunks: int = 0
    remaining_chunks: int = 0
    failed_chunks: int = 0
    reason: Optional[str] = None
    started_at: str
    updated_at: str
    completed_at: Optional[str] = None
    blocked_details: Optional[List[str]] = Field(default_factory=list)


# =============================================================================
# Phase 8C: Automated, Verified Node Drain Migration Models
# =============================================================================

class NodeDrainMigrationRecord(BaseModel):
    """Durable record of an individual chunk or shard migration job."""
    migration_id: str
    drain_id: str
    file_id: str
    chunk_id: str
    shard_index: Optional[int] = None
    source_node_id: str
    destination_node_id: Optional[str] = None
    status: str = Field(..., description="'pending', 'transferring', 'verifying', 'completed', 'retryable_failure', 'blocked'")
    retry_count: int = 0
    max_retries: int = 3
    last_error: Optional[str] = None
    payload_bytes: int = 0
    sha256_checksum: Optional[str] = None
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None


class NodeDrainMigrationListResponse(BaseModel):
    """List response for migration jobs associated with a node drain."""
    node_id: str
    drain_id: str
    migrations: List[NodeDrainMigrationRecord]
    count: int


class DrainWorkerStatusResponse(BaseModel):
    """Operational status and metrics of the background drain migration worker."""
    is_running: bool
    active_workers: int = 0
    pending_migrations: int = 0
    in_flight_migrations: int = 0
    completed_migrations: int = 0
    failed_migrations: int = 0
    blocked_migrations: int = 0






