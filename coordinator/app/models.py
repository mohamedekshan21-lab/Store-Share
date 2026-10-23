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
    lifecycle_state: Optional[str] = Field(None, description="Optional initial lifecycle state ('registered', 'probation', 'online')")
    status: Optional[str] = Field(None, description="Optional initial operational status")


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
    status: str = Field(..., description="Operational status ('registered', 'validation_in_progress', 'probation', 'online', 'unhealthy', 'offline', 'disabled', 'draining', 'drained')")
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
    lifecycle_state: str = Field(default="registered", description="Durable node lifecycle state ('registered', 'validation_in_progress', 'probation', 'online', 'unhealthy', 'disabled', 'draining', 'drained')")
    probation_started_at: Optional[str] = Field(None, description="ISO timestamp when node entered probation")
    promoted_at: Optional[str] = Field(None, description="ISO timestamp when node was promoted to online")
    health_check_success_count: int = Field(default=0, description="Count of successful validation and health checks")
    health_check_fail_count: int = Field(default=0, description="Count of failed validation and health checks")
    consecutive_failures: int = Field(default=0, description="Consecutive health check failures")
    last_health_check_at: Optional[str] = Field(None, description="ISO timestamp of last health check")
    last_health_check_status: Optional[str] = Field(None, description="Status of last health check ('success', 'failed', 'cleanup_failed')")
    last_health_check_error: Optional[str] = Field(None, description="Error message from last health check if failed")
    reliability_score: float = Field(default=0.0, description="Calculated reliability score in [0.0, 1.0]")
    probation_placed_bytes: int = Field(default=0, description="Bytes placed on this node during probation period")


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


# =============================================================================
# Phase 10A: Account Authentication, Roles & Multi-Tenant Identity Models
# =============================================================================

class RegisterAccountRequest(BaseModel):
    """Payload to register a new user account."""
    email: str = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")
    role: Optional[str] = Field("consumer", description="Account role: consumer or provider")
    provider_id: Optional[str] = Field(None, description="Optional provider identifier if acting as storage provider")


class LoginAccountRequest(BaseModel):
    """Payload to authenticate an account."""
    email: str = Field(..., description="Registered email address")
    password: str = Field(..., description="Account password")


class AccountResponse(BaseModel):
    """Safe public representation of a user account."""
    account_id: str
    email: str
    role: str
    capabilities: List[str]
    status: str
    provider_id: Optional[str] = None
    email_verified: bool
    email_verified_at: Optional[str] = None
    phone_number: Optional[str] = None
    phone_verified: bool = False
    phone_verified_at: Optional[str] = None
    created_at: str
    updated_at: str


class LoginSuccessResponse(BaseModel):
    """Response payload returned upon successful account login."""
    account: AccountResponse
    token: str
    csrf_token: str
    expires_at: str


# =============================================================================
# Phase 10B: Chunk Capability Authorization Models
# =============================================================================

class UploadCapabilityChunkItem(BaseModel):
    """Specification of a chunk requiring upload authorization."""
    chunk_id: str = Field(..., description="Chunk or shard identifier")
    node_ids: List[str] = Field(..., description="Target node IDs allocated for this chunk")
    size: Optional[int] = Field(None, description="Expected chunk size in bytes")
    sha256: Optional[str] = Field(None, description="Expected chunk SHA-256 digest")


class RequestUploadCapabilitiesRequest(BaseModel):
    """Request payload to authorize chunk uploads."""
    file_id: Optional[str] = Field(None, description="Logical file ID")
    chunks: List[UploadCapabilityChunkItem] = Field(..., description="List of chunks to authorize")
    original_size: Optional[int] = Field(None, description="Optional logical file size in bytes for quota reservation")


class RequestUploadCapabilitiesResponse(BaseModel):
    """Response returning signed upload capability tokens for each chunk and node."""
    capabilities: Dict[str, Dict[str, str]] = Field(
        ...,
        description="Mapping of chunk_id -> {node_id: capability_token}"
    )


class RequestDownloadCapabilitiesRequest(BaseModel):
    """Request payload to obtain download capabilities for an existing owned file."""
    file_id: str = Field(..., description="Logical file ID")
    chunk_ids: Optional[List[str]] = Field(None, description="Optional specific chunk IDs to authorize (all if None)")


class RequestDownloadCapabilitiesResponse(BaseModel):
    """Response returning signed download capability tokens for each chunk and placement."""
    file_id: str
    capabilities: Dict[str, Dict[str, str]] = Field(
        ...,
        description="Mapping of chunk_id -> {node_id: capability_token}"
    )


# =============================================================================
# Phase 10C: Provider Onboarding, Validation & Reliability Gating Models
# =============================================================================

class ProviderOnboardRequest(BaseModel):
    """Request payload to activate provider capabilities and accept terms."""
    terms_version: Optional[str] = Field(None, description="Terms of service version identifier")
    accept_terms: bool = Field(..., description="Must explicitly be True to record provider consent")
    provider_id: Optional[str] = Field(None, description="Optional custom provider identifier")


class ProviderOnboardResponse(BaseModel):
    """Response returned upon successful provider onboarding."""
    account_id: Optional[str] = None
    provider_id: str
    terms_version: str
    terms_accepted_at: Optional[str] = None
    accepted_at: Optional[str] = None
    is_verified: bool = Field(default=True)
    status: str
    message: str


class NodeValidationCheckItem(BaseModel):
    """Individual diagnostic check result within a node validation run."""
    name: str
    passed: bool
    message: Optional[str] = None
    duration_ms: Optional[float] = None


class NodeValidationResponse(BaseModel):
    """Result of a storage node health validation run."""
    validation_id: str
    node_id: str
    provider_id: str
    status: str
    lifecycle_state: str
    overall_status: Optional[str] = None
    resulting_lifecycle_state: Optional[str] = None
    checks: List[NodeValidationCheckItem] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    reliability_score: Optional[float] = 0.0
    performed_at: str
    duration_ms: float

    def model_post_init(self, __context: Any) -> None:
        if self.overall_status is None:
            self.overall_status = self.status
        if self.resulting_lifecycle_state is None:
            self.resulting_lifecycle_state = self.lifecycle_state


class NodeProbationStatusResponse(BaseModel):
    """Detailed probation progress and placement eligibility for a node."""
    node_id: str
    provider_id: str
    lifecycle_state: str
    status: str
    is_schedulable: bool
    reliability_score: float
    probation_started_at: Optional[str] = None
    promoted_at: Optional[str] = None
    health_check_success_count: int = 0
    health_check_fail_count: int = 0
    consecutive_failures: int = 0
    probation_placed_bytes: int = 0
    probation_max_bytes: int
    observation_period_met: bool
    health_checks_met: bool
    promotion_eligible: bool
    reason_blocked: Optional[str] = None


class ProviderNodeValidationHistoryResponse(BaseModel):
    """History of validation runs for a specific node."""
    node_id: str
    probation_status: Optional[NodeProbationStatusResponse] = None
    validations: List[NodeValidationResponse] = Field(default_factory=list)
    count: int = 0


# =============================================================================
# Phase 10D: Account Storage Quotas and Consumer File Management Models
# =============================================================================

class AccountQuotaResponse(BaseModel):
    """Account storage quota limits and usage figures."""
    account_id: str
    quota_bytes: int
    used_bytes: int
    reserved_bytes: int
    available_bytes: int
    file_count: int
    policy: str


class ReserveQuotaRequest(BaseModel):
    """Request to explicitly reserve storage quota before uploading."""
    expected_bytes: int
    file_id: Optional[str] = None
    ttl_seconds: Optional[int] = None


class ReserveQuotaResponse(BaseModel):
    """Response returned upon successful quota reservation."""
    reservation_id: str
    account_id: str
    reserved_bytes: int
    expires_at: str
    status: str


class ReleaseQuotaRequest(BaseModel):
    """Request to release an active upload quota reservation."""
    reservation_id: Optional[str] = None
    file_id: Optional[str] = None


class ReleaseQuotaResponse(BaseModel):
    """Response returned upon releasing a reservation."""
    status: str
    released_count: int


class UpdateAccountQuotaRequest(BaseModel):
    """Administrative request to change an account's quota limit."""
    quota_bytes: int = Field(..., ge=0, description="New quota limit in bytes")


class UpdateAccountQuotaResponse(BaseModel):
    """Response upon updating an account's quota."""
    account_id: str
    quota_bytes: int
    message: str


class FileStorageStatusResponse(BaseModel):
    """Storage health and status report for a logical file."""
    file_id: str
    owner_id: str
    original_filename: str
    original_size: int
    status: str
    redundancy_mode: str
    total_chunks: int
    total_placements_or_shards: int
    available_nodes_count: int
    health: str
    details: Dict[str, Any]
    created_at: str
    updated_at: str


# =============================================================================
# Phase 10E: Email/SMS Verification & Account Recovery Models
# =============================================================================

class VerifyEmailRequest(BaseModel):
    """Payload to redeem an email verification token."""
    token: str = Field(..., min_length=16, description="Cryptographically secure email verification token")


class VerifyEmailResponse(BaseModel):
    """Response returned upon successful email verification."""
    detail: str
    email_verified: bool
    email: Optional[str] = None
    account_id: Optional[str] = None


class ResendVerificationRequest(BaseModel):
    """Payload to request re-issuance of email verification link."""
    email: str = Field(..., description="User account email address")


class ForgotPasswordRequest(BaseModel):
    """Payload to request a password reset email."""
    email: str = Field(..., description="Registered account email address")


class ResetPasswordRequest(BaseModel):
    """Payload to confirm password reset using token."""
    token: str = Field(..., min_length=16, description="Single-use password reset token")
    new_password: str = Field(..., min_length=8, description="New account password (min 8 characters)")


class SendSmsCodeRequest(BaseModel):
    """Payload to request an SMS verification code."""
    phone_number: str = Field(..., min_length=7, max_length=20, description="E.164 phone number (e.g. +1234567890)")


class VerifySmsCodeRequest(BaseModel):
    """Payload to verify an SMS code."""
    phone_number: str = Field(..., min_length=7, max_length=20, description="E.164 phone number")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class ActionStatusResponse(BaseModel):
    """Generic action confirmation response."""
    detail: str
    success: bool = True


# =============================================================================
# Phase 10F: Admin APIs, Observability & Integrated UI Models
# =============================================================================

class AdminAccountListResponse(BaseModel):
    """Paginated list of accounts for administrative review."""
    total: int = Field(..., description="Total count of matching accounts")
    limit: int = Field(..., description="Pagination limit applied")
    offset: int = Field(..., description="Pagination offset applied")
    accounts: List[AccountResponse] = Field(..., description="Sanitized account records")


class AdminUpdateAccountStatusRequest(BaseModel):
    """Payload to update an account's operational status under explicit policy."""
    status: str = Field(..., description="New account status ('active', 'suspended', 'disabled')")
    reason: str = Field(..., min_length=3, description="Justification for status change")


class AdminDrainNodeRequest(BaseModel):
    """Payload for administrator to initiate graceful node drain."""
    reason: Optional[str] = Field("Admin-initiated drain", description="Administrative justification")


class AdminNodeListResponse(BaseModel):
    """Paginated list of storage nodes for administrative inspection."""
    total: int = Field(..., description="Total count of matching nodes")
    limit: int = Field(..., description="Pagination limit applied")
    offset: int = Field(..., description="Pagination offset applied")
    nodes: List[NodeRecord] = Field(..., description="Storage node records")


class AdminStatsOverviewResponse(BaseModel):
    """System-wide aggregate statistics across accounts, nodes, and storage."""
    accounts: Dict[str, int] = Field(..., description="Account counts by status and role")
    nodes: Dict[str, int] = Field(..., description="Storage node counts by status/lifecycle")
    storage: Dict[str, Any] = Field(..., description="Capacity, usage, and catalog totals")
    jobs: Dict[str, int] = Field(..., description="Operational background job counts")
    timestamp: str = Field(..., description="Evaluation timestamp")


class AdminAuditLogEntry(BaseModel):
    """Audit log entry representing a sensitive administrative action."""
    audit_id: str
    timestamp: str
    admin_account_id: str
    admin_email: str
    action: str
    target_type: str
    target_id: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None


class AdminAuditLogListResponse(BaseModel):
    """Paginated list of administrative audit logs."""
    total: int
    limit: int
    offset: int
    logs: List[AdminAuditLogEntry]


class LivenessResponse(BaseModel):
    """Coordinator service liveness health response."""
    status: str = "online"
    service: str = "coordinator"
    timestamp: str


class ReadinessResponse(BaseModel):
    """Coordinator service dependency readiness response."""
    status: str
    checks: Dict[str, Any]
    timestamp: str


class ObservabilityMetricsResponse(BaseModel):
    """Comprehensive coordinator operational metrics."""
    requests: Dict[str, Any]
    storage_nodes: Dict[str, int]
    storage_bytes: Dict[str, Any]
    quota: Dict[str, Any]
    jobs: Dict[str, int]
    active_sessions: int
    timestamp: str


class ConsumerFileItem(BaseModel):
    """Logical file summary for the Consumer file manager UI."""
    file_id: str
    original_filename: str
    original_size: int
    status: str
    redundancy_mode: str
    chunk_count: int
    created_at: str
    updated_at: str


class ConsumerFileListResponse(BaseModel):
    """Consumer file list and quota overview."""
    files: List[ConsumerFileItem]
    total_files: int
    total_bytes: int
    quota_bytes: int
    used_bytes: int
    available_bytes: int




