"""
Multi-Node Chunk Placement & Reachability Module for Expo (Phase 3C).
Handles Coordinator node discovery, filtering candidate Storage Nodes by available capacity & liveness,
consumer-side direct node reachability verification & latency measurement, and deterministic Round-Robin chunk placement.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import requests

from coordinator.coordinator_client import CoordinatorClient

logger = logging.getLogger("expo_client.placement")


@dataclass
class NodeReachabilityResult:
    """Dataclass holding consumer reachability check diagnostics for a Storage Node."""
    node_id: str
    endpoint: str
    reachability: str  # "REACHABLE", "UNREACHABLE", "UNKNOWN"
    latency_ms: Optional[float] = None
    protocol_version: Optional[str] = None
    reason: Optional[str] = None


def check_node_reachability(
    endpoint: str,
    node_id: str = "UNKNOWN",
    timeout: float = 5.0,
    verify_tls: bool = True,
) -> NodeReachabilityResult:
    """
    Attempts to connect to a Storage Node using its advertised endpoint via GET /health.
    Measures monotonic round-trip latency and validates node status response.
    Returns structured NodeReachabilityResult diagnostics.
    """
    clean_endpoint = endpoint.strip().rstrip("/")
    health_url = f"{clean_endpoint}/health?verbose=true"

    t0 = time.perf_counter()
    try:
        import httpx
        with httpx.Client(verify=verify_tls, timeout=httpx.Timeout(timeout, connect=min(5.0, timeout))) as http_client:
            response = http_client.get(health_url)
            t1 = time.perf_counter()
            latency = (t1 - t0) * 1000.0

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "online":
                    resp_node_id = data.get("node_id") or node_id
                    prot_ver = data.get("protocol_version") or "1.x"
                    return NodeReachabilityResult(
                        node_id=resp_node_id,
                        endpoint=clean_endpoint,
                        reachability="REACHABLE",
                        latency_ms=round(latency, 2),
                        protocol_version=prot_ver,
                    )
                else:
                    return NodeReachabilityResult(
                        node_id=node_id,
                        endpoint=clean_endpoint,
                        reachability="UNREACHABLE",
                        reason=f"Node status reported non-online: '{data.get('status')}'",
                    )
            else:
                return NodeReachabilityResult(
                    node_id=node_id,
                    endpoint=clean_endpoint,
                    reachability="UNREACHABLE",
                    reason=f"HTTP {response.status_code}: {response.text[:100]}",
                )
    except Exception as exc:
        err_str = str(exc)
        if "timeout" in err_str.lower() or "timed out" in err_str.lower():
            reason = "Connection timeout"
        elif "refused" in err_str.lower():
            reason = f"Connection refused: {err_str}"
        else:
            reason = f"Connection error: {err_str}"
        return NodeReachabilityResult(
            node_id=node_id,
            endpoint=clean_endpoint,
            reachability="UNREACHABLE",
            reason=reason,
        )


def select_nodes_for_placement(
    coordinator_client: CoordinatorClient,
    required_chunk_size: int,
    target_node_count: int = 3,
    preferred_connectivity: Optional[str] = None,
    require_reachable: bool = False,
    reachability_timeout: float = 5.0,
    connection_manager: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """
    Queries Coordinator to discover eligible online Storage Nodes with sufficient available capacity.
    If require_reachable is True, performs real-time reachability checks and filters out unreachable nodes.
    Ranks nodes by preferred connectivity, route priority (preferring DIRECT over RELAY), and available capacity,
    returning up to `target_node_count` nodes.
    """
    try:
        available_nodes = coordinator_client.list_nodes(
            status="online",
            min_available_bytes=required_chunk_size,
        )
    except Exception as exc:
        logger.warning("Failed to query Coordinator for node placement: %s", exc)
        return []

    if not available_nodes:
        return []

    if require_reachable:
        reachable_nodes = []
        for node in available_nodes:
            ep = node.get("advertised_endpoint") or node.get("endpoint")
            n_id = node.get("node_id", "UNKNOWN")
            if connection_manager is not None:
                route = connection_manager.resolve_route(n_id, direct_endpoint=ep)
                if route.is_routable:
                    node["reachability"] = "REACHABLE"
                    node["route_type"] = route.route_type.value if hasattr(route.route_type, "value") else str(route.route_type)
                    node["latency_ms"] = route.latency_ms
                    reachable_nodes.append(node)
                else:
                    logger.info("Node '%s' (%s) filtered out during placement: %s", n_id, ep, route.diagnostic_info)
            elif ep:
                res = check_node_reachability(endpoint=ep, node_id=n_id, timeout=reachability_timeout)
                if res.reachability == "REACHABLE":
                    node["reachability"] = "REACHABLE"
                    node["route_type"] = "DIRECT"
                    node["latency_ms"] = res.latency_ms
                    reachable_nodes.append(node)
                else:
                    logger.info("Node '%s' (%s) filtered out during placement: %s", n_id, ep, res.reason)
        available_nodes = reachable_nodes

    if not available_nodes:
        return []

    # Sort nodes by preferred connectivity match, route priority (DIRECT > RELAY), and available capacity descending
    pref = preferred_connectivity.strip().upper() if preferred_connectivity else None

    def node_rank(node: Dict[str, Any]) -> Tuple[int, int, int]:
        mode = node.get("connectivity_mode", "LAN").upper()
        conn_match = 1 if (pref and mode == pref) else 0
        r_type = node.get("route_type", "DIRECT")
        route_prio = 2 if r_type == "DIRECT" else (1 if r_type == "RELAY" else 0)
        avail = node.get("available_capacity_bytes", 0)
        return (conn_match, route_prio, avail)

    available_nodes.sort(key=node_rank, reverse=True)

    # Return top N nodes
    return available_nodes[:max(1, target_node_count)]



def assign_chunks_round_robin(
    chunks: List[Tuple[int, str, bytes, str]],
    selected_nodes: List[Dict[str, Any]],
) -> List[Tuple[int, str, bytes, str, Dict[str, Any]]]:
    """
    Assigns encrypted chunk payloads to selected Storage Nodes using a deterministic Round-Robin algorithm.
    Each tuple returned is `(sequence, chunk_id, chunk_bytes, chunk_sha256, target_node_dict)`.
    """
    if not selected_nodes:
        raise ValueError("Cannot assign chunks: No Storage Nodes available for placement.")

    assignments: List[Tuple[int, str, bytes, str, Dict[str, Any]]] = []
    num_nodes = len(selected_nodes)

    for seq, chunk_id, chunk_bytes, chunk_sha256 in chunks:
        target_node = selected_nodes[seq % num_nodes]
        assignments.append((seq, chunk_id, chunk_bytes, chunk_sha256, target_node))

    return assignments


def assign_chunks_with_replication(
    chunks: List[Tuple[int, str, bytes, str]],
    selected_nodes: List[Dict[str, Any]],
    replication_factor: int = 2,
) -> List[Tuple[int, str, bytes, str, List[Tuple[str, str, str]]]]:
    """
    Assigns encrypted chunk payloads to distinct Storage Nodes using a deterministic Round-Robin algorithm with replication.
    Each chunk is assigned `replication_factor` distinct nodes (1 PRIMARY + N-1 REPLICAS).
    Returns list of tuples: `(sequence, chunk_id, chunk_bytes, chunk_sha256, placements)`
    where placements is a list of tuples: `[(node_id, node_endpoint, role)]`.
    """
    if replication_factor < 1:
        raise ValueError("replication_factor must be an integer >= 1.")

    if not selected_nodes:
        raise ValueError("Cannot assign chunks: No Storage Nodes available for placement.")

    num_nodes = len(selected_nodes)
    if num_nodes < replication_factor:
        raise ValueError(
            f"Insufficient suitable Storage Nodes available ({num_nodes}) to satisfy requested replication_factor ({replication_factor})."
        )

    assignments: List[Tuple[int, str, bytes, str, List[Tuple[str, str, str]]]] = []

    for seq, chunk_id, chunk_bytes, chunk_sha256 in chunks:
        placements: List[Tuple[str, str, str]] = []
        node_ids_used = set()

        for idx in range(replication_factor):
            target_node = selected_nodes[(seq + idx) % num_nodes]
            n_id = target_node.get("node_id", f"NODE-{idx}")
            n_endpoint = target_node.get("advertised_endpoint") or target_node.get("endpoint") or ""
            role = "PRIMARY" if idx == 0 else "REPLICA"

            if n_id in node_ids_used:
                found_distinct = False
                for shift in range(1, num_nodes):
                    alt_node = selected_nodes[(seq + idx + shift) % num_nodes]
                    alt_id = alt_node.get("node_id", f"NODE-{idx}-{shift}")
                    if alt_id not in node_ids_used:
                        n_id = alt_id
                        n_endpoint = alt_node.get("advertised_endpoint") or alt_node.get("endpoint") or ""
                        found_distinct = True
                        break
                if not found_distinct:
                    raise ValueError(f"Unable to assign distinct Storage Node for placement role '{role}'.")

            node_ids_used.add(n_id)
            placements.append((n_id, n_endpoint, role))

        assignments.append((seq, chunk_id, chunk_bytes, chunk_sha256, placements))

    return assignments


def assign_shards_for_erasure_coding(
    encoded_chunks: List[Tuple[int, str, Any, int, int, int]],  # (sequence, chunk_id, shards_list, orig_size, encoded_size, padlen)
    selected_nodes: List[Dict[str, Any]],
    data_shards: int = 4,
    parity_shards: int = 2,
) -> List[Tuple[int, str, List[Tuple[Any, str, str]], int, int, int]]:
    """
    Assigns erasure-coded shards (DATA + PARITY) for each chunk to distinct Storage Nodes using deterministic Round-Robin.
    Enforces that each of the `k + m` shards of an encoded chunk MUST be placed on a distinct Storage Node ID.
    
    Returns list of tuples:
        `(sequence, chunk_id, shard_placements, orig_size, encoded_size, padlen)`
        where `shard_placements` is a list of tuples: `[(shard_data_obj, node_id, node_endpoint)]`.
    """
    total_shards = data_shards + parity_shards
    if total_shards < 2:
        raise ValueError("Total erasure coding shards (k + m) must be >= 2.")

    if not selected_nodes:
        raise ValueError("Cannot assign shards: No Storage Nodes available for placement.")

    num_nodes = len(selected_nodes)
    distinct_node_ids = {n.get("node_id") for n in selected_nodes if n.get("node_id")}
    if len(distinct_node_ids) < total_shards:
        raise ValueError(
            f"Insufficient suitable Storage Nodes available ({len(distinct_node_ids)} distinct) to satisfy requested erasure coding profile k={data_shards}, m={parity_shards} ({total_shards} total shards required)."
        )

    assignments: List[Tuple[int, str, List[Tuple[Any, str, str]], int, int, int]] = []

    for seq, chunk_id, shards_list, orig_size, enc_size, padlen in encoded_chunks:
        if len(shards_list) != total_shards:
            raise ValueError(
                f"Chunk sequence {seq} has {len(shards_list)} shards, expected {total_shards} (k={data_shards}, m={parity_shards})."
            )

        shard_placements: List[Tuple[Any, str, str]] = []
        node_ids_used = set()

        for idx, shard in enumerate(shards_list):
            target_node = selected_nodes[(seq * total_shards + idx) % num_nodes]
            n_id = target_node.get("node_id", f"NODE-{idx}")
            n_endpoint = target_node.get("advertised_endpoint") or target_node.get("endpoint") or ""

            if n_id in node_ids_used:
                found_distinct = False
                for shift in range(1, num_nodes):
                    alt_node = selected_nodes[(seq * total_shards + idx + shift) % num_nodes]
                    alt_id = alt_node.get("node_id", f"NODE-{idx}-{shift}")
                    if alt_id not in node_ids_used:
                        n_id = alt_id
                        n_endpoint = alt_node.get("advertised_endpoint") or alt_node.get("endpoint") or ""
                        found_distinct = True
                        break
                if not found_distinct:
                    raise ValueError(f"Unable to assign distinct Storage Node for shard index {shard.shard_index}.")

            node_ids_used.add(n_id)
            shard_placements.append((shard, n_id, n_endpoint))

        assignments.append((seq, chunk_id, shard_placements, orig_size, enc_size, padlen))

    return assignments


class InsufficientCapacityError(ValueError):
    """Raised when planned shard placements exceed a node's reported available capacity."""


def verify_shard_capacity(
    shard_assignments: List[Tuple[int, str, List[Tuple[Any, str, str]], int, int, int]],
    selected_nodes: List[Dict[str, Any]],
) -> Dict[str, int]:
    """
    Sums the actual shard bytes planned for each node across all chunks and compares the total
    with the node's reported `available_capacity_bytes` (when reported).

    Coordinator-reported capacity is advisory only: Storage Nodes still enforce their own quotas
    at write time (HTTP 507), which the upload pipeline treats as a failure + cleanup.
    Returns the planned bytes per node_id.
    """
    planned: Dict[str, int] = {}
    for _seq, _cid, shard_placements, _o, _e, _p in shard_assignments:
        for shard, n_id, _ep in shard_placements:
            planned[n_id] = planned.get(n_id, 0) + len(shard.payload)

    by_id = {n.get("node_id"): n for n in selected_nodes}
    shortfalls = []
    for n_id, need in planned.items():
        avail = by_id.get(n_id, {}).get("available_capacity_bytes")
        if avail is not None and need > int(avail):
            shortfalls.append(f"{n_id} (needs {need} B, reports {avail} B available)")
    if shortfalls:
        raise InsufficientCapacityError(
            "Insufficient capacity for planned shard placements: " + "; ".join(shortfalls)
        )
    return planned


