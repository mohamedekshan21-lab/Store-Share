"""
Connectivity Abstraction, Route State Machine & Connection Manager for Expo (Phase 6B).
Tracks node identity, route types (DIRECT, RELAY, UNAVAILABLE), reachability diagnostics,
route caching with TTL, and automatic relay fallback.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
import httpx

from client.placement import check_node_reachability, NodeReachabilityResult

logger = logging.getLogger("expo_connectivity")


class RouteType(str, Enum):
    """Enumeration of physical network routes to a Storage Node."""
    DIRECT = "DIRECT"
    RELAY = "RELAY"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class ReachabilityStatus(str, Enum):
    """Liveness probe reachability state."""
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ResolvedRoute:
    """Represents a resolved and verified network route to a Storage Node."""
    node_id: str
    route_type: RouteType
    target_url: str
    direct_endpoint: Optional[str] = None
    relay_endpoint: Optional[str] = None
    session_id: Optional[str] = None
    session_token: Optional[str] = None
    reachability: ReachabilityStatus = ReachabilityStatus.UNKNOWN
    latency_ms: Optional[float] = None
    last_probe_time: float = 0.0
    diagnostic_info: Optional[str] = None
    ttl_seconds: float = 30.0

    @property
    def is_valid(self) -> bool:
        """Returns True if route has not exceeded its TTL and is not UNAVAILABLE."""
        if self.route_type == RouteType.UNAVAILABLE:
            return False
        return (time.time() - self.last_probe_time) < self.ttl_seconds

    @property
    def is_routable(self) -> bool:
        """Returns True if the route can actively handle requests."""
        return self.route_type in (RouteType.DIRECT, RouteType.RELAY)


class ConnectionManager:
    """
    Manages node route discovery, reachability verification, caching, and fallback.
    Transparently falls back to an authenticated Relay when direct connection is unreachable.
    """

    def __init__(
        self,
        coordinator_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        probe_timeout: float = 3.0,
        route_ttl_seconds: float = 30.0,
        failure_ttl_seconds: float = 5.0,
        relay_enabled: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/") if coordinator_url else None
        self.auth_token = auth_token
        self.probe_timeout = probe_timeout
        self.route_ttl_seconds = route_ttl_seconds
        self.failure_ttl_seconds = failure_ttl_seconds
        self.relay_enabled = relay_enabled
        self.verify_tls = verify_tls
        self._route_cache: Dict[str, ResolvedRoute] = {}

    def _get_auth_headers(self) -> Dict[str, str]:
        headers = {}
        if self.auth_token and self.auth_token.strip():
            token = self.auth_token.strip()
            headers["X-Auth-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def resolve_route(
        self,
        node_id: str,
        direct_endpoint: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ResolvedRoute:
        """
        Resolves the best available network route to target node:
        1. Checks in-memory route cache if TTL valid.
        2. Probes direct advertised endpoint via GET /health.
        3. If direct probe fails, attempts establishing an authenticated relay session.
        4. If both fail, marks node as UNAVAILABLE.
        """
        now = time.time()

        # 1. Cache hit check
        cached = self._route_cache.get(node_id)
        if cached and not force_refresh:
            elapsed = now - cached.last_probe_time
            if elapsed < cached.ttl_seconds:
                return cached

        # Resolve direct endpoint if missing and coordinator available
        target_direct = direct_endpoint
        if not target_direct and self.coordinator_url:
            try:
                from coordinator.coordinator_client import CoordinatorClient
                coord = CoordinatorClient(coordinator_url=self.coordinator_url, timeout=self.probe_timeout)
                node_info = coord.get_node(node_id)
                target_direct = node_info.get("advertised_endpoint") or node_info.get("endpoint")
            except Exception as exc:
                logger.debug("Failed querying coordinator for node '%s': %s", node_id, exc)

        clean_direct = target_direct.strip().rstrip("/") if target_direct else None

        # 2. Probe direct advertised endpoint
        if clean_direct:
            probe_res = check_node_reachability(
                endpoint=clean_direct,
                node_id=node_id,
                timeout=self.probe_timeout,
                verify_tls=self.verify_tls,
            )
            if probe_res.reachability == "REACHABLE":
                route = ResolvedRoute(
                    node_id=node_id,
                    route_type=RouteType.DIRECT,
                    target_url=clean_direct,
                    direct_endpoint=clean_direct,
                    reachability=ReachabilityStatus.REACHABLE,
                    latency_ms=probe_res.latency_ms,
                    last_probe_time=now,
                    diagnostic_info="Direct TCP connection established successfully",
                    ttl_seconds=self.route_ttl_seconds,
                )
                self._route_cache[node_id] = route
                return route
            else:
                direct_diag = probe_res.reason or "Direct probe failed"
        else:
            direct_diag = "No direct endpoint configured"

        # 3. Direct unreachable -> Attempt Relay Fallback
        if self.relay_enabled and self.coordinator_url:
            relay_route = self._attempt_relay_fallback(
                node_id=node_id,
                direct_endpoint=clean_direct,
                direct_reason=direct_diag,
            )
            if relay_route:
                self._route_cache[node_id] = relay_route
                return relay_route

        # 4. Both Direct and Relay failed -> UNAVAILABLE
        unavail_route = ResolvedRoute(
            node_id=node_id,
            route_type=RouteType.UNAVAILABLE,
            target_url=clean_direct or "",
            direct_endpoint=clean_direct,
            reachability=ReachabilityStatus.UNREACHABLE,
            last_probe_time=now,
            diagnostic_info=f"All routes failed. Direct: {direct_diag}. Relay: Unavailable or failed.",
            ttl_seconds=self.failure_ttl_seconds,
        )
        self._route_cache[node_id] = unavail_route
        return unavail_route

    def _attempt_relay_fallback(
        self,
        node_id: str,
        direct_endpoint: Optional[str],
        direct_reason: str,
    ) -> Optional[ResolvedRoute]:
        """Requests an authenticated relay session from Coordinator and validates route."""
        now = time.time()
        sessions_url = f"{self.coordinator_url}/relay/sessions"
        headers = self._get_auth_headers()
        body = {
            "target_node_id": node_id,
            "client_id": "expo_client",
            "ttl_seconds": int(self.route_ttl_seconds * 4),
        }

        try:
            with httpx.Client(verify=self.verify_tls, timeout=self.probe_timeout) as client:
                res = client.post(sessions_url, json=body, headers=headers)
                if res.status_code == 201:
                    data = res.json()
                    session_id = data["session_id"]
                    session_token = data["session_token"]
                    relayed_url = f"{self.coordinator_url}/relay/{session_id}"

                    # Verify relayed health check
                    t0 = time.perf_counter()
                    health_headers = {"X-Relay-Token": session_token}
                    if self.auth_token:
                        health_headers["X-Auth-Token"] = self.auth_token

                    health_res = client.get(f"{relayed_url}/health?verbose=true", headers=health_headers)
                    t1 = time.perf_counter()
                    latency_ms = round((t1 - t0) * 1000.0, 2)

                    if health_res.status_code == 200:
                        logger.info("Relay fallback established for node '%s' via %s", node_id, relayed_url)
                        return ResolvedRoute(
                            node_id=node_id,
                            route_type=RouteType.RELAY,
                            target_url=relayed_url,
                            direct_endpoint=direct_endpoint,
                            relay_endpoint=self.coordinator_url,
                            session_id=session_id,
                            session_token=session_token,
                            reachability=ReachabilityStatus.REACHABLE,
                            latency_ms=latency_ms,
                            last_probe_time=now,
                            diagnostic_info=f"Relay fallback active (Direct failed: {direct_reason})",
                            ttl_seconds=self.route_ttl_seconds,
                        )
                    else:
                        logger.warning(
                            "Relay session established but probe failed (HTTP %d) for node '%s'",
                            health_res.status_code,
                            node_id,
                        )
                else:
                    logger.debug("Relay session creation rejected (HTTP %d): %s", res.status_code, res.text)
        except Exception as exc:
            logger.debug("Relay fallback error for node '%s': %s", node_id, exc)

        return None

    def invalidate_route(self, node_id: str) -> None:
        """Evicts cached route information for node_id to force rediscovery."""
        if node_id in self._route_cache:
            del self._route_cache[node_id]
            logger.debug("Invalidated cached route for node '%s'", node_id)

    def clear_cache(self) -> None:
        """Clears all cached routes."""
        self._route_cache.clear()

    def get_route(self, node_id: str) -> Optional[ResolvedRoute]:
        """Returns cached route for node_id without triggering active probe."""
        return self._route_cache.get(node_id)
