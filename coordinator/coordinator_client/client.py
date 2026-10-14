"""
Expo Coordinator Client API implementation (Phase 2B).
Enables Storage Nodes and Consumer Clients to communicate with the Expo Coordinator
over HTTP or secure HTTPS with custom TLS verification.
"""

from __future__ import annotations

import ssl
from typing import Any, Dict, List, Optional
import httpx


class CoordinatorClientError(Exception):
    """Base exception for Coordinator Client errors."""


class CoordinatorTLSError(CoordinatorClientError):
    """Raised when HTTPS/TLS certificate verification fails."""


class CoordinatorClient:
    """Client SDK for interacting with the Expo Coordinator Service over HTTP/HTTPS."""

    def __init__(
        self,
        coordinator_url: str = "http://127.0.0.1:9000",
        auth_token: Optional[str] = None,
        verify_tls: bool = True,
        ca_cert: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = coordinator_url.rstrip("/")
        self.auth_token = auth_token
        self.verify_tls = verify_tls
        self.ca_cert = ca_cert
        self.timeout = timeout

        # Resolve httpx verify setting
        if not verify_tls:
            self.verify: Any = False
        elif ca_cert and ca_cert.strip():
            self.verify = ca_cert.strip()
        else:
            self.verify = True

    def _get_headers(self) -> Dict[str, str]:
        """Builds HTTP headers including auth token if configured."""
        headers = {}
        if self.auth_token and self.auth_token.strip():
            token = self.auth_token.strip()
            headers["X-Auth-Token"] = token
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Helper to send HTTP/HTTPS requests with TLS error handling."""
        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        try:
            with httpx.Client(verify=self.verify, timeout=self.timeout) as client:
                res = client.request(method, url, headers=headers, **kwargs)
                return res
        except (httpx.ConnectError, ssl.SSLError) as exc:
            err_msg = str(exc)
            if "certificate verify failed" in err_msg.lower() or "ssl" in err_msg.lower():
                raise CoordinatorTLSError(f"TLS certificate verification failed for '{url}': {err_msg}") from exc
            raise CoordinatorClientError(f"Coordinator network error for '{url}': {err_msg}") from exc
        except httpx.RequestError as exc:
            raise CoordinatorClientError(f"Coordinator network error for '{url}': {str(exc)}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Coordinator HTTP error for '{url}': {str(exc)}") from exc

    def health(self) -> Dict[str, Any]:
        """Queries Coordinator liveness health status."""
        try:
            res = self._request("GET", "/health")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Coordinator health check failed: {str(exc)}") from exc

    def register_node(
        self,
        node_id: str,
        host: str,
        port: int,
        total_capacity_bytes: Optional[int] = None,
        used_capacity_bytes: Optional[int] = 0,
        available_capacity_bytes: Optional[int] = None,
        endpoint: Optional[str] = None,
        advertised_endpoint: Optional[str] = None,
        connectivity_mode: str = "LAN",
        protocol_version: str = "2B",
        provider_id: Optional[str] = None,
        is_schedulable: bool = True,
    ) -> Dict[str, Any]:
        """Registers or updates a Storage Node record with the Coordinator."""
        payload = {
            "node_id": node_id,
            "host": host,
            "port": port,
            "endpoint": endpoint,
            "advertised_endpoint": advertised_endpoint,
            "connectivity_mode": connectivity_mode,
            "protocol_version": protocol_version,
            "total_capacity_bytes": total_capacity_bytes,
            "used_capacity_bytes": used_capacity_bytes,
            "available_capacity_bytes": available_capacity_bytes,
            "is_schedulable": is_schedulable,
        }
        if provider_id is not None:
            payload["provider_id"] = provider_id
        res = self._request("POST", "/nodes/register", json=payload)
        if res.status_code == 401:
            raise CoordinatorClientError("Coordinator registration unauthorized: Missing or invalid token.")
        elif res.status_code == 400:
            detail = res.json().get("detail", res.text) if res.content else res.text
            raise CoordinatorClientError(f"Coordinator registration invalid (400): {detail}")
        
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Coordinator registration failed: {str(exc)}") from exc

    def heartbeat(
        self,
        node_id: str,
        used_capacity_bytes: Optional[int] = None,
        available_capacity_bytes: Optional[int] = None,
        status: str = "online",
        connectivity_mode: Optional[str] = None,
        protocol_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Sends periodic heartbeat liveness update and optional capacity updates."""
        payload = {
            "node_id": node_id,
            "status": status,
            "used_capacity_bytes": used_capacity_bytes,
            "available_capacity_bytes": available_capacity_bytes,
            "connectivity_mode": connectivity_mode,
            "protocol_version": protocol_version,
        }
        res = self._request("POST", f"/nodes/{node_id}/heartbeat", json=payload)
        if res.status_code == 401:
            raise CoordinatorClientError("Coordinator heartbeat unauthorized: Missing or invalid token.")
        elif res.status_code == 404:
            raise CoordinatorClientError(f"Coordinator heartbeat failed: Node '{node_id}' not found.")
        
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Coordinator heartbeat failed: {str(exc)}") from exc

    def list_nodes(
        self,
        status: Optional[str] = None,
        connectivity_mode: Optional[str] = None,
        min_available_bytes: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Lists registered Storage Nodes from Coordinator with advanced filtering."""
        params: Dict[str, Any] = {}
        if status:
            params["status"] = status
        if connectivity_mode:
            params["connectivity_mode"] = connectivity_mode
        if min_available_bytes is not None:
            params["min_available_bytes"] = min_available_bytes

        res = self._request("GET", "/nodes", params=params)
        try:
            res.raise_for_status()
            data = res.json()
            return data.get("nodes", [])
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"List nodes failed: {str(exc)}") from exc

    def select_node(
        self,
        required_bytes: int,
        online_only: bool = True,
        preferred_connectivity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries Coordinator to select the best eligible Storage Node."""
        params: Dict[str, Any] = {
            "required_bytes": required_bytes,
            "online_only": online_only,
        }
        if preferred_connectivity:
            params["preferred_connectivity"] = preferred_connectivity

        res = self._request("GET", "/nodes/select", params=params)
        if res.status_code == 404:
            raise CoordinatorClientError(f"No eligible storage node available matching criteria ({required_bytes} bytes).")
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Select node failed: {str(exc)}") from exc

    def get_node(self, node_id: str) -> Dict[str, Any]:
        """Queries Coordinator for information about a specific node_id."""
        res = self._request("GET", f"/nodes/{node_id}")
        if res.status_code == 404:
            raise CoordinatorClientError(f"Node '{node_id}' not found on Coordinator.")
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get node failed: {str(exc)}") from exc

    def delete_node(self, node_id: str) -> bool:
        """Deregisters / removes a Storage Node from Coordinator."""
        res = self._request("DELETE", f"/nodes/{node_id}")
        if res.status_code == 404:
            raise CoordinatorClientError(f"Node '{node_id}' not found on Coordinator.")
        try:
            res.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Delete node failed: {str(exc)}") from exc

    def list_repair_jobs(self, state: Optional[str] = None, file_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Queries Coordinator for list of tracked repair jobs."""
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if file_id:
            params["file_id"] = file_id
        res = self._request("GET", "/repair/jobs", params=params)
        try:
            res.raise_for_status()
            return res.json().get("jobs", [])
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"List repair jobs failed: {str(exc)}") from exc

    def create_repair_job(self, job_data: Dict[str, Any]) -> Dict[str, Any]:
        """Registers or updates a repair job record on the Coordinator."""
        res = self._request("POST", "/repair/jobs", json=job_data)
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Create repair job failed: {str(exc)}") from exc

    def get_repair_job(self, job_id: str) -> Dict[str, Any]:
        """Retrieves specific repair job record from Coordinator."""
        res = self._request("GET", f"/repair/jobs/{job_id}")
        if res.status_code == 404:
            raise CoordinatorClientError(f"Repair job '{job_id}' not found on Coordinator.")
        try:
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get repair job failed: {str(exc)}") from exc

    # Phase 5A / 5B File Catalog Operations
    
    def register_logical_file(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Registers a logical file using its manifest via the Coordinator."""
        try:
            res = self._request("POST", "/catalog/files", json={"manifest": manifest})
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Register logical file failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Register logical file network error: {str(exc)}") from exc

    def list_logical_files(self) -> List[Dict[str, Any]]:
        """Lists files owned by the authenticated user namespace."""
        try:
            res = self._request("GET", "/catalog/files")
            res.raise_for_status()
            return res.json().get("files", [])
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                raise CoordinatorClientError("Authentication failed: Missing or invalid token.") from exc
            raise CoordinatorClientError(f"List logical files failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"List logical files network error: {str(exc)}") from exc

    def get_logical_file(self, file_id: str) -> Dict[str, Any]:
        """Retrieves logical file catalog metadata and manifest."""
        try:
            res = self._request("GET", f"/catalog/files/{file_id}")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise CoordinatorClientError(f"Logical file not found (404): ID '{file_id}'") from exc
            raise CoordinatorClientError(f"Get logical file failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get logical file network error: {str(exc)}") from exc

    def delete_logical_file(self, file_id: str, finalize: bool = False) -> Dict[str, Any]:
        """Marks a logical file for deletion in the catalog, or marks it fully deleted if finalize=True."""
        try:
            url = f"/catalog/files/{file_id}"
            if finalize:
                url += "?finalize=true"
            res = self._request("DELETE", url)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise CoordinatorClientError(f"Logical file not found (404): ID '{file_id}'") from exc
            raise CoordinatorClientError(f"Delete logical file failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Delete logical file network error: {str(exc)}") from exc

    # Phase 7A: Metering Methods

    def get_metering_node_summary(self, node_id: str, window_hours: float = 24.0) -> Dict[str, Any]:
        """Queries the aggregated contribution summary for a specific storage node."""
        try:
            res = self._request("GET", f"/metering/nodes/{node_id}/summary", params={"window_hours": window_hours})
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise CoordinatorClientError(f"Storage node not found in registry (404): ID '{node_id}'") from exc
            raise CoordinatorClientError(f"Get node summary failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get node summary network error: {str(exc)}") from exc

    def get_metering_node_uptime(
        self,
        node_id: str,
        window_start: Optional[str] = None,
        window_end: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries calculated uptime and availability percentage for a storage node."""
        params = {}
        if window_start:
            params["window_start"] = window_start
        if window_end:
            params["window_end"] = window_end
        try:
            res = self._request("GET", f"/metering/nodes/{node_id}/uptime", params=params)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get node uptime network error: {str(exc)}") from exc

    def get_metering_cluster_summary(self, window_hours: float = 24.0) -> Dict[str, Any]:
        """Queries cluster-wide metering totals."""
        try:
            res = self._request("GET", "/metering/cluster/summary", params={"window_hours": window_hours})
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get cluster summary network error: {str(exc)}") from exc

    def record_metering_transfer(
        self,
        node_id: str,
        direction: str,
        operation_type: str,
        payload_bytes: int,
        chunk_id: Optional[str] = None,
        file_id: Optional[str] = None,
        status: str = "success",
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a transfer event on the Coordinator."""
        payload = {
            "node_id": node_id,
            "direction": direction,
            "operation_type": operation_type,
            "payload_bytes": payload_bytes,
            "chunk_id": chunk_id,
            "file_id": file_id,
            "status": status,
            "idempotency_key": idempotency_key,
        }
        try:
            res = self._request("POST", "/metering/transfers", json=payload)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Record transfer event network error: {str(exc)}") from exc

    # Phase 7B: Contribution Credits, Node Reputation & Accounting

    def get_credit_balance(self, node_id: str) -> Dict[str, Any]:
        """Queries the current reconciled ECC credit balance for a storage node."""
        try:
            res = self._request("GET", f"/credits/nodes/{node_id}/balance")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get credit balance network error: {str(exc)}") from exc

    def get_credit_ledger(
        self,
        node_id: str,
        limit: int = 50,
        offset: int = 0,
        category: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries paginated credit ledger entries for a storage node."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if category:
            params["category"] = category
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        try:
            res = self._request("GET", f"/credits/nodes/{node_id}/ledger", params=params)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get credit ledger network error: {str(exc)}") from exc

    def get_credit_summary(self, node_id: str) -> Dict[str, Any]:
        """Queries a categorized credit summary breakdown for a storage node."""
        try:
            res = self._request("GET", f"/credits/nodes/{node_id}/summary")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get credit summary network error: {str(exc)}") from exc

    def get_node_reputation(self, node_id: str, window_hours: float = 168.0) -> Dict[str, Any]:
        """Queries the calculated reputation score and confidence for a storage node."""
        try:
            res = self._request("GET", f"/reputation/nodes/{node_id}", params={"window_hours": window_hours})
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise CoordinatorClientError(f"Storage node not found in registry (404): ID '{node_id}'") from exc
            raise CoordinatorClientError(f"Get node reputation failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get node reputation network error: {str(exc)}") from exc

    def list_node_reputations(self, window_hours: float = 168.0) -> Dict[str, Any]:
        """Queries reputation scores for all registered nodes in the cluster."""
        try:
            res = self._request("GET", "/reputation/nodes", params={"window_hours": window_hours})
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"List node reputations network error: {str(exc)}") from exc

    def get_accounting_policy(self) -> Dict[str, Any]:
        """Queries the active credit and reputation accounting policy parameters."""
        try:
            res = self._request("GET", "/accounting/policy")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get accounting policy network error: {str(exc)}") from exc

    def get_accounting_cluster_summary(self) -> Dict[str, Any]:
        """Queries cluster-wide contribution credit totals and average reputation."""
        try:
            res = self._request("GET", "/accounting/cluster/summary")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get accounting cluster summary network error: {str(exc)}") from exc

    def reverse_credit_ledger_entry(
        self,
        entry_id: str,
        reason: str,
        amount: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Requests an administrative credit reversal for a ledger entry."""
        payload: Dict[str, Any] = {"entry_id": entry_id, "reason": reason}
        if amount is not None:
            payload["amount"] = amount
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        try:
            res = self._request("POST", "/accounting/credits/reverse", json=payload)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Reverse credit entry failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Reverse credit entry network error: {str(exc)}") from exc

    def trigger_credit_calculation(
        self,
        node_id: Optional[str] = None,
        window_hours: float = 24.0,
    ) -> Dict[str, Any]:
        """Triggers on-demand calculation and finalization of contribution credits."""
        payload = {"node_id": node_id, "window_hours": window_hours}
        try:
            res = self._request("POST", "/accounting/credits/calculate", json=payload)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Trigger credit calculation network error: {str(exc)}") from exc

    # =========================================================================
    # Phase 8A: Provider Monitoring and Node Management APIs
    # =========================================================================

    def get_provider_overview(
        self,
        window_hours: float = 24.0,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Queries aggregated provider capacity, bandwidth, balance, and node reputation."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "GET",
                "/provider/overview",
                params={"window_hours": window_hours},
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Get provider overview failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get provider overview network error: {str(exc)}") from exc

    def get_provider_nodes(
        self,
        provider_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists all nodes owned by the calling provider with status and reputation."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request("GET", "/provider/nodes", headers=headers)
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Get provider nodes failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get provider nodes network error: {str(exc)}") from exc

    def get_provider_node_detail(
        self,
        node_id: str,
        window_hours: float = 24.0,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves comprehensive diagnostic metrics for a specific provider-owned node."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "GET",
                f"/provider/nodes/{node_id}/detail",
                params={"window_hours": window_hours},
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Get provider node detail failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get provider node detail network error: {str(exc)}") from exc

    def set_node_scheduling(
        self,
        node_id: str,
        is_schedulable: bool = True,
        reason: Optional[str] = None,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enables or disables placement scheduling for a node owned by the provider."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        payload = {"is_schedulable": is_schedulable, "reason": reason}
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/scheduling",
                json=payload,
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Set node scheduling failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Set node scheduling network error: {str(exc)}") from exc

    def initiate_node_shutdown(
        self,
        node_id: str,
        reason: Optional[str] = None,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gracefully drains and marks a node as disabled/offline for maintenance."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        payload = {"reason": reason}
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/shutdown",
                json=payload,
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Initiate node shutdown failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Initiate node shutdown network error: {str(exc)}") from exc

    def initiate_node_drain(
        self,
        node_id: str,
        reason: Optional[str] = None,
        force: bool = False,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Initiates safe node draining and redundancy verification (Phase 8B)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        payload = {"reason": reason, "force": force}
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/drain",
                json=payload,
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Initiate node drain failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Initiate node drain network error: {str(exc)}") from exc

    def get_node_drain(
        self,
        node_id: str,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves durable status and progress for a node drain job (Phase 8B)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "GET",
                f"/provider/nodes/{node_id}/drain",
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Get node drain failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get node drain network error: {str(exc)}") from exc

    def retry_node_drain(
        self,
        node_id: str,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retries a blocked node drain job (Phase 8B)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/drain/retry",
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Retry node drain failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Retry node drain network error: {str(exc)}") from exc

    def complete_node_drain(
        self,
        node_id: str,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Completes a node drain and marks node as 'drained' (Phase 8B)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/drain/complete",
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Complete node drain failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Complete node drain network error: {str(exc)}") from exc

    def cancel_node_drain(
        self,
        node_id: str,
        provider_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancels a node drain job and restores node to 'disabled' (Phase 8B)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "POST",
                f"/provider/nodes/{node_id}/drain/cancel",
                headers=headers,
            )
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Cancel node drain failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Cancel node drain network error: {str(exc)}") from exc

    def list_drain_migrations(
        self,
        node_id: str,
        provider_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves granular chunk and shard migration records for a draining node (Phase 8C)."""
        headers = {}
        if provider_id:
            headers["X-Provider-Id"] = provider_id
        try:
            res = self._request(
                "GET",
                f"/provider/nodes/{node_id}/drain/migrations",
                headers=headers,
            )
            res.raise_for_status()
            return res.json().get("migrations", [])
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"List drain migrations failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"List drain migrations network error: {str(exc)}") from exc

    def get_drain_worker_status(self) -> Dict[str, Any]:
        """Queries operational metrics and status of the background migration worker (Phase 8C)."""
        try:
            res = self._request("GET", "/provider/drain/worker/status")
            res.raise_for_status()
            return res.json()
        except httpx.HTTPStatusError as exc:
            raise CoordinatorClientError(f"Get drain worker status failed ({exc.response.status_code}): {exc.response.text}") from exc
        except httpx.HTTPError as exc:
            raise CoordinatorClientError(f"Get drain worker status network error: {str(exc)}") from exc



