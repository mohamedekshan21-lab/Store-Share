"""
Coordinator integration for Expo Storage Node (Phase 2B).
Handles safe registration, heartbeat reporting, automatic reconnection,
and TLS security configuration from Storage Node to Coordinator.
Guarantees that Coordinator unavailability or failures never disrupt local Storage Node functionality.
"""

from __future__ import annotations

import logging
from typing import Optional

from coordinator.coordinator_client import CoordinatorClient, CoordinatorClientError
from storage_node.app.config import Settings
from storage_node.app.storage_manager import StorageManager

logger = logging.getLogger("expo_storage_node.coordinator")


class CoordinatorNotifier:
    """Safely manages Storage Node lifecycle interactions with the Coordinator over HTTP or HTTPS."""

    def __init__(self, settings: Settings, storage_manager: StorageManager) -> None:
        self.settings = settings
        self.storage_manager = storage_manager
        self.coordinator_url = settings.resolved_coordinator_url
        self.auth_token = settings.coordinator_auth_token
        self._registered = False

        if self.coordinator_url:
            self.client: Optional[CoordinatorClient] = CoordinatorClient(
                coordinator_url=self.coordinator_url,
                auth_token=self.auth_token,
                verify_tls=settings.coordinator_verify_tls,
                ca_cert=settings.coordinator_ca_cert,
            )
        else:
            self.client = None

    def register(self) -> Optional[dict]:
        """Attempts to register the Storage Node with the Coordinator. Returns node record or None on failure."""
        if not self.settings.coordinator_enabled or not self.client:
            logger.debug("Coordinator integration is disabled or no Coordinator URL is configured.")
            return None

        node_info = self.storage_manager.get_node_info()
        storage_info = self.storage_manager.get_storage_info()

        host = self.settings.host if self.settings.host != "0.0.0.0" else "127.0.0.1"
        port = self.settings.port
        adv_endpoint = self.settings.resolved_advertised_endpoint

        try:
            res = self.client.register_node(
                node_id=node_info.node_id,
                host=host,
                port=port,
                endpoint=f"http://{host}:{port}",
                advertised_endpoint=adv_endpoint,
                connectivity_mode=self.settings.connectivity_mode,
                protocol_version=self.settings.protocol_version,
                provider_id=self.settings.provider_id,
                total_capacity_bytes=storage_info.quota_bytes,
                used_capacity_bytes=storage_info.used_bytes,
                available_capacity_bytes=storage_info.available_bytes,
            )
            self._registered = True
            logger.info("Successfully registered node '%s' with Coordinator at %s", node_info.node_id, self.coordinator_url)
            return res
        except Exception as exc:
            self._registered = False
            logger.warning("Failed to register node with Coordinator at %s: %s", self.coordinator_url, exc)
            return None

    def heartbeat(self) -> Optional[dict]:
        """Sends liveness heartbeat and current capacity status to the Coordinator with auto-reconnect."""
        if not self.settings.coordinator_enabled or not self.client:
            return None

        # Auto-reconnect/re-register if not currently registered or previous connection failed
        if not self._registered:
            logger.info("Attempting auto-reconnect/re-registration with Coordinator...")
            reg_res = self.register()
            if not reg_res:
                return None

        node_info = self.storage_manager.get_node_info()
        storage_info = self.storage_manager.get_storage_info()

        try:
            res = self.client.heartbeat(
                node_id=node_info.node_id,
                used_capacity_bytes=storage_info.used_bytes,
                available_capacity_bytes=storage_info.available_bytes,
                status="online",
                connectivity_mode=self.settings.connectivity_mode,
                protocol_version=self.settings.protocol_version,
            )
            logger.debug("Sent heartbeat for node '%s' to Coordinator.", node_info.node_id)
            return res
        except Exception as exc:
            logger.warning("Failed heartbeat to Coordinator for node '%s' (%s). Triggering re-register on next tick.", node_info.node_id, exc)
            self._registered = False
            return None


import asyncio
import json
import struct
import httpx
import websockets


class RelayTunnelClient:
    """
    Maintains a persistent outbound reverse WebSocket tunnel from the Storage Node
    to the Coordinator Relay service.
    Allows the Coordinator to proxy client requests to this node even when behind NAT/firewalls.
    """

    def __init__(
        self,
        node_id: str,
        coordinator_url: str,
        local_port: int,
        auth_token: Optional[str] = None,
        verify_tls: bool = True,
    ) -> None:
        self.node_id = node_id
        self.coordinator_url = coordinator_url.rstrip("/")
        self.local_port = local_port
        self.auth_token = auth_token
        self.verify_tls = verify_tls
        self._running = False
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        self._running = True
        self._stop_event.clear()
        backoff = 1.0
        max_backoff = 30.0

        # Convert http(s) URL to ws(s) URL
        ws_url = self.coordinator_url
        if ws_url.startswith("https://"):
            ws_url = "wss://" + ws_url[8:]
        elif ws_url.startswith("http://"):
            ws_url = "ws://" + ws_url[7:]
        tunnel_endpoint = f"{ws_url}/relay/tunnel/{self.node_id}"

        headers = {}
        if self.auth_token:
            headers["X-Auth-Token"] = self.auth_token
            headers["Authorization"] = f"Bearer {self.auth_token}"

        while self._running:
            try:
                logger.info("Connecting outbound relay tunnel for node '%s' to %s...", self.node_id, tunnel_endpoint)
                async with websockets.connect(
                    tunnel_endpoint,
                    additional_headers=headers,
                    max_size=20 * 1024 * 1024,
                    ping_interval=20,
                    ping_timeout=10,
                ) as ws:
                    logger.info("Outbound reverse relay tunnel established for node '%s'.", self.node_id)
                    backoff = 1.0

                    async for frame in ws:
                        if not self._running:
                            break
                        asyncio.create_task(self._handle_request(ws, frame))

            except asyncio.CancelledError:
                break
            except Exception as exc:
                if not self._running:
                    break
                logger.warning(
                    "Relay tunnel connection failed/lost for node '%s': %s. Reconnecting in %.1fs...",
                    self.node_id,
                    exc,
                    backoff,
                )
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(max_backoff, backoff * 1.5)

    async def _handle_request(self, ws, frame: bytes) -> None:
        """Unpacks request frame, executes request against local Storage Node, and returns response."""
        if len(frame) < 4:
            return
        header_len = struct.unpack("!I", frame[:4])[0]
        if len(frame) < 4 + header_len:
            return
        header_dict = json.loads(frame[4 : 4 + header_len].decode("utf-8"))
        req_body = frame[4 + header_len :]

        req_id = header_dict["request_id"]
        method = header_dict["method"]
        path = header_dict["path"]
        query = header_dict.get("query", "")
        fwd_headers = header_dict.get("headers", {})

        url = f"http://127.0.0.1:{self.local_port}{path}"
        if query:
            url = f"{url}?{query}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                resp = await http.request(
                    method=method,
                    url=url,
                    headers=fwd_headers,
                    content=req_body,
                )
                resp_headers = dict(resp.headers)
                resp_content = resp.content
                status_code = resp.status_code
        except Exception as exc:
            logger.error("Error executing tunneled request locally: %s", exc)
            resp_headers = {"content-type": "application/json"}
            resp_content = json.dumps({"detail": f"Local storage error: {str(exc)}"}).encode("utf-8")
            status_code = 500

        resp_header_dict = {
            "request_id": req_id,
            "status_code": status_code,
            "headers": resp_headers,
        }
        resp_hdr_bytes = json.dumps(resp_header_dict).encode("utf-8")
        resp_frame = struct.pack("!I", len(resp_hdr_bytes)) + resp_hdr_bytes + resp_content

        try:
            await ws.send(resp_frame)
        except Exception as exc:
            logger.warning("Failed to return response frame over tunnel: %s", exc)

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
