"""
Authenticated Relay Service for Expo (Phase 6B).
Provides session-authorized, bounded, zero-knowledge HTTP relay forwarding
for Storage Nodes behind NAT, firewalls, or CGNAT.
"""

from __future__ import annotations

import logging
import asyncio
import json
import os
import secrets
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import httpx
from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field

from coordinator.app.node_registry import NodeRegistry, NodeNotFoundError

logger = logging.getLogger("expo_relay")

# Security and resource limits
DEFAULT_SESSION_TTL_SECONDS = 300.0  # 5 minutes
MAX_SESSION_TTL_SECONDS = 3600.0     # 1 hour
MAX_RELAY_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MB max chunk/file payload
MAX_CONCURRENT_SESSIONS = 256
ALLOWED_RELAY_PATH_PREFIXES = ("health", "node", "storage", "files")


@dataclass
class RelaySession:
    """Represents an active, authenticated relay session."""
    session_id: str
    session_token: str
    target_node_id: str
    target_endpoint: str
    client_id: str
    created_at: float
    expires_at: float
    last_activity: float
    bytes_relayed: int = 0
    requests_count: int = 0


class CreateRelaySessionRequest(BaseModel):
    """Request model for allocating a new relay session."""
    target_node_id: str = Field(..., description="Target Storage Node ID registered with Coordinator")
    client_id: Optional[str] = Field(None, description="Client or caller identifier")
    ttl_seconds: Optional[int] = Field(300, description="Session time-to-live in seconds (max 3600)")


class RelaySessionResponse(BaseModel):
    """Response model representing allocated relay session credentials."""
    session_id: str = Field(..., description="Unique relay session ID")
    target_node_id: str = Field(..., description="Target Storage Node ID")
    target_endpoint: str = Field(..., description="Internal destination endpoint")
    client_id: str = Field(..., description="Bound client identifier")
    session_token: str = Field(..., description="Secret bearer token for using the relay session")
    expires_at: str = Field(..., description="ISO 8601 or UNIX expiration timestamp")
    ttl_seconds: float = Field(..., description="Remaining session validity in seconds")


class RelaySessionSummary(BaseModel):
    """Summary model for listing active relay sessions."""
    session_id: str
    target_node_id: str
    client_id: str
    created_at: float
    expires_at: float
    requests_count: int
    bytes_relayed: int


class NodeTunnel:
    """Manages an active persistent reverse WebSocket tunnel to an authenticated Storage Node."""

    def __init__(self, node_id: str, websocket: WebSocket) -> None:
        self.node_id = node_id
        self.websocket = websocket
        self.created_at = time.time()
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.lock = asyncio.Lock()
        self.is_closed = False

    async def send_request(
        self,
        method: str,
        path: str,
        query: str,
        headers: Dict[str, str],
        body: bytes,
        timeout: float = 30.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        if self.is_closed:
            raise ConnectionError(f"Tunnel for node '{self.node_id}' is closed.")

        request_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.pending_requests[request_id] = future

        # Prepare frame: [4-byte uint header_len][JSON header UTF-8][body]
        header_dict = {
            "request_id": request_id,
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
        }
        header_bytes = json.dumps(header_dict).encode("utf-8")
        frame = struct.pack("!I", len(header_bytes)) + header_bytes + body

        try:
            async with self.lock:
                await self.websocket.send_bytes(frame)

            status_code, resp_headers, resp_body = await asyncio.wait_for(future, timeout=timeout)
            return status_code, resp_headers, resp_body
        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise TimeoutError(f"Tunnel request '{request_id}' to node '{self.node_id}' timed out after {timeout}s.")
        except Exception:
            self.pending_requests.pop(request_id, None)
            raise

    def handle_incoming_frame(self, frame_bytes: bytes) -> None:
        """Parses a response frame from the storage node and resolves the matching pending request."""
        if len(frame_bytes) < 4:
            logger.warning("Received malformed tunnel frame (< 4 bytes)")
            return
        header_len = struct.unpack("!I", frame_bytes[:4])[0]
        if len(frame_bytes) < 4 + header_len:
            logger.warning("Received truncated tunnel frame")
            return
        header_json = frame_bytes[4 : 4 + header_len].decode("utf-8")
        body = frame_bytes[4 + header_len :]

        try:
            header_dict = json.loads(header_json)
        except Exception as exc:
            logger.warning("Failed to decode tunnel frame header: %s", exc)
            return

        request_id = header_dict.get("request_id")
        status_code = header_dict.get("status_code", 200)
        headers = header_dict.get("headers", {})

        future = self.pending_requests.pop(request_id, None)
        if future and not future.done():
            future.set_result((status_code, headers, body))

    def close(self, exc: Optional[Exception] = None) -> None:
        self.is_closed = True
        err = exc or ConnectionResetError(f"Tunnel for node '{self.node_id}' disconnected.")
        for req_id, fut in list(self.pending_requests.items()):
            if not fut.done():
                fut.set_exception(err)
        self.pending_requests.clear()


class RelayService:
    """
    Manages authenticated relay sessions and safe request proxying.
    Guarantees SSRF protection by resolving targets solely from NodeRegistry.
    Supports persistent outbound reverse WebSocket tunnels from Storage Nodes behind NAT.
    """

    def __init__(
        self,
        registry: NodeRegistry,
        max_sessions: int = MAX_CONCURRENT_SESSIONS,
        max_payload_bytes: int = MAX_RELAY_PAYLOAD_BYTES,
    ) -> None:
        self.registry = registry
        self.max_sessions = max_sessions
        self.max_payload_bytes = max_payload_bytes
        self._sessions: Dict[str, RelaySession] = {}
        self._tunnels: Dict[str, NodeTunnel] = {}

    def register_tunnel(self, node_id: str, websocket: WebSocket) -> NodeTunnel:
        old_tunnel = self._tunnels.pop(node_id, None)
        if old_tunnel:
            old_tunnel.close(ConnectionResetError("Replaced by new tunnel connection"))
        tunnel = NodeTunnel(node_id=node_id, websocket=websocket)
        self._tunnels[node_id] = tunnel
        logger.info("Registered reverse relay tunnel for node '%s'", node_id)
        return tunnel

    def unregister_tunnel(self, node_id: str, tunnel: NodeTunnel) -> None:
        current = self._tunnels.get(node_id)
        if current is tunnel:
            self._tunnels.pop(node_id, None)
        tunnel.close()
        logger.info("Unregistered reverse relay tunnel for node '%s'", node_id)

    def get_tunnel(self, node_id: str) -> Optional[NodeTunnel]:
        tunnel = self._tunnels.get(node_id)
        if tunnel and tunnel.is_closed:
            self._tunnels.pop(node_id, None)
            return None
        return tunnel

    def cleanup_expired_sessions(self) -> int:
        """Purges expired sessions from memory. Returns count purged."""
        now = time.time()
        expired = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def create_session(
        self,
        target_node_id: str,
        client_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> RelaySession:
        """
        Creates an authorized relay session for target_node_id.
        Validates target exists in registry (SSRF prevention).
        """
        self.cleanup_expired_sessions()

        if len(self._sessions) >= self.max_sessions:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Relay capacity reached: Maximum concurrent sessions active.",
            )

        # Validate target node exists in NodeRegistry
        node = self.registry.get_node(target_node_id)
        if not node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target node '{target_node_id}' not found in registry.",
            )

        target_ep = (node.endpoint or node.advertised_endpoint or "").strip().rstrip("/")
        if not target_ep:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target node '{target_node_id}' has no valid registered endpoint.",
            )


        now = time.time()
        ttl = min(float(ttl_seconds or DEFAULT_SESSION_TTL_SECONDS), MAX_SESSION_TTL_SECONDS)
        if ttl <= 0:
            ttl = DEFAULT_SESSION_TTL_SECONDS

        session_id = str(uuid.uuid4())
        session_token = secrets.token_hex(24)
        c_id = (client_id or "anonymous").strip()

        session = RelaySession(
            session_id=session_id,
            session_token=session_token,
            target_node_id=target_node_id,
            target_endpoint=target_ep,
            client_id=c_id,
            created_at=now,
            expires_at=now + ttl,
            last_activity=now,
        )
        self._sessions[session_id] = session
        logger.info(
            "Created relay session %s for target node '%s' (expires in %.0fs)",
            session_id,
            target_node_id,
            ttl,
        )
        return session

    def get_session(self, session_id: str) -> Optional[RelaySession]:
        """Retrieves active session if valid and not expired."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        if session.expires_at <= time.time():
            self._sessions.pop(session_id, None)
            return None
        return session

    def close_session(self, session_id: str) -> bool:
        """Closes and removes an active relay session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info("Closed relay session %s", session_id)
            return True
        return False

    def list_sessions(self) -> List[RelaySession]:
        """Lists active, non-expired sessions."""
        self.cleanup_expired_sessions()
        return list(self._sessions.values())


# Router setup
relay_router = APIRouter(prefix="/relay", tags=["Relay"])


def get_relay_service(request: Request) -> RelayService:
    """Dependency provider for RelayService singleton on app state (HTTP endpoints)."""
    app_state = request.app.state
    if not hasattr(app_state, "relay_service"):
        from coordinator.app.main import get_registry
        registry = get_registry(request)
        app_state.relay_service = RelayService(registry)
    return app_state.relay_service


def get_relay_service_ws(websocket: WebSocket) -> RelayService:
    """Dependency provider for RelayService singleton on app state (WebSocket endpoints)."""
    app_state = websocket.app.state
    if not hasattr(app_state, "relay_service"):
        from coordinator.app.main import get_registry_from_state
        registry = get_registry_from_state(app_state)
        app_state.relay_service = RelayService(registry)
    return app_state.relay_service


@relay_router.post(
    "/sessions",
    response_model=RelaySessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Authenticated Relay Session",
)
def create_session(
    payload: CreateRelaySessionRequest,
    request: Request,
    relay_service: RelayService = Depends(get_relay_service),
) -> RelaySessionResponse:
    """
    Allocates an authorized relay session bound to a verified target node.
    Enforces SSRF safety by resolving destination from registry.
    """
    # Verify coordinator auth if configured
    from coordinator.app.main import verify_coordinator_auth, get_settings
    settings = get_settings(request)
    x_token = request.headers.get("X-Auth-Token")
    auth_hdr = request.headers.get("Authorization")
    verify_coordinator_auth(settings, x_auth_token=x_token, authorization=auth_hdr)

    session = relay_service.create_session(
        target_node_id=payload.target_node_id,
        client_id=payload.client_id,
        ttl_seconds=payload.ttl_seconds,
    )

    return RelaySessionResponse(
        session_id=session.session_id,
        target_node_id=session.target_node_id,
        target_endpoint=session.target_endpoint,
        client_id=session.client_id,
        session_token=session.session_token,
        expires_at=str(session.expires_at),
        ttl_seconds=max(0.0, session.expires_at - time.time()),
    )


@relay_router.get(
    "/sessions",
    response_model=List[RelaySessionSummary],
    summary="List Active Relay Sessions",
)
def list_sessions(
    request: Request,
    relay_service: RelayService = Depends(get_relay_service),
) -> List[RelaySessionSummary]:
    """Lists currently active, authorized relay sessions."""
    from coordinator.app.main import verify_coordinator_auth, get_settings
    settings = get_settings(request)
    verify_coordinator_auth(settings, request.headers.get("X-Auth-Token"), request.headers.get("Authorization"))

    sessions = relay_service.list_sessions()
    return [
        RelaySessionSummary(
            session_id=s.session_id,
            target_node_id=s.target_node_id,
            client_id=s.client_id,
            created_at=s.created_at,
            expires_at=s.expires_at,
            requests_count=s.requests_count,
            bytes_relayed=s.bytes_relayed,
        )
        for s in sessions
    ]


@relay_router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_200_OK,
    summary="Close Relay Session",
)
def close_session(
    session_id: str,
    request: Request,
    relay_service: RelayService = Depends(get_relay_service),
) -> Dict[str, Any]:
    """Explicitly closes an active relay session and releases resources."""
    from coordinator.app.main import verify_coordinator_auth, get_settings
    settings = get_settings(request)
    verify_coordinator_auth(settings, request.headers.get("X-Auth-Token"), request.headers.get("Authorization"))

    closed = relay_service.close_session(session_id)
    if not closed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Relay session '{session_id}' not found or already expired.",
        )
    return {"status": "closed", "session_id": session_id}


@relay_router.api_route(
    "/{session_id}/{path:path}",
    methods=["GET", "POST", "DELETE", "HEAD", "PUT"],
    summary="Transparent Relayed Request Forwarding",
)
async def relay_forward_request(
    session_id: str,
    path: str,
    request: Request,
    relay_service: RelayService = Depends(get_relay_service),
) -> Response:
    """
    Transparently forwards an HTTP request to the target Storage Node bound to session_id.
    Validates session token, path whitelist, and payload size.
    Preserves zero-knowledge ciphertext forwarding without inspecting or logging payloads.
    """
    session = relay_service.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Relay session '{session_id}' invalid, closed, or expired.",
        )

    # Validate session authorization token
    req_token = request.headers.get("X-Relay-Token")
    if not req_token:
        # Fall back to Authorization: Bearer <token>
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            req_token = auth[7:].strip()
    
    # Allow token match with session_token or Coordinator auth token
    if not req_token or (req_token != session.session_token):
        # Check if caller passed coordinator auth token
        from coordinator.app.main import get_settings
        settings = get_settings(request)
        if not (settings.auth_token and req_token == settings.auth_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Missing or invalid relay session token.",
            )

    # Validate path security (prevent path traversal & restrict to storage node endpoints)
    clean_path = path.lstrip("/")
    if ".." in clean_path:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Path traversal not allowed.",
        )

    if not any(clean_path.startswith(prefix) for prefix in ALLOWED_RELAY_PATH_PREFIXES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Relayed endpoint path '{clean_path}' not in allowed whitelist.",
        )

    # Validate payload size from header
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            cl = int(content_length)
            if cl > relay_service.max_payload_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Payload exceeds maximum relay size limit ({relay_service.max_payload_bytes} bytes).",
                )
        except ValueError:
            pass

    # Read body with bounded size check
    body = await request.body()
    if len(body) > relay_service.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload size ({len(body)} bytes) exceeds maximum relay limit.",
        )

    target_url = f"{session.target_endpoint}/{clean_path}"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    # Prepare forwarding headers
    hop_by_hop = {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-relay-token",
    }
    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in hop_by_hop
    }

    session.last_activity = time.time()
    session.requests_count += 1
    session.bytes_relayed += len(body)

    # 1. Prioritize active outbound reverse tunnel from Storage Node behind NAT
    tunnel = relay_service.get_tunnel(session.target_node_id)
    if tunnel and not tunnel.is_closed:
        try:
            status_code, resp_headers, resp_body = await tunnel.send_request(
                method=request.method,
                path=f"/{clean_path}",
                query=str(request.url.query) if request.url.query else "",
                headers=fwd_headers,
                body=body,
                timeout=30.0,
            )
            session.bytes_relayed += len(resp_body)

            # Phase 7A: Record verified transfer in MeteringService
            try:
                from coordinator.app.main import get_metering_service_from_state
                metering = get_metering_service_from_state(request.app.state)
                if request.method.upper() in ("POST", "PUT") and 200 <= status_code < 300:
                    metering.record_transfer_event(
                        node_id=session.target_node_id,
                        direction="upload",
                        operation_type="relay",
                        payload_bytes=len(body),
                        status="success",
                    )
                elif request.method.upper() == "GET" and 200 <= status_code < 300:
                    metering.record_transfer_event(
                        node_id=session.target_node_id,
                        direction="download",
                        operation_type="relay",
                        payload_bytes=len(resp_body),
                        status="success",
                    )
            except Exception:
                pass

            return Response(
                content=resp_body,
                status_code=status_code,
                headers={k: v for k, v in resp_headers.items() if k.lower() not in hop_by_hop},
            )
        except TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Relay reverse tunnel to node '{session.target_node_id}' timed out.",
            )
        except Exception as exc:
            logger.warning("Tunnel forwarding to '%s' failed: %s. Attempting fallback...", session.target_node_id, exc)

    # 2. Fall back to direct target_endpoint forwarding (for LAN or local development)
    try:
        # Honour TLS settings from Coordinator configuration instead of unconditionally
        # disabling certificate verification. Unverified TLS would let a MITM intercept
        # or tamper with ciphertext in transit even though the relay is meant to be zero-knowledge.
        # Storage Nodes on HTTP (LAN/localhost) are unaffected; HTTPS endpoints are properly verified.
        _verify_tls: bool = not target_url.startswith("http://")
        async with httpx.AsyncClient(timeout=30.0, verify=_verify_tls) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=fwd_headers,
                content=body,
            )

            # Prepare response headers
            resp_headers = {
                k: v for k, v in resp.headers.items()
                if k.lower() not in hop_by_hop
            }

            resp_content = resp.content
            session.bytes_relayed += len(resp_content)

            # Phase 7A: Record verified transfer in MeteringService
            try:
                from coordinator.app.main import get_metering_service_from_state
                metering = get_metering_service_from_state(request.app.state)
                if request.method.upper() in ("POST", "PUT") and 200 <= resp.status_code < 300:
                    metering.record_transfer_event(
                        node_id=session.target_node_id,
                        direction="upload",
                        operation_type="relay",
                        payload_bytes=len(body),
                        status="success",
                    )
                elif request.method.upper() == "GET" and 200 <= resp.status_code < 300:
                    metering.record_transfer_event(
                        node_id=session.target_node_id,
                        direction="download",
                        operation_type="relay",
                        payload_bytes=len(resp_content),
                        status="success",
                    )
            except Exception:
                pass

            return Response(
                content=resp_content,
                status_code=resp.status_code,
                headers=resp_headers,
                media_type=resp.headers.get("content-type"),
            )
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Storage Node '{session.target_node_id}' is unreachable: No active reverse relay tunnel and direct endpoint unreachable ({str(exc)}).",
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Relay gateway timed out connecting to destination node '{session.target_node_id}': {str(exc)}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Relay transfer error: {str(exc)}",
        )


@relay_router.websocket("/tunnel/{node_id}")
async def relay_tunnel_websocket(
    websocket: WebSocket,
    node_id: str,
    relay_service: RelayService = Depends(get_relay_service_ws),
) -> None:
    """
    Authenticated reverse WebSocket tunnel endpoint for Storage Nodes behind NAT.
    Enables Storage Nodes to establish an outbound connection through firewalls/NAT
    over which the Coordinator Relay proxies incoming client requests.
    """
    # get_settings_from_state reads app.state directly without requiring a Request object.
    from coordinator.app.main import get_settings_from_state
    settings = get_settings_from_state(websocket.app.state)

    # Validate authentication
    auth_token = (
        websocket.headers.get("x-auth-token")
        or websocket.query_params.get("auth_token")
        or websocket.query_params.get("token")
    )
    if not auth_token:
        auth_hdr = websocket.headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            auth_token = auth_hdr[7:].strip()

    if settings.auth_token and auth_token != settings.auth_token:
        logger.warning("Rejecting unauthorized tunnel connection for node '%s'", node_id)
        await websocket.close(code=4001, reason="Unauthorized: Invalid auth token")
        return

    # Verify node identity is registered in Coordinator NodeRegistry
    node = relay_service.registry.get_node(node_id)
    if not node:
        logger.warning("Rejecting tunnel connection for unregistered node '%s'", node_id)
        await websocket.close(code=4004, reason=f"Node '{node_id}' not found in registry")
        return

    await websocket.accept()
    tunnel = relay_service.register_tunnel(node_id, websocket)

    try:
        while True:
            frame_bytes = await websocket.receive_bytes()
            tunnel.handle_incoming_frame(frame_bytes)
    except WebSocketDisconnect:
        logger.info("Tunnel for node '%s' disconnected.", node_id)
    except Exception as exc:
        logger.warning("Tunnel error for node '%s': %s", node_id, exc)
    finally:
        relay_service.unregister_tunnel(node_id, tunnel)
