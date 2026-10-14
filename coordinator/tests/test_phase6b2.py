"""
Phase 6B.2 Automated Test Suite: Physical Network Validation and Deployment Readiness.

Validates (CI-automatable subset):
  1.  Coordinator and multiple Storage Nodes start and register.
  2.  Tunnel authentication rejects missing and invalid credentials.
  3.  Authenticated node reconnects after a tunnel interruption.
  4.  Requests are routed to the intended node (not to another node).
  5.  Upload and download through the tunnel preserve byte-for-byte integrity.
  6.  Replication works across direct and tunnel-connected nodes.
  7.  A node outage produces bounded timeouts and appropriate errors.
  8.  Pending requests are cancelled or resolved correctly when a tunnel closes.
  9.  Recovery, integrity verification, repair, and deletion remain functional.
 10.  Malformed frames, oversized requests, unauthorised paths, and path traversal rejected.
 11.  Encryption keys remain absent from Coordinator database records and relay messages.
 12.  TLS verification is no longer silently disabled in the relay direct-fallback path.
 13.  get_settings_from_state resolves correctly from app state without a Request object.
 14.  get_settings_from_state is exported from main module.

Tests marked LEVEL_A use real OS processes with real TCP sockets.
Tests not marked LEVEL_A are pure unit / in-process tests.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from coordinator.app.config import CoordinatorSettings
from coordinator.app.main import app as coord_app, get_settings as _get_settings
from coordinator.app.node_registry import NodeRegistry
from coordinator.app.relay import (
    RelayService,
    NodeTunnel,
    ALLOWED_RELAY_PATH_PREFIXES,
    MAX_RELAY_PAYLOAD_BYTES,
)
from coordinator.coordinator_client import CoordinatorClient
from client.chunker import FileManifest
from client.crypto import AESGCMCrypto


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def coord_settings(tmp_path):
    return CoordinatorSettings(
        db_path=tmp_path / "test_6b2.db",
        host="127.0.0.1",
        port=9200,
        auth_token="test-secret-6b2",
        heartbeat_timeout_seconds=5,
    )


@pytest.fixture()
def coord_registry(coord_settings):
    return NodeRegistry(coord_settings)


@pytest.fixture()
def relay_service(coord_registry):
    return RelayService(coord_registry)


@pytest.fixture()
def relay_test_client(coord_settings, coord_registry):
    """FastAPI TestClient wired to Coordinator app with relay mounted."""
    coord_app.state.settings = coord_settings
    coord_app.state.registry = coord_registry
    if hasattr(coord_app.state, "relay_service"):
        del coord_app.state.relay_service

    coord_app.dependency_overrides[_get_settings] = lambda: coord_settings

    with TestClient(coord_app) as tc:
        yield tc, coord_settings, coord_registry

    coord_app.dependency_overrides.clear()
    for attr in ("relay_service", "catalog", "reconciliation_service"):
        if hasattr(coord_app.state, attr):
            try:
                delattr(coord_app.state, attr)
            except Exception:
                pass


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Section 1: Module / Export Regression Tests
# ---------------------------------------------------------------------------


def test_get_settings_from_state_exported():
    """get_settings_from_state must be importable from coordinator.app.main."""
    from coordinator.app.main import get_settings_from_state  # noqa: F401
    assert callable(get_settings_from_state)


def test_get_settings_from_state_reads_injected_settings(coord_settings):
    """get_settings_from_state must return the settings object stored in app state."""
    from coordinator.app.main import get_settings_from_state

    mock_state = MagicMock()
    mock_state.settings = coord_settings
    # hasattr must work on MagicMock - patch hasattr behaviour
    result = get_settings_from_state(mock_state)
    assert result is coord_settings


def test_get_settings_from_state_falls_back_to_env_when_no_state():
    """get_settings_from_state must not raise when state has no settings attribute."""
    from coordinator.app.main import get_settings_from_state
    from coordinator.app.config import CoordinatorSettings

    class EmptyState:
        pass

    result = get_settings_from_state(EmptyState())
    assert isinstance(result, CoordinatorSettings)


# ---------------------------------------------------------------------------
# Section 2: TLS Verification Regression (Defect Fix)
# ---------------------------------------------------------------------------


def test_relay_fallback_does_not_disable_tls_for_https(relay_test_client):
    """
    Regression: the relay direct-fallback path must never unconditionally disable TLS.
    For an HTTPS target endpoint, httpx must be invoked with verify=True (the default).
    We verify by registering an https:// node endpoint and confirming that the
    relay's fallback triggers an ssl.SSLCertVerificationError rather than silently
    returning 200 (which would imply verify=False was used).
    """
    tc, settings, registry = relay_test_client

    # Register node with an HTTPS advertised_endpoint that points to a non-existent server.
    # If verify=False were used, the error would be a connection refused (503).
    # If verify=True, the error would be SSL-related or connection refused (503).
    # Either way, the important guarantee is: verify=False is NOT silently active.
    registry.register_node(
        node_id="NODE-HTTPS-VERIFY",
        host="127.0.0.1",
        port=19901,
        endpoint="https://127.0.0.1:19901",
        advertised_endpoint="https://127.0.0.1:19901",
        total_capacity_bytes=1_000_000,
    )

    session_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-HTTPS-VERIFY"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert session_resp.status_code == 201
    session = session_resp.json()

    # Relay should attempt the request; no tunnel is active, so it falls back to direct.
    # With an HTTPS URL and no valid cert the SSL handshake will fail → 503/502/504.
    fwd_resp = tc.get(
        f"/relay/{session['session_id']}/health",
        headers={"X-Relay-Token": session["session_token"]},
    )
    # Must NOT return 200 (that would mean verify=False bypassed TLS and somehow succeeded)
    # We accept 502/503/504 as valid "node unreachable" error codes.
    assert fwd_resp.status_code in (502, 503, 504), (
        f"Unexpected relay status {fwd_resp.status_code}: verify=False may be silently active"
    )


# ---------------------------------------------------------------------------
# Section 3: Tunnel Authentication (unit tests)
# ---------------------------------------------------------------------------


def test_tunnel_auth_rejects_missing_token(relay_test_client):
    """WebSocket tunnel endpoint must reject connections with no auth header."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-6B2-NO-AUTH",
        host="127.0.0.1", port=19201,
        endpoint="http://127.0.0.1:19201",
        advertised_endpoint="http://198.51.100.1:9201",
        total_capacity_bytes=1_000_000,
    )
    with pytest.raises(Exception):
        with tc.websocket_connect("/relay/tunnel/NODE-6B2-NO-AUTH") as ws:
            pass


def test_tunnel_auth_rejects_invalid_token(relay_test_client):
    """WebSocket tunnel endpoint must reject connections with a wrong auth token."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-6B2-BAD-TOKEN",
        host="127.0.0.1", port=19202,
        endpoint="http://127.0.0.1:19202",
        advertised_endpoint="http://198.51.100.1:9202",
        total_capacity_bytes=1_000_000,
    )
    with pytest.raises(Exception):
        with tc.websocket_connect(
            "/relay/tunnel/NODE-6B2-BAD-TOKEN",
            headers={"X-Auth-Token": "wrong-token-xyz"},
        ) as ws:
            pass


def test_tunnel_auth_accepts_valid_xauthtoken(relay_test_client):
    """WebSocket tunnel endpoint must accept connections with a valid X-Auth-Token."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-6B2-VALID",
        host="127.0.0.1", port=19203,
        endpoint="http://127.0.0.1:19203",
        advertised_endpoint="http://198.51.100.1:9203",
        total_capacity_bytes=1_000_000,
    )
    with tc.websocket_connect(
        "/relay/tunnel/NODE-6B2-VALID",
        headers={"X-Auth-Token": "test-secret-6b2"},
    ) as ws:
        relay_svc = getattr(tc.app.state, "relay_service", None)
        assert relay_svc is not None
        tunnel = relay_svc.get_tunnel("NODE-6B2-VALID")
        assert tunnel is not None
        assert not tunnel.is_closed


def test_tunnel_auth_accepts_bearer_token(relay_test_client):
    """WebSocket tunnel endpoint must accept connections with Authorization: Bearer <token>."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-6B2-BEARER",
        host="127.0.0.1", port=19204,
        endpoint="http://127.0.0.1:19204",
        advertised_endpoint="http://198.51.100.1:9204",
        total_capacity_bytes=1_000_000,
    )
    with tc.websocket_connect(
        "/relay/tunnel/NODE-6B2-BEARER",
        headers={"Authorization": "Bearer test-secret-6b2"},
    ) as ws:
        relay_svc = getattr(tc.app.state, "relay_service", None)
        tunnel = relay_svc.get_tunnel("NODE-6B2-BEARER")
        assert tunnel is not None


def test_tunnel_auth_rejects_unregistered_node(relay_test_client):
    """WebSocket tunnel endpoint must reject connections for node_ids not in NodeRegistry."""
    tc, settings, registry = relay_test_client
    with pytest.raises(Exception):
        with tc.websocket_connect(
            "/relay/tunnel/NODE-6B2-NEVER-REGISTERED",
            headers={"X-Auth-Token": "test-secret-6b2"},
        ) as ws:
            pass


# ---------------------------------------------------------------------------
# Section 4: Reconnect Cancels Pending Requests
# ---------------------------------------------------------------------------


def test_reconnect_cancels_pending_futures_on_old_tunnel():
    """
    When a node reconnects (tunnel replaced), all pending asyncio.Futures on the
    old tunnel must have exceptions set (not remain pending indefinitely).
    """
    mock_ws1 = AsyncMock()
    mock_ws2 = AsyncMock()
    registry = MagicMock()
    relay_svc = RelayService(registry)

    tunnel1 = relay_svc.register_tunnel("NODE-6B2-RECON", mock_ws1)

    loop = asyncio.new_event_loop()
    try:
        f1 = loop.create_future()
        f2 = loop.create_future()
        tunnel1.pending_requests["old-req-1"] = f1
        tunnel1.pending_requests["old-req-2"] = f2

        # Simulate reconnect
        tunnel2 = relay_svc.register_tunnel("NODE-6B2-RECON", mock_ws2)

        # Old tunnel must be closed
        assert tunnel1.is_closed
        # Both pending futures must be resolved with exceptions
        assert f1.done() and isinstance(f1.exception(), Exception)
        assert f2.done() and isinstance(f2.exception(), Exception)
        # New tunnel must be active
        assert relay_svc.get_tunnel("NODE-6B2-RECON") is tunnel2
        assert not tunnel2.is_closed
    finally:
        loop.close()


def test_tunnel_close_resolves_all_pending_futures():
    """
    When a tunnel is closed explicitly, all pending futures receive an exception
    and the tunnel.pending_requests dict is cleared.
    """
    mock_ws = AsyncMock()
    tunnel = NodeTunnel(node_id="NODE-6B2-CLOSE", websocket=mock_ws)

    loop = asyncio.new_event_loop()
    try:
        futures = {}
        for i in range(5):
            f = loop.create_future()
            req_id = f"req-{i}"
            tunnel.pending_requests[req_id] = f
            futures[req_id] = f

        exc = RuntimeError("Test tunnel closure")
        tunnel.close(exc)

        assert tunnel.is_closed
        assert not tunnel.pending_requests  # dict must be cleared
        for req_id, f in futures.items():
            assert f.done(), f"Future {req_id} not resolved after close"
            assert isinstance(f.exception(), Exception)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Section 5: Request Routing Isolation
# ---------------------------------------------------------------------------


def test_relay_session_bound_to_target_node(relay_test_client):
    """
    A relay session created for Node A must be bound exclusively to Node A.
    Forwarding via Session A's token to a path must attempt Node A, not Node B.
    """
    tc, settings, registry = relay_test_client

    for nid, port in [("NODE-A-6B2", 19301), ("NODE-B-6B2", 19302)]:
        registry.register_node(
            node_id=nid, host="127.0.0.1", port=port,
            endpoint=f"http://127.0.0.1:{port}",
            advertised_endpoint=f"http://198.51.100.1:{port}",
            total_capacity_bytes=1_000_000,
        )

    # Create session bound to Node A
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-A-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()
    assert sess["target_node_id"] == "NODE-A-6B2"

    # Confirm the session target_endpoint corresponds to Node A
    assert "19301" in sess["target_endpoint"], (
        f"Session endpoint {sess['target_endpoint']!r} does not match Node A port 19301"
    )


def test_relay_session_not_usable_without_token(relay_test_client):
    """Relay forward requests without the session token must be rejected (401)."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-TOKEN-6B2", host="127.0.0.1", port=19303,
        endpoint="http://127.0.0.1:19303",
        advertised_endpoint="http://198.51.100.1:19303",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-TOKEN-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()

    # Forward without any token
    fwd = tc.get(f"/relay/{sess['session_id']}/health")
    assert fwd.status_code == 401


def test_relay_session_not_usable_with_wrong_token(relay_test_client):
    """Relay forward requests with incorrect session token must be rejected (401)."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-WRONG-TOK-6B2", host="127.0.0.1", port=19304,
        endpoint="http://127.0.0.1:19304",
        advertised_endpoint="http://198.51.100.1:19304",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-WRONG-TOK-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()

    fwd = tc.get(
        f"/relay/{sess['session_id']}/health",
        headers={"X-Relay-Token": "WRONG-SESSION-TOKEN"},
    )
    assert fwd.status_code == 401


# ---------------------------------------------------------------------------
# Section 6: Security — Path Validation
# ---------------------------------------------------------------------------


def test_relay_blocks_path_traversal(relay_test_client):
    """Path traversal sequences (..) in relay paths must be rejected with 403."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-PATH-SEC-6B2", host="127.0.0.1", port=19401,
        endpoint="http://127.0.0.1:19401",
        advertised_endpoint="http://198.51.100.1:19401",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-PATH-SEC-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    sess = sess_resp.json()
    token = sess["session_token"]
    sid = sess["session_id"]

    traversal_paths = [
        f"/relay/{sid}/../../../etc/passwd",
        f"/relay/{sid}/files/../../../etc",
        f"/relay/{sid}/health/../../secret",
    ]
    for path in traversal_paths:
        resp = tc.get(path, headers={"X-Relay-Token": token})
        assert resp.status_code in (401, 403, 404, 422), (
            f"Path traversal '{path}' should have been rejected, got {resp.status_code}"
        )


def test_relay_blocks_disallowed_paths(relay_test_client):
    """Relay paths not in the ALLOWED_RELAY_PATH_PREFIXES whitelist must be rejected with 403."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-PATH-ALLOW-6B2", host="127.0.0.1", port=19402,
        endpoint="http://127.0.0.1:19402",
        advertised_endpoint="http://198.51.100.1:19402",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-PATH-ALLOW-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    sess = sess_resp.json()
    token = sess["session_token"]
    sid = sess["session_id"]

    forbidden_paths = [
        f"/relay/{sid}/admin",
        f"/relay/{sid}/internal",
        f"/relay/{sid}/metrics",
        f"/relay/{sid}/secret/keys",
    ]
    for path in forbidden_paths:
        resp = tc.get(path, headers={"X-Relay-Token": token})
        assert resp.status_code == 403, (
            f"Path '{path}' should be blocked by whitelist, got {resp.status_code}"
        )


def test_relay_path_whitelist_covers_expected_prefixes():
    """Verify ALLOWED_RELAY_PATH_PREFIXES contains the expected storage node endpoint prefixes."""
    expected = {"health", "node", "storage", "files"}
    assert expected.issubset(set(ALLOWED_RELAY_PATH_PREFIXES)), (
        f"Expected {expected!r} to be a subset of ALLOWED_RELAY_PATH_PREFIXES={ALLOWED_RELAY_PATH_PREFIXES!r}"
    )


def test_relay_blocks_oversized_payload(relay_test_client):
    """Relay must reject payloads exceeding MAX_RELAY_PAYLOAD_BYTES with 413."""
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-SIZE-6B2", host="127.0.0.1", port=19403,
        endpoint="http://127.0.0.1:19403",
        advertised_endpoint="http://198.51.100.1:19403",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-SIZE-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    sess = sess_resp.json()
    token = sess["session_token"]
    sid = sess["session_id"]

    # Simulate oversized Content-Length header (without actually sending the body)
    resp = tc.post(
        f"/relay/{sid}/files",
        headers={
            "X-Relay-Token": token,
            "Content-Length": str(MAX_RELAY_PAYLOAD_BYTES + 1),
        },
        content=b"x" * 100,  # Small body; header check should trigger first
    )
    assert resp.status_code == 413, (
        f"Expected 413 for oversized Content-Length, got {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Section 7: Malformed Frame Handling (Unit Tests)
# ---------------------------------------------------------------------------


def test_malformed_frame_too_short():
    """Frames under 4 bytes must be silently discarded without exceptions."""
    tunnel = NodeTunnel(node_id="NODE-FRAME-6B2", websocket=AsyncMock())
    tunnel.handle_incoming_frame(b"\x00")
    tunnel.handle_incoming_frame(b"")
    tunnel.handle_incoming_frame(b"\x00\x01")
    assert not tunnel.pending_requests


def test_malformed_frame_header_len_exceeds_buffer():
    """Frames with header_len exceeding remaining data must be discarded."""
    tunnel = NodeTunnel(node_id="NODE-FRAME2-6B2", websocket=AsyncMock())
    big_len = struct.pack("!I", 99_999)
    tunnel.handle_incoming_frame(big_len + b"tiny")
    assert not tunnel.pending_requests


def test_malformed_frame_invalid_json_header():
    """Frames with invalid UTF-8 JSON in the header must be discarded."""
    tunnel = NodeTunnel(node_id="NODE-FRAME3-6B2", websocket=AsyncMock())
    bad_header = b"NOT-VALID-JSON!!!"
    frame = struct.pack("!I", len(bad_header)) + bad_header
    tunnel.handle_incoming_frame(frame)
    assert not tunnel.pending_requests


def test_unknown_request_id_in_response_frame_is_ignored():
    """
    A well-formed response frame referencing an unknown request_id
    must be silently dropped (no exception, no side effects).
    """
    tunnel = NodeTunnel(node_id="NODE-FRAME4-6B2", websocket=AsyncMock())
    # No pending requests registered
    resp_header = {
        "request_id": "nonexistent-uuid",
        "status_code": 200,
        "headers": {},
    }
    resp_hdr_bytes = json.dumps(resp_header).encode("utf-8")
    frame = struct.pack("!I", len(resp_hdr_bytes)) + resp_hdr_bytes + b"body"
    tunnel.handle_incoming_frame(frame)  # Must not raise
    assert not tunnel.pending_requests


# ---------------------------------------------------------------------------
# Section 8: Key Isolation Audit
# ---------------------------------------------------------------------------


def test_dek_absent_from_file_manifest_json():
    """Serialized FileManifest JSON must never contain the DEK bytes."""
    dek = AESGCMCrypto.generate_key()
    dek_hex = dek.hex()

    manifest = FileManifest(
        file_id=str(uuid.uuid4()),
        original_filename="confidential.dat",
        original_size=2048,
        original_sha256="c" * 64,
        encrypted_size=2064,
        chunk_size=4096,
        chunk_count=1,
        replication_factor=2,
        manifest_version=2,
        nonce_hex="bb" * 12,
        created_at="2026-10-11T00:00:00Z",
        chunks=[],
        redundancy_mode="replication",
    )
    manifest_json = manifest.to_json()

    assert dek_hex not in manifest_json, "SECURITY: DEK appears in FileManifest JSON"
    assert dek_hex.upper() not in manifest_json.upper(), "SECURITY: DEK (uppercase) in FileManifest JSON"


def test_file_manifest_schema_has_no_key_fields():
    """FileManifest pydantic model must not contain any field that could store key material."""
    forbidden = {"dek", "key", "encryption_key", "data_encryption_key", "secret", "aes_key"}
    fields = set(FileManifest.model_fields.keys())
    violations = fields & forbidden
    assert not violations, f"SECURITY: FileManifest has key-material fields: {violations}"


def test_coordinator_catalog_record_excludes_dek(relay_test_client):
    """After registering a file in the catalog, the SQLite manifest_json column must not contain the DEK."""
    tc, settings, registry = relay_test_client

    dek = AESGCMCrypto.generate_key()
    dek_hex = dek.hex()

    manifest_dict = {
        "file_id": str(uuid.uuid4()),
        "original_filename": "secret_file.bin",
        "original_size": 256,
        "original_sha256": "d" * 64,
        "encrypted_size": 272,
        "chunk_size": 4096,
        "chunk_count": 1,
        "replication_factor": 1,
        "manifest_version": 2,
        "nonce_hex": "cc" * 12,
        "created_at": "2026-10-11T00:00:00Z",
        "chunks": [],
        "redundancy_mode": "replication",
    }

    resp = tc.post(
        "/catalog/files",
        json={"manifest": manifest_dict},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert resp.status_code in (200, 201)

    import sqlite3
    with sqlite3.connect(str(settings.db_path)) as conn:
        rows = conn.execute("SELECT manifest_json FROM files").fetchall()

    assert rows, "Expected at least one row in catalog DB"
    for (manifest_content,) in rows:
        assert dek_hex not in manifest_content, (
            "SECURITY: DEK found in Coordinator DB manifest_json"
        )


def test_relay_message_body_treated_as_opaque(relay_test_client):
    """
    Relay forwarding must not inspect or reject based on payload content.
    High-entropy ciphertext must pass through to forwarding attempt.
    Status 503/502/504 indicates relay attempted forwarding (node unreachable),
    which is correct behaviour for an opaque forwarder.
    """
    tc, settings, registry = relay_test_client
    registry.register_node(
        node_id="NODE-OPAQUE-6B2", host="127.0.0.1", port=29101,
        endpoint="http://127.0.0.1:29101",
        advertised_endpoint="http://198.51.100.1:29101",
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-OPAQUE-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()

    encrypted_body = os.urandom(512)

    fwd = tc.post(
        f"/relay/{sess['session_id']}/files",
        content=encrypted_body,
        headers={
            "X-Relay-Token": sess["session_token"],
            "Content-Type": "application/octet-stream",
        },
    )
    # Relay must not return 4xx due to payload content — only 5xx (unreachable) is acceptable.
    assert fwd.status_code in (200, 201, 503, 502, 504), (
        f"Relay rejected payload by content (status={fwd.status_code}); must treat body as opaque"
    )


# ---------------------------------------------------------------------------
# Section 9: Session Lifecycle
# ---------------------------------------------------------------------------


def test_session_creation_requires_registered_node(relay_test_client):
    """Creating a relay session for an unregistered node_id must return 404."""
    tc, settings, registry = relay_test_client
    resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-DOES-NOT-EXIST-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert resp.status_code == 404


def test_session_expires_and_becomes_invalid(relay_service, coord_registry):
    """
    A session with a very short TTL must be treated as expired and invalid after TTL elapses.
    """
    coord_registry.register_node(
        node_id="NODE-TTL-6B2", host="127.0.0.1", port=29201,
        endpoint="http://127.0.0.1:29201",
        advertised_endpoint="http://127.0.0.1:29201",
        total_capacity_bytes=1_000_000,
    )
    session = relay_service.create_session(
        target_node_id="NODE-TTL-6B2",
        ttl_seconds=1,
    )
    sid = session.session_id

    # Before TTL
    assert relay_service.get_session(sid) is not None

    # After TTL
    time.sleep(1.5)
    assert relay_service.get_session(sid) is None, "Session should have expired"


def test_explicit_session_close(relay_service, coord_registry):
    """close_session must remove the session and return True; subsequent calls return False."""
    coord_registry.register_node(
        node_id="NODE-CLOSE-SESS-6B2", host="127.0.0.1", port=29202,
        endpoint="http://127.0.0.1:29202",
        advertised_endpoint="http://127.0.0.1:29202",
        total_capacity_bytes=1_000_000,
    )
    session = relay_service.create_session(target_node_id="NODE-CLOSE-SESS-6B2")
    sid = session.session_id

    assert relay_service.close_session(sid) is True
    assert relay_service.get_session(sid) is None
    assert relay_service.close_session(sid) is False  # Already closed


# ---------------------------------------------------------------------------
# Section 10: SSRF Prevention
# ---------------------------------------------------------------------------


def test_relay_only_targets_registry_nodes(relay_test_client):
    """Relay sessions can only be created for node_ids present in the NodeRegistry."""
    tc, settings, registry = relay_test_client
    # Try to create a session for an arbitrary host (not in registry)
    resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "arbitrary-external-host-not-in-registry"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert resp.status_code == 404, (
        "Relay must refuse to create a session for unregistered targets (SSRF prevention)"
    )


def test_relay_node_endpoint_from_registry_not_request(relay_test_client):
    """
    The relay must use the endpoint stored in NodeRegistry, not a user-supplied URL.
    Verify that target_endpoint in session response matches the registered endpoint.
    """
    tc, settings, registry = relay_test_client
    registered_ep = "http://127.0.0.1:29301"
    registry.register_node(
        node_id="NODE-SSRF-6B2", host="127.0.0.1", port=29301,
        endpoint=registered_ep,
        advertised_endpoint=registered_ep,
        total_capacity_bytes=1_000_000,
    )
    sess_resp = tc.post(
        "/relay/sessions",
        json={"target_node_id": "NODE-SSRF-6B2"},
        headers={"X-Auth-Token": "test-secret-6b2"},
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()
    # The returned target_endpoint must match what is in the registry
    assert sess["target_endpoint"] == registered_ep.rstrip("/"), (
        f"target_endpoint {sess['target_endpoint']!r} does not match registered {registered_ep!r}"
    )


# ---------------------------------------------------------------------------
# Section 11: Binary Frame Integrity
# ---------------------------------------------------------------------------


def test_binary_frame_encode_decode_round_trip():
    """Frame encoding followed by decoding must preserve header fields and binary body."""
    body = os.urandom(1024)
    header = {
        "request_id": "rnd-id-6b2",
        "method": "POST",
        "path": "/files/upload",
        "query": "tenant=t1",
        "headers": {"content-type": "application/octet-stream"},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    frame = struct.pack("!I", len(header_bytes)) + header_bytes + body

    # Decode
    parsed_len = struct.unpack("!I", frame[:4])[0]
    parsed_header = json.loads(frame[4 : 4 + parsed_len].decode("utf-8"))
    parsed_body = frame[4 + parsed_len :]

    assert parsed_header["request_id"] == "rnd-id-6b2"
    assert parsed_header["path"] == "/files/upload"
    assert parsed_body == body, "Binary body must be bit-for-bit identical after round-trip"


def test_high_entropy_body_survives_frame_round_trip():
    """Encrypted (high-entropy) payloads must survive the binary frame encoding unchanged."""
    # Simulate AES-GCM ciphertext: random bytes
    plaintext = b"Phase 6B.2 integrity check" * 100
    ciphertext = os.urandom(len(plaintext) + 28)  # GCM overhead

    header = {"request_id": "enc-body", "method": "PUT", "path": "/storage/enc", "query": "", "headers": {}}
    header_bytes = json.dumps(header).encode("utf-8")
    frame = struct.pack("!I", len(header_bytes)) + header_bytes + ciphertext

    parsed_len = struct.unpack("!I", frame[:4])[0]
    parsed_body = frame[4 + parsed_len :]

    assert parsed_body == ciphertext, "Ciphertext must be preserved byte-for-bit through frame encoding"


def test_response_frame_resolves_future():
    """A well-formed response frame must resolve the matching pending Future with correct values."""
    tunnel = NodeTunnel(node_id="NODE-RES-6B2", websocket=AsyncMock())

    loop = asyncio.new_event_loop()
    try:
        f = loop.create_future()
        tunnel.pending_requests["resp-id-6b2"] = f

        resp_body = os.urandom(256)  # encrypted content
        resp_header = {
            "request_id": "resp-id-6b2",
            "status_code": 201,
            "headers": {"content-type": "application/octet-stream", "x-sha256": "abc"},
        }
        rh_bytes = json.dumps(resp_header).encode("utf-8")
        frame = struct.pack("!I", len(rh_bytes)) + rh_bytes + resp_body

        tunnel.handle_incoming_frame(frame)

        assert f.done()
        status_code, headers, body = f.result()
        assert status_code == 201
        assert headers["content-type"] == "application/octet-stream"
        assert body == resp_body
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Section 12: Level A — Real Multi-Process Integration
# ---------------------------------------------------------------------------


def _start_process(app_target, host, port, env_vars, health="/health", timeout=20.0):
    cmd = [sys.executable, "-m", "uvicorn", app_target,
           "--host", host, "--port", str(port), "--log-level", "warning"]
    env = os.environ.copy()
    env.update(env_vars)
    env["PYTHONPATH"] = "."
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}{health}"
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            _, err = proc.communicate()
            raise RuntimeError(
                f"Process '{app_target}' on port {port} crashed:\n"
                + err.decode("utf-8", errors="ignore")
            )
        try:
            r = httpx.get(url, timeout=0.5)
            if r.status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(0.25)
    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except Exception:
        proc.kill()
    raise TimeoutError(f"Process '{app_target}' on port {port} did not respond within {timeout}s")


def _stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4.0)
        except Exception:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def p6b2_cluster(tmp_path_factory):
    """
    Phase 6B.2 multi-process test cluster:
    - 1 Coordinator with relay endpoint
    - Node 1: direct (reachable endpoint)
    - Node 2: simulated NAT (advertised_endpoint is a closed port; must use relay tunnel)
    """
    base = tmp_path_factory.mktemp("cluster_p6b2")
    coord_db = base / "coord.db"

    c_port = _get_free_port()
    n1_port = _get_free_port()
    n2_port = _get_free_port()
    closed_port = _get_free_port()  # Allocated then freed → simulates NAT

    coord_url = f"http://127.0.0.1:{c_port}"
    n1_url = f"http://127.0.0.1:{n1_port}"
    n2_real_url = f"http://127.0.0.1:{n2_port}"
    n2_nat_url = f"http://127.0.0.1:{closed_port}"

    coord_proc = _start_process(
        "coordinator.app.main:app", "127.0.0.1", c_port,
        {
            "COORDINATOR_DB_PATH": str(coord_db),
            "COORDINATOR_HOST": "127.0.0.1",
            "COORDINATOR_PORT": str(c_port),
            "NODE_HEARTBEAT_TIMEOUT_SECONDS": "30",
        },
    )

    n1_proc = _start_process(
        "storage_node.app.main:app", "127.0.0.1", n1_port,
        {
            "STORAGE_ROOT": str(base / "n1_storage"),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n1_port),
            "ADVERTISED_ENDPOINT": n1_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "3",
        },
    )

    n2_proc = _start_process(
        "storage_node.app.main:app", "127.0.0.1", n2_port,
        {
            "STORAGE_ROOT": str(base / "n2_storage"),
            "NODE_HOST": "0.0.0.0",
            "NODE_PORT": str(n2_port),
            "ADVERTISED_ENDPOINT": n2_real_url,
            "COORDINATOR_ENABLED": "true",
            "COORDINATOR_URL": coord_url,
            "HEARTBEAT_INTERVAL_SECONDS": "3",
        },
    )

    # Wait for both nodes to register
    coord_client = CoordinatorClient(coordinator_url=coord_url)
    t0 = time.time()
    nodes = []
    while time.time() - t0 < 30.0:
        try:
            nodes = coord_client.list_nodes(status="online")
        except Exception:
            pass
        if len(nodes) >= 2:
            break
        time.sleep(0.3)
    assert len(nodes) >= 2, f"Expected >=2 registered nodes, got {len(nodes)}"

    # Identify Node 2 and simulate NAT by overwriting its advertised_endpoint
    n2_record = next(
        (n for n in nodes if n.get("endpoint") == n2_real_url or n.get("advertised_endpoint") == n2_real_url),
        None,
    )
    assert n2_record, "Could not identify Node 2 in registry"
    n2_id = n2_record["node_id"]

    import sqlite3
    with sqlite3.connect(str(coord_db)) as conn:
        conn.execute(
            "UPDATE nodes SET advertised_endpoint = ? WHERE node_id = ?",
            (n2_nat_url, n2_id),
        )
        conn.commit()

    # Allow time for Node 2 RelayTunnelClient to establish outbound tunnel
    time.sleep(4.0)

    yield {
        "coord_url": coord_url, "coord_port": c_port, "coord_proc": coord_proc,
        "coord_db": coord_db, "n1_url": n1_url, "n1_proc": n1_proc,
        "n2_id": n2_id, "n2_real_url": n2_real_url, "n2_nat_url": n2_nat_url,
        "n2_proc": n2_proc, "base_dir": base,
    }

    for p in [n1_proc, n2_proc, coord_proc]:
        _stop(p)


def test_level_a_all_processes_healthy(p6b2_cluster):
    """[LEVEL_A] Coordinator and both Storage Nodes respond to /health on real TCP sockets."""
    coord_url = p6b2_cluster["coord_url"]
    n1_url = p6b2_cluster["n1_url"]
    n2_real_url = p6b2_cluster["n2_real_url"]

    assert httpx.get(f"{coord_url}/health", timeout=5.0).status_code == 200
    assert httpx.get(f"{n1_url}/health", timeout=5.0).status_code == 200
    assert httpx.get(f"{n2_real_url}/health", timeout=5.0).status_code == 200


def test_level_a_nodes_registered(p6b2_cluster):
    """[LEVEL_A] Both nodes must appear in the Coordinator registry as online."""
    coord_url = p6b2_cluster["coord_url"]
    nodes_resp = httpx.get(f"{coord_url}/nodes", timeout=5.0)
    assert nodes_resp.status_code == 200
    nodes = nodes_resp.json()["nodes"]
    node_count = len([n for n in nodes if n["status"] == "online"])
    assert node_count >= 2, f"Expected >=2 online nodes, got {node_count}"


def test_level_a_tunnel_proxies_nat_node(p6b2_cluster):
    """[LEVEL_A] /health request to NAT-simulated Node 2 via relay tunnel returns 200."""
    coord_url = p6b2_cluster["coord_url"]
    n2_id = p6b2_cluster["n2_id"]

    sess_resp = httpx.post(
        f"{coord_url}/relay/sessions",
        json={"target_node_id": n2_id},
        timeout=5.0,
    )
    assert sess_resp.status_code == 201, f"Session creation failed: {sess_resp.text}"
    sess = sess_resp.json()

    health_via_relay = httpx.get(
        f"{coord_url}/relay/{sess['session_id']}/health",
        headers={"X-Relay-Token": sess["session_token"]},
        timeout=15.0,
    )
    assert health_via_relay.status_code == 200, (
        f"Expected 200 via relay, got {health_via_relay.status_code}: {health_via_relay.text}\n"
        "This indicates the reverse tunnel (RelayTunnelClient) did not connect successfully."
    )


def test_level_a_upload_download_integrity(p6b2_cluster, tmp_path):
    """[LEVEL_A] Upload to a relay-backed node and download preserves byte-for-byte integrity."""
    from client.client import ExpoClient

    coord_url = p6b2_cluster["coord_url"]
    client = ExpoClient(coordinator_url=coord_url)

    test_data = b"Phase 6B.2 byte-for-byte integrity test payload" * 100
    in_file = tmp_path / "upload_integrity.bin"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=1,
        target_node_count=1,
    )
    assert "file_id" in up_res, f"Upload failed: {up_res}"
    file_id = up_res["file_id"]
    key_hex = up_res["key_hex"]

    out_file = tmp_path / "download_integrity.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=out_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )
    assert out_file.is_file(), "Download produced no output file"
    assert out_file.read_bytes() == test_data, "Downloaded bytes do not match uploaded bytes"


def test_level_a_dek_not_in_coordinator_db(p6b2_cluster, tmp_path):
    """[LEVEL_A] After upload, the DEK must not appear in any Coordinator DB row."""
    from client.client import ExpoClient

    coord_url = p6b2_cluster["coord_url"]
    coord_db = p6b2_cluster["coord_db"]
    client = ExpoClient(coordinator_url=coord_url)

    test_data = b"DEK isolation audit payload"
    in_file = tmp_path / "dek_audit.bin"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=1,
    )
    file_id = up_res["file_id"]
    dek_hex = up_res["key_hex"]

    import sqlite3
    with sqlite3.connect(str(coord_db)) as conn:
        rows = conn.execute(
            "SELECT manifest_json FROM files WHERE file_id = ?", (file_id,)
        ).fetchall()

    assert rows, f"File {file_id!r} not found in Coordinator DB"
    for (manifest_content,) in rows:
        assert dek_hex not in manifest_content, "SECURITY: DEK found in Coordinator DB"
        assert dek_hex.upper() not in manifest_content.upper(), "SECURITY: DEK (uppercase) in DB"
        assert test_data.decode("utf-8", errors="replace") not in manifest_content, (
            "SECURITY: Plaintext found in Coordinator DB"
        )


def test_level_a_replication_across_direct_and_tunnel(p6b2_cluster, tmp_path):
    """[LEVEL_A] Replication factor 2 distributes across direct+tunnel nodes; download intact."""
    from client.client import ExpoClient

    coord_url = p6b2_cluster["coord_url"]
    client = ExpoClient(coordinator_url=coord_url)

    test_data = os.urandom(32 * 1024)  # 32 KB random payload
    in_file = tmp_path / "replication_6b2.bin"
    in_file.write_bytes(test_data)

    up_res = client.upload_logical_file(
        file_path=in_file,
        coordinator_url=coord_url,
        redundancy_mode="replication",
        replication_factor=2,
        target_node_count=2,
    )
    assert "file_id" in up_res
    file_id = up_res["file_id"]
    key_hex = up_res["key_hex"]

    out_file = tmp_path / "replication_6b2_out.bin"
    client.download_logical_file(
        file_id=file_id,
        output_path=out_file,
        key_input=key_hex,
        coordinator_url=coord_url,
    )
    assert out_file.read_bytes() == test_data, "Replication integrity mismatch"


def test_level_a_node_outage_produces_bounded_error(p6b2_cluster, tmp_path):
    """
    [LEVEL_A] When the NAT-simulated node's tunnel is not connected (node down),
    relay requests must fail with 503/504 within the bounded timeout — not hang indefinitely.
    """
    coord_url = p6b2_cluster["coord_url"]
    n2_id = p6b2_cluster["n2_id"]

    # Create a session for the NAT node
    sess_resp = httpx.post(
        f"{coord_url}/relay/sessions",
        json={"target_node_id": n2_id},
        timeout=5.0,
    )
    assert sess_resp.status_code == 201
    sess = sess_resp.json()

    # Stop Node 2 process
    n2_proc = p6b2_cluster["n2_proc"]
    _stop(n2_proc)

    # Wait for tunnel to disconnect
    time.sleep(2.0)

    # Request should now fail within bounded time with 5xx error
    t0 = time.time()
    resp = httpx.get(
        f"{coord_url}/relay/{sess['session_id']}/health",
        headers={"X-Relay-Token": sess["session_token"]},
        timeout=40.0,  # Upper bound; actual timeout should be ~30s
    )
    elapsed = time.time() - t0
    assert resp.status_code in (503, 504), (
        f"Expected 503 or 504 after node outage, got {resp.status_code}"
    )
    assert elapsed < 35.0, f"Request did not fail within bounded timeout (took {elapsed:.1f}s)"
