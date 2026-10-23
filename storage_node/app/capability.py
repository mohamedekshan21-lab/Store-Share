"""
Expo Phase 10B: Per-Chunk Capability Security Subsystem.
Implements cryptographically signed, narrowly scoped, short-lived HMAC-SHA-256 capability tokens
for Storage Node chunk operations (upload, download, delete).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from fastapi import Request


class CapabilityError(Exception):
    """Base exception for capability token validation failures."""
    pass


class InvalidCapabilitySignatureError(CapabilityError):
    """Raised when capability HMAC signature does not match."""
    pass


class ExpiredCapabilityError(CapabilityError):
    """Raised when capability token expiration time has passed."""
    pass


class ScopeMismatchCapabilityError(CapabilityError):
    """Raised when capability token claims do not authorize the requested node, chunk, or operation."""
    pass


class MalformedCapabilityError(CapabilityError):
    """Raised when capability token format or payload is invalid."""
    pass


@dataclass
class CapabilityToken:
    """Decoded and verified capability token claims."""
    jti: str
    node_id: str
    chunk_id: str
    op: str
    account_id: str
    exp: int
    iat: int
    expected_size: Optional[int] = None
    expected_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "jti": self.jti,
            "node_id": self.node_id,
            "chunk_id": self.chunk_id,
            "op": self.op,
            "account_id": self.account_id,
            "exp": self.exp,
            "iat": self.iat,
        }
        if self.expected_size is not None:
            d["expected_size"] = self.expected_size
        if self.expected_sha256 is not None:
            d["expected_sha256"] = self.expected_sha256
        return d


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def create_capability(
    secret: str,
    node_id: str,
    chunk_id: str,
    op: str,
    account_id: str = "system",
    ttl_seconds: int = 300,
    expected_size: Optional[int] = None,
    expected_sha256: Optional[str] = None,
    token_id: Optional[str] = None,
) -> str:
    """
    Creates an HMAC-SHA-256 signed capability token for a specific Storage Node operation.
    Format: v1.<payload_b64url>.<signature_b64url>
    """
    if not secret:
        raise ValueError("Capability signing secret must not be empty.")
    if op not in ("upload", "download", "delete"):
        raise ValueError(f"Invalid capability operation '{op}'. Must be 'upload', 'download', or 'delete'.")
    if not node_id:
        raise ValueError("node_id is required for capability token.")
    if not chunk_id:
        raise ValueError("chunk_id is required for capability token.")

    now = int(time.time())
    jti = token_id or str(uuid.uuid4())
    exp = now + int(ttl_seconds)

    payload: Dict[str, Any] = {
        "jti": jti,
        "node_id": node_id.strip(),
        "chunk_id": chunk_id.strip(),
        "op": op.strip().lower(),
        "account_id": account_id.strip(),
        "iat": now,
        "exp": exp,
    }
    if expected_size is not None:
        payload["expected_size"] = int(expected_size)
    if expected_sha256 is not None:
        payload["expected_sha256"] = expected_sha256.strip().lower()

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)

    mac = hmac.new(secret.encode("utf-8"), payload_json, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(mac)

    return f"v1.{payload_b64}.{sig_b64}"


def verify_capability(
    token_str: str,
    secret: str,
    expected_node_id: Optional[str] = None,
    expected_chunk_id: Optional[str] = None,
    expected_op: Optional[str] = None,
    current_time: Optional[float] = None,
) -> CapabilityToken:
    """
    Validates HMAC-SHA-256 signature, expiration, node scope, chunk scope, and operation.
    Constant-time comparison is used for signature checking.
    """
    if not secret:
        raise InvalidCapabilitySignatureError("Storage node capability secret is not configured.")
    if not token_str or not isinstance(token_str, str):
        raise MalformedCapabilityError("Missing or invalid capability token string.")

    token_str = token_str.strip()
    parts = token_str.split(".")
    if len(parts) != 3 or parts[0] != "v1":
        raise MalformedCapabilityError("Invalid capability token format; must be 'v1.<payload>.<sig>'.")

    _, payload_b64, sig_b64 = parts

    try:
        payload_bytes = _b64url_decode(payload_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as exc:
        raise MalformedCapabilityError(f"Base64 decoding failed for capability token: {exc}") from exc

    # 1. Constant-time HMAC verification
    expected_mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, sig_bytes):
        raise InvalidCapabilitySignatureError("Capability signature verification failed: invalid token signature.")

    # 2. Parse JSON claims
    try:
        data = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise MalformedCapabilityError(f"Failed to parse capability payload JSON: {exc}") from exc

    for req_field in ("jti", "node_id", "chunk_id", "op", "exp", "iat"):
        if req_field not in data:
            raise MalformedCapabilityError(f"Missing required claim '{req_field}' in capability token.")

    now = int(current_time if current_time is not None else time.time())

    # 3. Expiration validation
    exp = int(data["exp"])
    if now > exp:
        raise ExpiredCapabilityError(
            f"Capability token expired at {exp} (current time {now}, expired by {now - exp} seconds)."
        )

    # 4. Operation check
    token_op = str(data["op"]).lower()
    if expected_op and token_op != expected_op.lower():
        raise ScopeMismatchCapabilityError(
            f"Capability operation mismatch: token authorizes '{token_op}', but '{expected_op}' was requested."
        )

    # 5. Node scope check
    token_node = str(data["node_id"])
    if expected_node_id and token_node != "*" and token_node != expected_node_id:
        raise ScopeMismatchCapabilityError(
            f"Capability node mismatch: token is bound to node '{token_node}', but requested node is '{expected_node_id}'."
        )

    # 6. Chunk scope check
    token_chunk = str(data["chunk_id"])
    if expected_chunk_id and token_chunk != expected_chunk_id:
        raise ScopeMismatchCapabilityError(
            f"Capability chunk mismatch: token is bound to chunk '{token_chunk}', but requested chunk is '{expected_chunk_id}'."
        )

    return CapabilityToken(
        jti=str(data["jti"]),
        node_id=token_node,
        chunk_id=token_chunk,
        op=token_op,
        account_id=str(data.get("account_id", "system")),
        exp=exp,
        iat=int(data["iat"]),
        expected_size=data.get("expected_size"),
        expected_sha256=data.get("expected_sha256"),
    )


def extract_capability_from_request(
    request: Request,
    x_capability_token: Optional[str] = None,
    authorization: Optional[str] = None,
    cap_query: Optional[str] = None,
) -> Optional[str]:
    """Extracts capability token string from headers or query parameters."""
    if x_capability_token and x_capability_token.strip():
        return x_capability_token.strip()

    req_cap = request.headers.get("X-Capability-Token")
    if req_cap and req_cap.strip():
        return req_cap.strip()

    auth = authorization or request.headers.get("Authorization")
    if auth:
        auth_clean = auth.strip()
        if auth_clean.lower().startswith("bearer "):
            token = auth_clean[7:].strip()
            if token.startswith("v1."):
                return token
        elif auth_clean.lower().startswith("capability "):
            return auth_clean[11:].strip()

    q_cap = cap_query or request.query_params.get("cap")
    if q_cap and q_cap.strip():
        return q_cap.strip()

    return None
