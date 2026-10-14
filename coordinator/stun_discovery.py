"""
STUN Candidate & NAT Discovery Module for Expo (Phase 6B).
Implements RFC 5389 / RFC 3489 STUN Binding Request protocol over UDP
to discover externally observed reflexive IP and port mappings.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("expo.stun")

# RFC 5389 Constants
STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# Default public STUN servers for fallback candidate discovery
DEFAULT_STUN_SERVERS: List[Tuple[str, int]] = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
]


def build_stun_binding_request(transaction_id: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Builds a 20-byte RFC 5389 STUN Binding Request.
    Returns tuple of (packet_bytes, transaction_id).
    """
    if transaction_id is None:
        transaction_id = os.urandom(12)
    elif len(transaction_id) != 12:
        raise ValueError("STUN Transaction ID must be exactly 12 bytes.")

    msg_type = STUN_BINDING_REQUEST
    msg_length = 0
    header = struct.pack("!HHI12s", msg_type, msg_length, STUN_MAGIC_COOKIE, transaction_id)
    return header, transaction_id


def parse_stun_response(data: bytes, expected_transaction_id: bytes) -> Optional[Tuple[str, int]]:
    """
    Parses a STUN Binding Success Response (RFC 5389 / RFC 3489).
    Returns (reflexive_ip, reflexive_port) or None if invalid.
    """
    if len(data) < 20:
        logger.debug("STUN response too short (< 20 bytes)")
        return None

    msg_type, msg_length, magic_cookie, transaction_id = struct.unpack("!HHI12s", data[:20])

    if msg_type != STUN_BINDING_RESPONSE:
        logger.debug("Received non-success STUN response type: 0x%04x", msg_type)
        return None

    if transaction_id != expected_transaction_id:
        logger.debug("STUN transaction ID mismatch")
        return None

    # Parse TLV attributes
    offset = 20
    end = min(len(data), 20 + msg_length)

    xor_mapped = None
    mapped = None

    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset+4])
        attr_data = data[offset+4 : offset+4+attr_len]
        
        # Attribute values are padded to multiples of 4 bytes
        padding = (4 - (attr_len % 4)) % 4
        offset += 4 + attr_len + padding

        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(attr_data) >= 8:
            _, family, xor_port = struct.unpack("!BBH", attr_data[:4])
            port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)
            if family == 0x01:  # IPv4
                xor_ip_bytes = attr_data[4:8]
                ip_int = struct.unpack("!I", xor_ip_bytes)[0] ^ STUN_MAGIC_COOKIE
                ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
                xor_mapped = (ip_str, port)
        elif attr_type == ATTR_MAPPED_ADDRESS and len(attr_data) >= 8:
            _, family, port = struct.unpack("!BBH", attr_data[:4])
            if family == 0x01:  # IPv4
                ip_str = socket.inet_ntoa(attr_data[4:8])
                mapped = (ip_str, port)

    return xor_mapped or mapped


def probe_stun_server(
    stun_host: str,
    stun_port: int = 19302,
    timeout: float = 2.0,
    source_port: int = 0,
) -> Optional[Tuple[str, int]]:
    """
    Sends a STUN Binding Request over UDP to discover the external reflexive (IP, Port).
    Returns (ip, port) if discovered, or None if probe timed out or failed.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        if source_port > 0:
            sock.bind(("", source_port))

        req_packet, txn_id = build_stun_binding_request()
        
        # Resolve destination
        dest_addr = (stun_host, stun_port)
        sock.sendto(req_packet, dest_addr)

        resp_data, _ = sock.recvfrom(2048)
        return parse_stun_response(resp_data, txn_id)
    except (socket.timeout, TimeoutError):
        logger.debug("STUN probe to %s:%d timed out", stun_host, stun_port)
        return None
    except Exception as exc:
        logger.debug("STUN probe error against %s:%d: %s", stun_host, stun_port, exc)
        return None
    finally:
        if sock:
            sock.close()


def discover_external_candidate(
    stun_servers: Optional[List[Tuple[str, int]]] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Attempts STUN candidate discovery against configured STUN servers.
    Returns structured discovery diagnostics.
    """
    servers = stun_servers if stun_servers is not None else DEFAULT_STUN_SERVERS
    
    for host, port in servers:
        try:
            res = probe_stun_server(stun_host=host, stun_port=port, timeout=timeout)
            if res:
                ext_ip, ext_port = res
                return {
                    "status": "discovered",
                    "reflexive_ip": ext_ip,
                    "reflexive_port": ext_port,
                    "stun_server": f"{host}:{port}",
                    "candidate_url": f"http://{ext_ip}:{ext_port}",
                }
        except Exception as exc:
            logger.debug("STUN server %s:%d probe failed: %s", host, port, exc)

    return {
        "status": "unavailable",
        "reflexive_ip": None,
        "reflexive_port": None,
        "reason": "All STUN servers unreachable or UDP blocked by local network policy",
    }
