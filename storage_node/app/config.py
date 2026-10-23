"""
Configuration management for Expo Storage Node (Phase 2B).
Handles storage root sandbox path, storage quota, network host/port settings,
development authentication token, Coordinator URL, TLS/HTTPS settings,
and node connectivity capability metadata.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Storage Node configuration settings."""
    
    # Path to the dedicated storage sandbox root directory
    storage_root: Path = Field(
        default_factory=lambda: Path(os.getenv("STORAGE_ROOT", "./storage")).resolve()
    )
    
    # Optional explicitly configured Node ID
    node_id: Optional[str] = Field(
        default_factory=lambda: os.getenv("NODE_ID", None)
    )

    # Optional explicitly configured Provider ID
    provider_id: Optional[str] = Field(
        default_factory=lambda: os.getenv("PROVIDER_ID", os.getenv("NODE_PROVIDER_ID", None))
    )
    
    # Configured storage quota in Gigabytes (GB)
    storage_quota_gb: float = Field(
        default_factory=lambda: float(os.getenv("STORAGE_QUOTA_GB", "10.0"))
    )

    # Network host interface (e.g. 0.0.0.0 to listen on all LAN interfaces)
    host: str = Field(
        default_factory=lambda: os.getenv("HOST", os.getenv("NODE_HOST", "0.0.0.0"))
    )

    # Network port
    port: int = Field(
        default_factory=lambda: int(os.getenv("PORT", os.getenv("NODE_PORT", "8000")))
    )

    # Optional development authentication token
    auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("AUTH_TOKEN", os.getenv("EXPO_AUTH_TOKEN", None))
    )

    # Dedicated HMAC-SHA-256 Capability Secret (Phase 10B)
    capability_secret: Optional[str] = Field(
        default_factory=lambda: os.getenv("CAPABILITY_SECRET", os.getenv("NODE_CAPABILITY_SECRET", None))
    )

    # Environment: 'development', 'testing', or 'production'
    environment: str = Field(
        default_factory=lambda: os.getenv("EXPO_ENV", os.getenv("NODE_ENV", "development")).lower()
    )

    # Coordinator integration settings (Phase 2A & 2B)
    coordinator_enabled: bool = Field(
        default_factory=lambda: os.getenv("COORDINATOR_ENABLED", "false").lower() in ("true", "1", "yes")
    )
    coordinator_host: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_HOST", None)
    )
    coordinator_port: Optional[int] = Field(
        default_factory=lambda: int(os.getenv("COORDINATOR_PORT")) if os.getenv("COORDINATOR_PORT") else None
    )
    coordinator_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_URL", None)
    )
    coordinator_auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_AUTH_TOKEN", None)
    )
    
    # Configurable heartbeat interval
    heartbeat_interval_seconds: int = Field(
        default_factory=lambda: int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "15"))
    )

    # Phase 2B Internet Connectivity & TLS Settings
    coordinator_verify_tls: bool = Field(
        default_factory=lambda: os.getenv("COORDINATOR_VERIFY_TLS", "true").lower() in ("true", "1", "yes")
    )
    coordinator_ca_cert: Optional[str] = Field(
        default_factory=lambda: os.getenv("COORDINATOR_CA_CERT", None)
    )
    advertised_endpoint: Optional[str] = Field(
        default_factory=lambda: os.getenv("ADVERTISED_ENDPOINT", os.getenv("NODE_ADVERTISED_ENDPOINT", None))
    )
    connectivity_mode: str = Field(
        default_factory=lambda: os.getenv("CONNECTIVITY_MODE", "LAN").upper()
    )
    protocol_version: str = Field(
        default_factory=lambda: os.getenv("PROTOCOL_VERSION", "3C")
    )

    @property
    def resolved_coordinator_url(self) -> Optional[str]:
        """Resolves full Coordinator base URL if configured."""
        if self.coordinator_url and self.coordinator_url.strip():
            return self.coordinator_url.strip().rstrip("/")
        if self.coordinator_host and self.coordinator_port:
            return f"http://{self.coordinator_host.strip()}:{self.coordinator_port}"
        return None

    @property
    def resolved_advertised_endpoint(self) -> str:
        """Resolves public/advertised endpoint URL for node discovery."""
        from urllib.parse import urlparse
        if self.advertised_endpoint and self.advertised_endpoint.strip():
            ep = self.advertised_endpoint.strip().rstrip("/")
            try:
                parsed = urlparse(ep)
                port = parsed.port
                hostname = parsed.hostname
            except ValueError as exc:
                raise ValueError(f"Invalid advertised endpoint '{ep}': {exc}") from exc
            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError(f"Invalid advertised endpoint scheme (must be http/https): {ep}")
            if not parsed.netloc or not hostname:
                raise ValueError(f"Invalid advertised endpoint (missing host/hostname): {ep}")
            if port is not None and (port < 1 or port > 65535):
                raise ValueError(f"Invalid port in advertised endpoint '{ep}': must be between 1 and 65535.")
            return ep
        if self.port < 1 or self.port > 65535:
            raise ValueError(f"Invalid node port {self.port}: must be between 1 and 65535.")
        host_str = self.host if self.host != "0.0.0.0" else "127.0.0.1"
        return f"http://{host_str}:{self.port}"

    @property
    def storage_quota_bytes(self) -> int:
        """Returns the storage quota in bytes."""
        return int(self.storage_quota_gb * 1024 * 1024 * 1024)

    @property
    def effective_capability_secret(self) -> Optional[str]:
        """Resolves capability signing secret, providing secure dev fallback in non-production."""
        if self.capability_secret and self.capability_secret.strip():
            return self.capability_secret.strip()
        if self.environment != "production":
            return "expo-dev-capability-secret-shared-key-2026!"
        return None

    def resolve_sandbox_path(self) -> Path:
        """Ensure storage_root is fully resolved and created."""
        resolved = self.storage_root.resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved


def get_settings() -> Settings:
    """Returns initialized settings instance."""
    return Settings()
