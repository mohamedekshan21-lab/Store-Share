"""
Configuration management for Expo Client.
Reads target storage node host, port, and authentication token settings.
"""

from __future__ import annotations

import os
from typing import Optional
from pydantic import BaseModel, Field


class ClientSettings(BaseModel):
    """Client configuration settings."""
    
    node_host: str = Field(
        default_factory=lambda: os.getenv("NODE_HOST", "127.0.0.1")
    )
    node_port: int = Field(
        default_factory=lambda: int(os.getenv("NODE_PORT", "8000"))
    )
    auth_token: Optional[str] = Field(
        default_factory=lambda: os.getenv("AUTH_TOKEN", os.getenv("EXPO_AUTH_TOKEN", None))
    )
    redundancy_mode: str = Field(
        default_factory=lambda: os.getenv("EXPO_REDUNDANCY_MODE", "replication")
    )
    ec_data_shards: int = Field(
        default_factory=lambda: int(os.getenv("EXPO_EC_DATA_SHARDS", "4"))
    )
    ec_parity_shards: int = Field(
        default_factory=lambda: int(os.getenv("EXPO_EC_PARITY_SHARDS", "2"))
    )
    coordinator_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("EXPO_COORDINATOR_URL", os.getenv("COORDINATOR_URL", None))
    )

    @property
    def base_url(self) -> str:
        """Returns the full HTTP base URL for the Storage Node."""
        host = self.node_host
        if host == "0.0.0.0":
            host = "127.0.0.1"
        return f"http://{host}:{self.node_port}"


def get_client_settings() -> ClientSettings:
    return ClientSettings()
