# Expo Storage Node (Phase 2B)

> **LAN & Internet-Capable Storage Node Daemon** for the Expo Distributed Storage Network.

## Architecture Overview

```text
+------------------------------------+           Internet / LAN Network        +------------------------------------+
|             LAPTOP A               | --------------------------------------> |             LAPTOP B               |
|           (Expo Client)            |  HTTP/HTTPS Requests + Auth Header      |        (Expo Storage Node)         |
|                                    |                                         |                                    |
| - CLI (`python -m client.cli`)     | <-------------------------------------- | - FastAPI Daemon (`app.main`)       |
| - `ExpoClient` SDK (`client.py`)   |     JSON Response / Streamed File       | - Storage Sandbox (`./storage`)    |
| - SHA-256 Hash Pre-calculator      |                                         | - SQLite Metadata (`node_meta.db`) |
+------------------------------------+                                         +------------------------------------+
                                                                                  | Outbound Keepalive / Heartbeat
                                                                                  v
                                                                       +------------------------------------+
                                                                       |          EXPO COORDINATOR          |
                                                                       |     (Node Registry & Selection)    |
                                                                       +------------------------------------+
```

---

## Key Phase 2B Capabilities

1. **Persistent Stable Node ID**: `NODE-<UUID4>` stored in SQLite metadata database (`node_metadata.db`) that remains stable across server restarts and IP/endpoint changes.
2. **Outbound Coordinator Keepalive & Reconnect**: Connects outbound to `COORDINATOR_URL` (`http://` or `https://`). Automatically re-registers if Coordinator resets or network re-connects.
3. **Secure HTTPS/TLS Support**: Supports HTTPS Coordinator endpoints with configurable TLS certificate verification (`COORDINATOR_VERIFY_TLS`, `COORDINATOR_CA_CERT`).
4. **Connectivity Capability Reporting**: Advertises reachability capability mode (`LAN`, `DIRECT`, `RELAY`, `UNKNOWN`) and public advertised endpoint (`ADVERTISED_ENDPOINT`).
5. **Resilient Local Autonomy**: Coordinator failures, timeouts, or TLS errors never degrade or interrupt local storage file operations (upload, list, download, delete).

---

## Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Listening IP interface |
| `PORT` | `8000` | Listening port number |
| `STORAGE_ROOT` | `./storage` | Dedicated storage sandbox directory |
| `STORAGE_QUOTA_GB` | `10.0` | Maximum disk storage quota in GB |
| `AUTH_TOKEN` | `None` | Optional development auth token |
| `COORDINATOR_ENABLED` | `false` | Enable Coordinator registration (`true`/`false`) |
| `COORDINATOR_URL` | `None` | Target Coordinator URL (`http://` or `https://`) |
| `COORDINATOR_AUTH_TOKEN` | `None` | Auth token for Coordinator mutation requests |
| `COORDINATOR_VERIFY_TLS` | `true` | Verify TLS certificates for HTTPS Coordinator |
| `COORDINATOR_CA_CERT` | `None` | Optional custom CA certificate file path |
| `ADVERTISED_ENDPOINT` | `None` | Public/advertised endpoint URL for node discovery |
| `CONNECTIVITY_MODE` | `LAN` | Reachability mode (`LAN`, `DIRECT`, `RELAY`, `UNKNOWN`) |

---

## Run Automated Tests

```powershell
cd d:\expo
pytest
```
