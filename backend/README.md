# Expo Distributed Storage — Backend Services

This directory contains the orchestration, configuration, and runner scripts for the Expo distributed storage backend services.

## Services Architecture

The backend consists of two primary services:
1. **Coordinator Service (`coordinator/`)**:
   - Central registry, authentication, session tokens, HMAC capability signing, file catalog, account storage quotas, and administrative observability.
   - Default Port: `http://127.0.0.1:8000/`.
2. **Storage Node Daemon (`storage_node/`)**:
   - Sandboxed chunk storage daemon verifying capability tokens, storing AES-256-GCM encrypted chunks, computing SHA-256 checksums, and reporting periodic heartbeats.
   - Default Port: `http://127.0.0.1:8001/`.

## Running Backend Services

### 1. Run All Backend Services (Recommended)
From the project root or backend folder:
```bash
python backend/run_backend.py
```
This automatically launches both the Coordinator and Storage Node, validates their health, and monitors their execution.

### 2. Run Services Individually
- **Coordinator only:**
  ```bash
  python backend/run_coordinator.py
  ```
- **Storage Node only:**
  ```bash
  python backend/run_storage_node.py
  ```

## Environment Configuration

| Service | Environment Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| Coordinator | `COORDINATOR_PORT` | `8000` | Port for Coordinator API |
| Coordinator | `COORDINATOR_HOST` | `127.0.0.1` | Network interface |
| Coordinator | `COORDINATOR_DB_PATH` | `./coordinator_metadata.db` | SQLite database file |
| Coordinator | `CAPABILITY_SECRET` | `expo_test_secret_for_local_nodes_32bytes_long!` | HMAC-SHA256 capability secret |
| Storage Node | `PORT` | `8001` | Port for Storage Node daemon |
| Storage Node | `NODE_ID` | `node_local_01` | Unique node identifier |
| Storage Node | `STORAGE_ROOT` | `./storage/node_01` | Sandboxed disk storage path |
| Storage Node | `COORDINATOR_URL` | `http://127.0.0.1:8000` | Coordinator service base URL |
