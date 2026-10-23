# Expo Distributed Storage Network

Expo is a community-driven distributed storage network where providers voluntarily contribute controlled portions of their disk storage as Storage Nodes, and consumers can store and retrieve data securely across LAN or Internet networks using client-side AES-256-GCM encryption, deterministic chunking, redundant replication with integrity-based failover, and automatic self-healing repair.

---

## Project Architecture (Phase 4B)

```text
Original Consumer File
          │
          ▼
Generate AES-256 Key (DEK) & Nonce
          │
          ▼
Client-Side Encryption (AES-256-GCM)
          │
          ▼
Deterministic Payload Chunking (Default 4 MB)
          │
          ▼
Query Coordinator & Select Storage Nodes (Target Count + Replication Factor)
          │
          ▼
Redundant Chunk Placement (Distinct Node IDs per Chunk)
          │
  ┌───────┼────────────────────────┐
  ▼       ▼                        ▼
Chunk 0: Node A (PRIMARY)  +  Node D (REPLICA)
Chunk 1: Node B (PRIMARY)  +  Node E (REPLICA)
Chunk 2: Node C (PRIMARY)  +  Node F (REPLICA)
          │
          ▼
Uploaded Copies Integrity Verification (SHA-256 Checksum)
          │
          ▼
Generate Local JSON Manifest v2 (placements[]: node_id, node_endpoint, role)
```

### Automatic Self-Healing / Repair Subsystem

```text
              ┌───────────────┐
              │  Coordinator  │
              └───────┬───────┘
                      │
           detects under-replication
                      │
                      ▼
              ┌───────────────┐
              │ Repair Engine │
              └───────┬───────┘
                      │
         encrypted chunk transfer
                      │
             ┌────────┴────────┐
             ▼                 ▼
      Healthy Source     Replacement Node
             │                 │
             └───────┬─────────┘
                     │
              SHA-256 verify
                     │
                     ▼
           Atomic metadata update
                     │
                     ▼
           Replication restored
```

> **IMPORTANT ARCHITECTURAL DIRECTIVES**:  
> 1. **THE COORDINATOR DOES NOT STORE OR PROXY USER FILE CONTENTS.**  
> 2. **PLAINTEXT FILES & ENCRYPTION KEYS NEVER LEAVE THE CONSUMER MACHINE.**  
> Repair Workers and Storage Nodes operate strictly on opaque encrypted ciphertext binary chunks. Encryption keys (DEK/KEK) and plaintext are never transmitted or held by the repair worker.
> 3. **DISTINCT PHYSICAL NODE PLACEMENT**: Replicas MUST be assigned to distinct Storage Node IDs from existing healthy placements.
> 4. **ATOMIC METADATA COMMIT**: Manifest placements are only updated after the replacement copy passes destination SHA-256 verification and readability checks.
> 5. **PER-CHUNK REPAIR LOCKING & IDEMPOTENCY**: Bounded concurrent repair workers execute safely with chunk-level locking and persistent SQLite job history.

---

## Subsystems Overview

- **`backend/`**: Dedicated backend orchestration and startup module (`run_backend.py`, `run_coordinator.py`, `run_storage_node.py`), environment configurations, and dependency definitions (`requirements.txt`).
- **`frontend/`**: Standalone web application portal (`index.html`, `dashboard.css`, `dashboard.js`), native Node.js proxy server (`server.js`), and scripts (`package.json`).
- **`client/` (Phases 1B, 2B, 3A, 3B, 3C, 4A, 4B)**: Expo Remote Client library (`ExpoClient`), CLI tool (`python -m client.cli`), client-side AES-256-GCM encryption engine (`client/crypto.py`), deterministic payload chunker & Schema v2 manifest manager (`client/chunker.py`), multi-node selection, reachability probing, & redundant placement engine (`client/placement.py`), and Repair Engine & Job Store (`client/repair.py`).
- **`coordinator/` (Phases 2A, 2B, 3B, 3C, 4A, 4B, 10A-10F)**: Coordinator service, Node Registry database (`coordinator_metadata.db`), liveness heartbeats, offline detection, HTTPS/TLS support, connectivity modes (`LAN`, `DIRECT`, `RELAY`, `UNKNOWN`), node diagnostic connectivity endpoint (`GET /nodes/{node_id}/connectivity`), smart multi-node selection (`GET /nodes/select`), persistent Repair Job API (`GET/POST /repair/jobs`), session & token authentication, quota management, and account management.
- **`storage_node/` (Phases 1A, 1B, 2A, 2B, 3C, 10A-10F)**: Independent Storage Node daemon, sandbox isolation, quota enforcement, SQLite file metadata, persistent node identity (`NODE-<UUID4>`), public reachability endpoint (`GET /health`), advertised endpoint separation (`ADVERTISED_ENDPOINT`), SHA-256 integrity verification, HTTPS/TLS support, and auto-reconnecting Coordinator keepalives.

---

## Running the Application

### Option A: Run Backend & Frontend Concurrently (Recommended)

1. **Start the Backend Services (Coordinator on Port 8000 + Storage Node on Port 8001):**
   ```powershell
   python backend/run_backend.py
   ```
   Or run individually:
   ```powershell
   python backend/run_coordinator.py
   python backend/run_storage_node.py
   ```

2. **Start the Frontend Web Application (Port 3000):**
   ```powershell
   cd frontend
   npm start
   ```
   Access the UI at: **`http://localhost:3000/`** (transparently proxies API traffic to Coordinator on port 8000).

---

## Quick Command Reference

### 1. Run Automated Test Suite (463 Passing Tests)
```powershell
cd d:\expo
pytest
```

### 2. Check Self-Healing / Repair Job Status (Phase 4B)
```powershell
python -m client.cli repair-status --coordinator-url http://127.0.0.1:8000
```

### 3. Repair File Manifest / Under-Replicated Chunk (Phase 4B)
```powershell
python -m client.cli repair-file manifest.json --coordinator-url http://127.0.0.1:8000
python -m client.cli repair-chunk manifest.json <chunk_id> --coordinator-url http://127.0.0.1:8000
```

### 4. Multi-Node Replicated Encrypt & Upload (Phase 4A)
```powershell
python -m client.cli encrypt-upload sample_document.pdf --key-out my_key.hex --manifest-out manifest.json --nodes 3 --replication-factor 2 --coordinator-url http://127.0.0.1:8000
```

### 5. Automatic Download & Integrity Failover (Phase 4A)
```powershell
python -m client.cli download-decrypt manifest.json my_key.hex recovered_document.pdf --coordinator-url http://127.0.0.1:8000
```

### 6. Node Reachability Diagnostic (Phase 3C)
```powershell
python -m client.cli check-node NODE-A --coordinator-url http://127.0.0.1:8000
python -m client.cli check-nodes --coordinator-url http://127.0.0.1:8000
```

### 7. Query Registered Nodes & Smart Node Selection (Phase 2B)
```powershell
python -m client.cli nodes --coordinator-url http://127.0.0.1:8000 --status online
python -m client.cli select-node --coordinator-url http://127.0.0.1:8000 --min-bytes 1073741824
```

For detailed subsystem documentation:
- [backend/README.md](file:///d:/expo/backend/README.md)
- [frontend/README.md](file:///d:/expo/frontend/README.md)
- [coordinator/README.md](file:///d:/expo/coordinator/README.md)
- [storage_node/README.md](file:///d:/expo/storage_node/README.md)



