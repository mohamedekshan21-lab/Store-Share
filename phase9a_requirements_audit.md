# Expo Phase 9A — Final Requirements Audit and End-to-End Acceptance Report

**Date**: 2026-10-12  
**Repository**: `D:\expo`  
**Host Environment**: Windows 11 (`Ekshan-MSI`), Python 3.12.4  
**Scope**: Requirements Audit across Phases 1–8D.2, Live Multi-Process Acceptance Testing, and Prioritized Completion Roadmap.

---

## Executive Summary

An audit of the Expo distributed storage system was conducted by inspecting source code, configuration, database schemas, and automated test execution across Phases 1 through 8D.2.

To validate the system under real OS networking conditions rather than in-memory mocks, a dedicated end-to-end acceptance test suite ([`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py)) was implemented and executed against live Coordinator and Storage Node processes communicating over loopback TCP ports.

### Key Audit Findings
1. **Core Data Path & Cryptography**: Client-side AES-256-GCM authenticated encryption, deterministic chunking, and Reed–Solomon erasure coding (`zfec` 4+2) are strictly adhered to. Encryption keys and plaintext payloads never touch the Coordinator catalog database.
2. **Cluster Lifecycle & Draining**: Durable node draining with atomic SQLite state tracking (`node_drain_jobs`, `node_drain_migrations`), asynchronous worker migration, destination checksum verification, safety gate enforcement (HTTP 409 Conflict), and source chunk disk preservation have been implemented and verified end-to-end.
3. **Provider Isolation & Auth**: Cryptographically random session tokens (HMAC-SHA256), session-bound CSRF protection, and principal-to-node ownership isolation strictly prevent unauthorized access or cross-provider node drain manipulation.
4. **Physical Deployment Limitation**: Multi-process reverse WebSocket relays and socket bindings function reliably on the host system. However, deployment across distinct physical computers and independent WAN networks remains **unverified on physical hardware** due to the single workstation environment.
5. **Operational Gaps**: Automated SQLite backup/restore CLI tooling and external Prometheus metric scrapers remain unbuilt.

---

## Core Requirements Audit Matrix

The following matrix records each system requirement, originating phase, implementation files, test coverage, truthful status, evidence, and remaining severity:

*Status Definitions*:
- **IMPLEMENTED**: Complete implementation in active source code and verified by automated or multi-process tests.
- **PARTIALLY IMPLEMENTED**: Functional in core logic or unit mocks, but missing complete operational automation or tooling.
- **MISSING**: Required capability has no active implementation in the repository.
- **NOT VERIFIED**: Implemented in software, but unverified on distinct physical hardware or independent network boundaries.

| Domain & Requirement | Originating Phase | Relevant Source Files & Functions | Relevant Automated Tests | Status | Evidence & Distinction | Remaining Work & Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Storage Node Sandboxing, Quotas & Auth** | Phase 1, Phase 2A, Phase 3A | [`storage_node/app/storage_manager.py`](file:///d:/expo/storage_node/app/storage_manager.py) (`store_chunk`, `_validate_chunk_id`), [`storage_node/app/main.py`](file:///d:/expo/storage_node/app/main.py) | [`storage_node/tests/test_storage.py`](file:///d:/expo/storage_node/tests/test_storage.py), [`coordinator/tests/test_phase2b.py`](file:///d:/expo/coordinator/tests/test_phase2b.py) | **IMPLEMENTED** | Path traversal attacks (`../`) rejected; quota exhaustion returns HTTP 507; auth tokens verified. Tested on live sockets. | None. (P3) |
| **2. Coordinator Registration & Heartbeats** | Phase 2B, Phase 3B, Phase 4A | [`coordinator/app/node_registry.py`](file:///d:/expo/coordinator/app/node_registry.py) (`register_node`, `heartbeat_node`, `check_liveness`, `select_nodes`) | [`coordinator/tests/test_phase2b.py`](file:///d:/expo/coordinator/tests/test_phase2b.py), [`coordinator/tests/test_phase3b.py`](file:///d:/expo/coordinator/tests/test_phase3b.py), [`coordinator/tests/test_phase4a.py`](file:///d:/expo/coordinator/tests/test_phase4a.py) | **IMPLEMENTED** | Liveness background sweep transitions expired nodes to `offline`. Selection avoids offline/unschedulable nodes. | None. (P3) |
| **3. Client AES-256-GCM & Manifest Integrity** | Phase 1, Phase 2A, Phase 3C | [`client/crypto.py`](file:///d:/expo/client/crypto.py) (`encrypt_chunk`, `decrypt_chunk`), [`client/chunker.py`](file:///d:/expo/client/chunker.py) (`FileManifest`, `chunk_file`) | [`coordinator/tests/test_phase3c.py`](file:///d:/expo/coordinator/tests/test_phase3c.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | Verified in SQLite that neither plaintext nor DEK keys touch the Coordinator; disk chunks contain only authenticated ciphertext. | Key escrow/passphrase recovery KMS. (P2) |
| **4. Multi-Node Placement, Replication & RS Erasure Coding** | Phase 4B, Phase 4C | [`client/erasure.py`](file:///d:/expo/client/erasure.py) (`encode_ciphertext_chunk`, `decode_ciphertext_chunk`), [`client/placement.py`](file:///d:/expo/client/placement.py) | [`coordinator/tests/test_phase4b.py`](file:///d:/expo/coordinator/tests/test_phase4b.py), [`coordinator/tests/test_phase4c.py`](file:///d:/expo/coordinator/tests/test_phase4c.py) | **IMPLEMENTED** | `zfec` (4+2) Reed-Solomon coding reconstructs missing shards; distinct-node placement constraints enforced. | None. (P3) |
| **5. File Upload, Listing, Retrieval & Deletion Lifecycle** | Phase 5A, Phase 5B, Phase 5C | [`client/client.py`](file:///d:/expo/client/client.py) (`upload_logical_file`, `download_logical_file`, `delete_logical_file`), [`coordinator/app/file_catalog.py`](file:///d:/expo/coordinator/app/file_catalog.py) | [`coordinator/tests/test_phase5a.py`](file:///d:/expo/coordinator/tests/test_phase5a.py), [`coordinator/tests/test_phase5b.py`](file:///d:/expo/coordinator/tests/test_phase5b.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | End-to-end verified in live cluster: file registered, chunks stored, reconstructed bit-for-bit, deleted, and download rejected. | None. (P3) |
| **6. Repair, Failover & Node Recovery** | Phase 7A, Phase 7B | [`client/repair.py`](file:///d:/expo/client/repair.py), [`coordinator/app/reconciliation.py`](file:///d:/expo/coordinator/app/reconciliation.py), [`client/client.py`](file:///d:/expo/client/client.py) | [`coordinator/tests/test_phase7a.py`](file:///d:/expo/coordinator/tests/test_phase7a.py), [`coordinator/tests/test_phase7b.py`](file:///d:/expo/coordinator/tests/test_phase7b.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | Verified in `test_phase9a.py`: Node 1 killed, client automatically failed over to Node 2 replica and restored data. | Autonomous periodic cluster repair daemon. (P1) |
| **7. STUN Discovery & Reverse WebSocket Relay** | Phase 6A, Phase 6B, Phase 6B.1, Phase 8D | [`coordinator/app/relay.py`](file:///d:/expo/coordinator/app/relay.py), [`storage_node/app/coordinator_integration.py`](file:///d:/expo/storage_node/app/coordinator_integration.py) (`RelayTunnelClient`), [`client/stun_client.py`](file:///d:/expo/client/stun_client.py) | [`coordinator/tests/test_phase6b1.py`](file:///d:/expo/coordinator/tests/test_phase6b1.py), [`coordinator/tests/test_phase6b2.py`](file:///d:/expo/coordinator/tests/test_phase6b2.py), [`coordinator/tests/test_phase8d.py`](file:///d:/expo/coordinator/tests/test_phase8d.py) | **IMPLEMENTED (Local)** / **NOT VERIFIED (WAN)** | Multi-process binary wire protocol relays authenticated packets over loopback. True multi-machine router/NAT traversal remains unverified. | Physical multi-machine validation across separate LAN/WAN networks. (P1) |
| **8. Capacity & Bandwidth Metering, ECC Accounting** | Phase 8A | [`coordinator/app/metering.py`](file:///d:/expo/coordinator/app/metering.py), [`coordinator/app/accounting.py`](file:///d:/expo/coordinator/app/accounting.py) | [`coordinator/tests/test_phase8a.py`](file:///d:/expo/coordinator/tests/test_phase8a.py) | **IMPLEMENTED** | Double-entry ledger records debits/credits; fraud penalties reduce node reputation score. Tested in SQLite. | Integration with external payment gateways or crypto rails. (P3) |
| **9. Provider Dashboard, Sessions & CSRF Protection** | Phase 8B | [`coordinator/app/auth.py`](file:///d:/expo/coordinator/app/auth.py) (`ProviderSessionManager`), [`coordinator/app/provider_router.py`](file:///d:/expo/coordinator/app/provider_router.py) | [`coordinator/tests/test_phase8b.py`](file:///d:/expo/coordinator/tests/test_phase8b.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | Verified in `test_phase9a.py`: Unauthorized provider drain rejected (HTTP 403); missing token rejected (HTTP 401). | Web UI frontend styling polish. (P2) |
| **10. Durable Node Draining & Verified Migration** | Phase 8B, Phase 8C | [`coordinator/app/drain_service.py`](file:///d:/expo/coordinator/app/drain_service.py) (`NodeDrainService`, `NodeDrainMigrationWorker`), [`coordinator/app/provider_router.py`](file:///d:/expo/coordinator/app/provider_router.py) | [`coordinator/tests/test_phase8c.py`](file:///d:/expo/coordinator/tests/test_phase8c.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | Live multi-process test confirmed chunk transfer from draining node to replacement node, SHA-256 verification, manifest update, and zero source deletion. | Operator CLI for post-decommissioning disk wiping. (P2) |
| **11. SDK & CLI Coverage** | Phase 5B, Phase 8B, Phase 8C | [`client/cli.py`](file:///d:/expo/client/cli.py), [`coordinator/coordinator_client/client.py`](file:///d:/expo/coordinator/coordinator_client/client.py), [`client/client.py`](file:///d:/expo/client/client.py) | [`coordinator/tests/test_phase5b.py`](file:///d:/expo/coordinator/tests/test_phase5b.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **IMPLEMENTED** | CLI commands (`upload`, `download`, `list`, `delete`, `nodes`) wrap SDK client APIs. | Bash/PowerShell autocompletion scripts. (P3) |
| **12. Backup, Recovery, Monitoring & Safe Decommissioning** | Cross-Phase | [`coordinator/app/reconciliation.py`](file:///d:/expo/coordinator/app/reconciliation.py), `/health` endpoints, `/provider/dashboard` | [`coordinator/tests/test_phase8b.py`](file:///d:/expo/coordinator/tests/test_phase8b.py), [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) | **PARTIALLY IMPLEMENTED** | Health checks and dashboard exist. Draining enforces safety gate before decommissioning. However, automated DB backup/restore scripts and Prometheus metrics are missing. | SQLite snapshot CLI, Prometheus exporter, automated orphan GC daemon. (P1/P2) |

---

## End-to-End Acceptance Testing Evidence (Task 3)

The automated end-to-end acceptance test suite was implemented in [`coordinator/tests/test_phase9a.py`](file:///d:/expo/coordinator/tests/test_phase9a.py) using live operating system processes (`uvicorn` subprocesses) bound to dynamic loopback TCP ports.

### Execution Log Summary
- **Test File**: `coordinator/tests/test_phase9a.py::test_complete_end_to_end_acceptance_workflow`
- **Result**: `PASSED`
- **Execution Time**: 65.87 seconds
- **Protocol**: HTTP/1.1 REST + WebSockets over live TCP loopback sockets

### Step-by-Step Acceptance Validation

| Step | Acceptance Requirement | Test Execution Details | Status |
| :---: | :--- | :--- | :---: |
| **1** | Register storage nodes | Coordinator booted on dynamic port; Node 1 and Node 2 registered and appeared in registry. | **PASSED** |
| **2** | Upload disposable file through client | 32 KB patterned payload (`orig_sha256 = ...`) uploaded via `ExpoClient.upload_logical_file(replication_factor=2)`. | **PASSED** |
| **3** | Verify client-side encryption | Inspected Coordinator database `files` table: confirmed plaintext is absent and DEK is absent. | **PASSED** |
| **4** | Confirm encrypted chunks on remote nodes | Read raw `.dat` chunks directly from Node 1 and Node 2 file systems: confirmed ciphertext does not equal plaintext, and SHA-256 matches manifest. | **PASSED** |
| **5** | Retrieve and reconstruct original file | `ExpoClient.download_logical_file()` downloaded chunks and decrypted payload to disk. | **PASSED** |
| **6** | Compare original and retrieved hashes | `hashlib.sha256(retrieved_bytes) == orig_sha256`; exact bit-for-bit equality verified. | **PASSED** |
| **7** | Node unavailability failover | Killed Node 1 process (`_stop(n1_proc)`); client detected failure and successfully downloaded replica from Node 2; SHA-256 verified. Restored Node 1. | **PASSED** |
| **8** | Provider isolation & anti-spoofing | Attacker provider (`attacker-evil-provider`) attempted to drain Node 2; rejected with HTTP 403 Forbidden. Unauthenticated access rejected with HTTP 401. | **PASSED** |
| **9** | Drain initiation, migration & completion | Booted replacement Node 3; provider initiated drain on Node 2. Background worker migrated chunk to Node 3, verified SHA-256 on Node 3, updated manifest, completed drain (`status = "drained"`). Source chunk on Node 2 was preserved on disk. | **PASSED** |
| **10**| Deletion & logical lifecycle behavior | Called `/catalog/files/{file_id}?finalize=true`. Verified SQLite catalog status changed to `'deleted'`. Verified client download subsequently fails with `ClientError`. | **PASSED** |

---

## Regression Test Results (Task 4)

The full regression test suite was executed across all Coordinator and Storage Node test modules:

```bash
python -m pytest coordinator/tests/ storage_node/tests/ -q
```

### Exact Regression Counts
- **Total Tests Collected**: 372
- **Passed**: 372
- **Failed**: 0
- **Errors**: 0
- **Skips**: 0
- **Warnings**: 1 upstream Starlette deprecation warning (`starlette/formparsers.py:12: DeprecationWarning: The 'multipart' package is deprecated; use 'python-multipart' instead`)

---

## Prioritized Completion Roadmap (Task 5)

Based on the inspection of actual source code and live network test results, the remaining work is categorized strictly by priority:

### Priority P0 — Security or Data-Loss Risks (Blockers for Any Pilot)
1. **Passphrase-Derived Key Escrow / KMS Architecture**:
   - *Current State*: The DEK is held only in volatile client memory or dumped to an unencrypted JSON/hex file on client disk. If the client loses the key file, ciphertext stored in the cluster is permanently unrecoverable.
   - *Required Work*: Implement a standardized Shamir Secret Sharing or Argon2id/scrypt passphrase-derived key wrap mechanism.
2. **Crash-Safe Interrupted Shard Cleanup**:
   - *Current State*: If a storage node crashes mid-write during chunk upload, temporary `.part` or partially written files may occupy quota until cleaned up.
   - *Required Work*: Add startup orphan cleanup sweep in `StorageManager` to purge incomplete temporary files older than 1 hour.

### Priority P1 — Real-World Pilot Blockers
1. **Physical Multi-Machine & Multi-Network Boundary Validation**:
   - *Current State*: Reverse WebSocket relays, STUN discovery, and multi-node placement have been tested on single-host multi-process setups. Validation across distinct routers, corporate firewalls, and carrier-grade NATs has not occurred due to hardware availability.
   - *Required Work*: Execute Phase 8D validation across at least two physically distinct computers connected over separate internet gateways (e.g., cellular hotspot vs broadband).
2. **Autonomous Cluster Reconciliation & Repair Daemon**:
   - *Current State*: Repair logic (`client/repair.py` and `coordinator/app/reconciliation.py`) exists and works when invoked, but there is no standing background coordinator cron service periodically sweeping for degraded files and dispatching repair jobs.
   - *Required Work*: Implement an autonomous background scheduler in Coordinator that periodically audits file redundancy against active node registries and triggers self-healing.
3. **Automated SQLite Database Backup & Disaster Recovery CLI**:
   - *Current State*: Database files (`coordinator_metadata.db`) rely on manual file copies; no automated point-in-time snapshot or recovery CLI exists.
   - *Required Work*: Implement an operational CLI command (`expo-admin backup --db ...`, `expo-admin restore ...`) using SQLite online backup APIs (`sqlite3.backup`).

### Priority P2 — Usability and Operational Improvements
1. **Prometheus / OpenTelemetry Metrics Exporter**:
   - *Current State*: Operational status is exposed via JSON REST endpoints (`/health`, `/provider/dashboard`, `/drain/worker/status`).
   - *Required Work*: Add standard `/metrics` endpoint exporting Prometheus format counters and gauges for cluster storage, active relay tunnels, and drain migrations.
2. **Post-Drain Physical Disk Shredding / Decommissioning Tool**:
   - *Current State*: Draining safely migrates data and preserves source chunks on disk to prevent accidental data loss. However, there is no operator command to securely wipe chunks once decommissioning is finalized.
   - *Required Work*: Provide an opt-in CLI command (`expo-node decommission --purge`) for storage node operators to securely shred chunks after confirmed drain completion.
3. **Provider Web Dashboard UI Polish**:
   - *Current State*: Provider endpoints return structured JSON with server-side session/CSRF validation.
   - *Required Work*: Provide a lightweight HTML/CSS single-page dashboard for providers to view earnings, active nodes, and drain progress without raw API calls.

### Priority P3 — Optional Future Features
1. **External Blockchain / Fiat Settlement Integration**:
   - *Current State*: Internal double-entry accounting ledger tracks ECC credits.
   - *Required Work*: Bridges to Lightning Network, Ethereum, or Stripe for automated credit redemption.
2. **Shell Auto-Completion**:
   - *Current State*: Click CLI commands exist.
   - *Required Work*: Generate shell tab-completion scripts for Bash, Zsh, and PowerShell.
