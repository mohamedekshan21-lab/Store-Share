# Expo Phase 8D.2 — Physical Validation Execution and Evidence Audit Report

**Date:** October 12, 2026  
**Status:** Completed & Regression Verified (Empirical Host & Boundary Validations Complete; Multi-Machine Hardware Scenarios Documented as NOT TESTED on Separate Physical Hosts)  
**Baseline Test Suite:** 360 Passing Tests (Phase 8C Baseline)  
**Phase 8D.2 Test Suite:** 371 Passing Tests (11 Physical/Network Boundary & Failure Recovery Acceptance Tests in `coordinator/tests/test_phase8d.py`, 0 Failures, 0 Errors, 1 Upstream Warning)  
**Full Regression Run Time:** 557.50s (0:09:17)  

---

## 1. Executive Summary

Phase 8D.2 performs a rigorous evidence audit of Expo's physical deployment readiness, corrects prior networking and topology claims, executes all feasible empirical tests on available host hardware, and validates the complete failure recovery and data durability cycle.

Key outcomes of Phase 8D.2:
1. **Network Claim Corrections**: Audited and corrected network claims:
   - Explicitly clarified that `10.10.192.10` is an **RFC 1918 Class A Private IP address**, not a public Internet address.
   - Clarified that the observed STUN reflexive address (`104.28.164.45:14987`) reflects the **Cloudflare WARP VPN tunnel egress**, not the physical campus router or ISP public NAT gateway.
   - Corrected NAT reachability claims: Full Cone, Address-Restricted Cone, and Port-Restricted Cone NAT can support direct peer connections via hole punching or port mapping; it is specifically **Symmetric NAT** and ingress-blocking firewalls/VPN tunnels that necessitate reverse WebSocket relay fallback.
   - Confirmed that relay success is evidenced by active `NodeTunnel` WebSocket framing and incremented `bytes_relayed` counters, not inferred from transfer success alone.
   - Explicitly distinguished multi-process loopback tests from true physical multi-machine deployments.
2. **Task 4 Durability & Safety Gate Verification**: Added and verified an end-to-end durability acceptance test (`test_task4_durability_interrupted_transfer_and_safety_gate`):
   - Proved transfer interruption handling.
   - Proved the `/provider/nodes/{id}/drain/complete` safety gate returns `409 Conflict` until migrations are verified.
   - Proved storage node and coordinator restart recovery (`recover_in_flight_migrations()`).
   - Proved byte-for-byte SHA-256 integrity after recovery.
   - Proved strict source data preservation (zero deletion).
3. **Regression Suite**: Ran the full test suite (`python -m pytest coordinator/tests/ storage_node/tests/ -q`), achieving **371 passed, 1 warning, 0 failures** in 557.50s.
4. **Hardware Scope Declaration**: With only workstation `Ekshan-MSI` available, physical multi-machine LAN and separate WAN deployments are truthfully marked **NOT TESTED on distinct physical hardware** with copy-pasteable reproduction instructions provided.

---

## 2. Hardware and Network Environment Audit

### 2.1 Host Configuration

| Attribute | Observed Host Value | Network Scope & Classification |
|---|---|---|
| **Host Name** | `Ekshan-MSI` | Primary physical host executing validation |
| **Operating System** | Windows 11 / Windows NT 10.0 | Developer workstation |
| **Primary Wi-Fi Interface** | `10.10.193.27` (`psgitech.edu`) | Physical Intel(R) Wi-Fi 6E AX211 160MHz (RFC 1918 Private Subnet `/20`) |
| **Local Gateway Router** | `10.10.192.10` (MAC: `a8-c6-47-41-20-00`) | **RFC 1918 Private IPv4 Gateway** (`10.0.0.0/8`), local router on `10.10.192.0/20` |
| **Virtual Tunnel Interface** | `172.16.0.2` | Cloudflare WARP virtual network adapter |
| **STUN Observed IP** | `104.28.164.45` | **Cloudflare WARP Anycast VPN Egress IP** (AS13335), NOT physical router external NAT |
| **Python Environment** | Python 3.12.4 | Active interpreter |

### 2.2 Network Boundary & ARP Audit

```text
Interface: 10.10.193.27 (Local Subnet: 10.10.192.0/20, Broadcast: 10.10.207.255)
  Internet Address      Physical Address      Type
  10.10.192.10          a8-c6-47-41-20-00     dynamic (Private Gateway Router)
  10.10.193.154         ac-b6-87-4d-bd-12     dynamic
```

### 2.3 Hardware Availability Constraint

Only a single physical computer (`Ekshan-MSI`) is attached and authorized under operational control. No provisioned secondary physical computers exist on this subnet with authorized SSH or deployment credentials. Therefore, in strict compliance with Phase 8D.2 requirements:
- Single-host empirical socket tests, UDP STUN queries, and multi-process relay tests were executed directly on this host.
- Multi-machine physical LAN testing (Task 2) and separate-network WAN testing (Task 3) are marked **NOT TESTED on distinct physical hardware / separate networks**, with reproduction instructions documented.

---

## 3. Network Claims Audit & Path Verification

### 3.1 Clarification on Private Gateway `10.10.192.10`
In earlier working notes, `10.10.192.10` was occasionally termed the "external gateway". We clarify:
- `10.10.192.10` belongs to the RFC 1918 Class A private address space (`10.0.0.0/8`).
- It is the local institutional default gateway on the `/20` subnet (`10.10.192.0/20`).
- It is **not** a public Internet address. Any traffic traversing `10.10.192.10` to the Internet passes through upstream institutional NAT gateways or edge firewalls before reaching the public WAN.

### 3.2 The Meaning of the Reported STUN Mapping & VPN Egress
- **Observed Result**: STUN query to `stun.l.google.com:19302` reported reflexive address `104.28.164.45:14987`.
- **Egress Path**: Because Cloudflare WARP is active on adapter `172.16.0.2`, the Windows routing table directs default route UDP packets through the WARP WireGuard tunnel.
- **Classification**: `104.28.164.45` is Cloudflare's Anycast egress address (AS13335). It is **not** the physical router's public IP address.
- **Inbound Reachability**: Cloudflare WARP drops unsolicited inbound connections from the public Internet. Advertising `104.28.164.45:14987` to peer nodes does not permit inbound connections.
- **LAN Path Independence**: Local subnet traffic targeting `10.10.192.0/20` routes directly out physical adapter `10.10.193.27`, bypassing Cloudflare WARP entirely.

### 3.3 Accuracy of NAT Direct Reachability Claims
- Earlier documentation suggested direct peer connections are impossible across any NAT boundary without relay.
- **Correction**: Full Cone NAT (1:1 mapping), Address-Restricted Cone NAT, and Port-Restricted Cone NAT *can* permit direct peer connections using standard UDP hole punching or gateway port allocation protocols (UPnP, PCP, NAT-PMP) when supported by the router.
- **Relay Necessity**: Reverse WebSocket relay is mathematically required specifically when:
  1. Nodes are behind **Symmetric NAT** (where external port mappings differ per destination endpoint).
  2. Nodes are behind Carrier-Grade NAT (CGNAT) without port-forwarding control.
  3. Nodes are behind stateful firewalls or VPN tunnels that discard all unsolicited inbound connections.

### 3.4 Evidence of Relay Usage
A file transfer alone does not prove relay usage. In Expo, relay traversal is substantiated by:
1. **Outbound Reverse WebSocket Tunnel**: Node establishes connection to `ws://coordinator/relay/tunnel/{node_id}` (`NodeTunnel` instance).
2. **Authenticated Relay Session**: Client calls `POST /relay/sessions` with `target_node_id`, obtaining a cryptographically random session token and `session_id`.
3. **Explicit Relay Route**: Client sends requests directly to `http://coordinator/relay/{session_id}/{path}`.
4. **Binary Tunnel Framing**: Traffic is encapsulated into `[4-byte uint32 header_length][UTF-8 JSON header][payload bytes]` and dispatched over the WebSocket tunnel.
5. **Session Counter Evidence**: The Coordinator updates `session.requests_count` and `session.bytes_relayed` in `RelaySessionSummary`, confirming bytes traversed the tunnel.

### 3.5 Distinction Between Multi-Process Tests and Physical Validation
Level A tests in `coordinator/tests/test_phase6b2.py` run on a single machine across multiple local processes (`127.0.0.1` on distinct dynamic ports). While they prove process isolation, socket lifecycle, binary framing, and error handling on real OS TCP sockets:
- They do **not** prove physical multi-machine communication across independent hardware.
- Real physical deployment involves multi-hop routing, physical NIC buffers, MTU fragmentation, router NAT state timeouts, and physical link drops.

---

## 4. Actual Executed Empirical Validation Scenarios

### 4.1 Scenario A: Live Internet STUN Candidate Discovery (RFC 5389 UDP)
- **Command:** `discover_external_candidate(stun_servers=[("stun.l.google.com", 19302)])`
- **Protocol:** Real UDP datagrams (`socket.AF_INET`, `socket.SOCK_DGRAM`)
- **Observed Result:**
  ```json
  {
    "status": "discovered",
    "reflexive_ip": "104.28.164.45",
    "reflexive_port": 14987,
    "stun_server": "stun.l.google.com:19302",
    "candidate_url": "http://104.28.164.45:14987"
  }
  ```
- **Fallback Verification:** Probed unroutable RFC 5737 IP `198.51.100.1:19302`. Verified that `probe_stun_server()` timed out cleanly and returned `None` without unhandled exceptions or socket leaks.

### 4.2 Scenario B: Physical LAN Interface Socket Binding
- **Command:** Real TCP socket bind to physical Wi-Fi IP `10.10.193.27`:
  ```python
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('10.10.193.27', 0))
  port = s.getsockname()[1]
  s.listen(1)
  ```
- **Observed Result:** Successfully bound listening TCP socket on `10.10.193.27:60024`. Confirmed the operating system network stack permits non-loopback physical interface listening.

### 4.3 Scenario C: Multi-Process Cluster & Real Reverse WebSocket Relay (Level A)
- **Process Topology:**
  - Coordinator started on dynamic TCP port (`http://127.0.0.1:<c_port>`).
  - Storage Node 1 started on direct reachable endpoint (`http://127.0.0.1:<n1_port>`).
  - Storage Node 2 started on localhost port (`http://127.0.0.1:<n2_port>`), with its advertised endpoint simulated as closed port (`http://127.0.0.1:<closed_port>`), forcing relay usage.
  - Node 2 established an outbound reverse WebSocket connection (`ws://127.0.0.1:<c_port>/relay/tunnel/{node_id}`).
- **Relay Session Allocation:** Client requested `POST /relay/sessions` with `target_node_id: n2_id`. Coordinator allocated a 5-minute session token.
- **Relayed HTTP Payload:** Client sent HTTP request to `GET /relay/{session_id}/health`. Coordinator packed request into binary frame (`[4-byte len][JSON header][body]`), streamed it over the reverse WebSocket tunnel, Node 2 executed locally against `http://127.0.0.1:<n2_port>/health`, returned binary response frame, and Coordinator returned HTTP 200 OK.
- **Payload Integrity:** Client uploaded 4.7 KB and 32 KB random ciphertext payloads across direct and relay-connected nodes with replication factor 2. Downloaded bytes matched source bytes bit-for-bit (exact SHA-256 match).
- **Relay Outage Timeout:** Storage Node 2 process was terminated (`_stop()`). Relayed request to `GET /relay/{session_id}/health` returned HTTP `503 Service Unavailable` / `504 Gateway Timeout` within 30 seconds, confirming bounded timeout behavior without process hangs.

---

## 5. Failure Recovery & Durability Results (Step 4 / Task 4 Matrix)

The 11 physical/network boundary and failure recovery acceptance tests in [`coordinator/tests/test_phase8d.py`](file:///d:/expo/coordinator/tests/test_phase8d.py) were executed and verified:

| # | Scenario | Test Method | Observed Outcome | Evidence & Verification |
|---|---|---|---|---|
| 1 | **Node unreachable during upload** | `test_failure_storage_node_unreachable_during_upload` | **PASSED** | Connection failure caught cleanly; `retry_count` incremented; migration marked `retryable_failure`; source chunk intact. |
| 2 | **Coordinator restart while migration pending** | `test_failure_coordinator_restart_while_migration_pending` | **PASSED** | New Coordinator instance runs `recover_in_flight_migrations()`; job processed to `completed`; destination verified. |
| 3 | **Destination unreachable during transfer** | `test_failure_destination_unreachable_during_transfer` | **PASSED** | Network timeout caught; job transitioned to `retryable_failure`; source chunk preserved without deletion. |
| 4 | **Node returns after missing heartbeats** | `test_failure_node_returns_after_missing_heartbeats` | **PASSED** | Node `last_seen` aged past timeout; status transitioned `online -> offline`; new heartbeat restored `online` status. |
| 5 | **File retrieval after replica/shard unavailable** | `test_failure_file_retrieval_when_replica_or_shard_unavailable` | **PASSED** | 1. Primary replica offline -> secondary replica serves byte-identical payload.<br>2. 4+2 EC: 1 shard offline -> reconstructed from surviving 5 shards via Reed-Solomon polynomial interpolation. |
| 6 | **Drain with insufficient replacement capacity** | `test_failure_drain_blocked_and_retry_when_capacity_added` (Part A) | **PASSED** | Solo node drain with 0 available candidate destinations transitioned to `drain_blocked` with actionable reason. |
| 7 | **Blocked drain retried after capacity added** | `test_failure_drain_blocked_and_retry_when_capacity_added` (Part B) | **PASSED** | New storage node registered; `/provider/nodes/{id}/drain/retry` unblocked job; migration succeeded; drain completed (`drained`). |
| 8 | **Destination contains corrupted test data** | `test_failure_destination_contains_corrupted_data` | **PASSED** | Destination corrupted byte hash; SHA-256 verification detected mismatch; destination rejected; manifest uncommitted. |
| 9 | **Coordinator restart during in-flight migration** | `test_failure_coordinator_restart_during_active_migration` | **PASSED** | Migration forced to `transferring`; restart executed `recover_in_flight_migrations()`; reset to `pending`; subsequent worker completed cleanly. |
| 10 | **Data and metadata consistency audit** | `test_data_and_metadata_consistency_audit` | **PASSED** | 1. Zero DEK keys in SQLite `files` or `manifest_json`.<br>2. Zero plaintext user content in SQLite.<br>3. Verified SHA-256 chunk persistence. |
| 11 | **Task 4 End-to-End Durability & Safety Gate** | `test_task4_durability_interrupted_transfer_and_safety_gate` | **PASSED** | 1. 64 KB disposable test chunk.<br>2. Interrupted transfer mid-flight -> `retryable_failure`.<br>3. Early `/drain/complete` rejected with HTTP 409 Conflict.<br>4. Coordinator & Node restart recovery.<br>5. Resumed migration -> verified destination SHA-256.<br>6. `/drain/complete` succeeded (`200 OK`, `drained`).<br>7. Downloaded chunk SHA-256 matches pre-upload bit-for-bit.<br>8. Source chunk strictly preserved on disk (zero deletion). |

---

## 6. File Checksum Evidence

All transferred files were audited for byte-for-byte fidelity:

| Test Identifier | Payload Size | Pre-Upload SHA-256 Hash | Post-Download SHA-256 Hash | Transport Used | Status |
|---|---|---|---|---|---|
| `chk-fail-1` | 39 B | `a911a37c8ee3a44d71eb54b2d6a5462fc9265f7c3e5a5a1f6a1d8213e2bb8889` | (Source chunk preserved on disk) | Direct HTTP | **VERIFIED** |
| `chk-rst-1` | 36 B | `fa1bbdf1bc945b0d061cceb37341e976db2e646247cfaee0ae69b0faee7cf7b3` | `fa1bbdf1bc945b0d061cceb37341e976db2e646247cfaee0ae69b0faee7cf7b3` | Direct HTTP | **MATCH** |
| `chk-cor-1` | 26 B | `1b1311aa8bcbb6697a5a8f42f7d5fc7c220f4f9f7a796e6a12b2e8d98d6fa7c6` | (Corrupted copy rejected; source intact) | Direct HTTP | **REJECTED** |
| `chk-mid-1` | 40 B | `e0ef2b4585311509847a8b704cff58831e79fd82c5c4d125277a25ed04a5e7f1` | `e0ef2b4585311509847a8b704cff58831e79fd82c5c4d125277a25ed04a5e7f1` | Direct HTTP | **MATCH** |
| `chk-dur-1` | 64 KB | `0be80b3d5b244d8b56f3435165d7fead1b559b1fbf4cf43d7894541bf7fb7dd1` | `0be80b3d5b244d8b56f3435165d7fead1b559b1fbf4cf43d7894541bf7fb7dd1` | Restart Recovery Transport | **MATCH** |
| `level_a_single` | 4.7 KB | `9eb8140be87610f6ab1293c66f773449339e1a80d5257321528c11eb5a6d3215` | `9eb8140be87610f6ab1293c66f773449339e1a80d5257321528c11eb5a6d3215` | Reverse WSS Relay | **MATCH** |
| `level_a_rep2` | 32 KB | `f423ab10787a27eb2a363a0279a9cc7104a37b3f9c66e2c9e7a83d9bc37f0322` | `f423ab10787a27eb2a363a0279a9cc7104a37b3f9c66e2c9e7a83d9bc37f0322` | Direct + Relay | **MATCH** |
| `ec_recon_5of6` | 600 B | `072c448102a5c9f5e27a921d7b6f8490d1964f4347781b0a1a09d3b85f269411` | `072c448102a5c9f5e27a921d7b6f8490d1964f4347781b0a1a09d3b85f269411` | Reed-Solomon | **MATCH** |

---

## 7. Regression Test Suite Execution & Warning Investigation

The full regression suite was executed across the entire repository:

```powershell
python -m pytest coordinator/tests/ storage_node/tests/ -q
```

### 7.1 Exact Test Results

```text
........................................................................ [ 19%]
........................................................................ [ 38%]
........................................................................ [ 58%]
........................................................................ [ 77%]
........................................................................ [ 97%]
...........                                                              [100%]
============================== warnings summary ===============================
C:\Users\USER\AppData\Local\Programs\Python\Python312\Lib\site-packages\starlette\formparsers.py:12
  C:\Users\USER\AppData\Local\Programs\Python\Python312\Lib\site-packages\starlette\formparsers.py:12: PendingDeprecationWarning: Please use `import python_multipart` instead.
    import multipart

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
371 passed, 1 warning in 557.50s (0:09:17)
```

- **Total Tests Passed:** 371 (11 in `coordinator/tests/test_phase8d.py`)
- **Total Tests Failed:** 0
- **Total Tests Errored:** 0
- **Total Warnings:** 1 (Reduced from 12)
- **Execution Time:** 557.50s (9m 17s)

### 7.2 Warning Investigation and Resolution Summary

1. **11 Warnings in `coordinator/tests/test_phase8b.py` (RESOLVED)**:
   - **Warning Message**: `starlette/testclient.py:488: DeprecationWarning: Setting per-request cookies=<...> is being deprecated...`
   - **Resolution**: Refactored all 11 test client calls in [`coordinator/tests/test_phase8b.py`](file:///d:/expo/coordinator/tests/test_phase8b.py) to pass explicit RFC 6265 HTTP headers: `headers={"Cookie": f"expo_session={session_id}"}`. Completely eliminated all 11 deprecation warnings.
2. **1 Upstream Starlette Warning (DOCUMENTED & UNRESOLVED)**:
   - **Warning Message**: `starlette/formparsers.py:12: PendingDeprecationWarning: Please use import python_multipart instead. import multipart`
   - **Origin**: Upstream Starlette internal import statement inside `starlette/formparsers.py`. Outside Expo application codebase; does not impact runtime behavior or data integrity.

---

## 8. Separation of Validation Evidence Categories

To guarantee engineering veracity, validation results are classified into distinct tiers:

| Tier | Environment & Topology | Scope of Claims Validated | Status & Evidence |
|---|---|---|---|
| **Tier 1: Automated Software Invariants** | In-memory, SQLite WAL, Pydantic, Reed-Solomon | Software state machines, crypto math, atomic manifest updates | **371 PASSED** (Pytest suite) |
| **Tier 2: Single-Host OS Sockets & Multi-Process** | `Ekshan-MSI` (localhost ports, physical Wi-Fi IP `10.10.193.27`) | Real OS TCP listeners, process isolation, reverse WebSocket binary framing, session allocation | **VERIFIED** (`test_phase6b2.py` & `test_phase8d.py`) |
| **Tier 3: Live Public Internet STUN** | `Ekshan-MSI` -> UDP probe to `stun.l.google.com:19302` | RFC 5389 UDP packet processing, fallback timeouts, discovery of external egress IP (`104.28.164.45`) | **VERIFIED** (`test_real_internet_stun_candidate_discovery`) |
| **Tier 4: Physical Multi-Computer LAN** | Computer A (Coordinator) + Computer B (Storage Node) on distinct physical motherboards | Cross-hardware packet flow, physical NIC buffers, physical router LAN broadcast, distinct CPU clocks | **NOT TESTED on distinct physical hardware** (Single physical host available) |
| **Tier 5: Independent WAN / Cross-ISP** | Computer A on Cloud VPS + Computer C behind residential NAT/ISP | Asymmetric routing, residential CGNAT, physical packet drops, MTU blackholes | **NOT TESTED across independent networks** (Secondary WAN infrastructure not provisioned) |

---

## 9. Scenarios NOT TESTED on Separate Hardware & Execution Instructions

The following scenarios are explicitly marked **NOT TESTED on distinct physical hardware / independent networks**:
1. **Task 2 Physical LAN Validation**: Coordinator on Computer A and Storage Node on Computer B communicating across a physical Wi-Fi/Ethernet router.
2. **Task 3 Separate-Network WAN Validation**: Coordinator on a public cloud VPS and Storage Node behind an independent home router or mobile hotspot.
3. **Physical Hardware Disconnect**: Physically disconnecting an Ethernet cable or disabling a Wi-Fi radio on a remote host during an active 50 MB file transfer.

### Reason Not Tested
The agent environment is restricted to a single physical laptop (`Ekshan-MSI`). Secondary laptops and cloud servers were not provisioned. Results are truthfully reported without simulation or fabrication.

### Reproduction Runbooks for Operators with Secondary Hardware

#### Runbook A: Physical LAN Validation (Two Computers on Same Wi-Fi/Ethernet)

**1. Computer A (Coordinator & Relay Gateway on LAN IP `<COMP_A_LAN_IP>`):**
```powershell
Set-Location -Path "D:\expo"
$env:COORDINATOR_HOST = "0.0.0.0"
$env:COORDINATOR_PORT = "9000"
$env:COORDINATOR_DB_PATH = ".\coordinator_metadata.db"
$env:COORDINATOR_AUTH_TOKEN = "<CLUSTER_SHARED_SECRET_TOKEN>"
$env:COORDINATOR_ADMIN_AUTH_TOKEN = "<ADMIN_MANAGEMENT_SECRET_TOKEN>"
$env:COORDINATOR_ALLOW_RELAY = "true"
$env:NODE_HEARTBEAT_TIMEOUT_SECONDS = "15"

# Ensure Windows Firewall allows port 9000 on Private profile
New-NetFirewallRule -DisplayName "Expo Coordinator 9000" -Direction Inbound -LocalPort 9000 -Protocol TCP -Action Allow -Profile Private

python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```

**2. Computer B (Direct Storage Node on LAN IP `<COMP_B_LAN_IP>`):**
```powershell
Set-Location -Path "D:\expo"
$env:NODE_HOST = "0.0.0.0"
$env:NODE_PORT = "9001"
$env:STORAGE_ROOT = ".\node1_data"
$env:STORAGE_QUOTA_BYTES = "10737418240"
$env:ADVERTISED_ENDPOINT = "http://<COMP_B_LAN_IP>:9001"
$env:COORDINATOR_ENABLED = "true"
$env:COORDINATOR_URL = "http://<COMP_A_LAN_IP>:9000"
$env:COORDINATOR_AUTH_TOKEN = "<CLUSTER_SHARED_SECRET_TOKEN>"
$env:HEARTBEAT_INTERVAL_SECONDS = "5"
$env:CONNECTIVITY_MODE = "LAN"

New-NetFirewallRule -DisplayName "Expo Storage Node 9001" -Direction Inbound -LocalPort 9001 -Protocol TCP -Action Allow -Profile Private

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 9001
```

**3. Verification from Client Machine:**
```powershell
# Upload disposable test file
python -m client.cli upload test_10mb.bin --coordinator http://<COMP_A_LAN_IP>:9000 --token <CLUSTER_SHARED_SECRET_TOKEN>

# Download and verify SHA-256
python -m client.cli download <FILE_ID> downloaded_10mb.bin --coordinator http://<COMP_A_LAN_IP>:9000 --token <CLUSTER_SHARED_SECRET_TOKEN>
certutil -hashfile downloaded_10mb.bin SHA256
```

---

#### Runbook B: Separate-Network WAN Validation (Storage Node Behind NAT / Mobile Hotspot)

**1. Computer C (Storage Node on Separate Network / Hotspot, Inbound Ports Blocked):**
```powershell
Set-Location -Path "D:\expo"
# Bind strictly to loopback to prevent unsolicited LAN exposure
$env:NODE_HOST = "127.0.0.1"
$env:NODE_PORT = "9002"
$env:STORAGE_ROOT = ".\node2_data"
$env:STORAGE_QUOTA_BYTES = "10737418240"
$env:ADVERTISED_ENDPOINT = "http://127.0.0.1:9002"  # Inbound blocked by NAT
$env:COORDINATOR_ENABLED = "true"
$env:COORDINATOR_URL = "http://<COMP_A_PUBLIC_IP>:9000"
$env:COORDINATOR_AUTH_TOKEN = "<CLUSTER_SHARED_SECRET_TOKEN>"
$env:HEARTBEAT_INTERVAL_SECONDS = "5"
$env:CONNECTIVITY_MODE = "RELAY"
$env:TUNNEL_AUTO_CONNECT = "true"

python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 9002
```

**2. Verify Relay Connection on Coordinator:**
```powershell
curl -H "X-Auth-Token: <CLUSTER_SHARED_SECRET_TOKEN>" http://<COMP_A_PUBLIC_IP>:9000/relay/nodes
# Expect node listed with has_tunnel: true
```

---

## 10. Unresolved Defects & Security Risk Audit

1. **Symmetric NAT & Ingress-Blocking Firewalls**:
   - RFC 5389 STUN discovery correctly discovers external reflexive mappings, but symmetric NAT gateways assign different ports per destination, and corporate/VPN firewalls discard unsolicited inbound packets.
   - **Mitigation Active**: Expo's reverse WebSocket relay (`RelayTunnelClient`) tunnels traffic reliably over standard outbound TCP/TLS connections to the Coordinator.
2. **Plaintext & Key Isolation**:
   - Audited SQLite tables (`files`, `node_drain_jobs`, `node_drain_migrations`). Confirmed zero DEK encryption keys or user plaintext strings exist in metadata.
3. **Source Deletion Constraint**:
   - Confirmed zero source chunk deletion occurs during drain migrations. Source decommissioning remains an explicit subsequent operational workflow.
4. **Production Readiness Disclaimer**:
   - Passing 371 automated regression tests proves software correctness against defined assertions, but is **not proof of production readiness** across heterogeneous physical networks. Production readiness requires completing Runbooks A and B across physical hardware and distinct ISPs.
