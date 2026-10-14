# Expo Phase 8D — Physical Multi-Machine & Network Boundary Validation Plan

**Document:** `phase8d_validation_plan.md`  
**Target Release:** Expo v0.8.4 (Phase 8D)  
**Author:** Antigravity AI & Expo Core Systems Engineering  
**Scope:** Multi-Machine Physical LAN/WAN Topology, NAT/Firewall Boundary Traversal, Reverse WebSocket Relay Fallback, Failure Recovery, and Durability Verification  

---

## 1. Objective and Validation Scope

The objective of Phase 8D is to prepare, specify, and execute a comprehensive physical network validation campaign for the Expo distributed storage network.

While previous phases validated cluster invariants using automated unit, integration, and process-level tests (360 tests passing in Phase 8C), automated tests alone cannot verify physical multi-machine behavior under real-world networking conditions. This validation plan specifies:
1. **Physical LAN Validation**: Independent computers communicating over a shared physical local area network.
2. **Network Boundary & NAT Validation**: Storage Nodes positioned behind stateful firewalls, symmetric NAT, or Carrier-Grade NAT (CGNAT) where inbound ports are completely blocked.
3. **Reverse WebSocket Relay Fallback**: Validating that clients seamlessly fall back to authenticated Coordinator relay sessions when direct TCP reachability fails.
4. **Physical Failure Recovery**: Hardware disconnects, packet drops, node crashes during transfer, and Coordinator restarts during background drain migrations.
5. **Data & Metadata Durability Audits**: Proof that client-side encryption keys (DEK) never leak, SHA-256 chunk checksums match after network hops, and source chunks are never deleted during drain.

---

## 2. Hardware and Network Topology Specification

### 2.1 Node Roles and Hardware Configuration

Validation supports a minimum of **two physical computers** (with an optional third computer for multi-node replication and drain migration):

| Node / Computer Role | Recommended OS | Network Location | Primary Processes | Required Resources |
|---|---|---|---|---|
| **Computer A: Coordinator & Relay Gateway** | Windows 11 / Linux (Ubuntu 22.04+) | Reachable LAN host or Cloud VPS | `coordinator.app.main:app` (FastAPI/Uvicorn), SQLite DB | 2 vCPU, 2 GB RAM, 10 GB disk |
| **Computer B: Storage Node 1 (Direct)** | Windows 11 / Linux / macOS | Same LAN as Computer A | `storage_node.app.main:app` (Direct LAN Node) | 2 vCPU, 2 GB RAM, 20 GB disk |
| **Computer C: Storage Node 2 (NAT / Firewalled)** *(Recommended)* | Windows 10/11 / Linux | Disjoint Wi-Fi hotspot / Home NAT | `storage_node.app.main:app` (Reverse WebSocket Tunnel) | 2 vCPU, 2 GB RAM, 20 GB disk |
| **Client Workstation** | Windows / Linux / macOS | Any connected network | `client.cli` / `ExpoClient` SDK | Python 3.10+ |

```
                       [Computer A: Coordinator & Relay]
                          IP: 192.168.1.100 (or VPS Public IP)
                          Port: 9000 (HTTP/WS API & Relay)
                                    │
               ┌────────────────────┴────────────────────┐
               │ Direct LAN                             │ Reverse WebSocket Tunnel
               ▼ (Port 9001 accessible)                  ▼ (/relay/tunnel/{node_id})
  [Computer B: Storage Node 1]             [Computer C: Storage Node 2]
    LAN IP: 192.168.1.101                     Private IP: 10.0.0.15 (Behind NAT)
    Port: 9001 (Direct HTTP)                  Port: 9002 (Inbound BLOCKED)
                                                         │
                                                         ▼
                                          Reverse WS Tunnel Outbound to A:9000
```

---

## 3. Environment & Dependency Setup

### 3.1 Python Environment Setup

Execute on each computer:

#### Windows (PowerShell):
```powershell
Set-Location -Path "D:\expo"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r coordinator\requirements.txt
pip install -r storage_node\requirements.txt
```

#### Linux / macOS (bash):
```bash
cd /opt/expo
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r coordinator/requirements.txt
pip install -r storage_node/requirements.txt
```

### 3.2 Network Port Allocations & Firewall Rules

| Machine | Service | Protocol | Port | Bind Address | Advertised Endpoint | Firewall Requirement |
|---|---|---|---|---|---|---|
| **Computer A** | Coordinator HTTP/WS | TCP | `9000` | `0.0.0.0` | `http://<COMP_A_IP>:9000` | Inbound TCP 9000 **OPEN** |
| **Computer B** | Storage Node 1 | TCP | `9001` | `0.0.0.0` | `http://<COMP_B_IP>:9001` | Inbound TCP 9001 **OPEN** to LAN |
| **Computer C** | Storage Node 2 (NAT) | TCP | `9002` | `127.0.0.1` | `http://127.0.0.1:9002` | Inbound TCP **BLOCKED**; Outbound **OPEN** |

#### Firewall Configuration Commands:

**Computer A (Windows PowerShell as Admin):**
```powershell
New-NetFirewallRule -DisplayName "Expo Coordinator Port 9000" -Direction Inbound -LocalPort 9000 -Protocol TCP -Action Allow
```

**Computer B (Windows PowerShell as Admin):**
```powershell
New-NetFirewallRule -DisplayName "Expo Storage Node Port 9001" -Direction Inbound -LocalPort 9001 -Protocol TCP -Action Allow
```

**Computer C (Confirm Inbound Ports are Blocked):**
No inbound firewall rules allowed. Storage Node 2 binds only to `127.0.0.1`.

---

## 4. Startup Commands & Configuration

### 4.1 Computer A (Coordinator & Relay Gateway)

```powershell
Set-Location -Path "D:\expo"
$env:COORDINATOR_HOST = "0.0.0.0"
$env:COORDINATOR_PORT = "9000"
$env:COORDINATOR_DB_PATH = ".\coordinator_metadata.db"
$env:COORDINATOR_AUTH_TOKEN = "expo-cluster-shared-secret-token"
$env:COORDINATOR_ALLOW_RELAY = "true"
$env:NODE_HEARTBEAT_TIMEOUT_SECONDS = "15"

python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000
```

### 4.2 Computer B (Storage Node 1 — Direct LAN Node)

```powershell
Set-Location -Path "D:\expo"
$env:NODE_HOST = "0.0.0.0"
$env:NODE_PORT = "9001"
$env:STORAGE_ROOT = ".\storage_data_node1"
$env:STORAGE_QUOTA_BYTES = "10737418240" # 10 GB
$env:ADVERTISED_ENDPOINT = "http://<COMP_B_LAN_IP>:9001"
$env:COORDINATOR_ENABLED = "true"
$env:COORDINATOR_URL = "http://<COMP_A_LAN_IP>:9000"
$env:COORDINATOR_AUTH_TOKEN = "expo-cluster-shared-secret-token"
$env:HEARTBEAT_INTERVAL_SECONDS = "5"
$env:CONNECTIVITY_MODE = "LAN"

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 9001
```

### 4.3 Computer C (Storage Node 2 — NAT / Reverse WebSocket Relay Node)

```powershell
Set-Location -Path "D:\expo"
$env:NODE_HOST = "127.0.0.1"
$env:NODE_PORT = "9002"
$env:STORAGE_ROOT = ".\storage_data_node2"
$env:STORAGE_QUOTA_BYTES = "10737418240" # 10 GB
$env:ADVERTISED_ENDPOINT = "http://127.0.0.1:9002" # Unreachable directly by external peers
$env:COORDINATOR_ENABLED = "true"
$env:COORDINATOR_URL = "http://<COMP_A_LAN_IP>:9000"
$env:COORDINATOR_AUTH_TOKEN = "expo-cluster-shared-secret-token"
$env:HEARTBEAT_INTERVAL_SECONDS = "5"
python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 9002
```

### 4.4 Authentication, Provider Identity, & TLS / HTTPS Configuration

#### A. Authentication & Access Separation
Expo enforces strict separation between cluster node operations, provider-owned actions, and administrative operations:
```powershell
# Set on Computer A (Coordinator)
$env:COORDINATOR_AUTH_TOKEN = "<CLUSTER_SHARED_SECRET_TOKEN>"        # Shared node authentication token
$env:COORDINATOR_ADMIN_AUTH_TOKEN = "<ADMIN_MANAGEMENT_SECRET_TOKEN>" # Separate admin token for drain operations

# Set on Computer B & Computer C (Storage Nodes)
$env:COORDINATOR_AUTH_TOKEN = "<CLUSTER_SHARED_SECRET_TOKEN>"        # Required for registration and heartbeats
```
*Never share `$env:COORDINATOR_ADMIN_AUTH_TOKEN` with storage node host configurations.*

#### B. TLS / HTTPS Certificate Generation & Setup
To protect cluster control-plane and relay traffic against LAN packet sniffing, TLS must be enabled.

1. **Generate Local Certificate Authority and Host Certificates** (e.g. via OpenSSL):
```powershell
# Create private CA
openssl req -x509 -new -nodes -keyout ca.key -sha256 -days 365 -out ca.crt -subj "/CN=ExpoLocalRootCA"

# Generate certificate for Computer A (Coordinator)
openssl req -new -nodes -keyout coordinator.key -out coordinator.csr -subj "/CN=coordinator.local"
openssl x509 -req -in coordinator.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out coordinator.crt -days 365 -sha256
```

2. **Run Coordinator with TLS Enabled**:
```powershell
# On Computer A
python -m uvicorn coordinator.app.main:app `
    --host 0.0.0.0 `
    --port 9000 `
    --ssl-keyfile ".\coordinator.key" `
    --ssl-certfile ".\coordinator.crt"
```

3. **Configure Storage Nodes and Clients with CA Verification**:
```powershell
# On Computer B & Computer C (and Client)
$env:COORDINATOR_URL = "https://<COMP_A_LAN_IP>:9000"
$env:COORDINATOR_VERIFY_TLS = "true"
$env:COORDINATOR_CA_CERT = ".\ca.crt"
```
> [!IMPORTANT]
> Never set `COORDINATOR_VERIFY_TLS=false` or disable SSL verification to make connectivity work. Always provision the CA certificate path via `COORDINATOR_CA_CERT`.

---

### 4.5 Safe Startup, Process Shutdown, and Log Collection

#### A. Starting Services with Log Redirection
**Computer A (PowerShell):**
```powershell
# Run with stdout/stderr logged to rotating file
python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 9000 --access-log *>&1 | Tee-Object -FilePath ".\coordinator.log"
```

**Computer B (PowerShell):**
```powershell
python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 9001 --access-log *>&1 | Tee-Object -FilePath ".\node1.log"
```

**Computer C (PowerShell):**
```powershell
python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 9002 --access-log *>&1 | Tee-Object -FilePath ".\node2.log"
```

#### B. Graceful Shutdown Procedures
Always use graceful termination (`CTRL+C` or `SIGINT` / `SIGTERM`) to allow uvicorn and background workers to flush SQLite WAL journals and close active WebSocket tunnels:
```powershell
# Graceful process termination via PowerShell
Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*coordinator.app.main*" } | Stop-Process
Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*storage_node.app.main*" } | Stop-Process
```

#### C. Log Collection & Sanitization
Before archiving or sharing operational logs:
```powershell
# Sanitize tokens and keys from log files
(Get-Content .\coordinator.log) -replace 'Bearer [A-Za-z0-9_-]+', 'Bearer [REDACTED]' `
                               -replace 'X-Auth-Token: [A-Za-z0-9_-]+', 'X-Auth-Token: [REDACTED]' |
    Set-Content .\coordinator_sanitized.log
```

---

### 4.6 Trusted LAN Isolation & Pre-Flight Security Checklist

> [!IMPORTANT]
> Keep all Coordinator and Storage Node ports strictly private to the trusted LAN. Do not open ports to public networks or internet gateways until authentication, TLS, and firewall rules are verified.

Before starting any service on `0.0.0.0` or opening firewall ports:
- [ ] **Authentication Verified**: Ensure `COORDINATOR_AUTH_TOKEN` is set and non-empty. Never bind `0.0.0.0` without an active auth token.
- [ ] **Admin Authorization Isolated**: Confirm `COORDINATOR_ADMIN_AUTH_TOKEN` is distinct from the shared cluster token so normal storage node tokens cannot execute admin drain operations.
- [ ] **Firewall Profile Scoped**: Ensure Windows Firewall rules for ports 9000 and 9001 are restricted to the **Private** network profile only (`-Profile Private`), explicitly blocking access from the **Public** profile.
- [ ] **No Public Port Forwards**: Verify on the physical router/gateway (e.g. `10.10.192.10`) that UPnP is disabled and no WAN-to-LAN port forwards exist for ports `9000-9005`.
- [ ] **Host-Only Bind for Firewalled Nodes**: Ensure nodes behind NAT (Computer C) bind strictly to `127.0.0.1` and connect outbound via reverse WebSocket.
- [ ] **Pre-Flight Connection Test**: Perform a local probe with `Test-NetConnection -Port 9000 -ComputerName 127.0.0.1` before allowing remote LAN packets.

---

### 4.7 Investigation: VPN Egress (Cloudflare WARP) vs. Physical Router NAT Mapping

When investigating network paths and STUN address discovery:
1. **The Masking Effect of VPNs**:
   - If an endpoint runs a VPN client (such as Cloudflare WARP with adapter `172.16.0.2`), default route queries to public STUN servers (`stun.l.google.com`) are routed through the VPN tunnel.
   - The STUN server observes and reports the **VPN Anycast egress IP** (e.g. `104.28.164.45`), **NOT** the upstream institutional/ISP public NAT gateway address.
   - Note that the local gateway `10.10.192.10` is an RFC 1918 private address (`10.0.0.0/8`), not a public Internet address.
2. **Inbound Unreachability of VPN Egress**:
   - Cloudflare WARP and standard commercial VPN tunnels do not accept unsolicited inbound TCP/UDP packets from the public internet to client ports.
   - Therefore, advertising the STUN-discovered IP (`104.28.164.45:14987`) to peer nodes **will always result in direct connection timeouts**.
3. **LAN vs. Internet Path Separation**:
   - For peers on the **same LAN**, nodes must advertise their physical LAN IP (e.g. `10.10.193.27`), which routes over the physical Ethernet/Wi-Fi adapter, bypassing the VPN tunnel entirely.
   - For peers across **different networks / WAN boundaries**, nodes behind restrictive NAT or VPNs must rely on the **Reverse WebSocket Relay** (`RelayTunnelClient` -> `/relay/tunnel/{node_id}`).
4. **NAT Traversal Dynamics & Direct Connectivity**:
   - Direct peer connectivity is not impossible for every NAT: Full Cone NAT (1:1 mapping), Address-Restricted Cone NAT, and Port-Restricted Cone NAT can allow direct peer connections using UDP hole punching or gateway port allocation protocols (UPnP, PCP, NAT-PMP) where supported.
   - However, under **Symmetric NAT**, the NAT gateway allocates a different external port for every unique destination endpoint. Simple STUN port prediction cannot anticipate the peer port.
   - For Symmetric NAT, Carrier-Grade NAT (CGNAT) without port control, and corporate firewalls that block unsolicited inbound traffic, reverse WebSocket relay tunnels are mathematically required for 100% reachability.

---

## 5. Test Files & Checksum Matrix

Disposable test files generated across multiple size tiers:

| File Identifier | Payload Size | Generation Method | Purpose | Expected Checksum |
|---|---|---|---|---|
| `test_small.bin` | 1 KB (1,024 B) | Static test pattern | Quick connectivity probe | Compute via `certutil -hashfile` or `hashlib` |
| `test_medium.bin` | 64 KB (65,536 B) | Structured pseudo-random | Chunk boundary test | Pre-record SHA-256 before upload |
| `test_1mb.bin` | 1 MB (1,048,576 B) | High-entropy byte sequence | Single standard chunk upload | Pre-record SHA-256 before upload |
| `test_10mb.bin` | 10 MB (10,485,760 B) | Multi-chunk payload | Multi-chunk + multi-node placement | Pre-record SHA-256 before upload |
| `test_50mb.bin` | 50 MB (52,428,800 B) | Multi-chunk payload | High-throughput drain migration | Pre-record SHA-256 before upload |

### Generation Command (PowerShell):
```powershell
# Generate 1 KB file
[System.IO.File]::WriteAllBytes("test_small.bin", [System.Text.Encoding]::UTF8.GetBytes("Expo_Physical_Test_Data_1KB_" * 36))

# Generate 1 MB file
$bytes = New-Object byte[] 1048576; (New-Object System.Random(42)).NextBytes($bytes); [System.IO.File]::WriteAllBytes("test_1mb.bin", $bytes)

# Verify SHA-256
certutil -hashfile test_1mb.bin SHA256
```

---

## 6. Step-by-Step Validation Procedures

### Procedure 1: Same-LAN Direct Connectivity
1. Start Coordinator on Computer A (`192.168.1.100:9000`).
2. Start Storage Node 1 on Computer B (`192.168.1.101:9001`).
3. Check registration on Coordinator: `curl -H "X-Auth-Token: ..." http://192.168.1.100:9000/nodes`.
4. Check heartbeat renewal every 5 seconds.
5. Upload `test_1mb.bin` from client workstation using `client.cli upload`.
6. Download file using `client.cli download` and verify SHA-256 matches bit-for-bit.
7. Disconnect Wi-Fi on Computer B for 20 seconds. Confirm node transitions to `offline` on Coordinator.
8. Reconnect Wi-Fi on Computer B. Confirm node recovers to `online` on next heartbeat without restarting service.

### Procedure 2: Network Boundary & Reverse WebSocket Relay
1. Start Storage Node 2 on Computer C (behind separate NAT or firewall, port 9002 bound to `127.0.0.1`).
2. Verify outbound reverse tunnel registers on Coordinator:
   `curl -H "X-Auth-Token: ..." http://192.168.1.100:9000/relay/nodes`
   Expect: `has_tunnel: true`.
3. Client attempts direct connection to Node 2 advertised endpoint (`127.0.0.1:9002`), which fails.
4. Client `ConnectionManager` detects direct probe failure and triggers `_attempt_relay_fallback()`.
5. Client downloads file chunk through Coordinator relay session (`http://192.168.1.100:9000/relay/{session_id}/files/{chunk_id}`).
6. Verify relayed payload SHA-256 matches source chunk.
7. Confirm Coordinator relay logs show chunk traffic traversing the WebSocket tunnel frames.

### Procedure 3: Failure Recovery & Durable Migration Under Physical Stress
1. Start drain on Node 1: `curl -X POST .../provider/nodes/NODE-1/drain`.
2. While worker is transferring chunks to Node 2, disconnect network cable / disable adapter on Computer A (Coordinator crash simulation).
3. Restart Coordinator service on Computer A.
4. Verify `recover_in_flight_migrations()` executes on startup, returning `transferring` records to `pending`.
5. Worker resumes migration and completes transfer to Node 2.
6. Verify destination checksum verification succeeds.
7. Attempt premature drain complete: `POST .../drain/complete` -> confirm `409 Conflict` until all migrations report `completed`.
8. Verify source chunks on Node 1 disk are **never deleted**.

---

## 7. Evidence Collection Matrix

For every physical scenario executed:
- [ ] Command executed (with auth secrets redacted).
- [ ] Timestamp in UTC.
- [ ] Source IP and Destination IP.
- [ ] Protocol used (Direct HTTP vs Reverse WSS Relay).
- [ ] HTTP status code and response payload.
- [ ] Pre-upload and post-download SHA-256 hashes.
- [ ] SQLite database state inspection before and after test.
- [ ] Wireshark / packet capture / server log excerpt.
