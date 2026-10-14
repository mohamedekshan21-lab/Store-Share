# Expo — Phase 6B.2: Physical Network Validation Runbook

This runbook provides exact, reproducible, and copyable commands for validating the Expo distributed storage system across physical network boundaries, NAT gateways, and stateful firewalls.

---

## 1. Architecture Overview & Security Model

In an untrusted or heterogeneous physical deployment:
1. **Coordinator** acts as the cluster directory, relay gateway, and metadata catalog. It may be hosted on a LAN machine or a publicly reachable VPS/cloud server.
2. **Storage Nodes** store ciphertext chunks in isolated sandboxes. Storage Nodes located behind NAT, CGNAT, or restrictive inbound firewalls **never expose their private HTTP ports to the public internet**. Instead, they establish an outbound, authenticated persistent reverse WebSocket tunnel (`/relay/tunnel/{node_id}`) to the Coordinator.
3. **Clients** upload and download files using client-side AES-GCM-256 encryption. DEKs (Data Encryption Keys) are generated in client memory and **never** transmitted to the Coordinator, relay frames, or Storage Nodes.
4. **Relay Gateway**: When a client cannot directly reach a Storage Node's advertised endpoint, the client routes chunk requests through the Coordinator's authenticated relay sessions (`/relay/{session_id}/{path}`). The Coordinator forwards frames across the reverse WebSocket tunnel without inspecting or caching chunk ciphertext.

---

## 2. Setup A: Coordinator & Node 1 on Machine A; Node 2 on Machine B Behind NAT/Firewall

### 2.1 Topology Description
- **Machine A (e.g., Ubuntu/Linux or Windows)**:
  - IP: `<MACHINE_A_LAN_IP>` (e.g., `192.168.1.100`)
  - Runs Coordinator on port `<COORDINATOR_PORT>` (default `8000`)
  - Runs Storage Node 1 on port `<NODE1_PORT>` (default `8001`)
  - Accessible on LAN by Machine B
- **Machine B (e.g., Windows or Linux behind home/office NAT or firewall)**:
  - Private IP: `<MACHINE_B_PRIVATE_IP>` (e.g., `192.168.2.50` or `10.0.0.15`)
  - Inbound ports: **Completely blocked** by stateful firewall/NAT.
  - Outbound traffic: Allows HTTP/WebSocket connections to Machine A.
  - Runs Storage Node 2 on localhost port `<NODE2_PORT>` (default `8002`).
  - Storage Node 2 connects outbound to Coordinator via reverse WebSocket tunnel.

---

### 2.2 Machine A Setup Instructions

#### Step A.1: Prerequisites & Virtual Environment
**Linux (bash):**
```bash
cd /opt/expo  # Or path to expo repo
python3 -m venv .venv
source .venv/bin/activate
pip install -r coordinator/requirements.txt
pip install -r storage_node/requirements.txt
```

**Windows (PowerShell):**
```powershell
Set-Location -Path "D:\expo"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r coordinator\requirements.txt
pip install -r storage_node\requirements.txt
```

#### Step A.2: Launch Coordinator on Machine A
**Linux (bash):**
```bash
export COORDINATOR_HOST="0.0.0.0"
export COORDINATOR_PORT=8000
export COORDINATOR_AUTH_TOKEN="sec-cluster-token-xyz"
export COORDINATOR_DB_PATH="./coordinator_data.db"
export COORDINATOR_ALLOW_RELAY=true

python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 8000
```

**Windows (PowerShell):**
```powershell
$env:COORDINATOR_HOST = "0.0.0.0"
$env:COORDINATOR_PORT = "8000"
$env:COORDINATOR_AUTH_TOKEN = "sec-cluster-token-xyz"
$env:COORDINATOR_DB_PATH = ".\coordinator_data.db"
$env:COORDINATOR_ALLOW_RELAY = "true"

python -m uvicorn coordinator.app.main:app --host 0.0.0.0 --port 8000
```

#### Step A.3: Launch Storage Node 1 on Machine A
In a separate terminal on Machine A:
**Linux (bash):**
```bash
export STORAGE_HOST="0.0.0.0"
export STORAGE_PORT=8001
export STORAGE_ROOT="./node1_storage"
export STORAGE_QUOTA_GB=10.0
export STORAGE_AUTH_TOKEN="sec-cluster-token-xyz"
export STORAGE_ADVERTISED_ENDPOINT="http://<MACHINE_A_LAN_IP>:8001"
export COORDINATOR_URL="http://127.0.0.1:8000"
export COORDINATOR_AUTH_TOKEN="sec-cluster-token-xyz"

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 8001
```

**Windows (PowerShell):**
```powershell
$env:STORAGE_HOST = "0.0.0.0"
$env:STORAGE_PORT = "8001"
$env:STORAGE_ROOT = ".\node1_storage"
$env:STORAGE_QUOTA_GB = "10.0"
$env:STORAGE_AUTH_TOKEN = "sec-cluster-token-xyz"
$env:STORAGE_ADVERTISED_ENDPOINT = "http://<MACHINE_A_LAN_IP>:8001"
$env:COORDINATOR_URL = "http://127.0.0.1:8000"
$env:COORDINATOR_AUTH_TOKEN = "sec-cluster-token-xyz"

python -m uvicorn storage_node.app.main:app --host 0.0.0.0 --port 8001
```

---

### 2.3 Machine B Setup Instructions (Behind NAT/Firewall)

#### Step B.1: Confirm Inbound Port Isolation
Ensure no inbound port forwards are enabled on Machine B's router or firewall. Node 2's listening port (`8002`) should **only** bind to `127.0.0.1`.

#### Step B.2: Launch Storage Node 2 on Machine B
**Linux (bash):**
```bash
cd /opt/expo
source .venv/bin/activate

export STORAGE_HOST="127.0.0.1"
export STORAGE_PORT=8002
export STORAGE_ROOT="./node2_storage"
export STORAGE_QUOTA_GB=10.0
export STORAGE_AUTH_TOKEN="sec-cluster-token-xyz"
# Advertised endpoint set to private unreachable address or localhost
export STORAGE_ADVERTISED_ENDPOINT="http://127.0.0.1:8002"
export COORDINATOR_URL="http://<MACHINE_A_LAN_IP>:8000"
export COORDINATOR_AUTH_TOKEN="sec-cluster-token-xyz"
export TUNNEL_AUTO_CONNECT=true

python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 8002
```

**Windows (PowerShell):**
```powershell
Set-Location -Path "D:\expo"
.\.venv\Scripts\Activate.ps1

$env:STORAGE_HOST = "127.0.0.1"
$env:STORAGE_PORT = "8002"
$env:STORAGE_ROOT = ".\node2_storage"
$env:STORAGE_QUOTA_GB = "10.0"
$env:STORAGE_AUTH_TOKEN = "sec-cluster-token-xyz"
$env:STORAGE_ADVERTISED_ENDPOINT = "http://127.0.0.1:8002"
$env:COORDINATOR_URL = "http://<MACHINE_A_LAN_IP>:8000"
$env:COORDINATOR_AUTH_TOKEN = "sec-cluster-token-xyz"
$env:TUNNEL_AUTO_CONNECT = "true"

python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 8002
```

---

### 2.4 Setup A Health Checks & Verification Commands

#### Health Check 1: Verify Coordinator Registry
```bash
curl -s -H "X-Auth-Token: sec-cluster-token-xyz" http://<MACHINE_A_LAN_IP>:8000/nodes | jq .
```
Expected output: Both Node 1 and Node 2 appear as registered and `ONLINE`.

#### Health Check 2: Check Active Reverse Tunnel for Node 2
```bash
curl -s -H "X-Auth-Token: sec-cluster-token-xyz" http://<MACHINE_A_LAN_IP>:8000/relay/nodes | jq .
```
Expected output: Node 2 is listed with `has_tunnel: true`.

#### Health Check 3: End-to-End Client Upload with Replication
Execute client upload test using python SDK:
```python
import asyncio
from coordinator.coordinator_client import CoordinatorClient
from client.storage_client import EncryptedStorageClient

async def test_replicated_upload():
    client = EncryptedStorageClient(
        coordinator_url="http://<MACHINE_A_LAN_IP>:8000",
        auth_token="sec-cluster-token-xyz",
    )
    test_data = b"Hello Physical Network Validation Phase 6B.2!" * 1024
    manifest = await client.upload_file(
        tenant_id="tenant-alpha",
        filename="physical_test.bin",
        data=test_data,
        replication_factor=2,
    )
    print("Uploaded manifest:", manifest.file_id)
    
    # Download and verify bit-for-bit integrity
    downloaded = await client.download_file(manifest)
    assert downloaded == test_data, "Integrity check failed!"
    print("Download integrity verified successfully!")

asyncio.run(test_replicated_upload())
```

---

## 3. Setup B: Coordinator on Public Cloud / VPS; Nodes on Separate Disjoint Networks

### 3.1 Topology Description
- **Public Coordinator (VPS/Cloud)**:
  - Public Domain/IP: `coordinator.example.com` (TLS terminated via reverse proxy, e.g., nginx/caddy or uvicorn with SSL).
  - Public Port: `443` (HTTPS / WSS).
  - Inbound HTTP/HTTPS permitted; database isolated.
- **Node 1 (Office LAN / ISP A)**:
  - Behind NAT; no public IP.
  - Outbound WSS connection to `wss://coordinator.example.com/relay/tunnel/{node_id}`.
- **Node 2 (Home LAN / ISP B)**:
  - Behind CGNAT / NAT; no public IP.
  - Outbound WSS connection to `wss://coordinator.example.com/relay/tunnel/{node_id}`.
- **Client (Mobile / Remote)**:
  - Reaches Coordinator at `https://coordinator.example.com`.
  - Connects to nodes via Coordinator Relay Sessions (`https://coordinator.example.com/relay/{session_id}/{path}`).

---

### 3.2 Coordinator Deployment Commands (Public Endpoint)

#### Step B.1: Nginx TLS Reverse Proxy Configuration (Sample)
```nginx
server {
    listen 443 ssl http2;
    server_name coordinator.example.com;

    ssl_certificate /etc/letsencrypt/live/coordinator.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/coordinator.example.com/privkey.pem;

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /relay/tunnel/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

#### Step B.2: Start Coordinator Service
```bash
export COORDINATOR_HOST="127.0.0.1"
export COORDINATOR_PORT=8000
export COORDINATOR_AUTH_TOKEN="<STRONG_PRODUCTION_SECRET>"
export COORDINATOR_DB_PATH="/var/lib/expo/coordinator.db"
export COORDINATOR_ALLOW_RELAY=true

python -m uvicorn coordinator.app.main:app --host 127.0.0.1 --port 8000
```

---

### 3.3 Storage Node Deployment Commands (Remote Networks)

#### Node 1 (Location A):
```bash
export STORAGE_HOST="127.0.0.1"
export STORAGE_PORT=9001
export STORAGE_ROOT="/var/lib/expo/node_data"
export STORAGE_QUOTA_GB=50.0
export STORAGE_AUTH_TOKEN="<STRONG_PRODUCTION_SECRET>"
export STORAGE_ADVERTISED_ENDPOINT="http://127.0.0.1:9001"
export COORDINATOR_URL="https://coordinator.example.com"
export COORDINATOR_AUTH_TOKEN="<STRONG_PRODUCTION_SECRET>"
export TUNNEL_AUTO_CONNECT=true

python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 9001
```

#### Node 2 (Location B):
```bash
export STORAGE_HOST="127.0.0.1"
export STORAGE_PORT=9002
export STORAGE_ROOT="/var/lib/expo/node_data"
export STORAGE_QUOTA_GB=50.0
export STORAGE_AUTH_TOKEN="<STRONG_PRODUCTION_SECRET>"
export STORAGE_ADVERTISED_ENDPOINT="http://127.0.0.1:9002"
export COORDINATOR_URL="https://coordinator.example.com"
export COORDINATOR_AUTH_TOKEN="<STRONG_PRODUCTION_SECRET>"
export TUNNEL_AUTO_CONNECT=true

python -m uvicorn storage_node.app.main:app --host 127.0.0.1 --port 9002
```

---

## 4. Evidence-Based Testing & Validation Checklist

When conducting multi-machine validation, record actual empirical observations in this checklist.

| Field | Configuration / Observation Record |
|-------|------------------------------------|
| **Test Date & Time** | `YYYY-MM-DD HH:MM:SS UTC` |
| **Machine A (Coordinator) OS** | e.g. Ubuntu 22.04 LTS / Windows 11 Pro 23H2 |
| **Machine B (Node) OS** | e.g. Debian 12 / Windows 10 Home 22H2 |
| **Machine C (Node) OS** | e.g. macOS Sonoma 14.5 / Fedora 40 |
| **Network Type** | Machine A: Public Cloud VPS; Nodes: Residential CGNAT / Corporate 802.1x |
| **Firewall Inbound on Nodes** | Verified BLOCKED (`nmap -p 8000-9000 <NODE_IP>` returns filtered/closed) |
| **WebSocket Tunnel Connection** | Confirmed established (`101 Switching Protocols` in Coordinator access log) |
| **Tunnel Interruption Test** | Machine B network adapter disabled for 30s; reconnected cleanly |
| **File Sizes Tested** | 1 KB, 64 KB, 1 MB, 10 MB, 50 MB |
| **SHA-256 Checksum Verification** | Source Hash == Decrypted Hash (Byte-for-byte exact match) |
| **Primary Node Failover** | Primary node process terminated (`kill -9`); Replica retrieved seamlessly |
| **DEK Isolation Check** | `sqlite3 coordinator.db "SELECT * FROM logical_files"` contains zero key material |
| **Observed Errors / Latencies** | Round-trip relay overhead: ~15-25 ms over WAN; 0 corruptions |

---

## 5. Teardown & Cleanup Instructions

### Linux:
```bash
# Terminate uvicorn processes
pkill -f "uvicorn storage_node.app.main"
pkill -f "uvicorn coordinator.app.main"

# Clean temporary test storage directories
rm -rf ./node1_storage ./node2_storage ./coordinator_data.db
```

### Windows (PowerShell):
```powershell
Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*uvicorn*" } | Stop-Process -Force
Remove-Item -Recurse -Force -Path ".\node1_storage", ".\node2_storage", ".\coordinator_data.db" -ErrorAction SilentlyContinue
```
