# Phase 7B Report — Contribution Credits, Node Reputation and Trust Scoring

## 1. Executive Summary

Phase 7B establishes an auditable, deterministic, zero-knowledge contribution accounting and node reputation scoring engine for the Expo distributed storage network. The system introduces:

1. **Expo Contribution Credits (ECC)**: Non-monetary, versioned accounting units measuring verified storage maintained, payload bytes transferred (ingress and egress), and self-healing repair/replication operations.
2. **Persistent Transactional Credit Ledger**: An immutable, append-only SQLite ledger (`credit_ledger_entries`) with strict idempotency, balance reconciliation, and explicit compensating reversal entries (never silently overwriting history).
3. **Multi-Factor Node Reputation Scoring (0 to 100)**: An objective trust score composed of observed availability, transfer integrity, and recovery reliability, paired with a statistical confidence indicator based on observation volume.
4. **Hardened Trust Boundaries**: Strict validation preventing public API callers or unverified nodes from self-awarding credits, claiming false capacity, or forging uptime.
5. **Coordinator REST APIs, Python SDK, and CLI Extensions**: Complete interfaces for inspecting balances, querying paginated ledgers, evaluating reputation, and viewing cluster summaries.

**Explicit Confirmation**: Expo Contribution Credits (ECC) are strictly non-monetary accounting units. No real-money payments, cryptocurrency, tokens with monetary value, public trading, deposits, withdrawals, or marketplaces are implemented or enabled.

---

## 2. Phase 7A Trust-Boundary Audit

During the initial audit of Phase 7A's metering components (`node_capacity_snapshots`, `metering_transfer_events`, `node_heartbeat_observations`, `metering_operation_events`), the trust boundaries were analyzed:

1. **Event Ingestion vs Credit Awarding**:
   - In Phase 7A, raw metering ingestion recorded telemetry data.
   - For Phase 7B, the boundary was hardened: raw telemetry records cannot directly award credits. All credit issuance is computed authoritatively by the Coordinator's `AccountingService`.
   - Any transfer event with negative bytes (`payload_bytes < 0`) is rejected at both the REST API validation layer (HTTP 400) and the service engine layer (`ValueError`).
2. **Authoritative Storage vs Self-Reported Quota**:
   - Storage nodes report their configured quota and host disk space via heartbeats and registration.
   - **Crucial Rule**: Unused quota is merely capacity offered, NOT storage maintained.
   - Storage credits are awarded strictly based on verified bytes in active file manifests (`calculate_authoritative_stored_bytes(node_id)` from `files` in the File Catalog). Quota changes cannot claim retroactive storage credits.
3. **Uptime & Heartbeat Verification**:
   - Heartbeat timestamps are recorded by the Coordinator upon arrival (`_now_iso()`). Nodes cannot manipulate heartbeat timestamps to fabricate uptime.
   - Missing observations create offline gaps according to the configured `heartbeat_timeout_seconds`.
4. **Operation & Repair Verification**:
   - Recovery operations (replication and repair) earn credits only when marked `completed` and associated with verified target storage nodes. Failed repair attempts earn 0 credits and negatively impact the node's recovery reliability score.

---

## 3. Credit Policy, Formulas, Weights, and Versioning

The accounting engine uses a centralized, versioned policy model (`AccountingPolicyConfig`, default version `"7B-v1.0"`).

### 3.1 Policy Configuration Parameters
| Parameter | Default Value | Description |
|---|---|---|
| `policy_version` | `"7B-v1.0"` | Current active policy version string |
| `storage_weight_per_gb_day` | `1.0` ECC | Credits earned per GB-day of verified stored data |
| `upload_weight_per_gb` | `1.0` ECC | Credits earned per GB of client upload payload received |
| `download_weight_per_gb` | `1.5` ECC | Credits earned per GB of client download payload served |
| `replication_op_weight` | `0.5` ECC | Base bonus per completed proactive chunk replication |
| `replication_weight_per_gb`| `0.5` ECC | Byte bonus per GB replicated |
| `repair_op_weight` | `2.0` ECC | Base bonus per completed self-healing chunk repair |
| `repair_weight_per_gb` | `1.0` ECC | Byte bonus per GB repaired |
| `availability_multiplier_min`| `0.5` | Minimum availability multiplier (at 0% uptime) |
| `availability_multiplier_max`| `1.0` | Maximum availability multiplier (at 100% uptime) |
| `availability_weight` | `0.40` (40%) | Weight of observed uptime in reputation score |
| `integrity_weight` | `0.35` (35%) | Weight of transfer success rate in reputation score |
| `recovery_weight` | `0.25` (25%) | Weight of recovery task completion in reputation score |

### 3.2 Formulas
1. **Verified Storage Contribution**:
   $$\text{gb\_days} = \frac{\text{verified\_bytes} \times \text{window\_hours}}{1024^3 \times 24}$$
   $$\text{avail\_multiplier} = \text{min\_mult} + (\text{max\_mult} - \text{min\_mult}) \times \frac{\text{availability\_pct}}{100}$$
   $$\text{storage\_credits} = \text{round}(\text{gb\_days} \times \text{storage\_weight} \times \text{avail\_multiplier}, 4)$$

2. **Bandwidth Transfer Contribution**:
   - Upload (Ingress):
     $$\text{upload\_credits} = \text{round}\left(\frac{\text{payload\_bytes}}{1024^3} \times \text{upload\_weight}, 4\right)$$
   - Download (Egress):
     $$\text{download\_credits} = \text{round}\left(\frac{\text{payload\_bytes}}{1024^3} \times \text{download\_weight}, 4\right)$$
   - Failed or cancelled transfers: 0 credits.

3. **Recovery & Self-Healing Operations**:
   - Proactive Replication:
     $$\text{replication\_credits} = \text{round}\left(\text{replication\_op\_weight} + \frac{\text{payload\_bytes}}{1024^3} \times \text{replication\_byte\_weight}, 4\right)$$
   - Self-Healing Repair:
     $$\text{repair\_credits} = \text{round}\left(\text{repair\_op\_weight} + \frac{\text{payload\_bytes}}{1024^3} \times \text{repair\_byte\_weight}, 4\right)$$
   - Failed operations: 0 credits.

---

## 4. Persistent SQLite Credit Ledger & Transaction Design

### 4.1 Schema
```sql
CREATE TABLE IF NOT EXISTS credit_ledger_entries (
    entry_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    category TEXT NOT NULL,
    credit_delta REAL NOT NULL,
    event_id TEXT,
    policy_version TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    audit_metadata TEXT,
    reversal_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_cle_node_ts ON credit_ledger_entries (node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_cle_idem ON credit_ledger_entries (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_cle_category ON credit_ledger_entries (category);

CREATE TABLE IF NOT EXISTS credit_balances (
    node_id TEXT PRIMARY KEY,
    total_credits REAL NOT NULL DEFAULT 0.0,
    lifetime_earned REAL NOT NULL DEFAULT 0.0,
    lifetime_reversed REAL NOT NULL DEFAULT 0.0,
    last_reconciled_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounting_audit_logs (
    audit_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    target_id TEXT,
    actor TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON accounting_audit_logs (target_id, timestamp);
```

### 4.2 Transaction Rules & Reversals
- **Append-Only Immutability**: No rows in `credit_ledger_entries` are ever modified or deleted.
- **Idempotency Guarantee**: Unique constraint on `idempotency_key` ensures identical event retries return the existing entry without double-awarding credits.
- **Explicit Compensating Entries**: Credit corrections or dispute resolutions create a compensating entry with `category = 'reversal'`, negative `credit_delta`, and `reversal_ref = original_entry_id`.
- **Double-Reversal Prevention**: Once an entry is referenced by a reversal entry, subsequent reversal requests are rejected with a 400 Bad Request.
- **Atomic Balance Updates**: Balance adjustments are committed in the same SQLite transaction as the ledger insert. `reconcile_balance()` enforces full reconciliation against `SUM(credit_delta)`.

---

## 5. Node Reputation & Trust Scoring (0 to 100)

Reputation is evaluated objectively and is strictly independent of a node's physical storage capacity or total credit balance:

### 5.1 Component Factors
1. **Availability Score ($S_{avail} \in [0, 100]$)**:
   Calculated directly from rolling heartbeat observations:
   $$S_{avail} = \text{round}(\text{availability\_percentage}, 2)$$
2. **Integrity Score ($S_{integ} \in [0, 100]$)**:
   Transfer success ratio over evaluated rolling window:
   $$S_{integ} = \begin{cases} 100.0 & \text{if total\_transfers} = 0 \\ \text{round}\left(\frac{\text{successful\_transfers}}{\text{total\_transfers}} \times 100, 2\right) & \text{otherwise} \end{cases}$$
3. **Recovery Score ($S_{recov} \in [0, 100]$)**:
   Assigned self-healing and replication task completion ratio:
   $$S_{recov} = \begin{cases} 100.0 & \text{if total\_operations} = 0 \\ \text{round}\left(\frac{\text{completed\_operations}}{\text{total\_operations}} \times 100, 2\right) & \text{otherwise} \end{cases}$$
4. **Composite Reputation Score ($S_{rep} \in [0, 100]$)**:
   $$S_{rep} = \min(100.0, \max(0.0, S_{avail} \times 0.40 + S_{integ} \times 0.35 + S_{recov} \times 0.25))$$

### 5.2 Confidence & Data Sufficiency Rules
To prevent brand-new nodes or Sybil nodes from masquerading as battle-tested nodes:
$$C_{hb} = \min(1.0, \text{hb\_count} / 10), \quad C_{tx} = \min(1.0, \text{tx\_count} / 5), \quad C_{time} = \min(1.0, \text{online\_seconds} / 3600)$$
$$\text{confidence} = \text{round}(C_{hb} \times 0.4 + C_{tx} \times 0.3 + C_{time} \times 0.3, 2)$$

- `sufficient`: $\text{confidence} \ge 0.8$
- `provisional`: $0.3 \le \text{confidence} < 0.8$
- `insufficient`: $\text{confidence} < 0.3$

---

## 6. Anti-Abuse and Authorization Safeguards

1. **Tamper-Proof Ingestion**: Payloads with negative bytes are rejected (`payload_bytes >= 0` check).
2. **Zero-Knowledge Privacy**: No Data Encryption Keys (DEKs), file contents, or personal secrets are stored in ledger records or metadata.
3. **Admin Token Authorization**: Administrative endpoints (`PUT /accounting/policy`, `POST /accounting/credits/reverse`, `POST /accounting/credits/calculate`) require coordinator authentication (`verify_coordinator_auth`).
4. **Idempotent Storage Windows**: Time-window accounting uses deterministic keys (`storage:<node_id>:<start>:<end>`), preventing double counting during overlapping cron jobs.

---

## 7. Coordinator APIs, SDK, and CLI Additions

### 7.1 REST API Endpoints
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/credits/nodes/{node_id}/balance` | GET | Public | Reconciled ECC credit balance and lifetime totals |
| `/credits/nodes/{node_id}/ledger` | GET | Public | Paginated credit ledger entries (`limit`, `offset`, `category`) |
| `/credits/nodes/{node_id}/summary` | GET | Public | Categorized credit breakdown (storage, upload, download, repair) |
| `/reputation/nodes/{node_id}` | GET | Public | Node reputation score (0-100) and confidence indicator |
| `/reputation/nodes` | GET | Public | Cluster-wide reputation listing across all registered nodes |
| `/accounting/policy` | GET | Public | Active credit and reputation policy weights and version |
| `/accounting/policy` | PUT | Admin | Update policy parameters with audit log generation |
| `/accounting/cluster/summary` | GET | Public | Cluster totals: ECC issued, reversed, net, and average reputation |
| `/accounting/credits/calculate` | POST | Admin | Trigger on-demand batch credit calculation |
| `/accounting/credits/reverse` | POST | Admin | Issue an administrative compensating reversal entry |

### 7.2 Python SDK (`CoordinatorClient`)
- `get_credit_balance(node_id)`
- `get_credit_ledger(node_id, limit, offset, category, start_time, end_time)`
- `get_credit_summary(node_id)`
- `get_node_reputation(node_id, window_hours)`
- `list_node_reputations(window_hours)`
- `get_accounting_policy()`
- `get_accounting_cluster_summary()`
- `reverse_credit_ledger_entry(entry_id, reason)`
- `trigger_credit_calculation(node_id, window_hours)`

### 7.3 CLI Commands (`expo`)
- `expo credits-balance <node_id>`
- `expo credits-ledger <node_id> [--limit 50] [--offset 0] [--category CAT]`
- `expo credits-summary <node_id>`
- `expo reputation-show <node_id> [--window-hours 168.0]`
- `expo reputation-list [--window-hours 168.0]`
- `expo accounting-policy`
- `expo accounting-summary`

---

## 8. Database Migrations and Backward Compatibility

- SQLite `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` migrations run automatically inside `init_db(db_path)`.
- All Phase 1 through Phase 7A tables, records, manifests, and indexes remain unchanged and fully functional.
- Process restarts preserve all ledger entries, balances, and reputation records.

---

## 9. Comprehensive Test Suite Results

### 9.1 Test Suites Executed
1. **Phase 7B Test Suite**: `pytest coordinator/tests/test_phase7b.py -v`
   - Result: **18 passed** in 2.28s.
2. **Phase 7A + Phase 7B Test Suite**: `pytest coordinator/tests/test_phase7a.py coordinator/tests/test_phase7b.py -v`
   - Result: **46 passed** in 4.18s.
3. **Phase 5A + Phase 7A + Phase 7B Test Suite**: `pytest coordinator/tests/test_phase5a.py coordinator/tests/test_phase7a.py coordinator/tests/test_phase7b.py -v`
   - Result: **51 passed** in 4.58s.
4. **Full Regression Suite**: `pytest coordinator/tests/ storage_node/tests/ -q`
   - Result: **299 passed** (259 Coordinator + 40 Storage Node) with 0 failures.

---

## 10. Synthetic Data Credit Calculation Examples

### Example A: Verified Storage Contribution
- Storage node `NODE-01` stores 50 GB of verified active chunk data over a 24-hour window with 98% observed availability.
- Formula:
  $$\text{gb\_days} = \frac{50 \times 1024^3 \times 24}{1024^3 \times 24} = 50.0$$
  $$\text{multiplier} = 0.5 + 0.5 \times 0.98 = 0.99$$
  $$\text{credits} = 50.0 \times 1.0 \times 0.99 = 49.5000\text{ ECC}$$

### Example B: Bandwidth Transfers
- Node `NODE-01` completes 10 GB of client upload ingress and 20 GB of client download egress:
  - Upload Credits: $10.0 \times 1.0 = 10.0000\text{ ECC}$
  - Download Credits: $20.0 \times 1.5 = 30.0000\text{ ECC}$
  - Net Bandwidth Credits: $40.0000\text{ ECC}$

### Example C: Self-Healing Repair
- Node `NODE-01` receives and reconstructs a repaired 1 GB erasure-coded chunk:
  - Base Repair Bonus: $2.0\text{ ECC}$
  - Byte Rate: $1.0\text{ ECC/GB} \times 1.0 = 1.0\text{ ECC}$
  - Total Repair Credits: $3.0000\text{ ECC}$

---

## 11. Known Limitations and Manual Network Instructions

1. **Pending Physical Network Multi-Machine Validation**: Physical multi-machine validation across real WAN/LAN hardware remains pending as established in prior phases.
2. **Manual Inspection Commands**:
   ```bash
   # 1. View active accounting policy
   python -m client.cli accounting-policy --coordinator-url http://127.0.0.1:9000

   # 2. Inspect node credit balance
   python -m client.cli credits-balance NODE-1 --coordinator-url http://127.0.0.1:9000

   # 3. View paginated credit ledger
   python -m client.cli credits-ledger NODE-1 --limit 10 --coordinator-url http://127.0.0.1:9000

   # 4. Inspect node reputation and confidence
   python -m client.cli reputation-show NODE-1 --coordinator-url http://127.0.0.1:9000

   # 5. List cluster-wide reputation
   python -m client.cli reputation-list --coordinator-url http://127.0.0.1:9000
   ```
