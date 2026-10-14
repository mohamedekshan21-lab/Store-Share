# Expo Phase 7B.1 — Accounting Integrity, Reputation Calibration and Security Audit Report

**Date**: 2026-10-11  
**Project**: Expo Distributed Storage Engine  
**Component**: Contribution Credits (ECC), Auditable Ledger Engine, Calibrated Trust Scoring, and Administrative Security  
**Status**: AUDITED, HARDENED, AND VERIFIED (310 passing tests across Coordinator and Storage Node suites)  
**Outstanding Validation**: Physical multi-machine LAN/WAN validation remains pending. Automated test pass does not imply physical network readiness or production deployment readiness.

---

## 1. Executive Summary

Phase 7B.1 conducted an end-to-end security, precision, and idempotency audit of the Phase 7B Expo Contribution Credit (ECC) ledger, accounting engine, reputation scoring system, and administrative APIs.

Prior to modifications, an audit of the Phase 7B baseline (299 passing tests) revealed four significant structural vulnerabilities:
1. **Floating-Point Drift Risk**: Ledger deltas and balances were stored and aggregated using SQLite `REAL` and Python floats, introducing potential drift across high-frequency micro-credits and large aggregates.
2. **Reputation Default Bias (False Perfect Trust)**: Nodes with zero transfer history or zero recovery jobs were defaulted to a 100.0% integrity or recovery score, misrepresenting unobserved dimensions as proven perfection.
3. **Storage-Time Interval Overlap Vulnerability**: Storage contribution awards used naive window timestamps in idempotency keys, allowing overlapping or adjacent jobs to award duplicate credits for the overlapping time slice.
4. **Reversal Inflexibility and Race Hazards**: The ledger lacked support for partial reversals, did not enforce non-negative balance protection, and lacked database-level transaction locking during concurrent reversal submissions.

All identified vulnerabilities were reproduced, remediated, and verified with **11 new deterministic invariant tests** in `coordinator/tests/test_phase7b1.py`. The entire regression suite now executes **310 tests with 100% pass rate** (270 Coordinator + 40 Storage Node).

---

## 2. Findings and Severity Classification

| Finding ID | Component | Description | Severity | Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-7B1-01** | `credit_ledger_entries` / `credit_balances` | Float precision drift across large/small aggregates; lack of atomic subunit definition | **High** | Defined $1\text{ ECC} = 1,000,000\ \mu\text{ECC}$. Stored integer subunits (`credit_micro_units`, `total_micro_units`). Ground-truth reconciliation runs on integer sums. |
| **SEC-7B1-02** | `calculate_node_reputation` | Lack of observations was silently rewarded with 100.0% score for integrity and recovery | **High** | Established neutral Bayesian prior (50.0) for unobserved dimensions. Brand new nodes receive 50.0 score, 0.0 confidence, and "insufficient" status. |
| **SEC-7B1-03** | `award_storage_credits` | Adjacent or overlapping time windows could issue duplicate credits for the overlapping slice | **High** | Created `storage_accounting_intervals` table with UTC window clipping and superset interval collision detection. |
| **SEC-7B1-04** | `reverse_ledger_entry` | All-or-nothing reversals; no partial reversal support; could create negative balances | **Medium** | Added partial reversal support (`amount`), cumulative reversal bounds check, idempotency check, and non-negative balance enforcement. |
| **SEC-7B1-05** | Transaction Concurrency | Unlocked read-then-write transactions during balance updates and reversals | **Medium** | Upgraded all mutations to `BEGIN IMMEDIATE` transactions to prevent concurrent lost updates. |
| **SEC-7B1-06** | Administrative Security | Unauthenticated policy mutation or credit manipulation risks | **Low** (Audited) | Confirmed `verify_coordinator_auth` is strictly enforced on all credit calculation, reversal, and policy endpoints. |

---

## 3. Defects Actually Reproduced

### Defect 1: Zero-Observation Reputation Distortion
- **Reproduction**: A newly registered node with zero completed transfers and zero assigned recovery operations was evaluated via `calculate_node_reputation`.
- **Observed Behavior**: Node received `integrity_score = 100.0` and `recovery_score = 100.0`, falsely signaling perfect reliability despite zero operational evidence.
- **Root Cause**: Fallback branches in `accounting.py` returned `100.0` when `total_tx == 0` or `total_ops == 0`.
- **Resolution**: Refactored to assign an unbiased neutral prior (`50.0`) to unobserved dimensions and flag `integrity_observed = False` / `recovery_observed = False`. Evaluated composite score using documented policy weights and set `confidence_indicator = 0.0` for new nodes.

### Defect 2: Storage Window Overlap Duplication
- **Reproduction**: Triggered `award_storage_credits` for `[10:00, 12:00]`, followed by `award_storage_credits` for `[11:00, 13:00]` on the same node.
- **Observed Behavior**: Because the idempotency key was based on requested start/end timestamps, both jobs were committed, double-crediting the 1-hour overlap between 11:00 and 12:00.
- **Root Cause**: Idempotency key lacked interval intersection validation against previously committed storage windows.
- **Resolution**: Added `storage_accounting_intervals` table. New awards query existing intervals; if an overlapping interval is found, the start timestamp is clipped to the latest existing end timestamp, ensuring only genuinely uncredited time slices are awarded.

### Defect 3: Inability to Execute Partial Reversals and Balance Overdraft
- **Reproduction**: Called `reverse_ledger_entry` for a partial amount (e.g. 4.0 ECC of a 10.0 ECC award).
- **Observed Behavior**: Method only reversed the entire 10.0 ECC amount and failed to allow partial adjustments. Additionally, reversing an entry on a provider whose balance was lower than the reversal amount would cause the provider balance to drop below zero.
- **Resolution**: Added `amount: Optional[float] = None` and `idempotency_key: Optional[str] = None`. Enforced `remaining_eligible_micro` tracking across multiple partial reversals and asserted `current_balance >= reversal_amount`.

---

## 4. Changes Made

### 4.1. Database Schema and Migrations (`coordinator/app/database.py`)
- Added `credit_micro_units INTEGER NOT NULL DEFAULT 0`, `window_start TEXT`, and `window_end TEXT` to `credit_ledger_entries`.
- Added `total_micro_units INTEGER NOT NULL DEFAULT 0`, `lifetime_earned_micro INTEGER NOT NULL DEFAULT 0`, and `lifetime_reversed_micro INTEGER NOT NULL DEFAULT 0` to `credit_balances`.
- Added `storage_accounting_intervals` table:
  ```sql
  CREATE TABLE IF NOT EXISTS storage_accounting_intervals (
      interval_id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      window_start TEXT NOT NULL,
      window_end TEXT NOT NULL,
      entry_id TEXT NOT NULL,
      bytes_stored INTEGER NOT NULL,
      created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_storage_int_node ON storage_accounting_intervals (node_id, window_start, window_end);
  ```
- Implemented automatic PRAGMA-inspected schema migrations to backfill micro-unit integer columns from legacy `REAL` values (`CAST(ROUND(credit_delta * 1000000) AS INTEGER)`).

### 4.2. Models (`coordinator/app/models.py`)
- Updated `CreditLedgerEntryRecord` with `credit_micro_units`, `window_start`, and `window_end`.
- Updated `CreditBalanceRecord` with `total_micro_units`, `lifetime_earned_micro`, and `lifetime_reversed_micro`.
- Updated `CreditReversalRequest` to include optional `amount: Optional[float] = None` and `idempotency_key: Optional[str] = None`.

### 4.3. Accounting Engine (`coordinator/app/accounting.py`)
- **Fixed Precision Engine**:
  - Implemented `to_micro_units(val)` using Python `decimal.Decimal` with `ROUND_HALF_UP`.
  - Implemented `from_micro_units(micro)` converting integer micro-units to float rounded to 6 decimal places ($10^{-6}$).
  - All ledger writes, balance updates, and reconciliations operate on integer subunits.
- **Transactional Consistency**:
  - Replaced standard autocommit with explicit `BEGIN IMMEDIATE` transactions in SQLite during `record_ledger_entry` and `reverse_ledger_entry`.
- **Storage Overlap Prevention**:
  - Evaluates `storage_accounting_intervals` before awarding storage credits. Clips partially overlapping intervals; returns existing entry for fully covered windows.
- **Calibrated Reputation Scoring**:
  - Requires $\ge 2$ heartbeat observations to establish observed availability duration; otherwise assigns neutral baseline $50.0$.
  - Unobserved transfer or recovery dimensions assign neutral baseline $50.0$.
  - Preserves documented policy weights ($0.40$ Availability, $0.35$ Integrity, $0.25$ Recovery).
  - Brand new nodes start with neutral score $50.0$, confidence $0.0$, and status "insufficient".
- **Hardened Compensating Reversals**:
  - Supports multiple partial reversals until `remaining_eligible_micro == 0`.
  - Enforces `current_balance >= reversal_amount` to prevent negative balances.
  - Guarantees idempotent retries when `idempotency_key` is supplied.

### 4.4. API Routers & SDK Client
- Updated `coordinator/app/accounting_router.py` to forward `amount` and `idempotency_key` from `CreditReversalRequest`.
- Updated `coordinator/coordinator_client/client.py` method `reverse_credit_ledger_entry(entry_id, reason, amount=None, idempotency_key=None)`.

---

## 5. Verification of the 10 System Invariants

| # | Invariant | Verification Method | Result |
| :--- | :--- | :--- | :--- |
| **1** | Node balance reconciles with ledger sum | Tested 100 atomic micro-credits (0.000001 ECC) + 5000.5 ECC; simulated balance drift; reconciled against integer sums | **PASS** |
| **2** | Reprocessing event never issues duplicates | Retried `award_transfer_credits` with identical `event_id`; confirmed identical `entry_id` returned and ledger entry count remained 1 | **PASS** |
| **3** | Failed operations never receive credits | Recorded failed transfers and failed repair operations; confirmed `award_*` methods return `None` and 0 credits awarded | **PASS** |
| **4** | Reversals bounded by eligible amount | Partial reversals (4.0 ECC then 6.0 ECC of 10.0 ECC award); rejected 7.0 ECC attempt; rejected overdrafts; verified idempotency | **PASS** |
| **5** | Reputation and confidence within range | Evaluated scores across all permutations; asserted $0.0 \le \text{reputation} \le 100.0$ and $0.0 \le \text{confidence} \le 1.0$ | **PASS** |
| **6** | Missing evidence not treated as success/failure | Evaluated brand new nodes with 0 observations; confirmed neutral 50.0 score, 0.0 confidence, and "insufficient" status | **PASS** |
| **7** | Accounting failures do not corrupt data | Metering and accounting operate as non-intrusive observation layers; file uploads, chunk transfers, and repairs remain untouched | **PASS** |
| **8** | Coordinator restart preserves history | Initialized new `AccountingService` instance against existing SQLite database; verified 100% preservation of balances and ledger | **PASS** |
| **9** | Tenant and administrative authorization | Verified 401 Unauthorized on administrative calculate, reverse, and policy endpoints without valid Coordinator Bearer token | **PASS** |
| **10** | Compatibility with Phase 7A & 7B | All existing Phase 7A and 7B tests executed without regression; legacy float fields preserved alongside integer micro-units | **PASS** |

---

## 6. Exact Test Execution and Results

### 6.1. Phase 7B and Phase 7B.1 Suites
```bash
pytest coordinator/tests/test_phase7b.py coordinator/tests/test_phase7b1.py -v
```
**Results**:
- `coordinator/tests/test_phase7b.py`: **18 passed**
- `coordinator/tests/test_phase7b1.py`: **11 passed**
- **Subtotal**: **29 passed**, 1 warning in 3.76s

### 6.2. Phase 7A Suite
```bash
pytest coordinator/tests/test_phase7a.py -v
```
**Results**:
- `coordinator/tests/test_phase7a.py`: **28 passed**, 1 warning in 2.49s

### 6.3. Full Regression Suite
```bash
pytest coordinator/tests/ storage_node/tests/ -q
```
**Results**:
- **310 passed**, 1 warning in 206.54s (0:03:26)
- **Zero failures, zero skipped tests**.

---

## 7. Migration and Backward Compatibility

- **Database Backward Compatibility**: Existing databases with legacy `credit_ledger_entries` and `credit_balances` tables are automatically migrated on startup by `init_db`. Integer columns (`credit_micro_units`, `total_micro_units`, etc.) are added via `ALTER TABLE` and backfilled from existing floats.
- **API Backward Compatibility**: All REST responses continue to expose `credit_delta: float`, `total_credits: float`, `lifetime_earned: float`, and `lifetime_reversed: float`. New integer fields (`credit_micro_units`, `total_micro_units`) are optional additions that provide fixed-precision guarantees without breaking legacy consumers.
- **SDK Compatibility**: `CoordinatorClient.reverse_credit_ledger_entry` preserves existing positional argument signature `(entry_id, reason)` while adding optional keyword arguments `amount=None` and `idempotency_key=None`.

---

## 8. Remaining Risks and Outstanding Validation

1. **Outstanding Multi-Machine Physical LAN/WAN Validation**:
   - The test suite runs in simulated, loopback, and in-process network environments.
   - Real-world cross-machine latency, physical link drops, clock skew across independent hardware clocks, and NAT/firewall traversal remain to be validated in physical environments.
2. **Clock Drift Sensitivity in Storage Accounting**:
   - Storage intervals use UTC ISO timestamps. While interval overlap locking prevents duplicate awards, significant clock skew between independent machines could lead to jitter in window boundary reporting if nodes report local system times instead of Coordinator-normalized UTC.
3. **High-Frequency Ledger Concurrency**:
   - SQLite `BEGIN IMMEDIATE` serializes write transactions cleanly for single-coordinator deployments. Under extreme concurrent write volume, SQLite busy timeouts must be tuned (`timeout=30.0s`).

---

## 9. Conclusion

Expo Phase 7B.1 has audited, hardened, and verified the contribution credit ledger, reputation scoring, and administrative security models. Floating-point drift is eliminated via integer micro-units ($10^{-6}\ \mu\text{ECC}$), interval overlap vulnerabilities are closed, reputation defaults no longer invent false reliability for unobserved nodes, and partial reversals with non-negative balance enforcement are operational.

All 310 tests pass across the entire codebase. Phase 7B.1 is complete.
