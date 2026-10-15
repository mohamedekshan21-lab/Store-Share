# Store-Share Secure JWT Authentication & Role-Based Access Control (RBAC) Architecture

## 1. Architectural Overview

Store-Share is a decentralized, zero-knowledge distributed storage network. The authentication architecture introduces a human user authentication and authorization layer based on **PyJWT** and **Argon2id** while strictly preserving backward compatibility with existing storage node daemon machine authentication, Phase 8B provider HMAC sessions, reverse WebSocket relays, and client-side encryption.

```
                              ┌───────────────────────────────────┐
                              │     Human Users / Browser UI      │
                              └─────────────────┬─────────────────┘
                                                │
                               Authorization: Bearer <JWT>
                               or Cookie: expo_jwt (HttpOnly)
                                                ▼
┌────────────────────────┐            ┌───────────────────────────────────┐
│ Storage Node Daemons   ├───────────►│       FastAPI Coordinator         │
│ & Client Core Daemons  │            │   Unified Auth & RBAC Gatekeeper   │
└────────────────────────┘            └─────────────────┬─────────────────┘
  X-Auth-Token: <machine_token>                         │
                                                        ▼
                                      ┌───────────────────────────────────┐
                                      │      SQLite Metadata Store        │
                                      │  • users (Argon2id, role_version) │
                                      │  • revoked_tokens (jti blacklist) │
                                      │  • provider_credentials & sessions│
                                      └───────────────────────────────────┘
```

### Core Security Invariants

1. **Zero-Knowledge Guarantee**:
   All consumer files are encrypted client-side using **AES-256-GCM** before distribution into Cauchy Reed-Solomon shards or replicas. Neither the Coordinator, nor Administrators, nor Storage Providers possess consumer Data Encryption Keys (DEKs), Key Encryption Keys (KEKs), or plaintext file contents. File keys and plaintext are **NEVER** stored in database tables, logged, or encoded within JWT claims.
2. **Dual Authentication Path**:
   - **Human Users**: Authenticate via `POST /auth/login` using credentials (username or email + password), validated against Argon2id hashes, and issued signed JWTs (`HS256`).
   - **Machine Daemons (Storage Nodes)**: Authenticate using pre-shared machine tokens (`X-Auth-Token`) via `verify_coordinator_auth` for low-overhead heartbeats, capacity reporting, and block registration.
3. **Immediate Role Revocation via `role_version`**:
   Stateless JWTs inherently suffer from revocation lag. Store-Share addresses this by embedding a monotonically increasing `role_version` in both the user database record and the JWT claims. Whenever an administrator changes a user's role or updates account status (active/deactivated), `role_version` is incremented. Any pre-existing token presenting an older `role_version` is rejected with `401 Unauthorized` on its next request.
4. **Token Blacklisting**:
   `POST /auth/logout` explicitly records the unique token identifier (`jti`) into a persistent `revoked_tokens` table, terminating browser sessions immediately even before expiration.

---

## 2. Required User Roles & Server-Side Enforcement

### 1. ADMIN
- **Cluster Dashboard**: Inspect cluster-wide capacity, online nodes, traffic, and aggregate metrics.
- **Node Lifecycle**: View all storage nodes, configure scheduling, initiate safe node draining, and monitor migration status.
- **Provider Enrollment**: Manage user accounts, promote users to providers, assign authorized `provider_id` scopes, activate/deactivate accounts.
- **Accounting & Policy**: View cluster-wide ECC credit balances, update contribution policies, trigger scheduled or on-demand reconciliation.
- **Reconciliation & Auditing**: Run reconciliation sweeps to detect stalled deletions, orphaned chunks, or under-replicated files.
- *Strict Boundary*: Administrators **cannot** inspect or download consumer plaintext files or decrypt stored chunks.

### 2. PROVIDER
- **Provider Dashboard**: Access `/provider/overview` to view total quota, verified stored bytes, and physical disk utilization across owned nodes.
- **Storage Node Operations**: View own nodes, toggle scheduling on own nodes, and initiate authorized safe-drain workflows.
- **Accounting & Credits**: View own nodes' ECC credit balances, lifetime earning summaries, and objective reputation scores.
- *Strict Boundary*: Providers **cannot** access or control nodes belonging to other providers (`403 Forbidden`), cannot modify global accounting policy, and cannot access consumer file catalogs.

### 3. CONSUMER
- **File Management**: Register logical file manifests, inspect own file metadata, download encrypted chunks, and trigger logical deletions.
- **Client-Side Workflow**: Performs client-side AES-256-GCM encryption/decryption and Cauchy Reed-Solomon erasure coding.
- *Strict Boundary*: Consumers **cannot** access administrator endpoints, cannot access provider management dashboards, cannot access other consumers' files (`403 Forbidden`), and cannot control storage nodes.

---

## 3. Role-to-Endpoint Permission Matrix

| HTTP Method | Route / Endpoint Path | Minimum Role Required | Machine Daemon Allowed | Ownership / Scope Enforced |
|---|---|---|---|---|
| `POST` | `/auth/register` | Public | No | Defaults strictly to `consumer` |
| `POST` | `/auth/login` | Public | No | Verifies Argon2id password hash |
| `GET` | `/auth/me` | Consumer | No | Returns authenticated user profile |
| `POST` | `/auth/logout` | Consumer | No | Revokes token `jti` in blacklist |
| `GET` | `/auth/admin/users` | **Admin** | No | Cluster-wide user account audit |
| `POST` | `/auth/admin/users/{id}/role` | **Admin** | No | Updates role and provider binding |
| `POST` | `/auth/admin/users/{id}/status` | **Admin** | No | Activates or deactivates account |
| `GET` | `/nodes` | Consumer | Yes | Public topology and reachability |
| `POST` | `/nodes/register` | Admin | Yes | Storage node enrollment |
| `DELETE` | `/nodes/{node_id}` | Admin / Provider | Yes | Provider must own node (`provider_id`) |
| `POST` | `/nodes/{node_id}/heartbeat` | Machine | Yes | Verifies `X-Auth-Token` |
| `GET` | `/catalog/files` | Consumer / Admin | Yes | Consumer sees own; Admin sees all |
| `POST` | `/catalog/files` | Consumer / Admin | Yes | Registers file owned by authenticated user |
| `GET` | `/catalog/files/{file_id}` | Consumer / Admin | Yes | Strictly enforces `owner_id` |
| `DELETE` | `/catalog/files/{file_id}` | Consumer / Admin | Yes | Strictly enforces `owner_id` |
| `POST` | `/catalog/reconcile` | **Admin** | Yes | Dry-run or durable cleanup |
| `GET` | `/provider/overview` | Provider / Admin | Yes | Scoped to caller's `provider_id` |
| `GET` | `/provider/nodes` | Provider / Admin | Yes | Scoped to caller's `provider_id` |
| `GET` | `/provider/nodes/{id}/detail`| Provider / Admin | Yes | Verifies node belongs to provider |
| `POST` | `/provider/nodes/{id}/drain` | Provider / Admin | Yes | Redundancy safety gate verified |
| `GET` | `/credits/nodes/{id}/balance` | Provider / Admin | Yes | Node must belong to provider |
| `GET` | `/credits/nodes/{id}/ledger` | Provider / Admin | Yes | Node must belong to provider |
| `GET` | `/reputation/nodes/{id}` | Provider / Admin | Yes | Node must belong to provider |
| `GET` | `/accounting/policy` | Public / Consumer | Yes | Read-only policy inspection |
| `PUT` | `/accounting/policy` | **Admin** | Yes | Policy parameter updates |
| `GET` | `/accounting/cluster/summary`| Provider / Admin | Yes | Consumer forbidden |
| `POST` | `/accounting/credits/calculate`| **Admin** | Yes | Reconciles ECC credits |
| `POST` | `/accounting/credits/reverse` | **Admin** | Yes | Reverses erroneous credit award |

---

## 4. Database Schema & Migration

Database initialization in `coordinator/app/database.py` manages tables and schema migrations idempotently via `PRAGMA user_version`.

```sql
-- Human User Accounts
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'consumer',
    is_active INTEGER NOT NULL DEFAULT 1,
    provider_id TEXT,
    role_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider_id);

-- Token Revocation Blacklist
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    reason TEXT DEFAULT 'logout'
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);
```

---

## 5. Browser Session & Frontend Security

1. **Cookie Configuration**:
   - `expo_jwt`: Stored with `HttpOnly=True`, `SameSite=Lax`, and `Secure` (in HTTPS production). JavaScript cannot read this cookie, eliminating XSS token theft.
   - Session storage fallback: The frontend client stores the access token in memory (`sessionStorage`) to support multi-tab operations while preventing persistent credential leakage.
2. **CSRF Protection**:
   - `expo_csrf`: A secure, cryptographically random CSRF token issued at login. State-changing requests (`POST`, `PUT`, `DELETE`, `PATCH`) using cookie credentials must supply a matching `X-CSRF-Token` header.
3. **CORS Hardening**:
   - `CORSMiddleware` explicitly allows trusted frontend origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, `http://127.0.0.1:5173`) with `allow_credentials=True`. Wildcard origins (`*`) are disallowed.

---

## 6. Local Setup and Role Verification Guide

### 1. Provision the Initial Administrator
Run the secure bootstrap script to create the master administrator account without hardcoding credentials in source code:

```bash
python -m coordinator.bootstrap_admin --username admin --email admin@storeshare.net
# Enter a secure password (minimum 8 characters) when prompted
```

### 2. Start the Coordinator
```bash
python -m uvicorn coordinator.app.main:app --host 127.0.0.1 --port 9000 --reload
```

### 3. Start the Frontend Dev Server
```bash
cd frontend
npm install
npm run dev
# Accessible at http://localhost:3000/
```

### 4. Testing All Three Human Roles in the UI
The frontend includes a quick persona switcher in the navigation bar (`ADM`, `PRV`, `CNS`) and interactive authentication modals:

1. **Sign in as Administrator (`admin`)**:
   - Access **User Accounts**: promote users, assign provider IDs, or toggle user status.
   - Access **Cluster Overview**, **Storage Nodes**, **Self-Healing & Repair**, and **Accounting & Policy**.
2. **Sign in as Provider (`provider_alpha`)**:
   - View **Provider Overview**, **My Storage Nodes**, and **My Capacity & Credits**.
   - Notice that administrative tabs (User Accounts, Self-Healing) and consumer file registers are inaccessible.
   - Authorized safe-drain operations can only be initiated on nodes bound to `provider-primary-alpha`.
3. **Sign in as Consumer (`alice`)**:
   - Access **My Files** to upload, download, and delete files.
   - Notice that cluster management, nodes, repair, and accounting tabs are completely hidden, and direct API calls return `403 Forbidden`.
