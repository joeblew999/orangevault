# Plan: Bitwarden-Compatible API Server on Cloudflare Workers

## Context

Vaultwarden is a full-featured Bitwarden-compatible server written in Rust, but its dependency tree (Rocket, Diesel, OpenSSL, Ring, Tokio full runtime) makes it impossible to compile to `wasm32-unknown-unknown`. Rather than attempting to port it, this plan designs a **new, purpose-built implementation** targeting Cloudflare Workers from day one, using D1 (edge SQLite), R2 (object storage), Durable Objects (WebSocket + stateful compute), and KV (caching).

The goal is full compatibility with official Bitwarden clients (web vault, browser extensions, desktop, mobile, CLI) by implementing the same REST API contract.

---

## Architecture Overview

```
                         Cloudflare Edge
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ┌─────────────┐    ┌──────┐    ┌────────────────┐  │
│  │   Worker     │───▶│  D1  │    │  Durable Object│  │
│  │  (API Router)│    │(SQLite)   │  (WebSocket    │  │
│  │             │    └──────┘    │   Notifications)│  │
│  │  - Auth     │                │                │  │
│  │  - Sync     │    ┌──────┐    │  Per-user DO    │  │
│  │  - CRUD     │───▶│  R2  │    │  with hibernate │  │
│  │  - 2FA      │    │(Files)│    └────────────────┘  │
│  │  - Orgs     │    └──────┘                        │
│  │             │                                    │
│  │             │    ┌──────┐                        │
│  │             │───▶│  KV  │                        │
│  │             │    │(Cache)│                        │
│  └─────────────┘    └──────┘                        │
│                                                     │
│  ┌─────────────┐                                    │
│  │ Cron Trigger│  (scheduled purge/cleanup jobs)    │
│  └─────────────┘                                    │
└─────────────────────────────────────────────────────┘
```

**Key design principle**: The server is **zero-knowledge**. It stores only encrypted blobs. All encryption/decryption happens client-side. The server's crypto responsibilities are limited to: password hash verification, JWT signing/validation, TOTP verification, and Send password hashing.

---

## Phase 0: Project Scaffolding & Crypto Foundation

### 0.1 Project Setup
- Initialize with `npm create cloudflare@latest -- --template cloudflare/workers-rs`
- Target: `wasm32-unknown-unknown`, Rust edition `2024`
- Build: `cargo install -q worker-build@^0.7 && worker-build --release` (proven by spike)
- Core deps: `worker = "0.7"`, `worker-macros = "0.7"`, `serde = "1"`, `serde_json = "1"`, `serde_repr = "0.1"`, `wasm-bindgen = "0.2"`, `js-sys = "0.3"`, `web-sys = "0.3"` (with `Crypto` feature)
- Use **workers-rs built-in Router** (not Axum -- smaller WASM binary, fewer compatibility issues)
- Structure:

```
src/
├── lib.rs              # Entry point, router setup, event handlers
├── auth/
│   ├── mod.rs          # JWT creation/validation, auth middleware
│   ├── claims.rs       # JWT claim structs (Login, Refresh, Invite, etc.)
│   └── guards.rs       # Auth extraction from headers
├── crypto/
│   ├── mod.rs          # Web Crypto API wrappers
│   ├── pbkdf2.rs       # PBKDF2-HMAC-SHA256 via SubtleCrypto
│   ├── rsa.rs          # RSA key management via SubtleCrypto
│   ├── hmac.rs         # HMAC operations
│   └── random.rs       # CSPRNG via crypto.getRandomValues()
├── api/
│   ├── mod.rs          # Route registration
│   ├── identity.rs     # POST /identity/connect/token (login, refresh, API key)
│   ├── accounts.rs     # /api/accounts/* (profile, password, KDF, keys)
│   ├── sync.rs         # GET /api/sync
│   ├── ciphers.rs      # /api/ciphers/* (CRUD, share, bulk ops)
│   ├── folders.rs      # /api/folders/* (CRUD)
│   ├── sends.rs        # /api/sends/* (create, access, file upload)
│   ├── organizations.rs# /api/organizations/* (org, members, collections, groups, policies)
│   ├── two_factor.rs   # /api/two-factor/* (TOTP, email, WebAuthn, recovery)
│   ├── icons.rs        # /icons/<domain>/icon.png (favicon proxy)
│   ├── emergency.rs    # /api/emergency-access/*
│   ├── events.rs       # /events/*
│   ├── notifications.rs# /notifications/hub (WebSocket via DO)
│   └── web.rs          # Static web vault serving (from R2 or KV)
├── middleware/
│   ├── mod.rs          # Middleware chain
│   ├── cors.rs         # CORS preflight + response headers
│   └── headers.rs      # Security headers, client version extraction
├── db/
│   ├── mod.rs          # D1 connection helpers, query builders, PRAGMA setup
│   ├── models.rs       # Rust structs matching DB schema (serde Deserialize)
│   └── schema.sql      # Canonical schema (applied via `wrangler d1 migrations`)
├── models/             # API request/response types (serde Serialize/Deserialize)
│   ├── mod.rs
│   ├── cipher.rs
│   ├── user.rs
│   ├── organization.rs
│   ├── send.rs
│   └── ...
├── error.rs            # Unified error type → HTTP responses
├── config.rs           # Environment/secret access
└── util.rs             # Shared helpers (UUID generation, date formatting)
```

### 0.2 Crypto Layer (Web Crypto API via `web-sys` / `js-sys`)

This is the most critical foundation. All crypto must go through the browser-standard Web Crypto API available in the Workers runtime.

| Vaultwarden Operation | Workers Implementation |
|---|---|
| **PBKDF2-HMAC-SHA256** (password hashing) | `crypto.subtle.importKey("raw", ...)` then `crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt, iterations}, ...)` |
| **RSA-2048 key generation** (JWT signing) | `crypto.subtle.generateKey({name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256"}, true, ["sign", "verify"])` |
| **RSA-SHA256 signing** (JWT) | `crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, data)` |
| **HMAC-SHA256** | `crypto.subtle.sign("HMAC", key, data)` |
| **HMAC-SHA1** (legacy TOTP) | `crypto.subtle.sign({name: "HMAC", hash: "SHA-1"}, key, data)` |
| **SHA-256 digest** | `crypto.subtle.digest("SHA-256", data)` |
| **CSPRNG** | `crypto.getRandomValues(new Uint8Array(n))` via `js_sys` |
| **Argon2id** | **Not available in Web Crypto.** Options: (a) use a pure-Rust WASM Argon2 crate like `argon2` compiled to WASM (risky — 64MB memory cost may exceed 128MB Worker limit), (b) only support PBKDF2 KDF for server-side operations (clients do their own Argon2), (c) proxy to an external Argon2 service. **Recommendation: (b)** — the server only needs to hash the *master password hash* it receives, not run Argon2 itself. Argon2 is client-side KDF. Server stores PBKDF2 hash of the client-provided hash. |

**RSA Key Persistence**: Generate RSA key pair on first request, export as JWK, store in KV (`RSA_PRIVATE_KEY`, `RSA_PUBLIC_KEY`) with no expiration. Load on each request.

**JWT Library**: Use `jsonwebtoken` crate if it compiles to WASM (it has a `rust_crypto` feature that avoids Ring). If not, implement JWT RS256 manually: base64url-encode header + claims, sign with `crypto.subtle.sign`, concatenate. This is straightforward since RS256 is just RSASSA-PKCS1-v1_5 with SHA-256.

**Alternative**: Use a pure-Rust JWT crate that compiles to WASM, or the [`jwt-simple`](https://crates.io/crates/jwt-simple) crate.

### 0.3 WASM-Compatible Dependency Audit

Must compile to `wasm32-unknown-unknown`:
- `serde`, `serde_json` -- yes
- `uuid` (v4 with `js` feature) -- yes
- `chrono` (with `wasmbind` feature) -- yes
- `base64`, `data-encoding` -- yes
- `worker` crate -- yes (that's the whole point)
- `totp-lite` -- likely yes (pure Rust, uses `hmac` + `sha1` traits -- need WASM-compatible backends)
- `serde_repr` -- yes, for enum-to-integer serialization (SignalR message types, Bitwarden enums)
- `rmpv` -- yes, for MessagePack value encoding (SignalR binary hub protocol). Vaultwarden uses `rmpv::encode::write_value` for notification frames
- `web-sys` (with `Crypto` feature) -- yes, for Web Crypto API + `crypto.getRandomValues()`
- `webauthn-rs` -- **unlikely** (depends on `ring`). Alternative: implement WebAuthn verification manually using Web Crypto, or use `webauthn-rs` with a `crypto` backend swap.

### 0.4 CORS Middleware

Bitwarden clients (web vault, browser extensions) make cross-origin requests. Every response must include CORS headers, and `OPTIONS` preflight must be handled globally.

```rust
fn cors_headers(origin: &str) -> Headers {
    let mut headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", origin)?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers",
        "Authorization, Content-Type, Accept, Device-Type, Bitwarden-Client-Name, Bitwarden-Client-Version")?;
    headers.set("Access-Control-Allow-Credentials", "true")?;
    headers.set("Access-Control-Max-Age", "86400")?;
    headers
}
```

- Register a global `OPTIONS` catch-all returning 204 with CORS headers
- Apply CORS headers to all responses via a wrapper around the router's response
- Validate `Origin` against configured `DOMAIN` (reject unexpected origins in production)

### 0.5 Error Response Format

Bitwarden clients expect a specific error JSON shape. All error responses must conform to this contract:

```json
{
  "error": "invalid_grant",
  "error_description": "Two factor required.",
  "ErrorModel": {
    "Message": "Two factor required.",
    "ValidationErrors": null,
    "ExceptionMessage": null,
    "ExceptionStackTrace": null,
    "InnerExceptionMessage": null,
    "Object": "error"
  },
  "TwoFactorProviders": [0],
  "Object": "error"
}
```

Implement a unified `AppError` enum that serializes to this shape. Identity endpoints use the OAuth `error`/`error_description` fields; API endpoints use `ErrorModel`. Getting this wrong causes clients to show cryptic errors or fail silently.

### 0.6 D1 Schema Management & Foreign Keys

**Migrations**: Use D1's built-in migration tooling (`wrangler d1 migrations create/apply`) rather than a custom in-app runner. Store migration SQL files in `migrations/` directory. This integrates with Wrangler's deployment flow and avoids reinventing migration tracking.

**Foreign Keys**: SQLite (and D1) does **not** enforce foreign key constraints by default. The schema uses `REFERENCES` throughout, but these are silently ignored without `PRAGMA foreign_keys = ON`. Two options:
- **(a) Application-enforced integrity** (recommended): Accept that FKs are documentation-only in D1. Enforce referential integrity in application code. This avoids a per-request PRAGMA and is more predictable.
- **(b) PRAGMA per request**: Issue `PRAGMA foreign_keys = ON` as the first statement in every D1 batch. Risk: if D1 ever resets this between batch statements, constraints become inconsistent.

**Recommendation**: Option (a). Treat FK declarations as schema documentation and enforce in code.

### 0.7 Request Context Pattern

`workers-rs` Router has limited middleware support. Define a `RequestContext` struct that carries auth state and bindings through the request lifecycle:

```rust
pub struct RequestContext {
    pub db: D1Database,
    pub kv: KvStore,
    pub r2: Bucket,
    pub env: Env,
    pub user: Option<AuthenticatedUser>,  // populated by auth guard
    pub client_info: ClientInfo,          // Bitwarden-Client-Name/Version
}

pub struct ClientInfo {
    pub name: Option<String>,    // "web", "browser", "desktop", "mobile", "cli"
    pub version: Option<String>, // e.g. "2024.1.0"
}
```

Auth-required routes call `RequestContext::authenticated(&self) -> Result<&AuthenticatedUser>` which returns 401 if `user` is `None`. This avoids scattered auth checks in individual handlers.

---

## Phase 1: Core Authentication (Identity API)

### Endpoints
| Priority | Method | Path | Purpose |
|----------|--------|------|---------|
| P0 | POST | `/identity/connect/token` | Login (password, refresh, client_credentials) |
| P0 | POST | `/accounts/prelogin` | Return user's KDF params |
| P0 | POST | `/identity/accounts/register` | User registration |
| P0 | GET | `/api/config` | Server configuration (feature flags, version, environment) |
| P0 | GET | `/alive`, `/api/alive` | Health check (return 200 OK, empty or `{"status":"ok"}`) |
| P1 | POST | `/identity/accounts/register/send-verification-email` | Email verification |
| P1 | POST | `/identity/accounts/register/finish` | Complete registration |

### `/api/config` Response

Clients fetch this on startup to discover server capabilities. Must return:
```json
{
  "version": "2024.1.0",
  "gitHash": "",
  "server": { "name": "orangevault", "url": "" },
  "environment": {
    "api": "https://vault.example.com/api",
    "identity": "https://vault.example.com/identity",
    "notifications": "https://vault.example.com/notifications",
    "sso": ""
  },
  "featureStates": {},
  "object": "config"
}
```

### Rate Limiting (Auth Endpoints)

Login brute-force protection is critical for a password manager. Implement rate limiting on `/identity/connect/token` and `/accounts/prelogin`:

- Track failed login attempts per email in D1 (or KV for lower latency):
  ```sql
  CREATE TABLE login_attempts (
    email TEXT NOT NULL,
    attempt_at TEXT NOT NULL,
    ip_address TEXT
  );
  CREATE INDEX idx_login_attempts_email ON login_attempts(email, attempt_at);
  ```
- After **5 failed attempts** in 15 minutes: add increasing delay (captcha challenge or 429 response)
- After **10 failed attempts** in 1 hour: lock account temporarily (15 min), return HTTP 429 with `Retry-After`
- Successful login resets the counter
- Purge old attempt records via cron job (Phase 7)

### Login Flow Implementation

```
Client                                    Worker
  │                                         │
  │─── POST /accounts/prelogin ───────────▶│
  │    { email }                            │
  │◀── { kdf:0, kdfIterations:600000 } ────│  (D1 lookup, or defaults if user missing)
  │                                         │
  │  [Client derives masterKey from         │
  │   password using KDF params,            │
  │   then hashes masterKey with PBKDF2     │
  │   to produce masterPasswordHash]        │
  │                                         │
  │─── POST /identity/connect/token ──────▶│
  │    grant_type=password                  │
  │    username=email                       │
  │    password=masterPasswordHash          │
  │    device_*=...                         │
  │                                         │
  │    [Worker: D1 lookup user by email]    │
  │    [Worker: PBKDF2 verify hash]         │
  │    [Worker: check 2FA requirement]      │
  │    [Worker: create/update Device in D1] │
  │    [Worker: sign JWT access + refresh]  │
  │                                         │
  │◀── { access_token, refresh_token,  ────│
  │      Key, PrivateKey, Kdf*, ... }       │
```

### D1 Schema (users table)
```sql
CREATE TABLE users (
  uuid TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash BLOB NOT NULL,       -- PBKDF2 output (32 bytes)
  salt BLOB NOT NULL,                -- 64 random bytes
  password_iterations INTEGER NOT NULL DEFAULT 600000,
  akey TEXT,                         -- encrypted user symmetric key
  private_key TEXT,                  -- encrypted RSA private key
  public_key TEXT,                   -- RSA public key
  security_stamp TEXT NOT NULL,      -- UUID, rotated on password change
  client_kdf_type INTEGER NOT NULL DEFAULT 0,
  client_kdf_iter INTEGER NOT NULL DEFAULT 600000,
  client_kdf_memory INTEGER,
  client_kdf_parallelism INTEGER,
  api_key TEXT,
  avatar_color TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  totp_recover TEXT,                 -- recovery code
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE devices (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  name TEXT NOT NULL,
  atype INTEGER NOT NULL,            -- device type enum
  push_uuid TEXT,
  push_token TEXT,
  refresh_token TEXT NOT NULL,       -- 64 random bytes, base64url
  twofactor_remember TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### JWT Implementation
- **Access token**: RS256, 2-hour expiry, claims: `{ sub, email, name, premium, sstamp, device, scope, amr, ... }`
- **Refresh token**: RS256, 30-day expiry (90 for mobile), claims: `{ sub (auth_method), device_token }`
- RSA private key stored in KV as JWK
- On cold start: load key from KV, import via `crypto.subtle.importKey("jwk", ...)`

---

## Phase 2: Vault CRUD & Sync

### Endpoints
| Priority | Method | Path |
|----------|--------|------|
| P0 | GET | `/api/sync` |
| P0 | GET/POST/PUT/DELETE | `/api/ciphers/*` (full CRUD, ~30 routes) |
| P0 | GET/POST/PUT/DELETE | `/api/folders/*` (4 routes) |
| P1 | POST/DELETE | `/api/ciphers/*/attachment/*` (~10 routes) |

### D1 Schema (vault tables)
```sql
CREATE TABLE ciphers (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT REFERENCES users(uuid),
  organization_uuid TEXT REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,           -- 1=Login, 2=Note, 3=Card, 4=Identity, 5=SSH
  name TEXT NOT NULL,               -- encrypted
  notes TEXT,                       -- encrypted
  fields TEXT,                      -- encrypted JSON
  data TEXT NOT NULL,               -- encrypted type-specific JSON
  key TEXT,                         -- cipher key (org ciphers)
  password_history TEXT,            -- encrypted JSON
  reprompt INTEGER DEFAULT 0,
  deleted_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE folders (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  name TEXT NOT NULL,               -- encrypted
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders(uuid),
  PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE favorites (
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  PRIMARY KEY (user_uuid, cipher_uuid)
);

CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  file_name TEXT,
  file_size INTEGER,
  akey TEXT                         -- encrypted attachment key
);
```

### Sync Response Assembly
The `/api/sync` endpoint is the most critical — clients call it on every app open. It must return:
```json
{
  "profile": { /* user profile + org memberships */ },
  "ciphers": [ /* all user ciphers + org ciphers user has access to */ ],
  "folders": [ /* all user folders */ ],
  "collections": [ /* all collections user has access to */ ],
  "policies": [ /* org policies */ ],
  "sends": [ /* all user sends */ ],
  "domains": { /* equivalent domain groups */ },
  "object": "sync"
}
```

This requires multiple D1 queries. Use **D1 batch** to run them in a single round-trip.

**D1 constraints to observe**:
- Max **100 bound parameters** per query — keep subqueries simple; avoid deeply nested IN clauses with many binds
- Max **1,000 queries per Worker invocation** (paid) / 50 (free) — sync batches count toward this
- Max **6 simultaneous D1 connections** per Worker — batch API uses a single connection
- Max **30s query duration** — complex org-cipher joins on large vaults should be monitored

**IMPORTANT**: Avoid deeply nested subqueries that compound bound parameters. The original approach of `WHERE uuid IN (SELECT ... WHERE ... IN (SELECT ...))` is fragile — it can exceed D1's 100 bound-parameter limit for users in many orgs. Instead, decompose into staged queries within the batch:

```rust
// Step 1: Batch the independent lookups
let results = db.batch(vec![
    db.prepare("SELECT * FROM users WHERE uuid = ?1").bind(&[user_id])?,
    db.prepare("SELECT * FROM ciphers WHERE user_uuid = ?1").bind(&[user_id])?,
    db.prepare("SELECT * FROM folders WHERE user_uuid = ?1").bind(&[user_id])?,
    db.prepare("SELECT * FROM sends WHERE user_uuid = ?1").bind(&[user_id])?,
    // Get user's org memberships (confirmed only)
    db.prepare("SELECT * FROM memberships WHERE user_uuid = ?1 AND status = 2").bind(&[user_id])?,
    // Get user's collection access
    db.prepare("SELECT collection_uuid FROM users_collections WHERE user_uuid = ?1").bind(&[user_id])?,
]).await?;

// Step 2: From memberships, determine which orgs grant access_all
// From collection UUIDs, fetch org ciphers in a second batch
// Keep IN-clause bind count within 100 by chunking if necessary
let org_uuids: Vec<&str> = /* extract from memberships where access_all=1 */;
let collection_uuids: Vec<&str> = /* extract from users_collections */;

// Build targeted queries for org ciphers (chunked if > 90 orgs/collections)
let org_cipher_results = db.batch(vec![
    db.prepare(&format!(
        "SELECT * FROM ciphers WHERE organization_uuid IN ({})",
        placeholders(org_uuids.len())
    )).bind(&org_uuids)?,
    db.prepare(&format!(
        "SELECT cipher_uuid FROM ciphers_collections WHERE collection_uuid IN ({})",
        placeholders(collection_uuids.len())
    )).bind(&collection_uuids)?,
]).await?;

// Step 3: Merge and deduplicate cipher lists in application code
```

### Equivalent Domains

The sync response `domains` field provides equivalent domain groups for autofill (e.g., google.com ↔ youtube.com ↔ gmail.com). Bitwarden defines a set of **global equivalent domains** (hardcoded, same as official server) plus optional **user-defined custom domains**.

```sql
CREATE TABLE equivalent_domains (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  global_equiv_domains TEXT,         -- JSON array of enabled global domain group indices
  custom_equiv_domains TEXT          -- JSON array of custom domain groups, e.g. [["a.com","b.com"]]
);
```

The global domain list should be a static constant in code (copy from Bitwarden's source). Sync response returns both global groups and user overrides.

### Attachments
- Binary files stored in **R2** at key: `attachments/{cipher_uuid}/{attachment_id}`
- Metadata (filename, size, encryption key) in D1 `attachments` table
- Upload: for files under 100MB, multipart form data → parse in Worker → write to R2. For larger files, consider R2 presigned upload URLs to bypass Worker memory/body-size limits.
- Download: generate R2 presigned URL (preferred — avoids streaming through the Worker) or stream from R2 for smaller files

---

## Phase 3: Organizations & Sharing

### D1 Schema
```sql
CREATE TABLE organizations (
  uuid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  billing_email TEXT NOT NULL,
  private_key TEXT,
  public_key TEXT
);

CREATE TABLE memberships (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  akey TEXT,                        -- user's org key (encrypted)
  atype INTEGER NOT NULL,           -- 0=Owner, 1=Admin, 2=User, 3=Manager
  status INTEGER NOT NULL,          -- 0=Invited, 1=Accepted, 2=Confirmed
  access_all INTEGER DEFAULT 0,
  external_id TEXT,
  reset_password_key TEXT
);

CREATE TABLE collections (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  name TEXT NOT NULL,               -- encrypted
  external_id TEXT
);

CREATE TABLE users_collections (
  user_uuid TEXT NOT NULL,
  collection_uuid TEXT NOT NULL,
  read_only INTEGER DEFAULT 0,
  hide_passwords INTEGER DEFAULT 0,
  manage INTEGER DEFAULT 0,
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE ciphers_collections (
  cipher_uuid TEXT NOT NULL,
  collection_uuid TEXT NOT NULL,
  PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE groups (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  name TEXT NOT NULL
);

CREATE TABLE groups_users (
  group_uuid TEXT NOT NULL,
  user_uuid TEXT NOT NULL,
  PRIMARY KEY (group_uuid, user_uuid)
);

CREATE TABLE collections_groups (
  collection_uuid TEXT NOT NULL,
  group_uuid TEXT NOT NULL,
  read_only INTEGER DEFAULT 0,
  hide_passwords INTEGER DEFAULT 0,
  PRIMARY KEY (collection_uuid, group_uuid)
);

CREATE TABLE org_policies (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,
  enabled INTEGER DEFAULT 0,
  data TEXT                         -- JSON policy config
);
```

### Permission Checks
Every cipher/collection operation must verify:
1. User is authenticated (JWT valid, security stamp matches)
2. For personal ciphers: `cipher.user_uuid == user.uuid`
3. For org ciphers: user has membership in org with correct status (Confirmed) and either `access_all=true` or explicit collection membership
4. Write operations: check `read_only` flag on collection membership
5. Admin operations: check `atype` (Owner=0, Admin=1)

Implement as a reusable `check_cipher_access(user_id, cipher_id, write_required) -> Result<()>` helper.

---

## Phase 4: Two-Factor Authentication

### Supported Methods (by priority)
| Priority | Method | Implementation Notes |
|----------|--------|---------------------|
| P0 | **TOTP** | Pure Rust `totp-lite` (if WASM-compatible) or manual HMAC-SHA1 via Web Crypto. Store base32 secret in D1. |
| P0 | **Recovery Codes** | Generate 20 random bytes, encode base32, store in `users.totp_recover`. |
| P1 | **Email OTP** | Generate 6-digit code, store with expiry in D1, send via external email service (see Phase 6). |
| P1 | **WebAuthn/FIDO2** | Challenge: needs `webauthn-rs` or manual implementation. Registration/authentication ceremony via Web Crypto for signature verification. |
| P2 | **Duo** | HTTP API calls to Duo. Use Workers `fetch()` for outbound requests. |
| P2 | **YubiKey** | OTP validation via Yubico cloud API (outbound fetch). |

### 2FA Login Flow
```
1. Login with password → server detects 2FA enabled
2. Return HTTP 400 with:
   { "error": "invalid_grant",
     "error_description": "Two factor required.",
     "TwoFactorProviders": [0, 1, ...],  // available methods
     "TwoFactorToken": "<JWT>" }         // short-lived token
3. Client re-submits with:
   twoFactorToken=<JWT>&twoFactorProvider=0&twoFactorRemember=1
4. Server validates 2FA code, issues access token
5. If twoFactorRemember=1, issue remember token (30 days)
```

### D1 Schema
```sql
CREATE TABLE two_factor (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  atype INTEGER NOT NULL,
  enabled INTEGER DEFAULT 1,
  data TEXT NOT NULL,               -- JSON provider data
  last_used INTEGER DEFAULT 0       -- Unix timestamp
);
```

---

## Phase 5: Sends (Secure Sharing)

### Endpoints (~12 routes)
Create, access (anonymous), update, delete text/file sends.

### D1 Schema
```sql
CREATE TABLE sends (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT REFERENCES users(uuid),
  organization_uuid TEXT REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,           -- 0=Text, 1=File
  name TEXT NOT NULL,               -- encrypted
  notes TEXT,                       -- encrypted
  data TEXT NOT NULL,               -- encrypted
  akey TEXT NOT NULL,               -- encrypted send key
  password_hash BLOB,              -- PBKDF2 hash if password-protected
  password_salt BLOB,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER DEFAULT 0,
  disabled INTEGER DEFAULT 0,
  hide_email INTEGER DEFAULT 0,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### File Sends
- File stored in R2 at `sends/{send_uuid}/{file_id}`
- Anonymous access: verify send password (if set) via PBKDF2, check expiry/access count, stream file from R2

---

## Phase 6: Real-Time Notifications (SignalR over Durable Objects)

> **Spike reference**: See `cf-signalr-example` for a proven Worker + SignalR implementation. The spike validates the DO patterns (Hibernation API, alarm-based ping, WebSocket lifecycle). However, the spike uses JSON hub protocol — Bitwarden clients require **MessagePack hub protocol** (matching Vaultwarden).

### SignalR Protocol — MessagePack Hub Protocol (Matching Vaultwarden)

Bitwarden clients use Microsoft's **SignalR MessagePack Hub Protocol** over WebSocket. This is what Vaultwarden implements. The handshake is JSON, but all subsequent messages are **binary MessagePack frames**.

**Key differences from the spike:**
- Handshake protocol field: `"messagepack"` not `"json"`
- Post-handshake messages: binary WebSocket frames (not text), using `BinaryMessageFormat` (VarInt length prefix + MessagePack payload)
- Need `rmpv` crate for MessagePack encoding (confirmed WASM-compatible)
- No `/notifications/hub/negotiate` endpoint — Vaultwarden omits it and clients handle this gracefully (direct WebSocket connection)

**Patterns reused from spike:**
- Hibernation API with `serialize_attachment`/`deserialize_attachment` for connection state
- DO alarms for 15-second server-initiated ping
- `web-sys` `Crypto` feature for random ID generation
- `websocket_close` / `websocket_error` lifecycle handlers

#### Connection Flow
```
Client                                        Worker / DO
  │                                              │
  │─── GET /notifications/hub ─────────────────▶│  (WebSocket upgrade, auth via query param or header)
  │    Connection: Upgrade                       │
  │    Upgrade: websocket                        │
  │                                              │
  │──▶ WS text: {"protocol":"messagepack",  ───▶│  (client handshake — JSON text frame)
  │              "version":1}\x1E                │
  │◀── WS binary: [0x7b, 0x7d, 0x1e]  ────────│  (server accepts — {}\x1E as bytes)
  │                                              │
  │    [All subsequent messages: binary frames]  │
  │    [BinaryMessageFormat: VarInt len + msgpack]│
  │                                              │
  │◀── WS binary: [len][msgpack array]  ───────│  (server push notification)
  │    payload = [1, {}, nil, "ReceiveMessage",  │
  │               [{ContextId, Type, Payload}]]  │
  │                                              │
  │◀── WS binary: [len][msgpack [6]]  ─────────│  (server ping, every 15s)
```

#### Binary Message Format (SignalR `BinaryMessageFormat`)
Post-handshake messages use a length-prefixed binary format:
1. **VarInt length prefix**: encodes the byte length of the MessagePack payload using variable-length encoding (7 bits per byte, high bit = continuation)
2. **MessagePack payload**: the actual message encoded as a MessagePack array

```rust
fn serialize(value: &rmpv::Value) -> Vec<u8> {
    let mut msgpack_buf = Vec::new();
    rmpv::encode::write_value(&mut msgpack_buf, value).unwrap();

    let mut output = Vec::new();
    // Write VarInt length prefix
    let mut len = msgpack_buf.len();
    loop {
        let mut byte = (len & 0x7F) as u8;
        len >>= 7;
        if len > 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if len == 0 { break; }
    }
    output.extend_from_slice(&msgpack_buf);
    output
}
```

#### MessagePack Message Structures
Notifications are MessagePack arrays (not maps). Matching Vaultwarden's format:

```rust
// Invocation (type 1) — server push notification
fn create_notification(notification_type: u8, context_id: &str) -> rmpv::Value {
    rmpv::Value::Array(vec![
        rmpv::Value::from(1),                    // type: Invocation
        rmpv::Value::Map(vec![]),                 // headers: empty map
        rmpv::Value::Nil,                         // invocationId: null (fire-and-forget)
        rmpv::Value::from("ReceiveMessage"),      // target
        rmpv::Value::Array(vec![                  // arguments
            rmpv::Value::Map(vec![
                (rmpv::Value::from("ContextId"), rmpv::Value::from(context_id)),
                (rmpv::Value::from("Type"), rmpv::Value::from(notification_type as i64)),
                (rmpv::Value::from("Payload"), rmpv::Value::Map(vec![])),
            ])
        ]),
    ])
}

// Ping (type 6) — keep-alive
fn create_ping() -> rmpv::Value {
    rmpv::Value::Array(vec![rmpv::Value::from(6)])
}
```

#### Notification Type Constants
```rust
pub enum NotificationType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,        // full vault resync
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
}
```

### Durable Object Architecture

Each user gets a Durable Object instance (keyed by user UUID). The DO handles WebSocket lifecycle, SignalR MessagePack framing, and ping keep-alive. The DO lifecycle patterns (Hibernation API, alarm-based ping, attachment state) are proven by the `cf-signalr-example` spike.

**Connection state** (survives DO hibernation via attachment serialization):
```rust
#[derive(Serialize, Deserialize)]
struct ConnectionState {
    handshake_complete: bool,
}
```

```rust
#[durable_object]
pub struct UserNotifier {
    state: State,
    env: Env,
}

impl DurableObject for UserNotifier {
    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        match url.path() {
            "/connect" => {
                // WebSocket upgrade (same pattern as spike)
                let pair = WebSocketPair::new()?;
                let server = pair.server;
                self.state.accept_web_socket(&server);
                server.serialize_attachment(&ConnectionState {
                    handshake_complete: false,
                })?;
                self.state.storage().set_alarm(Duration::from_secs(15)).await?;
                Response::from_websocket(pair.client)
            }
            "/notify" => {
                // Internal: Worker posts here after vault mutations
                let notification = req.json::<Notification>().await?;
                let msg = serialize(&create_notification(
                    notification.notification_type,
                    &notification.context_id,
                ));
                for socket in self.state.get_websockets() {
                    let state: ConnectionState = socket.deserialize_attachment()?;
                    if state.handshake_complete {
                        socket.send_with_bytes(&msg)?;  // binary frame
                    }
                }
                Response::ok("sent")
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        let mut state: ConnectionState = ws.deserialize_attachment()?;
        if !state.handshake_complete {
            // First message is JSON text: {"protocol":"messagepack","version":1}\x1E
            // Validate protocol field == "messagepack"
            // Respond with {}\x1E as bytes: [0x7b, 0x7d, 0x1e]
            ws.send_with_bytes(&[0x7b, 0x7d, 0x1e])?;
            state.handshake_complete = true;
            ws.serialize_attachment(&state)?;
            return Ok(());
        }
        // Post-handshake: binary MessagePack frames
        // Client may send Ping ([6]) — no response needed
        // Bitwarden clients don't send invocations to the notification hub
        Ok(())
    }

    async fn websocket_close(&self, _ws: WebSocket, _code: usize, _reason: String, _was_clean: bool) -> Result<()> {
        Ok(()) // Hibernation API handles cleanup
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        // Send SignalR Ping as binary MessagePack — every 15s (same cadence as spike)
        let ping = serialize(&create_ping());
        for socket in self.state.get_websockets() {
            let state: ConnectionState = socket.deserialize_attachment()?;
            if state.handshake_complete {
                socket.send_with_bytes(&ping)?;
            }
        }
        // Re-arm alarm
        self.state.storage().set_alarm(Duration::from_secs(15)).await?;
        Response::ok("")
    }
}
```

### Triggering Notifications
After any vault mutation in the main Worker, send an internal fetch to the user's DO:
```rust
let do_ns = env.durable_object("USER_NOTIFIER")?;
let stub = do_ns.id_from_name(&user_uuid)?.get_stub()?;
stub.fetch_with_request(Request::new_with_init(
    "/notify",
    RequestInit::new().with_method(Method::Post).with_body(serde_json::to_string(&Notification {
        context_id: cipher_id.to_string(),
        notification_type: NotificationType::SyncCipherUpdate as u8,
    })?),
)?).await?;
```

For organization mutations, fan out to all confirmed org members:
```rust
let members = db.prepare("SELECT user_uuid FROM memberships WHERE org_uuid = ?1 AND status = 2")
    .bind(&[&org_uuid])?.all().await?;
for member in members {
    // Send notification to each member's DO
}
```

---

## Phase 7: Background Jobs (Cron Triggers)

### wrangler.toml
```toml
[triggers]
crons = [
  "0 */6 * * *",    # Every 6 hours: purge expired sends
  "0 0 * * *",      # Daily: purge trashed ciphers (30+ days old)
  "0 */12 * * *",   # Every 12 hours: purge expired auth requests + old login_attempts
  "0 1 * * *",      # Daily: emergency access timeout processing
  "0 2 * * *",      # Daily: event log cleanup
]
```

### Implementation
```rust
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, ctx: ScheduleContext) {
    let db = env.d1("DB").unwrap();
    match event.cron().as_str() {
        "0 */6 * * *" => purge_expired_sends(&db).await,
        "0 0 * * *"   => purge_old_trash(&db).await,
        // ...
    }
}
```

---

## Phase 8: Remaining Features

### Emergency Access (~15 routes)
- Invite, accept, confirm, initiate, approve, reject, view, takeover
- Requires timed state machine (wait_time_days) -- use DO alarms

### Events/Audit Logging (~4 routes)
- Store events in D1, query by org/cipher/user
- Purge via cron trigger

### Icons/Favicons
- Proxy: `GET /icons/<domain>/icon.png`
- Fetch from external sites via `Fetch` API
- Cache in KV with 30-day TTL
- HTML parsing for `<link rel="icon">` -- use a lightweight WASM-compatible HTML parser

### Admin Panel
- Optional, lower priority
- Serve admin SPA from R2/KV
- Admin auth via token in secrets

### Web Vault Serving
- Store web vault static files in R2
- Serve via catch-all route
- Or: use Cloudflare Pages for the static web vault, Workers for the API
- **Security headers** for HTML responses: `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Strict-Transport-Security: max-age=31536000`

### Email
- Workers cannot do SMTP directly (no raw TCP for SMTP)
- Options: (a) Use a transactional email API (SendGrid, Mailgun, Resend, Postmark) via `fetch()`, (b) Use Cloudflare Email Workers (send-only), (c) Queue emails to a Cloudflare Queue consumed by an external service
- **Recommendation**: Use Resend/SendGrid HTTP API -- simple `fetch()` call with API key from secrets

### SSO/OIDC
- OIDC authorization code flow via outbound `fetch()` to provider
- Store SSO state in KV with short TTL
- Token exchange and user creation/linking in D1

---

## Phase Implementation Order

| Phase | Scope | Estimated Complexity | Enables |
|-------|-------|---------------------|---------|
| **0** | Scaffolding + crypto + CORS + error format + request context | High (crypto is fiddly in WASM) | Everything |
| **1** | Auth (login, register, prelogin, refresh, `/api/config`, `/alive`, rate limiting) | High | Client can connect and authenticate |
| **2** | Ciphers + Folders + Sync + Equivalent Domains | High (largest surface area) | Basic vault usage |
| **3** | Organizations + Collections | Medium-High | Team/sharing features |
| **4** | Two-Factor Auth | Medium | Security hardening |
| **5** | Sends | Medium | Secure sharing |
| **6** | SignalR notifications (MessagePack hub protocol over DO, no negotiate) | **Medium** (DO patterns proven by spike, MessagePack framing is straightforward) | Real-time sync |
| **7** | Cron jobs | Low | Maintenance/cleanup |
| **8** | Emergency, Events, Icons, Admin, Email, SSO | Medium (breadth) | Feature parity |

---

## Key Risks & Mitigations

### 1. CPU Time Limit (30s per request)
- **Risk**: PBKDF2 with 600,000 iterations on server side could be slow in WASM
- **Mitigation**: Benchmark early in Phase 0. If too slow, reduce server-side iterations (server is hashing the *client's hash*, not the raw password -- fewer iterations acceptable). Vaultwarden uses only 1 server-side PBKDF2 iteration for password verification (the 600K iterations are client-side).
- **CRITICAL FINDING**: Vaultwarden's `crypto::verify_password()` uses `ring::pbkdf2::verify` with `PBKDF2_ITERATIONS = NonZeroU32::new(1)` -- the server only does **1 PBKDF2 iteration** for verification, not 600K. The heavy KDF is purely client-side. This is fine for Workers.

### 2. D1 Limits
- **Risk**: D1 has hard limits that affect design decisions
- **Actual limits** (from [Cloudflare docs](https://developers.cloudflare.com/d1/platform/limits/)):
  - Max row/string/BLOB size: **2 MB** (not ~1MB as previously assumed — individual cipher entries are typically a few KB, so this is a non-issue for normal usage)
  - Max bound parameters per query: **100** — complex org-cipher queries with many IN clauses must stay within this; decompose into multiple simpler queries if needed
  - Max queries per Worker invocation: **1,000** (paid) / **50** (free) — the free tier is very restrictive; sync + CRUD in a single request should be counted carefully
  - Max database size: **10 GB** (paid) / **500 MB** (free)
  - Max SQL statement length: **100 KB**
  - Max columns per table: **100** (current schema is well within this)
  - Max simultaneous connections per Worker: **6**
  - Max LIKE/GLOB pattern: **50 bytes** (relevant if vault search is ever server-side)
  - Single-threaded: each D1 database processes queries sequentially — batch API helps but doesn't parallelize
- **Mitigation**: For the rare case where a cipher's encrypted data exceeds 2MB (e.g., very large secure notes), store the `data` column in R2 and keep only a pointer in D1. The 100 bound-parameter limit is the more practical concern — keep queries simple and use batch for grouping, not for complex multi-bind statements. Free-tier query limit (50/invocation) may require a paid plan for production use.

### 3. WASM Binary Size
- **Risk**: Too many dependencies bloat the WASM module past Workers limits
- **Mitigation**: Minimize dependencies. Use `opt-level = "z"`, `lto = true`, `codegen-units = 1`. Feature-gate optional functionality. Target < 5MB compressed.

### 4. WebAuthn Without Ring
- **Risk**: `webauthn-rs` depends on `ring` which doesn't compile to WASM
- **Mitigation**: Implement FIDO2 attestation/assertion verification manually using Web Crypto API for signature verification (ECDSA P-256 or RSA). This is a contained scope -- only need to verify signatures and parse CBOR attestation objects.

### 5. JWT Without Ring
- **Risk**: `jsonwebtoken` crate's default features pull in `ring`
- **Mitigation**: Use `jsonwebtoken` with `features = ["use_pem", "rust_crypto"]` which uses `rsa` + `sha2` crates instead of ring. Alternatively, build JWT manually with Web Crypto `RSASSA-PKCS1-v1_5` signing.

### 6. Cold Start Latency
- **Risk**: Loading RSA keys from KV on every cold start adds latency
- **Mitigation**: KV reads are fast (~10ms). RSA key import via Web Crypto is also fast. Total cold start overhead should be < 50ms. Can also use Worker global scope caching (globals *can* survive across requests in the same isolate, but aren't guaranteed — treat as a best-effort cache).

### 7. SignalR Protocol Complexity — PARTIALLY MITIGATED BY SPIKE
- **Risk**: Bitwarden clients require SignalR **MessagePack Hub Protocol** (binary frames), not JSON. The `cf-signalr-example` spike proves the DO patterns work (Hibernation API, alarm-based ping, WebSocket lifecycle) but uses JSON hub protocol — the wire format must be swapped to binary MessagePack to match Vaultwarden.
- **Remaining work**: (a) Switch handshake to accept `"messagepack"` protocol, (b) encode all post-handshake messages using `rmpv` + VarInt length prefix, (c) send as binary WebSocket frames via `send_with_bytes`. The message structures (Invocation array, Ping array) are straightforward — Vaultwarden's `create_update()` function is the reference.
- **Mitigation**: Port the spike's DO lifecycle patterns directly. Replace JSON encoding with the `serialize()` / `create_notification()` functions from the plan. Verify with `rmpv` that it compiles to WASM (likely yes — pure Rust). Test with Bitwarden web vault DevTools → Network → WS tab to verify binary frames are received and parsed.

### 8. RSA Key Persistence Across Isolates
- **Risk**: Worker globals are not guaranteed to persist across requests. If the RSA key is only cached in a global variable, some requests may need a KV read. This is fine for latency (~10ms) but must be accounted for in request handling — every handler must handle the "key not loaded yet" case.
- **Mitigation**: Lazy-load pattern: check global, if missing read from KV and import. KV reads in Workers are consistently fast. Alternatively, consider storing the key in a Durable Object singleton for guaranteed persistence, at the cost of routing all JWT operations through the DO.

---

## wrangler.toml Configuration

```toml
name = "orangevault"
main = "build/worker/shim.mjs"
compatibility_date = "2026-04-01"

[build]
command = "cargo install -q worker-build@^0.7 && worker-build --release"

[[d1_databases]]
binding = "DB"
database_name = "vaultwarden"
database_id = "<auto-generated>"

[[r2_buckets]]
binding = "FILES"
bucket_name = "vaultwarden-files"

[[kv_namespaces]]
binding = "CACHE"
id = "<auto-generated>"

[[durable_objects.bindings]]
name = "USER_NOTIFIER"
class_name = "UserNotifier"

[[migrations]]
tag = "v1"
new_classes = ["UserNotifier"]

[triggers]
crons = ["0 */6 * * *", "0 0 * * *", "0 */12 * * *"]

[vars]
DOMAIN = "https://vault.example.com"
SIGNUPS_ALLOWED = "true"
WEB_VAULT_ENABLED = "true"

# Secrets (set via `wrangler secret put`):
# ADMIN_TOKEN, SMTP_API_KEY, RSA_PRIVATE_KEY_JWK (auto-generated on first run)
```

---

## Verification / Testing Strategy

### 1. Unit Tests
- `wasm-bindgen-test` for crypto functions (PBKDF2 output matches known test vectors, JWT round-trips)
- Error response serialization matches Bitwarden's expected format
- SignalR message encoding/framing round-trips correctly

### 2. Integration Tests (CI)
- **Framework**: Vitest + Miniflare 4 (proven by `cf-signalr-example` spike)
  - TypeScript test files in `integration-tests/`
  - Miniflare loads compiled WASM binary, simulates DO locally
  - Test helpers for HTTP requests and WebSocket connection + SignalR handshake
- Automated test suite hitting all implemented endpoints
- Test both success paths and error paths (401, 403, 404, 429 for rate limiting)
- SignalR-specific tests: handshake, binary MessagePack frame parsing, ping keep-alive
- Use Bitwarden CLI (`bw`) as an automated integration test client:
  ```bash
  bw config server http://localhost:8787
  bw register --email test@test.com --password test1234
  bw login test@test.com test1234
  bw sync
  bw create item '{"type":1,"name":"test","login":{"username":"u","password":"p"}}'
  bw list items
  bw delete item <id>
  ```

### 3. Client Compatibility (Manual)
Point official Bitwarden web vault at the Worker URL, test:
- Register new account
- Login (password flow)
- Create/edit/delete cipher
- Full sync
- Folder CRUD
- Logout + refresh token flow
- WebSocket connection (verify SignalR handshake completes in DevTools → Network → WS)
- `/api/config` returns expected shape (check DevTools → Network on app load)

### 4. Load Testing
- Verify sync endpoint stays under 30s CPU time with realistic vault sizes (100, 1000, 10000 ciphers)
- Verify D1 query count per sync stays well under 1,000 limit

### 5. Crypto Verification
- Compare PBKDF2/HMAC outputs against Vaultwarden's test suite to ensure bit-for-bit compatibility
- Verify JWT tokens produced by orangevault are accepted by Bitwarden clients (and vice versa for refresh)

---

## Total API Surface

Based on Vaultwarden analysis: **~200+ distinct route handlers** across all modules. A minimum viable product (Phases 0-2) covers ~50 routes and enables basic vault usage with any Bitwarden client.
