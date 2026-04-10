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
- Initialize with `cargo generate cloudflare/workers-rs`
- Target: `wasm32-unknown-unknown`
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
├── db/
│   ├── mod.rs          # D1 connection helpers, query builders
│   ├── models.rs       # Rust structs matching DB schema (serde Deserialize)
│   └── migrations.rs   # SQL migration runner
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
- `webauthn-rs` -- **unlikely** (depends on `ring`). Alternative: implement WebAuthn verification manually using Web Crypto, or use `webauthn-rs` with a `crypto` backend swap.

---

## Phase 1: Core Authentication (Identity API)

### Endpoints
| Priority | Method | Path | Purpose |
|----------|--------|------|---------|
| P0 | POST | `/identity/connect/token` | Login (password, refresh, client_credentials) |
| P0 | POST | `/accounts/prelogin` | Return user's KDF params |
| P0 | POST | `/identity/accounts/register` | User registration |
| P1 | POST | `/identity/accounts/register/send-verification-email` | Email verification |
| P1 | POST | `/identity/accounts/register/finish` | Complete registration |

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

This requires multiple D1 queries. Use **D1 batch** to run them in a single round-trip:
```rust
let results = db.batch(vec![
    db.prepare("SELECT * FROM users WHERE uuid = ?").bind(&[user_id])?,
    db.prepare("SELECT * FROM ciphers WHERE user_uuid = ? OR uuid IN (SELECT cipher_uuid FROM ciphers_collections WHERE collection_uuid IN (SELECT collection_uuid FROM users_collections WHERE user_uuid = ?))").bind(&[user_id, user_id])?,
    db.prepare("SELECT * FROM folders WHERE user_uuid = ?").bind(&[user_id])?,
    // ... collections, policies, sends
]).await?;
```

### Attachments
- Binary files stored in **R2** at key: `attachments/{cipher_uuid}/{attachment_id}`
- Metadata (filename, size, encryption key) in D1 `attachments` table
- Upload via multipart form data → parse in Worker → stream to R2
- Download: generate time-limited URL or stream from R2

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

## Phase 6: Real-Time Notifications (Durable Objects)

### Architecture
Each user gets a Durable Object instance (keyed by user UUID). When a vault mutation occurs (cipher create/update/delete, folder change, etc.), the Worker sends a message to the user's DO, which broadcasts to all connected WebSocket clients.

```rust
#[durable_object]
pub struct UserNotifier {
    state: State,
    env: Env,
}

impl DurableObject for UserNotifier {
    // Accept WebSocket connections with hibernation
    async fn fetch(&self, req: Request) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        self.state.accept_websocket(&pair.server);
        pair.server.serialize_attachment(&UserWsState { ... })?;
        Response::from_websocket(pair.client)
    }

    // Broadcast mutation notifications
    async fn websocket_message(&self, ws: WebSocket, msg: WebSocketIncomingMessage) -> Result<()> {
        // Handle incoming commands or broadcast to all connected sockets
        for socket in self.state.get_websockets() {
            socket.send_with_str(&notification_json)?;
        }
        Ok(())
    }
}
```

### Notification Types (MessagePack or JSON)
- `SyncCipherUpdate`, `SyncCipherDelete`, `SyncCipherCreate`
- `SyncFolderUpdate`, `SyncFolderDelete`, `SyncFolderCreate`
- `SyncVault` (full resync needed)
- `SyncOrgKeys`, `SyncSettings`
- `AuthRequest`, `AuthRequestResponse`
- `LogOut`

### Triggering Notifications
After any vault mutation in the main Worker, send an internal fetch to the user's DO:
```rust
let do_ns = env.durable_object("USER_NOTIFIER")?;
let stub = do_ns.id_from_name(&user_uuid)?.get_stub()?;
stub.fetch_with_str(&format!("/notify?type=SyncCipherUpdate&cipher_id={}", cipher_id)).await?;
```

---

## Phase 7: Background Jobs (Cron Triggers)

### wrangler.toml
```toml
[triggers]
crons = [
  "0 */6 * * *",    # Every 6 hours: purge expired sends
  "0 0 * * *",      # Daily: purge trashed ciphers (30+ days old)
  "0 */12 * * *",   # Every 12 hours: purge expired auth requests
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
| **0** | Scaffolding + crypto layer | High (crypto is fiddly in WASM) | Everything |
| **1** | Auth (login, register, prelogin, refresh) | High | Client can authenticate |
| **2** | Ciphers + Folders + Sync | High (largest surface area) | Basic vault usage |
| **3** | Organizations + Collections | Medium-High | Team/sharing features |
| **4** | Two-Factor Auth | Medium | Security hardening |
| **5** | Sends | Medium | Secure sharing |
| **6** | WebSocket notifications | Medium | Real-time sync |
| **7** | Cron jobs | Low | Maintenance/cleanup |
| **8** | Emergency, Events, Icons, Admin, Email, SSO | Medium (breadth) | Feature parity |

---

## Key Risks & Mitigations

### 1. CPU Time Limit (30s per request)
- **Risk**: PBKDF2 with 600,000 iterations on server side could be slow in WASM
- **Mitigation**: Benchmark early in Phase 0. If too slow, reduce server-side iterations (server is hashing the *client's hash*, not the raw password -- fewer iterations acceptable). Vaultwarden uses only 1 server-side PBKDF2 iteration for password verification (the 600K iterations are client-side).
- **CRITICAL FINDING**: Vaultwarden's `crypto::verify_password()` uses `ring::pbkdf2::verify` with `PBKDF2_ITERATIONS = NonZeroU32::new(1)` -- the server only does **1 PBKDF2 iteration** for verification, not 600K. The heavy KDF is purely client-side. This is fine for Workers.

### 2. D1 Limits
- **Risk**: D1 has row-size limits and query complexity limits
- **Mitigation**: Encrypted cipher data can be large. If a single cipher exceeds D1's row limit (~1MB), store the `data` column in R2 and keep only a pointer in D1. Monitor during testing.

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
- **Mitigation**: KV reads are fast (~10ms). RSA key import via Web Crypto is also fast. Total cold start overhead should be < 50ms. Can also use Worker global scope caching.

---

## wrangler.toml Configuration

```toml
name = "vaultwarden-edge"
main = "build/worker/shim.mjs"
compatibility_date = "2024-01-01"

[build]
command = "cargo install worker-build && worker-build --release"

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

1. **Unit tests**: `wasm-bindgen-test` for crypto functions (PBKDF2 output matches known test vectors, JWT round-trips)
2. **Integration tests**: `wrangler dev --local` with Miniflare -- hit endpoints with `curl` or a test harness
3. **Client compatibility**: Point official Bitwarden web vault at the Worker URL, test:
   - Register new account
   - Login (password flow)
   - Create/edit/delete cipher
   - Full sync
   - Folder CRUD
   - Logout + refresh token flow
4. **Load testing**: Verify sync endpoint stays under 30s CPU time with realistic vault sizes (100, 1000, 10000 ciphers)
5. **Crypto verification**: Compare PBKDF2/HMAC outputs against Vaultwarden's test suite to ensure bit-for-bit compatibility

---

## Total API Surface

Based on Vaultwarden analysis: **~200+ distinct route handlers** across all modules. A minimum viable product (Phases 0-2) covers ~50 routes and enables basic vault usage with any Bitwarden client.
