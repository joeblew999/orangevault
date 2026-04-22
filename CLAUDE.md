# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is this?

OrangeVault is a Bitwarden-compatible password vault API built in Rust, compiled to WebAssembly, and deployed on Cloudflare Workers. It implements the Bitwarden API surface so official Bitwarden clients can connect to it.

## Build & Test Commands

```bash
# Build the Rust worker (compiles to WASM)
cargo install -q worker-build@^0.8 && worker-build --release

# Run all integration tests (builds first)
cd integration-tests && npm test

# Run tests without rebuilding (faster iteration when only changing tests)
cd integration-tests && npm run test:no-build

# Run a single test file
cd integration-tests && npx vitest run tests/auth.test.ts

# Run a single test by name
cd integration-tests && npx vitest run -t "test name"

# Watch mode
cd integration-tests && npm run test:watch
```

There is no separate lint or format command configured. Use `cargo check` for type checking.

## Architecture

**Runtime stack**: Rust (2024 edition) -> WASM -> Cloudflare Workers, with D1 (SQLite) for storage, R2 for file storage, KV for caching, and Durable Objects for WebSocket notifications. The Worker also serves the patched Bitwarden web vault as a static Assets binding.

**Cloudflare bindings** (defined in `wrangler.toml`):

- `DB` — D1 database
- `FILES` — R2 bucket (send file attachments)
- `CACHE` — KV namespace (RSA JWT keys, generated on first use)
- `USER_NOTIFIER` — Durable Object class (WebSocket notifications)
- `ASSETS` — static Workers Assets binding serving `./web-vault/` with SPA fallback; `run_worker_first` in `wrangler.toml` lists the API paths that bypass the static server

### Request flow

1. `src/lib.rs` — Entry point. `#[event(fetch)]` handler resolves the allowed CORS origin, short-circuits OPTIONS preflight, extracts client info, then dispatches via `Router` with `RequestContext` as data. All non-WebSocket responses are funneled through `cors::apply_cors_headers` and `security::apply_security_headers` on the way out.
2. Route handlers live in `src/api/`. Each handler wraps its body in `error::into_response()` for consistent Bitwarden-compatible error formatting.
3. Authenticated handlers call `auth_from_request(&req, &ctx.data)` (from `auth::guards`) at the top to validate the Bearer JWT; this also checks the token's `sstamp` claim against the user's current `security_stamp` so password/KDF/key rotations invalidate outstanding tokens immediately.
4. Database access goes through `src/db/queries.rs` (raw D1 SQL with `prepare -> bind -> execute`) with typed models in `src/db/models.rs`.

### Key modules

- `src/api/` — Route handlers organized by feature: `accounts`, `ciphers`, `emergency`, `events`, `folders`, `icons`, `identity`, `notifications`, `organizations`, `sends`, `sync`, `two_factor`, `web`
- `src/auth/` — JWT creation/validation (`jwt.rs`), claim types (`claims.rs`), `auth_from_request` / `validate_access_token` guards (`guards.rs`)
- `src/crypto/` — PBKDF2, HMAC-SHA256, RSA, TOTP, `random` — all via `web-sys` SubtleCrypto (no native crypto crates)
- `src/db/` — `models.rs` (D1 row types with serde) and `queries.rs` (all SQL)
- `src/middleware/` — `cors` (origin resolution + preflight), `security` (defense-in-depth response headers), `headers` (extract Bitwarden client info from request headers)
- `src/models/` — API request/response DTOs (separate from DB models)
- `src/config.rs` — `RequestContext` (holds `env`, optional authenticated user, client info) and `ClientInfo`
- `src/notifications.rs` — `UserNotifier` Durable Object: WebSocket upgrade, SignalR binary MessagePack framing, hibernation-aware
- `src/jobs.rs` — `#[event(scheduled)]` cron handler (purge expired sends + R2 files, purge trashed ciphers)
- `src/error.rs` — `AppError` enum (Unauthorized, BadRequest, NotFound, Forbidden, Conflict, PayloadTooLarge, TooManyRequests, Internal, OAuth) mapped to Bitwarden-compatible JSON error responses (`ErrorModel` / `ApiErrorResponse`, plus OAuth-style for identity endpoints)

### Testing

Tests are TypeScript integration tests in `integration-tests/tests/` using Vitest + Miniflare. They exercise the full worker via HTTP requests against a local emulator. Test helpers in `helpers.ts` provide `workerFetch`, `authenticatedFetch`, `getD1`, and `applyMigrations`.

## Key Patterns

- **All cryptography** uses the Web Crypto API via `web-sys` bindings — no native Rust crypto crates (they don't compile to `wasm32-unknown-unknown`).
- **SQLite booleans**: D1/SQLite stores booleans as 0/1 integers. Use `de_bool_from_int` deserializer on model fields.
- **Bitwarden API compat**: Response JSON uses PascalCase field names (`#[serde(rename = "...")]`). Error responses follow Bitwarden's `ErrorModel`/`ApiErrorResponse` shape. OAuth token responses use Bitwarden's format.
- **Notifications**: Handlers fire `notifications::send_notification()` as fire-and-forget after mutations. The Durable Object uses SignalR binary MessagePack protocol.
- **Config access**: `ctx.data.db()`, `ctx.data.kv()`, `ctx.data.r2()`, `ctx.data.var(..)`, `ctx.data.secret(..)`, `ctx.data.domain()`, `ctx.data.signups_allowed()`, `ctx.data.web_vault_enabled()` on `RequestContext`. Vars like `DOMAIN`, `SIGNUPS_ALLOWED`, `WEB_VAULT_ENABLED` are declared under `[vars]` in `wrangler.toml`.
- **WASM size**: Release profile uses `opt-level = "s"` and LTO to minimize binary size.
- **DB migrations**: SQL lives in `migrations/` (currently just `0001_initial.sql`) and is applied via D1 migration tooling. Tests apply migrations via `applyMigrations()` helper.
- **Web vault**: `./web-vault/` is not checked in — populate with `scripts/fetch-web-vault.sh` before building if you want the static client. The worker serves `/app-id.json` dynamically so the FIDO2 origin matches `DOMAIN`.
