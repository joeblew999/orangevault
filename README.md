# 🍊 OrangeVault

A Bitwarden-compatible password vault API, written in Rust, compiled to WebAssembly, and deployed on Cloudflare Workers.

It implements the Bitwarden REST API, so the official clients (web, browser extension, desktop, mobile, CLI) connect without any patches. Vault data is encrypted on the client; the server only ever sees ciphertext.

## Why

Vaultwarden depends on Rocket, Tokio, and OpenSSL, none of which run on Workers. This is a port that targets D1, R2, KV, and Durable Objects instead, so there's no VM or container to manage.

## What works

- Register, login via the OAuth token endpoint, RS256 access/refresh JWTs, device tracking
- Full vault sync (ciphers, folders, collections, organizations)
- Cipher CRUD, including soft-delete and trash
- Encrypted folders
- Organizations with collection-based access, groups, and policies
- TOTP two-factor with recovery codes
- Sends: encrypted text and file sharing, with passwords, expirations, and access limits
- Real-time push over WebSockets via a Durable Object speaking SignalR's binary MessagePack protocol
- Cron that purges expired sends and ciphers trashed for 30+ days

## Stack

| Layer        | Tech                                                                                          |
| ------------ | --------------------------------------------------------------------------------------------- |
| Language     | Rust (2024 edition), `wasm32-unknown-unknown` target                                          |
| Runtime      | Cloudflare Workers                                                                            |
| Database     | Cloudflare D1                                                                                 |
| File storage | Cloudflare R2                                                                                 |
| Cache        | Cloudflare KV                                                                                 |
| WebSockets   | Cloudflare Durable Objects                                                                    |
| Crypto       | Web Crypto API (PBKDF2, RSA, HMAC, TOTP). No native crypto crates; they don't build for wasm. |
| Tests        | Vitest + Miniflare                                                                            |

## Layout

```
src/
  lib.rs              # router, entry point, fetch handler
  config.rs           # request context, env/secret access
  error.rs            # error type -> HTTP response
  auth/               # JWT (RS256), claims, auth guard
  crypto/             # PBKDF2, RSA, HMAC, TOTP via SubtleCrypto
  db/                 # D1 models and queries
  middleware/         # CORS, security headers
  api/                # route handlers
  models/             # API request/response types
  notifications.rs    # SignalR framing + Durable Object handlers
  jobs.rs             # cron handlers
migrations/           # D1 schema
integration-tests/    # Vitest + Miniflare tests
```

## Prerequisites

- Rust with the wasm target: `rustup target add wasm32-unknown-unknown`
- Node.js (for Wrangler and the tests)
- A Cloudflare account with D1, R2, KV, and Durable Objects available

## Setup

Clone and set up:

```bash
git clone https://github.com/connyay/orangevault.git
cd orangevault
```

Fill in your Cloudflare resource IDs in `wrangler.toml`:

```toml
[[d1_databases]]
database_id = "<your-d1-database-id>"

[[kv_namespaces]]
id = "<your-kv-namespace-id>"
```

Create the D1 database and apply migrations:

```bash
npx wrangler d1 create orangevault
npx wrangler d1 migrations apply orangevault
```

Create the R2 bucket:

```bash
npx wrangler r2 bucket create orangevault-files
```

## Build

```bash
cargo install -q worker-build@^0.8 && worker-build --release
```

Output lands in `build/`.

## Dev

```bash
npx wrangler dev
```

## Tests

Integration tests run against a local Miniflare worker:

```bash
cd integration-tests
npm install
npm test
```

Other options:

```bash
npm run test:watch      # watch mode
npm run test:no-build   # skip the worker rebuild
```

## Web vault

OrangeVault can serve the patched Bitwarden web client from [dani-garcia/bw_web_builds](https://github.com/dani-garcia/bw_web_builds) as a Workers Assets binding. The bundle isn't checked in; fetch it before you build:

```bash
scripts/fetch-web-vault.sh                # latest release
scripts/fetch-web-vault.sh v2026.2.0      # pinned version
```

That populates `./web-vault/`, which `wrangler.toml` wires up as the `ASSETS` binding. SPA fallback is on, so Angular routes fall through to `index.html` while API paths (`/api/*`, `/identity/*`, `/notifications/*`, etc.) go to the worker. The worker also serves `/app-id.json` dynamically so the WebAuthn origin matches `DOMAIN` instead of whatever placeholder was baked into the bundle.

If you don't want the web vault, leave `./web-vault/` empty or drop the `[assets]` block from `wrangler.toml`.

## Deploy

```bash
npx wrangler deploy
```

## Config

Set in `wrangler.toml` under `[vars]` or via `wrangler secret put`:

| Variable            | Description                                                                                                                                                                                  | Default                     |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| `DOMAIN`            | Base URL of your instance                                                                                                                                                                    | `https://vault.example.com` |
| `SIGNUPS_ALLOWED`   | Allow new user registration                                                                                                                                                                  | `true`                      |
| `WEB_VAULT_ENABLED` | Controls the dynamic `/app-id.json` handler. Set `false` to turn off the FIDO2 trusted-apps endpoint. Static asset serving is controlled separately, by whether `./web-vault/` is populated. | `true`                      |

RSA signing keys are generated on first use and stored in KV.

## Bindings

| Binding         | Service        | Purpose                           |
| --------------- | -------------- | --------------------------------- |
| `DB`            | D1             | All vault data                    |
| `FILES`         | R2             | Send file uploads                 |
| `CACHE`         | KV             | RSA keys and general cache        |
| `USER_NOTIFIER` | Durable Object | Per-user WebSockets for sync push |

## Cron

| Schedule      | Task                                    |
| ------------- | --------------------------------------- |
| Every 6 hours | Delete expired sends and their R2 files |
| Daily         | Delete ciphers trashed 30+ days ago     |

## License

AGPL-3.0, matching [vaultwarden](https://github.com/dani-garcia/vaultwarden), which this is a port of. See [LICENSE](LICENSE).
