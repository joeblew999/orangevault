import { mf, mfUrl } from "./mf";

interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export async function workerFetch(path: string, options: FetchOptions = {}) {
  const { body, ...rest } = options;
  return mf.dispatchFetch(`${mfUrl}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...rest.headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function authenticatedFetch(
  path: string,
  token: string,
  options: FetchOptions = {},
) {
  return workerFetch(path, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...options.headers },
  });
}

export async function getD1() {
  return mf.getD1Database("DB");
}

export async function applyMigrations() {
  const { readFileSync } = await import("node:fs");
  const { dirname, resolve } = await import("node:path");
  const { fileURLToPath } = await import("node:url");

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const migrationPath = resolve(
    __dirname,
    "..",
    "..",
    "migrations",
    "0001_initial",
    "up.sql",
  );
  const sql = readFileSync(migrationPath, "utf-8");

  const db = await getD1();

  // Strip SQL comments, then split on semicolons and run each statement
  const cleaned = sql
    .split("\n")
    .map((line) => {
      const idx = line.indexOf("--");
      return idx >= 0 ? line.slice(0, idx) : line;
    })
    .join("\n");

  const statements = cleaned
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  for (const stmt of statements) {
    await db.prepare(stmt).run();
  }
}

function generateUniqueId(prefix: string): string {
  const shortTimestamp = Date.now().toString().slice(-6);
  const randomPart = Math.random().toString(36).slice(2, 6);
  return `${prefix}_${shortTimestamp}_${randomPart}`;
}

export function generateTestUser(prefix: string = "test") {
  const uniqueId = generateUniqueId(prefix);
  return {
    name: uniqueId,
    email: `${uniqueId}@test.example.com`,
    masterPasswordHash: "dGVzdA==", // placeholder base64
  };
}

export async function registerUser(user: {
  name: string;
  email: string;
  masterPasswordHash: string;
}) {
  return workerFetch("/identity/accounts/register", {
    method: "POST",
    body: {
      name: user.name,
      email: user.email,
      masterPasswordHash: user.masterPasswordHash,
      key: "encrypted-key-placeholder",
      kdf: 0,
      kdfIterations: 600000,
      keys: {
        publicKey: "public-key-placeholder",
        encryptedPrivateKey: "encrypted-private-key-placeholder",
      },
    },
  });
}

export async function loginUser(
  email: string,
  masterPasswordHash: string,
  opts?: {
    twoFactorProvider?: string;
    twoFactorToken?: string;
    deviceIdentifier?: string;
  },
) {
  const params: Record<string, string> = {
    grant_type: "password",
    username: email,
    password: masterPasswordHash,
    scope: "api offline_access",
    client_id: "web",
    deviceType: "10",
    deviceIdentifier: opts?.deviceIdentifier ?? "test-device-id",
    deviceName: "Test Browser",
  };
  if (opts?.twoFactorProvider != null) {
    params.twoFactorProvider = opts.twoFactorProvider;
  }
  if (opts?.twoFactorToken != null) {
    params.twoFactorToken = opts.twoFactorToken;
  }
  const body = new URLSearchParams(params);
  return mf.dispatchFetch(`${mfUrl}/identity/connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
}

export async function generateTotpCode(base32Key: string): Promise<string> {
  const secret = base32Decode(base32Key);
  const time = Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / 30);

  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setBigUint64(0, BigInt(counter));

  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  const hmac = await crypto.subtle.sign("HMAC", key, counterBuf);
  const hmacBytes = new Uint8Array(hmac);

  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const code =
    (((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff)) %
    1000000;

  return code.toString().padStart(6, "0");
}

function base32Decode(encoded: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0;
  let bits = 0;
  const result: number[] = [];
  for (const ch of encoded.toUpperCase()) {
    const val = alphabet.indexOf(ch);
    if (val === -1) continue;
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      result.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(result);
}
