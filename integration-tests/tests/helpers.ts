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
