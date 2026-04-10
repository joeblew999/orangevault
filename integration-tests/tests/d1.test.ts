import { describe, it, expect, beforeAll } from "vitest";
import { applyMigrations, getD1 } from "./helpers";

describe("D1 schema", () => {
  beforeAll(async () => {
    await applyMigrations();
  });

  it("migrations create the users table", async () => {
    const db = await getD1();
    const result = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
      )
      .first<{ name: string }>();
    expect(result?.name).toBe("users");
  });

  it("migrations create all expected tables", async () => {
    const db = await getD1();
    const results = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      )
      .all<{ name: string }>();

    const tables = results.results.map((r) => r.name);

    const expected = [
      "attachments",
      "ciphers",
      "ciphers_collections",
      "collections",
      "collections_groups",
      "devices",
      "equivalent_domains",
      "favorites",
      "folders",
      "folders_ciphers",
      "groups",
      "groups_users",
      "memberships",
      "org_policies",
      "organizations",
      "sends",
      "two_factor",
      "users",
      "users_collections",
    ];

    for (const table of expected) {
      expect(tables).toContain(table);
    }
  });

  it("migrations create expected indexes", async () => {
    const db = await getD1();
    const results = await db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name",
      )
      .all<{ name: string }>();

    const indexes = results.results.map((r) => r.name);

    expect(indexes).toContain("idx_devices_user");
    expect(indexes).toContain("idx_ciphers_user");
    expect(indexes).toContain("idx_ciphers_org");
    expect(indexes).toContain("idx_folders_user");
    expect(indexes).toContain("idx_memberships_user");
    expect(indexes).toContain("idx_sends_user");
  });

  it("can insert and query a user row", async () => {
    const db = await getD1();

    await db
      .prepare(
        `INSERT INTO users (uuid, email, name, password_hash, salt, password_iterations,
         security_stamp, client_kdf_type, client_kdf_iter, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        "test-uuid-001",
        "test@example.com",
        "Test User",
        "AQID",
        "BAUG",
        600000,
        "stamp-001",
        0,
        600000,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
      )
      .run();

    const user = await db
      .prepare("SELECT email, name FROM users WHERE uuid = ?")
      .bind("test-uuid-001")
      .first<{ email: string; name: string }>();

    expect(user?.email).toBe("test@example.com");
    expect(user?.name).toBe("Test User");
  });
});
