import { describe, it, expect, beforeAll } from "vitest";
import {
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
  futureIso,
  pastIso,
} from "./helpers";
import { getD1 } from "./helpers";

let authToken: string;

beforeAll(async () => {
  await applyMigrations();

  const user = generateTestUser("cron");
  await registerUser(user);
  const loginRes = await loginUser(user.email, user.masterPasswordHash);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
});

describe("Purge expired sends", () => {
  it("expired sends are deleted by direct SQL purge", async () => {
    // Create a send with a deletion date in the past
    const pastDeletion = pastIso(120);
    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.expired_key",
        name: "2.expired_send",
        text: { text: "2.text" },
        deletionDate: pastDeletion,
      },
    });
    expect(res.status).toBe(200);
    const send = (await res.json()) as Record<string, unknown>;
    const sendId = send.Id as string;

    // Verify it exists in the DB
    const db = await getD1();
    const before = await db
      .prepare("SELECT COUNT(*) as cnt FROM sends WHERE uuid = ?")
      .bind(sendId)
      .first<{ cnt: number }>();
    expect(before?.cnt).toBe(1);

    // Simulate the cron purge by running the same SQL
    const now = new Date().toISOString();
    await db
      .prepare("DELETE FROM sends WHERE deletion_date <= ?")
      .bind(now)
      .run();

    // Verify it's gone
    const after = await db
      .prepare("SELECT COUNT(*) as cnt FROM sends WHERE uuid = ?")
      .bind(sendId)
      .first<{ cnt: number }>();
    expect(after?.cnt).toBe(0);
  });
});

describe("Purge trashed ciphers", () => {
  it("soft-deleted ciphers older than 30 days are purged", async () => {
    // Create a cipher
    const createRes = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.trash_cipher",
        login: { username: "2.u", password: "2.p" },
      },
    });
    expect(createRes.status).toBe(200);
    const cipher = (await createRes.json()) as Record<string, unknown>;
    const cipherId = cipher.Id as string;

    // Soft-delete it
    const delRes = await authenticatedFetch(
      `/api/ciphers/${cipherId}/delete`,
      authToken,
      { method: "PUT" },
    );
    expect(delRes.status).toBe(200);

    // Backdate the deleted_at to 31 days ago via direct SQL
    const db = await getD1();
    const oldDate = new Date(
      Date.now() - 31 * 24 * 60 * 60 * 1000,
    ).toISOString();
    await db
      .prepare("UPDATE ciphers SET deleted_at = ? WHERE uuid = ?")
      .bind(oldDate, cipherId)
      .run();

    // Run the purge query (same as cron job)
    const cutoff = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    await db
      .prepare(
        "DELETE FROM folders_ciphers WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at <= ?)",
      )
      .bind(cutoff)
      .run();
    await db
      .prepare(
        "DELETE FROM favorites WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at <= ?)",
      )
      .bind(cutoff)
      .run();
    await db
      .prepare(
        "DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at <= ?)",
      )
      .bind(cutoff)
      .run();
    await db
      .prepare(
        "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at <= ?",
      )
      .bind(cutoff)
      .run();

    // Verify it's gone
    const after = await db
      .prepare("SELECT COUNT(*) as cnt FROM ciphers WHERE uuid = ?")
      .bind(cipherId)
      .first<{ cnt: number }>();
    expect(after?.cnt).toBe(0);
  });

  it("recently trashed ciphers are NOT purged", async () => {
    // Create and soft-delete a cipher (with current timestamp)
    const createRes = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.recent_trash",
        login: { username: "2.u", password: "2.p" },
      },
    });
    const cipher = (await createRes.json()) as Record<string, unknown>;
    const cipherId = cipher.Id as string;

    await authenticatedFetch(`/api/ciphers/${cipherId}/delete`, authToken, {
      method: "PUT",
    });

    // Run purge with 30-day cutoff
    const db = await getD1();
    const cutoff = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000,
    ).toISOString();
    await db
      .prepare(
        "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at <= ?",
      )
      .bind(cutoff)
      .run();

    // Should still exist (deleted less than 30 days ago)
    const after = await db
      .prepare("SELECT COUNT(*) as cnt FROM ciphers WHERE uuid = ?")
      .bind(cipherId)
      .first<{ cnt: number }>();
    expect(after?.cnt).toBe(1);
  });
});
