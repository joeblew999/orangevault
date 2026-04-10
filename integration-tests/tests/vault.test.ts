import { describe, it, expect, beforeAll } from "vitest";
import { mf, mfUrl } from "./mf";
import {
  workerFetch,
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
} from "./helpers";

let authToken: string;
let userEmail: string;

beforeAll(async () => {
  await applyMigrations();

  // Register and login a test user
  const user = generateTestUser("vault");
  const regRes = await registerUser(user);
  expect(regRes.status).toBe(200);

  const loginRes = await loginUser(user.email, user.masterPasswordHash);
  expect(loginRes.status).toBe(200);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
  userEmail = user.email;
});

// --- Sync ---

describe("GET /api/sync", () => {
  it("returns sync response with empty vault", async () => {
    const res = await authenticatedFetch("/api/sync", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Object).toBe("sync");
    expect(body.Profile).toBeDefined();
    expect(body.Ciphers).toEqual([]);
    expect(body.Folders).toEqual([]);
    expect(body.Collections).toEqual([]);
    expect(body.Sends).toEqual([]);
    expect(body.Domains).toBeDefined();
  });

  it("requires authentication", async () => {
    const res = await workerFetch("/api/sync");
    expect(res.status).toBe(401);
  });

  it("profile has correct email", async () => {
    const res = await authenticatedFetch("/api/sync", authToken);
    const body = (await res.json()) as { Profile: Record<string, unknown> };
    expect(body.Profile.Email).toBe(userEmail);
    expect(body.Profile.Premium).toBe(true);
    expect(body.Profile.Object).toBe("profile");
  });
});

// --- Folders ---

describe("Folder CRUD", () => {
  let folderId: string;

  it("POST /api/folders creates a folder", async () => {
    const res = await authenticatedFetch("/api/folders", authToken, {
      method: "POST",
      body: { name: "2.encrypted_folder_name" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("2.encrypted_folder_name");
    expect(body.Id).toBeDefined();
    expect(body.Object).toBe("folder");
    folderId = body.Id as string;
  });

  it("GET /api/folders lists folders", async () => {
    const res = await authenticatedFetch("/api/folders", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.length).toBeGreaterThanOrEqual(1);
    expect(body.Data.some((f) => f.Id === folderId)).toBe(true);
  });

  it("PUT /api/folders/:id updates a folder", async () => {
    const res = await authenticatedFetch(`/api/folders/${folderId}`, authToken, {
      method: "PUT",
      body: { name: "2.updated_name" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("2.updated_name");
  });

  it("DELETE /api/folders/:id deletes a folder", async () => {
    const res = await authenticatedFetch(`/api/folders/${folderId}`, authToken, {
      method: "DELETE",
    });
    expect(res.status).toBe(200);

    // Verify it's gone
    const list = await authenticatedFetch("/api/folders", authToken);
    const body = (await list.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.some((f) => f.Id === folderId)).toBe(false);
  });
});

// --- Ciphers ---

describe("Cipher CRUD", () => {
  let cipherId: string;

  it("POST /api/ciphers creates a login cipher", async () => {
    const res = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.encrypted_name",
        notes: "2.encrypted_notes",
        login: { uris: [{ uri: "2.encrypted_uri" }], username: "2.user", password: "2.pass" },
        favorite: false,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Type).toBe(1);
    expect(body.Name).toBe("2.encrypted_name");
    expect(body.Object).toBe("cipherDetails");
    expect(body.Id).toBeDefined();
    cipherId = body.Id as string;
  });

  it("GET /api/ciphers lists ciphers", async () => {
    const res = await authenticatedFetch("/api/ciphers", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.length).toBeGreaterThanOrEqual(1);
  });

  it("GET /api/ciphers/:id returns a cipher", async () => {
    const res = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Id).toBe(cipherId);
    expect(body.Name).toBe("2.encrypted_name");
  });

  it("PUT /api/ciphers/:id updates a cipher", async () => {
    const res = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken, {
      method: "PUT",
      body: {
        type: 1,
        name: "2.updated_name",
        notes: null,
        login: { uris: [{ uri: "2.new_uri" }], username: "2.user", password: "2.new_pass" },
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("2.updated_name");
  });

  it("PUT /api/ciphers/:id/delete soft-deletes a cipher", async () => {
    const res = await authenticatedFetch(
      `/api/ciphers/${cipherId}/delete`,
      authToken,
      { method: "PUT" },
    );
    expect(res.status).toBe(200);

    // Verify it's soft-deleted (still exists but has DeletedDate)
    const getRes = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken);
    const body = (await getRes.json()) as Record<string, unknown>;
    expect(body.DeletedDate).toBeDefined();
    expect(body.DeletedDate).not.toBeNull();
  });

  it("PUT /api/ciphers/:id/restore restores a cipher", async () => {
    const res = await authenticatedFetch(
      `/api/ciphers/${cipherId}/restore`,
      authToken,
      { method: "PUT" },
    );
    expect(res.status).toBe(200);

    const getRes = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken);
    const body = (await getRes.json()) as Record<string, unknown>;
    expect(body.DeletedDate).toBeNull();
  });

  it("DELETE /api/ciphers/:id hard-deletes a cipher", async () => {
    const res = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken, {
      method: "DELETE",
    });
    expect(res.status).toBe(200);

    // Verify it's gone
    const getRes = await authenticatedFetch(`/api/ciphers/${cipherId}`, authToken);
    expect(getRes.status).toBe(404);
  });
});

describe("Sync includes vault data", () => {
  it("sync reflects created ciphers and folders", async () => {
    // Create a folder
    const folderRes = await authenticatedFetch("/api/folders", authToken, {
      method: "POST",
      body: { name: "2.sync_folder" },
    });
    const folder = (await folderRes.json()) as Record<string, unknown>;

    // Create a cipher in the folder
    await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.sync_cipher",
        login: { username: "2.u", password: "2.p" },
        folderId: folder.Id,
      },
    });

    // Sync
    const syncRes = await authenticatedFetch("/api/sync", authToken);
    expect(syncRes.status).toBe(200);
    const body = (await syncRes.json()) as {
      Ciphers: Record<string, unknown>[];
      Folders: Record<string, unknown>[];
    };

    expect(body.Folders.some((f) => f.Name === "2.sync_folder")).toBe(true);
    expect(body.Ciphers.some((c) => c.Name === "2.sync_cipher")).toBe(true);

    // Verify cipher has folder assignment
    const syncCipher = body.Ciphers.find((c) => c.Name === "2.sync_cipher") as Record<string, unknown>;
    expect(syncCipher.FolderId).toBe(folder.Id);
  });
});
