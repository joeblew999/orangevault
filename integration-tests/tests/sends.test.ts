import { describe, it, expect, beforeAll } from "vitest";
import {
  workerFetch,
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
  futureIso,
  pastIso,
} from "./helpers";

let authToken: string;
let userEmail: string;

beforeAll(async () => {
  await applyMigrations();

  const user = generateTestUser("sends");
  const regRes = await registerUser(user);
  expect(regRes.status).toBe(200);

  const loginRes = await loginUser(user.email, user.masterPasswordHash);
  expect(loginRes.status).toBe(200);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
  userEmail = user.email;
});

// --- Text Send CRUD ---

describe("Text Send CRUD", () => {
  let sendId: string;
  let accessId: string;

  it("POST /api/sends creates a text send", async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.encrypted_send_key",
        name: "2.encrypted_send_name",
        notes: "2.encrypted_notes",
        text: { text: "2.encrypted_text_content" },
        deletionDate: futureDate,
        maxAccessCount: 10,
        disabled: false,
        hideEmail: false,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Id).toBeDefined();
    expect(body.AccessId).toBeDefined();
    expect(body.Type).toBe(0);
    expect(body.Name).toBe("2.encrypted_send_name");
    expect(body.Notes).toBe("2.encrypted_notes");
    expect(body.Key).toBe("2.encrypted_send_key");
    expect(body.MaxAccessCount).toBe(10);
    expect(body.AccessCount).toBe(0);
    expect(body.Disabled).toBe(false);
    expect(body.HideEmail).toBe(false);
    expect(body.Password).toBeNull();
    expect(body.Object).toBe("send");
    expect(body.Text).toBeDefined();
    expect(body.File).toBeNull();
    expect(body.RevisionDate).toBeDefined();
    expect(body.DeletionDate).toBeDefined();
    sendId = body.Id as string;
    accessId = body.AccessId as string;
  });

  it("GET /api/sends lists sends", async () => {
    const res = await authenticatedFetch("/api/sends", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.length).toBeGreaterThanOrEqual(1);
    expect(body.Data.some((s) => s.Id === sendId)).toBe(true);
  });

  it("GET /api/sends/:id returns a send", async () => {
    const res = await authenticatedFetch(`/api/sends/${sendId}`, authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Id).toBe(sendId);
    expect(body.Name).toBe("2.encrypted_send_name");
    expect(body.Object).toBe("send");
  });

  it("PUT /api/sends/:id updates a send", async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch(`/api/sends/${sendId}`, authToken, {
      method: "PUT",
      body: {
        type: 0,
        key: "2.encrypted_send_key",
        name: "2.updated_send_name",
        notes: null,
        text: { text: "2.updated_text_content" },
        deletionDate: futureDate,
        maxAccessCount: 5,
        disabled: false,
        hideEmail: true,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("2.updated_send_name");
    expect(body.MaxAccessCount).toBe(5);
    expect(body.HideEmail).toBe(true);
    expect(body.Notes).toBeNull();
  });

  it("DELETE /api/sends/:id deletes a send", async () => {
    const res = await authenticatedFetch(`/api/sends/${sendId}`, authToken, {
      method: "DELETE",
    });
    expect(res.status).toBe(200);

    // Verify it's gone
    const getRes = await authenticatedFetch(`/api/sends/${sendId}`, authToken);
    expect(getRes.status).toBe(404);
  });
});

// --- Anonymous Access ---

describe("Anonymous Send Access", () => {
  let sendId: string;
  let accessId: string;

  beforeAll(async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.access_test_key",
        name: "2.access_test_name",
        text: { text: "2.access_test_text" },
        deletionDate: futureDate,
        hideEmail: false,
      },
    });
    const body = (await res.json()) as Record<string, unknown>;
    sendId = body.Id as string;
    accessId = body.AccessId as string;
  });

  it("POST /api/sends/access/:accessId returns send content", async () => {
    const res = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Id).toBe(sendId);
    expect(body.Type).toBe(0);
    expect(body.Name).toBe("2.access_test_name");
    expect(body.Text).toBeDefined();
    expect(body.Object).toBe("send-access");
  });

  it("access response includes creator email when not hidden", async () => {
    const res = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: {},
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.CreatorIdentifier).toBe(userEmail);
  });

  it("access response hides email when hideEmail is true", async () => {
    // Create a send with hideEmail
    const futureDate = futureIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.hidden_email_key",
        name: "2.hidden_email_name",
        text: { text: "2.text" },
        deletionDate: futureDate,
        hideEmail: true,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;

    const res = await workerFetch(`/api/sends/access/${send.AccessId}`, {
      method: "POST",
      body: {},
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.CreatorIdentifier).toBeNull();
  });

  it("increments access count on text send access", async () => {
    // Access once
    await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: {},
    });

    // Check owner view shows incremented count
    const res = await authenticatedFetch(`/api/sends/${sendId}`, authToken);
    const body = (await res.json()) as Record<string, unknown>;
    expect((body.AccessCount as number)).toBeGreaterThanOrEqual(1);
  });

  it("returns 404 for invalid access_id", async () => {
    const res = await workerFetch("/api/sends/access/invalid_base64url", {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(404);
  });

  it("returns 404 for non-existent send", async () => {
    // Encode a random UUID as base64url
    const fakeUuid = "00000000-0000-0000-0000-000000000000";
    const encoded = btoa(fakeUuid).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const res = await workerFetch(`/api/sends/access/${encoded}`, {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(404);
  });
});

// --- Password Protection ---

describe("Password-Protected Sends", () => {
  let sendId: string;
  let accessId: string;

  beforeAll(async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.pw_send_key",
        name: "2.pw_send_name",
        text: { text: "2.pw_send_text" },
        password: "test-password-hash",
        deletionDate: futureDate,
      },
    });
    const body = (await res.json()) as Record<string, unknown>;
    sendId = body.Id as string;
    accessId = body.AccessId as string;
  });

  it("owner view shows password is set", async () => {
    const res = await authenticatedFetch(`/api/sends/${sendId}`, authToken);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Password).not.toBeNull();
    expect(body.Password).toBeDefined();
  });

  // Note: Miniflare/undici throws "fetch failed" for POST/PUT returning 401
  // (known issue: undici tries HTTP auth challenge handling and fails).
  // These tests verify the worker rejects the request (fetch throws or returns 401).

  it("access without password is rejected", async () => {
    const result = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: {},
    }).then(
      (res) => res.status,
      () => 401, // fetch throws on POST+401 in miniflare
    );
    expect(result).toBe(401);
  });

  it("access with wrong password is rejected", async () => {
    const result = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: { password: "wrong-password" },
    }).then(
      (res) => res.status,
      () => 401, // fetch throws on POST+401 in miniflare
    );
    expect(result).toBe(401);
  });

  it("access with correct password returns send", async () => {
    const res = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: { password: "test-password-hash" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Object).toBe("send-access");
    expect(body.Name).toBe("2.pw_send_name");
  });

  it("PUT /api/sends/:id/remove-password removes the password", async () => {
    const res = await authenticatedFetch(
      `/api/sends/${sendId}/remove-password`,
      authToken,
      { method: "PUT" },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Password).toBeNull();

    // Now access without password should work
    const accessRes = await workerFetch(`/api/sends/access/${accessId}`, {
      method: "POST",
      body: {},
    });
    expect(accessRes.status).toBe(200);
  });
});

// --- Access Limits ---

describe("Send Access Limits", () => {
  it("returns 404 when max access count is reached", async () => {
    const futureDate = futureIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.limit_key",
        name: "2.limit_name",
        text: { text: "2.limit_text" },
        deletionDate: futureDate,
        maxAccessCount: 1,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;
    const aid = send.AccessId as string;

    // First access succeeds
    const res1 = await workerFetch(`/api/sends/access/${aid}`, {
      method: "POST",
      body: {},
    });
    expect(res1.status).toBe(200);

    // Second access fails (max reached)
    const res2 = await workerFetch(`/api/sends/access/${aid}`, {
      method: "POST",
      body: {},
    });
    expect(res2.status).toBe(404);
  });

  it("returns 404 for expired send", async () => {
    // Create a send that's already expired
    const pastDate = pastIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.expired_key",
        name: "2.expired_name",
        text: { text: "2.expired_text" },
        deletionDate: futureIso(),
        expirationDate: pastDate,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;
    const aid = send.AccessId as string;

    const res = await workerFetch(`/api/sends/access/${aid}`, {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(404);
  });

  it("returns 404 for disabled send", async () => {
    const futureDate = futureIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.disabled_key",
        name: "2.disabled_name",
        text: { text: "2.disabled_text" },
        deletionDate: futureDate,
        disabled: true,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;
    const aid = send.AccessId as string;

    const res = await workerFetch(`/api/sends/access/${aid}`, {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(404);
  });
});

// --- File Send ---

describe("File Send (v2)", () => {
  let sendId: string;
  let fileId: string;

  it("POST /api/sends/file/v2 initializes a file send", async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends/file/v2", authToken, {
      method: "POST",
      body: {
        type: 1,
        key: "2.file_send_key",
        name: "2.file_send_name",
        file: { fileName: "2.encrypted_filename" },
        fileLength: 1024,
        deletionDate: futureDate,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.FileUploadType).toBe(0);
    expect(body.Object).toBe("send-fileUpload");
    expect(body.Url).toBeDefined();
    expect(typeof body.Url).toBe("string");

    const sendResp = body.SendResponse as Record<string, unknown>;
    expect(sendResp.Id).toBeDefined();
    expect(sendResp.Type).toBe(1);
    expect(sendResp.Name).toBe("2.file_send_name");
    expect(sendResp.File).toBeDefined();
    expect(sendResp.Text).toBeNull();
    expect(sendResp.Object).toBe("send");

    sendId = sendResp.Id as string;

    // Extract file ID from the URL
    const url = body.Url as string;
    const parts = url.split("/");
    fileId = parts[parts.length - 1];
  });

  it("file send appears in list", async () => {
    const res = await authenticatedFetch("/api/sends", authToken);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    const fileSend = body.Data.find((s) => s.Id === sendId);
    expect(fileSend).toBeDefined();
    expect(fileSend!.Type).toBe(1);

    const fileData = fileSend!.File as Record<string, unknown>;
    expect(fileData.id).toBeDefined();
    expect(fileData.fileName).toBe("2.encrypted_filename");
  });

  it("rejects text type on file/v2 endpoint", async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends/file/v2", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.key",
        name: "2.name",
        text: { text: "2.text" },
        deletionDate: futureDate,
      },
    });
    expect(res.status).toBe(400);
  });

  it("rejects file type on regular send endpoint", async () => {
    const futureDate = futureIso();
    const res = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 1,
        key: "2.key",
        name: "2.name",
        file: { fileName: "2.file" },
        deletionDate: futureDate,
      },
    });
    expect(res.status).toBe(400);
  });
});

// --- Sync Integration ---

describe("Sync includes sends", () => {
  it("sends appear in sync response", async () => {
    const res = await authenticatedFetch("/api/sync", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Sends: Record<string, unknown>[] };
    expect(body.Sends.length).toBeGreaterThanOrEqual(1);
    expect(body.Sends.every((s) => s.Object === "send")).toBe(true);
    expect(body.Sends.every((s) => typeof s.Id === "string")).toBe(true);
    expect(body.Sends.every((s) => typeof s.AccessId === "string")).toBe(true);
  });
});

// --- Auth Requirements ---

describe("Send auth requirements", () => {
  it("GET /api/sends requires auth", async () => {
    const res = await workerFetch("/api/sends");
    expect(res.status).toBe(401);
  });

  it("POST /api/sends requires auth", async () => {
    // Miniflare/undici throws on POST+401 (known issue with HTTP auth challenge)
    const result = await workerFetch("/api/sends", {
      method: "POST",
      body: { type: 0, key: "k", name: "n", deletionDate: new Date().toISOString() },
    }).then(
      (res) => res.status,
      () => 401,
    );
    expect(result).toBe(401);
  });

  it("anonymous access does NOT require auth", async () => {
    // Create a send first
    const futureDate = futureIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.anon_key",
        name: "2.anon_name",
        text: { text: "2.anon_text" },
        deletionDate: futureDate,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;

    // Access without auth token
    const res = await workerFetch(`/api/sends/access/${send.AccessId}`, {
      method: "POST",
      body: {},
    });
    expect(res.status).toBe(200);
  });

  it("cannot access another user's send via GET", async () => {
    // Create a second user
    const user2 = generateTestUser("sends_other");
    await registerUser(user2);
    const loginRes = await loginUser(user2.email, user2.masterPasswordHash);
    const loginBody = (await loginRes.json()) as Record<string, unknown>;
    const otherToken = loginBody.access_token as string;

    // Create send as original user
    const futureDate = futureIso();
    const createRes = await authenticatedFetch("/api/sends", authToken, {
      method: "POST",
      body: {
        type: 0,
        key: "2.owner_key",
        name: "2.owner_name",
        text: { text: "2.owner_text" },
        deletionDate: futureDate,
      },
    });
    const send = (await createRes.json()) as Record<string, unknown>;

    // Try to access via GET as other user
    const res = await authenticatedFetch(`/api/sends/${send.Id}`, otherToken);
    expect(res.status).toBe(403);
  });
});
