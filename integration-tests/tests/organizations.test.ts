import { describe, it, expect, beforeAll } from "vitest";
import {
  workerFetch,
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
} from "./helpers";

let authToken: string;

beforeAll(async () => {
  await applyMigrations();
  const user = generateTestUser("org");
  await registerUser(user);
  const loginRes = await loginUser(user.email, user.masterPasswordHash);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
});

describe("Organization CRUD", () => {
  let orgId: string;

  it("POST /api/organizations creates an org", async () => {
    const res = await authenticatedFetch("/api/organizations", authToken, {
      method: "POST",
      body: {
        name: "Test Org",
        billingEmail: "billing@test.com",
        collectionName: "Default Collection",
        key: "2.encrypted-org-key",
        keys: {
          encryptedPrivateKey: "2.org-priv-key",
          publicKey: "org-pub-key",
        },
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("Test Org");
    expect(body.SelfHost).toBe(true);
    expect(body.UsersGetPremium).toBe(true);
    expect(body.Object).toBe("organization");
    orgId = body.Id as string;
  });

  it("GET /api/organizations/:org_id returns the org", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Id).toBe(orgId);
    expect(body.Name).toBe("Test Org");
  });

  it("org appears in sync profile.organizations", async () => {
    const res = await authenticatedFetch("/api/sync", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      Profile: { Organizations: Record<string, unknown>[] };
    };
    const orgs = body.Profile.Organizations;
    expect(orgs.length).toBeGreaterThanOrEqual(1);
    const org = orgs.find((o) => o.Id === orgId) as Record<string, unknown>;
    expect(org).toBeDefined();
    expect(org.Name).toBe("Test Org");
    expect(org.Key).toBe("2.encrypted-org-key");
    expect(org.Status).toBe(2); // Confirmed
    expect(org.Type).toBe(0); // Owner
    expect(org.Object).toBe("profileOrganization");
  });
});

describe("Collection management", () => {
  let orgId: string;
  let collectionId: string;

  beforeAll(async () => {
    // Create a fresh org
    const res = await authenticatedFetch("/api/organizations", authToken, {
      method: "POST",
      body: {
        name: "Collection Test Org",
        billingEmail: "col@test.com",
        key: "2.col-org-key",
      },
    });
    const body = (await res.json()) as Record<string, unknown>;
    orgId = body.Id as string;
  });

  it("POST creates a collection", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/collections`,
      authToken,
      {
        method: "POST",
        body: { name: "2.encrypted-col-name" },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Name).toBe("2.encrypted-col-name");
    expect(body.OrganizationId).toBe(orgId);
    expect(body.Object).toBe("collection");
    collectionId = body.Id as string;
  });

  it("GET lists collections", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/collections`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.some((c) => c.Id === collectionId)).toBe(true);
  });

  it("collections appear in sync", async () => {
    const syncRes = await authenticatedFetch("/api/sync", authToken);
    const body = (await syncRes.json()) as {
      Collections: Record<string, unknown>[];
    };
    expect(body.Collections.some((c) => c.Id === collectionId)).toBe(true);
  });

  it("DELETE removes a collection", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/collections/${collectionId}`,
      authToken,
      { method: "DELETE" },
    );
    expect(res.status).toBe(200);
  });
});

describe("Cipher sharing", () => {
  let orgId: string;
  let collectionId: string;
  let cipherId: string;

  beforeAll(async () => {
    // Create org with default collection
    const orgRes = await authenticatedFetch("/api/organizations", authToken, {
      method: "POST",
      body: {
        name: "Share Test Org",
        billingEmail: "share@test.com",
        collectionName: "Default",
        key: "2.share-org-key",
      },
    });
    const orgBody = (await orgRes.json()) as Record<string, unknown>;
    orgId = orgBody.Id as string;

    // Get the default collection
    const colRes = await authenticatedFetch(
      `/api/organizations/${orgId}/collections`,
      authToken,
    );
    const colBody = (await colRes.json()) as { Data: Record<string, unknown>[] };
    collectionId = colBody.Data[0].Id as string;

    // Create a personal cipher
    const cipherRes = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.cipher-to-share",
        login: { username: "2.user", password: "2.pass" },
      },
    });
    const cipherBody = (await cipherRes.json()) as Record<string, unknown>;
    cipherId = cipherBody.Id as string;
  });

  it("PUT /api/ciphers/:id/share shares a cipher to org", async () => {
    const res = await authenticatedFetch(
      `/api/ciphers/${cipherId}/share`,
      authToken,
      {
        method: "PUT",
        body: {
          cipher: {
            type: 1,
            organizationId: orgId,
            name: "2.shared-cipher",
            key: "2.cipher-key",
            login: { username: "2.user", password: "2.pass" },
          },
          collectionIds: [collectionId],
        },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.OrganizationId).toBe(orgId);
  });

  it("shared cipher appears in sync", async () => {
    const syncRes = await authenticatedFetch("/api/sync", authToken);
    const body = (await syncRes.json()) as {
      Ciphers: Record<string, unknown>[];
    };
    const shared = body.Ciphers.find((c) => c.Id === cipherId);
    expect(shared).toBeDefined();
    expect(shared!.OrganizationId).toBe(orgId);
  });
});

describe("Org members", () => {
  let orgId: string;

  beforeAll(async () => {
    const res = await authenticatedFetch("/api/organizations", authToken, {
      method: "POST",
      body: {
        name: "Members Test Org",
        billingEmail: "members@test.com",
        key: "2.members-org-key",
      },
    });
    const body = (await res.json()) as Record<string, unknown>;
    orgId = body.Id as string;
  });

  it("GET /api/organizations/:org_id/users lists members", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/users`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: Record<string, unknown>[] };
    expect(body.Data.length).toBe(1); // Just the owner
    expect(body.Data[0].Type).toBe(0); // Owner
    expect(body.Data[0].Status).toBe(2); // Confirmed
  });
});

describe("Org deletion", () => {
  it("DELETE /api/organizations/:org_id deletes the org", async () => {
    // Create a throwaway org
    const createRes = await authenticatedFetch(
      "/api/organizations",
      authToken,
      {
        method: "POST",
        body: {
          name: "Delete Me Org",
          billingEmail: "delete@test.com",
          key: "2.delete-org-key",
        },
      },
    );
    const org = (await createRes.json()) as Record<string, unknown>;

    const res = await authenticatedFetch(
      `/api/organizations/${org.Id}`,
      authToken,
      { method: "DELETE" },
    );
    expect(res.status).toBe(200);

    // Verify it's gone (403 because membership was deleted too)
    const getRes = await authenticatedFetch(
      `/api/organizations/${org.Id}`,
      authToken,
    );
    expect([403, 404]).toContain(getRes.status);
  });
});

describe("Admin-console endpoints", () => {
  let orgId: string;
  let collectionId: string;
  let cipherId: string;

  beforeAll(async () => {
    const orgRes = await authenticatedFetch("/api/organizations", authToken, {
      method: "POST",
      body: {
        name: "Admin Console Org",
        billingEmail: "admin@test.com",
        collectionName: "Default",
        key: "2.admin-org-key",
        keys: {
          encryptedPrivateKey: "2.admin-priv",
          publicKey: "admin-pub",
        },
      },
    });
    orgId = ((await orgRes.json()) as Record<string, unknown>).Id as string;

    const colRes = await authenticatedFetch(
      `/api/organizations/${orgId}/collections`,
      authToken,
    );
    const colBody = (await colRes.json()) as {
      Data: Record<string, unknown>[];
    };
    collectionId = colBody.Data[0].Id as string;

    const cipherRes = await authenticatedFetch("/api/ciphers", authToken, {
      method: "POST",
      body: {
        type: 1,
        name: "2.personal-cipher",
        login: { username: "2.user", password: "2.pass" },
      },
    });
    cipherId = ((await cipherRes.json()) as Record<string, unknown>).Id as string;

    await authenticatedFetch(`/api/ciphers/${cipherId}/share`, authToken, {
      method: "PUT",
      body: {
        cipher: {
          type: 1,
          organizationId: orgId,
          name: "2.org-cipher",
          key: "2.cipher-key",
          login: { username: "2.user", password: "2.pass" },
        },
        collectionIds: [collectionId],
      },
    });
  });

  it("GET /api/organizations/:id/keys returns public+private", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/keys`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Object).toBe("organizationKeys");
    expect(body.PublicKey).toBe("admin-pub");
    expect(body.PrivateKey).toBe("2.admin-priv");
  });

  it("GET /api/organizations/:id/keys is forbidden to non-members", async () => {
    const other = generateTestUser("nonmember");
    await registerUser(other);
    const loginRes = await loginUser(other.email, other.masterPasswordHash);
    const otherToken = ((await loginRes.json()) as Record<string, unknown>)
      .access_token as string;
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/keys`,
      otherToken,
    );
    expect(res.status).toBe(403);
  });

  it("GET /api/organizations/:id/groups returns empty list (unused feature)", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/groups`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Object).toBe("list");
    expect(body.Data).toEqual([]);
  });

  it("GET /api/organizations/:id/groups/details returns empty list", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/groups/details`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: unknown[] };
    expect(body.Data).toEqual([]);
  });

  it("GET /api/organizations/:id/collections/details returns access info", async () => {
    const res = await authenticatedFetch(
      `/api/organizations/${orgId}/collections/details`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      Data: Record<string, unknown>[];
    };
    const col = body.Data.find((c) => c.Id === collectionId) as
      | Record<string, unknown>
      | undefined;
    expect(col).toBeDefined();
    expect(col!.Object).toBe("collectionAccessDetails");
    expect(col!.Assigned).toBe(true);
    expect(col!.Groups).toEqual([]);
    // Owner is a manage-all member so should appear in Users
    const users = col!.Users as Record<string, unknown>[];
    expect(users.length).toBeGreaterThan(0);
    expect(users.some((u) => u.Manage === true)).toBe(true);
  });

  it("GET /api/ciphers/organization-details returns org ciphers", async () => {
    const res = await authenticatedFetch(
      `/api/ciphers/organization-details?organizationId=${orgId}`,
      authToken,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      Data: Record<string, unknown>[];
    };
    const shared = body.Data.find((c) => c.Id === cipherId);
    expect(shared).toBeDefined();
    expect(shared!.OrganizationId).toBe(orgId);
    expect(shared!.CollectionIds).toEqual([collectionId]);
  });

  it("GET /api/ciphers/organization-details requires admin/owner access", async () => {
    const other = generateTestUser("nonadmin");
    await registerUser(other);
    const loginRes = await loginUser(other.email, other.masterPasswordHash);
    const otherToken = ((await loginRes.json()) as Record<string, unknown>)
      .access_token as string;
    const res = await authenticatedFetch(
      `/api/ciphers/organization-details?organizationId=${orgId}`,
      otherToken,
    );
    expect(res.status).toBe(404);
  });

  it("GET /api/ciphers/organization-details rejects missing organizationId", async () => {
    const res = await authenticatedFetch(
      `/api/ciphers/organization-details`,
      authToken,
    );
    expect(res.status).toBe(400);
  });

  it("POST /api/ciphers/create creates an org cipher with collection", async () => {
    const res = await authenticatedFetch(`/api/ciphers/create`, authToken, {
      method: "POST",
      body: {
        cipher: {
          type: 1,
          organizationId: orgId,
          name: "2.created-in-org",
          key: "2.cipher-key",
          login: { username: "2.u", password: "2.p" },
        },
        collectionIds: [collectionId],
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.OrganizationId).toBe(orgId);
    expect(body.CollectionIds).toEqual([collectionId]);
    expect(body.Object).toBe("cipherDetails");

    // Should also show up in the org-details listing
    const listRes = await authenticatedFetch(
      `/api/ciphers/organization-details?organizationId=${orgId}`,
      authToken,
    );
    const listBody = (await listRes.json()) as {
      Data: Record<string, unknown>[];
    };
    expect(listBody.Data.some((c) => c.Id === body.Id)).toBe(true);
  });

  it("POST /api/ciphers/create without org creates a personal cipher", async () => {
    const res = await authenticatedFetch(`/api/ciphers/create`, authToken, {
      method: "POST",
      body: {
        cipher: {
          type: 1,
          name: "2.personal-via-create",
          login: { username: "2.u", password: "2.p" },
        },
        collectionIds: [],
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.OrganizationId).toBeNull();
    expect(body.CollectionIds).toEqual([]);
  });

  it("POST /api/ciphers/create rejects non-members", async () => {
    const other = generateTestUser("nonmember2");
    await registerUser(other);
    const loginRes = await loginUser(other.email, other.masterPasswordHash);
    const otherToken = ((await loginRes.json()) as Record<string, unknown>)
      .access_token as string;
    const res = await authenticatedFetch(`/api/ciphers/create`, otherToken, {
      method: "POST",
      body: {
        cipher: {
          type: 1,
          organizationId: orgId,
          name: "2.nope",
          key: "2.k",
          login: {},
        },
        collectionIds: [collectionId],
      },
    });
    expect(res.status).toBe(403);
  });
});
