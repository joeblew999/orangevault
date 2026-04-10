import { describe, it, expect, beforeAll } from "vitest";
import {
  authenticatedFetch,
  applyMigrations,
  generateTestUser,
  generateTotpCode,
  registerUser,
  loginUser,
} from "./helpers";

let authToken: string;
let testUser: { name: string; email: string; masterPasswordHash: string };

beforeAll(async () => {
  await applyMigrations();
  testUser = generateTestUser("2fa");
  await registerUser(testUser);
  const loginRes = await loginUser(testUser.email, testUser.masterPasswordHash);
  const loginBody = (await loginRes.json()) as Record<string, unknown>;
  authToken = loginBody.access_token as string;
});

describe("TOTP 2FA setup", () => {
  let totpKey: string;

  it("GET /api/two-factor lists no providers initially", async () => {
    const res = await authenticatedFetch("/api/two-factor", authToken);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { Data: unknown[] };
    expect(body.Data).toEqual([]);
  });

  it("POST /api/two-factor/get-authenticator returns a secret", async () => {
    const res = await authenticatedFetch(
      "/api/two-factor/get-authenticator",
      authToken,
      {
        method: "POST",
        body: { masterPasswordHash: testUser.masterPasswordHash },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Enabled).toBe(false);
    expect(body.Key).toBeDefined();
    expect(typeof body.Key).toBe("string");
    expect((body.Key as string).length).toBeGreaterThan(10);
    expect(body.Object).toBe("twoFactorAuthenticator");
    totpKey = body.Key as string;
  });

  it("POST /api/two-factor/authenticator rejects wrong TOTP code", async () => {
    const res = await authenticatedFetch(
      "/api/two-factor/authenticator",
      authToken,
      {
        method: "POST",
        body: {
          masterPasswordHash: testUser.masterPasswordHash,
          key: totpKey,
          token: "000000",
        },
      },
    );
    expect(res.status).toBe(400);
  });

  it("POST /api/two-factor/authenticator enables TOTP with valid code", async () => {
    // Generate a valid TOTP code using the key
    const code = await generateTotpCode(totpKey);

    const res = await authenticatedFetch(
      "/api/two-factor/authenticator",
      authToken,
      {
        method: "POST",
        body: {
          masterPasswordHash: testUser.masterPasswordHash,
          key: totpKey,
          token: code,
        },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Enabled).toBe(true);
  });

  it("GET /api/two-factor now lists authenticator provider", async () => {
    const res = await authenticatedFetch("/api/two-factor", authToken);
    const body = (await res.json()) as {
      Data: { Type: number; Enabled: boolean }[];
    };
    expect(body.Data.length).toBe(1);
    expect(body.Data[0].Type).toBe(0);
    expect(body.Data[0].Enabled).toBe(true);
  });

  it("POST /api/two-factor/get-recover returns recovery code", async () => {
    const res = await authenticatedFetch(
      "/api/two-factor/get-recover",
      authToken,
      {
        method: "POST",
        body: { masterPasswordHash: testUser.masterPasswordHash },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Code).toBeDefined();
    expect(typeof body.Code).toBe("string");
    expect((body.Code as string).length).toBeGreaterThan(10);
  });
});

describe("2FA login flow", () => {
  it("login without 2FA token returns error with TwoFactorProviders", async () => {
    // testUser has TOTP enabled from above tests
    const res = await loginUser(testUser.email, testUser.masterPasswordHash);
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toBe("Two factor required.");
    expect(body.TwoFactorProviders).toEqual([0]);
  });

  it("login with valid TOTP code succeeds", async () => {
    const getRes = await authenticatedFetch(
      "/api/two-factor/get-authenticator",
      authToken,
      {
        method: "POST",
        body: { masterPasswordHash: testUser.masterPasswordHash },
      },
    );
    const getBody = (await getRes.json()) as Record<string, unknown>;
    const totpKey = getBody.Key as string;
    const code = await generateTotpCode(totpKey);

    const res = await loginUser(testUser.email, testUser.masterPasswordHash, {
      twoFactorProvider: "0",
      twoFactorToken: code,
      deviceIdentifier: "test-2fa-device",
    });

    expect(res.status).toBe(200);
    const resBody = (await res.json()) as Record<string, unknown>;
    expect(resBody.access_token).toBeDefined();
    expect(resBody.refresh_token).toBeDefined();
  });

  it("login with wrong TOTP code fails", async () => {
    const res = await loginUser(testUser.email, testUser.masterPasswordHash, {
      twoFactorProvider: "0",
      twoFactorToken: "000000",
      deviceIdentifier: "test-2fa-device-2",
    });
    expect(res.status).toBe(400);
  });
});

describe("Recovery code flow", () => {
  it("login with recovery code disables 2FA", async () => {
    // Get recovery code
    const recoverRes = await authenticatedFetch(
      "/api/two-factor/get-recover",
      authToken,
      {
        method: "POST",
        body: { masterPasswordHash: testUser.masterPasswordHash },
      },
    );
    const recoverBody = (await recoverRes.json()) as Record<string, unknown>;
    const recoveryCode = recoverBody.Code as string;

    const res = await loginUser(testUser.email, testUser.masterPasswordHash, {
      twoFactorProvider: "8",
      twoFactorToken: recoveryCode,
      deviceIdentifier: "test-recovery-device",
    });

    expect(res.status).toBe(200);
    const resBody = (await res.json()) as Record<string, unknown>;
    expect(resBody.access_token).toBeDefined();

    // Now login should work without 2FA (it was disabled by recovery)
    const normalLogin = await loginUser(
      testUser.email,
      testUser.masterPasswordHash,
    );
    expect(normalLogin.status).toBe(200);
  });
});

