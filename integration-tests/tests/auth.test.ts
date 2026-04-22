import { describe, it, expect, beforeAll } from "vitest";
import { mf, mfUrl } from "./mf";
import {
  workerFetch,
  applyMigrations,
  generateTestUser,
  registerUser,
  loginUser,
} from "./helpers";

beforeAll(async () => {
  await applyMigrations();
});

describe("/api/config", () => {
  it("returns 200 with expected shape", async () => {
    const res = await workerFetch("/api/config");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.version).toBe("2024.1.0");
    expect(body.object).toBe("config");
    expect(body.server).toEqual({ name: "orangevault", url: "" });
    expect(body.featureStates).toEqual({});
  });

  it("environment URLs use configured domain", async () => {
    const res = await workerFetch("/api/config");
    const body = (await res.json()) as {
      environment: Record<string, string>;
    };
    expect(body.environment.api).toBe("http://localhost/api");
    expect(body.environment.identity).toBe("http://localhost/identity");
    expect(body.environment.notifications).toBe(
      "http://localhost/notifications",
    );
  });
});

describe("/accounts/prelogin", () => {
  it("returns defaults for unknown email", async () => {
    const res = await workerFetch("/accounts/prelogin", {
      method: "POST",
      body: { email: "nobody@example.com" },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Kdf).toBe(0);
    expect(body.KdfIterations).toBe(600000);
    expect(body.KdfMemory).toBeUndefined();
    expect(body.KdfParallelism).toBeUndefined();
  });

  it("returns registered user KDF params", async () => {
    const user = generateTestUser("prelogin");
    const regRes = await registerUser(user);
    expect(regRes.status).toBe(200);

    const res = await workerFetch("/accounts/prelogin", {
      method: "POST",
      body: { email: user.email },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.Kdf).toBe(0);
    expect(body.KdfIterations).toBe(600000);
  });

  it("returns 400 for missing body", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/accounts/prelogin`, {
      method: "POST",
    });
    expect(res.status).toBe(400);
  });
});

describe("/identity/accounts/register", () => {
  it("creates a user successfully", async () => {
    const user = generateTestUser("register");
    const res = await registerUser(user);
    expect(res.status).toBe(200);
  });

  it("rejects duplicate email", async () => {
    const user = generateTestUser("dup");
    await registerUser(user);
    const res = await registerUser(user);
    expect(res.status).toBe(409);
  });

  it("rejects missing email", async () => {
    const res = await workerFetch("/identity/accounts/register", {
      method: "POST",
      body: { masterPasswordHash: "abc" },
    });
    expect(res.status).toBe(400);
  });
});

describe("/identity/accounts/register/send-verification-email", () => {
  it("returns a JWT string that register/finish accepts", async () => {
    const user = generateTestUser("verify");

    const verifyRes = await workerFetch(
      "/identity/accounts/register/send-verification-email",
      {
        method: "POST",
        body: { email: user.email, name: user.name },
      },
    );
    expect(verifyRes.status).toBe(200);
    const token = (await verifyRes.json()) as string;
    expect(typeof token).toBe("string");
    expect(token.split(".").length).toBe(3);

    const finishRes = await workerFetch("/identity/accounts/register/finish", {
      method: "POST",
      body: {
        email: user.email,
        name: user.name,
        masterPasswordHash: user.masterPasswordHash,
        emailVerificationToken: token,
        key: "encrypted-key-placeholder",
        kdf: 0,
        kdfIterations: 600000,
        keys: {
          publicKey: "public-key-placeholder",
          encryptedPrivateKey: "encrypted-private-key-placeholder",
        },
      },
    });
    expect(finishRes.status).toBe(200);

    const loginRes = await loginUser(user.email, user.masterPasswordHash);
    expect(loginRes.status).toBe(200);
  });

  it("register/finish rejects a token for a different email", async () => {
    const verifyRes = await workerFetch(
      "/identity/accounts/register/send-verification-email",
      {
        method: "POST",
        body: { email: "alice@test.example.com", name: "Alice" },
      },
    );
    const token = (await verifyRes.json()) as string;

    const finishRes = await workerFetch("/identity/accounts/register/finish", {
      method: "POST",
      body: {
        email: "mallory@test.example.com",
        masterPasswordHash: "dGVzdA==",
        emailVerificationToken: token,
        key: "encrypted-key-placeholder",
        kdf: 0,
        kdfIterations: 600000,
        keys: {
          publicKey: "public-key-placeholder",
          encryptedPrivateKey: "encrypted-private-key-placeholder",
        },
      },
    });
    expect(finishRes.status).toBe(400);
  });

  it("register/finish accepts userSymmetricKey / userAsymmetricKeys aliases", async () => {
    const user = generateTestUser("aliases");

    const verifyRes = await workerFetch(
      "/identity/accounts/register/send-verification-email",
      {
        method: "POST",
        body: { email: user.email, name: user.name },
      },
    );
    const token = (await verifyRes.json()) as string;

    const finishRes = await workerFetch("/identity/accounts/register/finish", {
      method: "POST",
      body: {
        email: user.email,
        masterPasswordHash: user.masterPasswordHash,
        emailVerificationToken: token,
        userSymmetricKey: "encrypted-key-placeholder",
        userAsymmetricKeys: {
          publicKey: "public-key-placeholder",
          encryptedPrivateKey: "encrypted-private-key-placeholder",
        },
        kdf: 0,
        kdfIterations: 600000,
      },
    });
    expect(finishRes.status).toBe(200);

    const loginRes = await loginUser(user.email, user.masterPasswordHash);
    expect(loginRes.status).toBe(200);
    const login = (await loginRes.json()) as Record<string, unknown>;
    expect(login.Key).toBe("encrypted-key-placeholder");
    expect(login.PrivateKey).toBe("encrypted-private-key-placeholder");
    expect(login.AccountKeys).not.toBeNull();
    expect(
      (login.UserDecryptionOptions as { MasterPasswordUnlock: unknown })
        .MasterPasswordUnlock,
    ).not.toBeNull();
  });

  it("register/finish rejects a missing token", async () => {
    const user = generateTestUser("notoken");
    const res = await workerFetch("/identity/accounts/register/finish", {
      method: "POST",
      body: {
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
    expect(res.status).toBe(400);
  });
});

describe("/identity/connect/token (password grant)", () => {
  it("returns tokens for valid credentials", async () => {
    const user = generateTestUser("login");
    await registerUser(user);

    const res = await loginUser(user.email, user.masterPasswordHash);
    expect(res.status).toBe(200);

    const body = (await res.json()) as Record<string, unknown>;
    expect(body.access_token).toBeDefined();
    expect(typeof body.access_token).toBe("string");
    expect(body.refresh_token).toBeDefined();
    expect(typeof body.refresh_token).toBe("string");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(7200);
    expect(body.Key).toBe("encrypted-key-placeholder");
    expect(body.Kdf).toBe(0);
    expect(body.KdfIterations).toBe(600000);
    expect(body.unofficialServer).toBe(true);
    expect(body.UserDecryptionOptions).toMatchObject({
      HasMasterPassword: true,
      Object: "userDecryptionOptions",
      MasterPasswordUnlock: {
        Kdf: {
          KdfType: 0,
          Iterations: 600000,
        },
        MasterKeyEncryptedUserKey: "encrypted-key-placeholder",
        MasterKeyWrappedUserKey: "encrypted-key-placeholder",
        Salt: expect.stringMatching(/@test\.example\.com$/),
      },
    });
    expect(body.AccountKeys).toEqual({
      Object: "privateKeys",
      publicKeyEncryptionKeyPair: {
        Object: "publicKeyEncryptionKeyPair",
        wrappedPrivateKey: "encrypted-private-key-placeholder",
        publicKey: "public-key-placeholder",
      },
    });
  });

  it("rejects wrong password", async () => {
    const user = generateTestUser("wrongpw");
    await registerUser(user);

    const res = await loginUser(user.email, "wrong-hash");
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects unknown user", async () => {
    const res = await loginUser("noone@example.com", "hash");
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("invalid_grant");
  });
});

describe("/identity/connect/token (refresh grant)", () => {
  it("returns new tokens with valid refresh_token", async () => {
    const user = generateTestUser("refresh");
    await registerUser(user);

    // Login to get initial tokens
    const loginRes = await loginUser(user.email, user.masterPasswordHash);
    expect(loginRes.status).toBe(200);
    const loginBody = (await loginRes.json()) as Record<string, unknown>;
    const refreshToken = loginBody.refresh_token as string;

    // Use refresh token
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    const res = await mf.dispatchFetch(`${mfUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    expect(res.status).toBe(200);

    const refreshBody = (await res.json()) as Record<string, unknown>;
    expect(refreshBody.access_token).toBeDefined();
    expect(refreshBody.refresh_token).toBeDefined();
    // New tokens should be different from old ones
    expect(refreshBody.refresh_token).not.toBe(refreshToken);
  });

  it("rejects old refresh_token after rotation", async () => {
    const user = generateTestUser("rotate");
    await registerUser(user);

    const loginRes = await loginUser(user.email, user.masterPasswordHash);
    const loginBody = (await loginRes.json()) as Record<string, unknown>;
    const oldRefreshToken = loginBody.refresh_token as string;

    // Refresh once (rotates the token)
    const refreshBody = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: oldRefreshToken,
    });
    const refreshRes = await mf.dispatchFetch(
      `${mfUrl}/identity/connect/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: refreshBody.toString(),
      },
    );
    expect(refreshRes.status).toBe(200);

    // Try old token again — should fail
    const retryRes = await mf.dispatchFetch(
      `${mfUrl}/identity/connect/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: refreshBody.toString(),
      },
    );
    expect(retryRes.status).toBe(400);
  });

  it("rejects invalid refresh_token", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "not.a.valid.token",
    });
    const res = await mf.dispatchFetch(`${mfUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    expect(res.status).toBe(400);
  });
});
