import { describe, it, expect } from "vitest";
import { mf, mfUrl } from "./mf";

describe("CORS", () => {
  it("OPTIONS preflight returns 204 with CORS headers", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/api/alive`, {
      method: "OPTIONS",
      headers: {
        Origin: "https://vault.example.com",
      },
    });

    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://vault.example.com",
    );
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("GET");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("PUT");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("DELETE");
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain(
      "Authorization",
    );
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain(
      "Content-Type",
    );
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain(
      "Bitwarden-Client-Name",
    );
    expect(res.headers.get("Access-Control-Allow-Credentials")).toBe("true");
    expect(res.headers.get("Access-Control-Max-Age")).toBe("86400");
  });

  it("OPTIONS preflight on any path returns 204", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/any/random/path`, {
      method: "OPTIONS",
      headers: { Origin: "https://vault.example.com" },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://vault.example.com",
    );
  });

  it("regular responses include CORS headers", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/alive`, {
      headers: { Origin: "https://vault.example.com" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://vault.example.com",
    );
    expect(res.headers.get("Access-Control-Allow-Credentials")).toBe("true");
  });

  it("requests without Origin get * as Allow-Origin", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/alive`);

    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});
