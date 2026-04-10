import { describe, it, expect } from "vitest";
import { workerFetch } from "./helpers";

describe("smoke", () => {
  it("GET /alive returns 200", async () => {
    const res = await workerFetch("/alive");
    expect(res.status).toBe(200);
  });

  it("GET /api/alive returns 200", async () => {
    const res = await workerFetch("/api/alive");
    expect(res.status).toBe(200);
  });

  it("unknown route returns 404", async () => {
    const res = await workerFetch("/does-not-exist");
    expect(res.status).toBe(404);
  });
});
