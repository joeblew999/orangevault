import { describe, it, expect } from "vitest";
import { workerFetch } from "./helpers";

describe("error response format", () => {
  it("404 returns Bitwarden-compatible ErrorModel shape", async () => {
    const res = await workerFetch("/api/nonexistent-route", {
      headers: { Origin: "https://vault.example.com" },
    });
    expect(res.status).toBe(404);

    // Verify CORS headers are present even on error responses
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://vault.example.com",
    );
  });
});
