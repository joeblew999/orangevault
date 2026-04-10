import { Miniflare } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const buildDir = resolve(__dirname, "..", "..", "build");

const jsCode = readFileSync(resolve(buildDir, "index.js"), "utf-8");
const wasmBytes = readFileSync(resolve(buildDir, "index_bg.wasm"));

const mf_instance = new Miniflare({
  workers: [
    {
      name: "orangevault",
      modules: [
        { type: "ESModule", path: "index.js", contents: jsCode },
        {
          type: "CompiledWasm",
          path: "index_bg.wasm",
          contents: wasmBytes,
        },
      ],
      compatibilityDate: "2026-04-01",
      d1Databases: ["DB"],
      kvNamespaces: ["CACHE"],
      r2Buckets: ["FILES"],
      bindings: {
        DOMAIN: "http://localhost",
        SIGNUPS_ALLOWED: "true",
        WEB_VAULT_ENABLED: "true",
      },
    },
  ],
});

export const mfUrl = (await mf_instance.ready).toString().replace(/\/$/, "");
export const mf = mf_instance;
