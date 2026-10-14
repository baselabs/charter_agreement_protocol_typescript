import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

for (const shape of ["sparse", "proxy", "message", "set bytes", "wide", "shared", "deep"]) {
  test(`entry copy bounds ${shape} input cost`, () => {
    const script = `
      import * as api from ${JSON.stringify(new URL("./core.ts", import.meta.url).href)};
      const empty = { revisions: [], acceptances: [], descriptors: [], terminations: [] };
      let run;
      if (${JSON.stringify(shape)} === "sparse" || ${JSON.stringify(shape)} === "proxy") {
        const list = [];
        list.length = 2 ** 32 - 1;
        const source = ${JSON.stringify(shape)} === "proxy" ? new Proxy([], {
          get(target, key) { if (key === "length") return 2 ** 32 - 1; return Reflect.get(target, key); }
        }) : list;
        run = () => api.verifyChain({ ...empty, revisions: source });
      } else if (${JSON.stringify(shape)} === "message") {
        const bytes = new Uint8Array(200 * 1024 * 1024);
        run = () => api.verifySignature(bytes, new Uint8Array(64), "AAAA", "Ed25519");
      } else if (${JSON.stringify(shape)} === "set bytes") {
        const text = "x".repeat(65536);
        const set = { revisions: Array(1024).fill(text), acceptances: Array(1024).fill(text), descriptors: Array(1024).fill(text), terminations: [] };
        run = () => api.verifyChain(set);
      } else {
        let claims = {};
        if (${JSON.stringify(shape)} === "shared") {
          for (let i = 0; i < 40; i++) claims = { left: claims, right: claims };
        } else if (${JSON.stringify(shape)} === "deep") {
          for (let i = 0; i < 20000; i++) claims = { nested: claims };
        } else {
          claims = { items: Array.from({ length: 100000 }, (_, i) => ({ i, values: [i, i, i] })) };
        }
        run = () => api.prepareSigning("receipt", "k", claims, "AAAA", "x");
      }
      const start = performance.now();
      const result = run();
      console.log(JSON.stringify({ result, elapsed: performance.now() - start }));
    `;
    const child = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], {
      encoding: "utf8", timeout: 4000,
    });
    assert.equal(child.status, 0, child.error?.message ?? child.stderr);
    const { result, elapsed } = JSON.parse(child.stdout);
    assert.deepEqual(result, shape === "message" ? false : { ok: false, code:
      ["wide", "shared", "deep"].includes(shape) ? "signing_input_invalid" : "limit_exceeded" });
    assert.ok(elapsed < (shape === "message" ? 100 : 1000), `${shape}: ${elapsed}ms`);
    console.log(`${shape}: ${elapsed.toFixed(2)}ms, ${JSON.stringify(result)}`);
  });
}
