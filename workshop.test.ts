import test from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createContext, runInContext } from "node:vm";
import { webcrypto } from "node:crypto";
import { browserBundleOptions } from "./web/bundle.ts";

test("workshop signs both acceptances and a receipt with the site's browser shims", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-workshop-"));
  try {
    const outfile = join(scratch, "workshop.js");
    await build({
      ...browserBundleOptions, bundle: true, format: "iife", globalName: "WorkshopPage", outfile,
      stdin: { contents: 'export { Workshop } from "./web/flow.ts"; export { verifyChain, verifyReceipt } from "./index.ts";', resolveDir: process.cwd() },
    });
    const source = readFileSync(outfile, "utf8");
    await t.test("WebCrypto non-extractable", async () => {
      const page = createContext({ TextEncoder, TextDecoder, atob, btoa, crypto: webcrypto });
      runInContext(source, page);
      assert.equal(runInContext("typeof process", page), "undefined");
      await runInContext(`(async () => {
        const workshop = new WorkshopPage.Workshop();
        await workshop.reset();
        globalThis.workshop = workshop;
        globalThis.steps = [await workshop.form(), await workshop.accept()];
        if (steps.every((step) => step.ok)) steps.push(await workshop.signActionReceipt());
      })()`, page);
      const steps = JSON.parse(runInContext("JSON.stringify(steps)", page));
      assert.deepEqual(steps, [{ ok: true }, { ok: true }, { ok: true }]);
      assert.equal(runInContext("workshop.issuer.key.mode", page), "WebCrypto non-extractable");
      assert.equal(runInContext("workshop.acceptor.key.mode", page), "WebCrypto non-extractable");
      assert.equal(runInContext("WorkshopPage.verifyChain(workshop.view()).ok", page), true);
      assert.equal(runInContext("workshop.view().acceptances.length", page), 2);
      assert.equal(runInContext("WorkshopPage.verifyReceipt(workshop.receipt, workshop.view()).ok", page), true);
      for (const kind of ["revision", "descriptor"]) {
        const valid = await runInContext(`workshop.tampered(${JSON.stringify(kind)}).then((view) => WorkshopPage.verifyChain(view).ok)`, page);
        assert.equal(valid, false, kind);
      }
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
