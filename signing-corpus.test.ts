import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import * as api from "./index.ts";

const cases: api.ConformanceCase[] = JSON.parse(readFileSync(new URL("./conformance/cases/signing-prepare.json", import.meta.url), "utf8")).cases;

test("signing corpus runner matches Elixir kinds contexts and closed options", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-runner-"));
  try {
    const modulePath = join(scratch, "core.ts");
    // Expose the actual private runner in an isolated copy of the source.
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    const byId = (id: string) => {
      const one = cases.find((one) => one.id === id);
      assert.ok(one, id);
      return one;
    };
    const descriptor = byId("signing-ed25519-party_descriptor");
    const acceptance = byId("signing-ed25519-acceptance");
    const receipt = byId("signing-ed25519-receipt");
    const invalidType: api.CaseResult = { status: "invalid", error_code: "invalid_type" };
    const checks: Array<[string, api.ConformanceCase, Record<string, any>, api.CaseResult]> = [
      ["descriptor alias", descriptor, { kind: "descriptor" }, invalidType],
      ["receipt set wrapper", receipt, { context: acceptance.input.context }, invalidType],
      ["acceptance chain wrapper", acceptance, { context: receipt.input.context }, invalidType],
      ["termination chain wrapper", byId("signing-ed25519-termination"), { context: receipt.input.context }, invalidType],
      ["receipt raw revision", receipt, { context: receipt.input.context.chain.revisions[0] }, invalidType],
      ["acceptance raw set", acceptance, { context: acceptance.input.context.set }, invalidType],
      ["receipt raw set", receipt, { context: receipt.input.context.chain }, invalidType],
      ["profile extra member", descriptor, { profile: { unknown: 42 } }, invalidType],
      ["profile extra unrecognized name", descriptor, { profile: { ts_verifier_uninterned_member_12345: 42 } }, invalidType],
      ["limits extra member", descriptor, { limits: { unknown: 42 } }, invalidType],
      ["revision bounds extra member", descriptor, { profile: { revisions: { min: 1, max: 3, unknown: 42 } } }, invalidType],
      ["null profile", descriptor, { profile: null }, invalidType],
      ["null limits", descriptor, { limits: null }, invalidType],
      ["null revision bounds", descriptor, { profile: { revisions: null } }, invalidType],
      ["null algorithms", descriptor, { profile: { algorithms: null } }, { status: "invalid", error_code: "invalid_profile" }],
      ["limits before wrong kind", descriptor, { kind: "descriptor", limits: { max_bytes: -1 } }, { status: "invalid", error_code: "invalid_limits" }],
      ["profile before wrong context", receipt, { context: acceptance.input.context, profile: { algorithms: [] } }, { status: "invalid", error_code: "invalid_profile" }],
      ["key decode before wrong kind", descriptor, { kind: "descriptor", public_key: "=" }, { status: "invalid", error_code: "base64url_padded" }],
      ["chain read before wrong kind", acceptance, { context: { chain: { ...receipt.input.context.chain, descriptors: ["garbage"] } } }, { status: "invalid", error_code: "compact_invalid" }],
    ];
    for (const [name, one, patch, expected] of checks) await t.test(name, () => {
      assert.deepEqual(executeCase({ ...one, input: { ...one.input, ...patch } }), expected);
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("corpus runner rejects unknown options before every surface executes", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-runner-options-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    const index = JSON.parse(readFileSync(new URL("./conformance/index.json", import.meta.url), "utf8"));
    for (const file of index.files) {
      const document = JSON.parse(readFileSync(new URL(`./conformance/${file.path}`, import.meta.url), "utf8"));
      const one = document.cases[0];
      for (const patch of [{ limits: { unknown: 42 } }, { profile: { unknown: 42 } },
        { profile: { revisions: { min: 1, max: 3, unknown: 42 } } }, { limits: null },
        { profile: null }, { profile: { revisions: null } }]) {
        await t.test(`${one.surface} ${JSON.stringify(patch)}`, () => {
          assert.deepEqual(executeCase({ ...one, input: { ...one.input, ...patch } }), { status: "invalid", error_code: "invalid_type" });
        });
      }
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("receipt corpus runner applies caller limits to its chain context", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-runner-receipt-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    const receiptCases = JSON.parse(readFileSync(new URL("./conformance/cases/receipt-verify.json", import.meta.url), "utf8")).cases;
    const one = receiptCases.find((one: api.ConformanceCase) => one.id === "receipt-strict-chain-limits");
    assert.ok(one);
    assert.ok(api.verifyReceipt(one.input.compact, one.input.chain).ok);
    assert.deepEqual(api.verifyReceipt(one.input.compact, one.input.chain, { limits: one.input.limits }), { ok: false, code: "limit_exceeded" });
    assert.deepEqual(executeCase(one), one.expect);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("public signing preparation matches artifact corpus projections independently", async (t) => {
  assert.equal(cases.length, 69);
  for (const one of cases.filter((one) => !one.id.startsWith("signing-unknown-"))) await t.test(one.id, () => {
    const input = one.input;
    let context: any = input.context;
    if (context && typeof context === "object" && "set" in context) context = context.set;
    else if (context && typeof context === "object" && "chain" in context) {
      const checked = api.verifyChain(context.chain, { limits: context.chain.limits });
      assert.ok(checked.ok, one.id);
      context = context.chain;
    } else if (context && typeof context === "object" && "revision_text" in context) {
      assert.ok(api.decodeCharterRevision(context.revision_text).ok, one.id);
      context = context.revision_text;
    } else if (context && typeof context === "object" && "predecessor_compacts" in context) {
      let previous: api.DescriptorPredecessor | null = null;
      for (const compact of context.predecessor_compacts) {
        const checked = api.verifyDescriptor(compact, previous);
        assert.ok(checked.ok, one.id);
        previous = checked.facts as api.DescriptorPredecessor;
      }
      context = previous;
    }
    const kind = input.kind === "party_descriptor" ? "descriptor" : input.kind as api.SigningKind;
    const prepared = api.prepareSigning(kind, input.kid, input.claims, input.public_key, context,
      { algorithm: input.algorithm, limits: input.limits, profile: input.profile });
    const actual = prepared.ok ? { status: "valid", output: {
      protected_segment: prepared.plan.input.protectedSegment,
      payload_segment: prepared.plan.input.payloadSegment, key: prepared.plan.key,
    } } : { status: "invalid", error_code: prepared.code };
    assert.deepEqual(actual, one.expect);
    if (prepared.ok && prepared.plan.input.alg === "Ed25519") {
      // The mixed-order fixture supplies public bytes without a signing seed.
      if (one.id !== "signing-ed25519-mixed-order") {
        const privateKey = Array.from({ length: 9 }, (_, i) => createPrivateKey({
          key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, i + 1)]),
          format: "der", type: "pkcs8",
        })).find((key) => createPublicKey(key).export({ format: "jwk" }).x === input.public_key);
        assert.ok(privateKey, one.id);
        assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, privateKey)).ok);
      }
      if (prepared.plan.key === "matched") {
        assert.deepEqual(api.finishSigning(prepared.plan, Buffer.alloc(64)), { ok: false, code: "signature_invalid" });
      }
    }
  });
});
