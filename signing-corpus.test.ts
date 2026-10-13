import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import * as api from "./index.ts";

const cases: api.ConformanceCase[] = JSON.parse(readFileSync(new URL("./conformance/cases/signing-prepare.json", import.meta.url), "utf8")).cases;

test("public signing preparation matches every corpus projection independently", async (t) => {
  assert.equal(cases.length, 57);
  for (const one of cases) await t.test(one.id, () => {
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
      const privateKey = Array.from({ length: 9 }, (_, i) => createPrivateKey({
        key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, i + 1)]),
        format: "der", type: "pkcs8",
      })).find((key) => createPublicKey(key).export({ format: "jwk" }).x === input.public_key);
      assert.ok(privateKey, one.id);
      assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, privateKey)).ok);
      if (prepared.plan.key === "matched") {
        assert.deepEqual(api.finishSigning(prepared.plan, Buffer.alloc(64)), { ok: false, code: "signature_invalid" });
      }
    }
  });
});
