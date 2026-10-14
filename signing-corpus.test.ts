import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import * as api from "./index.ts";

const corpusCases = api.loadCorpus(new URL("./conformance", import.meta.url).pathname).cases;
const cases = corpusCases.filter((one) => one.surface === "signing.prepare");

test("byte decoding preserves parser order before UTF-8 errors", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-byte-reader-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    for (const [text, limits, code] of [
      [[0x5b, 0xff], { max_depth: 0 }, "limit_exceeded"],
      [[0x5b, 0x31, 0x5d, 0xff], {}, "trailing_bytes"],
      [[0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d], { max_depth: 0 }, "limit_exceeded"],
      [[0x7b, 0xff], { max_depth: 0 }, "invalid_encoding"],
      [[0x22, 0xff, 0x22], {}, "invalid_encoding"],
      [[0x5b, 0xff], {}, "invalid_encoding"],
    ] as const) await t.test(`${Buffer.from(text).toString("hex")} ${JSON.stringify(limits)}`, () => {
      assert.deepEqual(executeCase({ surface: "json.decode", input: {
        bytes_base64url: Buffer.from(text).toString("base64url"), limits,
      } }), { status: "invalid", error_code: code });
    });
    const text = '["é","𝄞",{"中":"\\u0000"}]';
    assert.deepEqual(executeCase({ surface: "json.decode", input: { bytes_base64url: Buffer.from(text).toString("base64url") } }),
      executeCase({ surface: "json.decode", input: { text } }));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("foundation runner surfaces validate their complete inputs", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-foundation-inputs-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") +
      "\nexport { execute as executeCase, readCaseJson as parseCaseText };\n");
    const { executeCase, parseCaseText } = await import(pathToFileURL(modulePath).href);
    const checks: Array<[string, Record<string, any>, api.CaseResult]> = [
      ["canonicalization.encode", { tag: "string_codepoint", value: "+0041" }, { status: "valid", output: { text: '"A"' } }],
      ["canonicalization.encode", { tag: "string_codepoint", value: "D800" }, { status: "invalid", error_code: "invalid_type" }],
      ["canonicalization.encode", { tag: "integer", text_value: "+007" }, { status: "valid", output: { text: "7" } }],
      ["canonicalization.encode", { tag: "integer", text_value: "-0" }, { status: "valid", output: { text: "0" } }],
      ["canonicalization.encode", { tag: "integer", text_value: 1 }, { status: "invalid", error_code: "invalid_type" }],
      ["canonicalization.encode", { tag: "integer", text_value: "1x" }, { status: "invalid", error_code: "invalid_type" }],
      ["canonicalization.encode", { tag: "object", members: [["a", { tag: "integer", value: "1" }]] }, { status: "invalid", error_code: "invalid_type" }],
      ["digest.hash", { bytes_base64url: "e30", domain: "unknown" }, { status: "invalid", error_code: "invalid_type" }],
      ["digest.hash", { bytes_base64url: "AB" }, { status: "invalid", error_code: "base64url_invalid" }],
      ["digest.hash", { bytes_base64url: 1 }, { status: "invalid", error_code: "invalid_type" }],
      ["digest.hash", { bytes_base64url: "e30", tagged: api.taggedDigest("charter_revision_content", Buffer.from("{}")) }, { status: "valid", output: {} }],
      ["schema.validate", { members: [] }, { status: "invalid", error_code: "invalid_type" }],
      ["json.decode", { kind: "integer", value: "[1]" }, { status: "invalid", error_code: "invalid_type" }],
      ["digest.hash", { kind: "integer", value: "{}" }, { status: "invalid", error_code: "invalid_type" }],
    ];
    for (const [surface, input, expected] of checks) await t.test(`${surface} ${JSON.stringify(input)}`, () => {
      assert.deepEqual(executeCase({ surface, input }), expected);
    });
    for (const literal of ["9007199254740993", "-9007199254740993", "1000000000000000000000000000000000000000000000000000000000"]) {
      const text = `{"surface":"canonicalization.encode","input":{"tag":"object","members":[["a",{"tag":"integer","value":${literal}}]]}}`;
      await t.test(`integer token ${literal}`, () => {
        assert.deepEqual(executeCase(parseCaseText(text)), { status: "invalid", error_code: "integer_magnitude" });
      });
    }
    const float = '{"surface":"canonicalization.encode","input":{"tag":"object","members":[["a",{"tag":"integer","value":1.0}]]}}';
    assert.deepEqual(executeCase(parseCaseText(float)), { status: "invalid", error_code: "invalid_type" });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("runner chain views contain exactly four lists and use top level limits", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-case-views-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    for (const id of ["signing-ed25519-receipt"]) {
      const one = cases.find((one) => one.id === id)!;
      const member = id.endsWith("acceptance") ? "set" : "chain";
      for (const extra of ["note", "limits"]) await t.test(`${id} ${extra}`, () => {
        const context = { [member]: { ...one.input.context[member], [extra]: {} } };
        assert.deepEqual(executeCase({ ...one, input: { ...one.input, context } }), { status: "invalid", error_code: "invalid_type" });
      });
    }
    const one = corpusCases.find((one) => one.id === "receipt-signed-governing-match")!;
    assert.deepEqual(executeCase({ ...one, input: { ...one.input, chain: { ...one.input.chain, limits: {} } } }),
      { status: "invalid", error_code: "invalid_type" });
    assert.deepEqual(executeCase({ ...one, input: { ...one.input, limits: { max_artifact_set_items: 0 } } }),
      { status: "invalid", error_code: "limit_exceeded" });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("runner reads receipt contexts before profile admission and preparation", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-receipt-order-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    const receipt = corpusCases.find((one) => one.id === "receipt-profile-context-algorithm-outside")!;
    for (const limits of [{ max_object_members: 8 }, { max_object_members: 10 }, { max_array_items: 1 }, { max_string_bytes: 50 }]) {
      await t.test(JSON.stringify(limits), () => {
        assert.deepEqual(executeCase({ ...receipt, input: { ...receipt.input, limits } }), { status: "invalid", error_code: "limit_exceeded" });
      });
    }
    const signing = cases.find((one) => one.id === "signing-strict-receipt-limits")!;
    for (const member of ["revisions", "acceptances"]) await t.test(member, () => {
      const chain = { ...signing.input.context.chain, [member]: [1, ...signing.input.context.chain[member].slice(1)] };
      assert.deepEqual(executeCase({ ...signing, input: { ...signing.input, context: { chain } } }),
        { status: "invalid", error_code: "invalid_type" });
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("runner matches every certified case with typed results", async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-runner-cases-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") + "\nexport { execute as executeCase };\n");
    const { executeCase } = await import(pathToFileURL(modulePath).href);
    assert.equal(corpusCases.length, 541);
    for (const one of corpusCases) await t.test(one.id, () => {
      assert.deepEqual(executeCase(one), one.expect);
    });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("case reader preserves float lexemes for integer fields", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-case-numbers-"));
  try {
    const modulePath = join(scratch, "core.ts");
    writeFileSync(modulePath, readFileSync(new URL("./core.ts", import.meta.url), "utf8") +
      '\nexport { execute as executeCase, readCaseJson as parseCaseText };\n');
    const { executeCase, parseCaseText } = await import(pathToFileURL(modulePath).href);
    const one = cases.find((one) => one.id === "signing-ed25519-party_descriptor")!;
    const text = JSON.stringify(one).replace('"protocol_revision":2', '"protocol_revision":2.0');
    assert.notEqual(text, JSON.stringify(one));
    assert.deepEqual(executeCase(parseCaseText(text)), { status: "invalid", error_code: "signing_input_invalid" });
    const limitsText = JSON.stringify({ ...one, input: { ...one.input, limits: { max_bytes: 20000 } } })
      .replace('"max_bytes":20000', '"max_bytes":20000.0');
    assert.deepEqual(executeCase(parseCaseText(limitsText)), { status: "invalid", error_code: "invalid_limits" });
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

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
      ["profile extra member", descriptor, { profile: { unknown: 42 } }, { status: "invalid", error_code: "invalid_profile" }],
      ["profile extra unrecognized name", descriptor, { profile: { ts_verifier_uninterned_member_12345: 42 } }, { status: "invalid", error_code: "invalid_profile" }],
      ["limits extra member", descriptor, { limits: { unknown: 42 } }, { status: "invalid", error_code: "invalid_limits" }],
      ["revision bounds extra member", descriptor, { profile: { revisions: { min: 1, max: 3, unknown: 42 } } }, { status: "invalid", error_code: "invalid_profile" }],
      ["null profile", descriptor, { profile: null }, { status: "invalid", error_code: "invalid_profile" }],
      ["null limits", descriptor, { limits: null }, { status: "invalid", error_code: "invalid_limits" }],
      ["null revision bounds", descriptor, { profile: { revisions: null } }, { status: "invalid", error_code: "invalid_profile" }],
      ["null algorithms", descriptor, { profile: { algorithms: null } }, { status: "invalid", error_code: "invalid_profile" }],
      ["limits before wrong kind", descriptor, { kind: "descriptor", limits: { max_bytes: -1 } }, { status: "invalid", error_code: "invalid_limits" }],
      ["profile before wrong context", receipt, { context: acceptance.input.context, profile: { algorithms: [] } }, { status: "invalid", error_code: "invalid_profile" }],
      ["key decode before wrong kind", descriptor, { kind: "descriptor", public_key: "=" }, { status: "invalid", error_code: "base64url_padded" }],
      ["chain read before wrong kind", acceptance, { context: { chain: { ...receipt.input.context.chain, descriptors: ["garbage"] } } }, { status: "invalid", error_code: "compact_invalid" }],
      ["null set", acceptance, { context: { set: null } }, invalidType],
      ["null set before short key", byId("signing-key-before-bad-set"), { context: { set: null } }, invalidType],
      ["set missing terminations", acceptance, { context: { set: { ...acceptance.input.context.set, terminations: undefined } } }, invalidType],
      ["nontext predecessor", descriptor, { context: { predecessor_compacts: [1] } }, invalidType],
      ["null receipt chain", receipt, { context: { chain: null } }, invalidType],
    ];
    for (const [name, one, patch, expected] of checks) await t.test(name, () => {
      assert.deepEqual(executeCase({ ...one, input: { ...one.input, ...patch } }), expected);
    });
    for (const member of ["revisions", "acceptances", "descriptors", "terminations"]) await t.test(`set missing ${member}`, () => {
      const set = { ...acceptance.input.context.set };
      delete set[member];
      assert.deepEqual(executeCase({ ...acceptance, input: { ...acceptance.input, context: { set } } }), invalidType);
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
          assert.deepEqual(executeCase({ ...one, input: { ...one.input, ...patch } }), { status: "invalid", error_code: "limits" in patch ? "invalid_limits" : "invalid_profile" });
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
  assert.equal(cases.length, 107);
  for (const one of cases.filter((one) => !one.id.startsWith("signing-unknown-") && !Object.hasOwn(one.input, "value") &&
    (!one.input.context?.chain || Object.keys(one.input.context.chain).length === 4))) await t.test(one.id, () => {
    const input = one.input;
    let context: any = input.context;
    if (context && typeof context === "object" && "set" in context) context = context.set;
    else if (context && typeof context === "object" && "chain" in context) {
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
