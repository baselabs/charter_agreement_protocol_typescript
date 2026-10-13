import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as api from "./index.ts";

function fixture(file: string, id: string): any {
  const document = JSON.parse(readFileSync(new URL(`./conformance/cases/${file}.json`, import.meta.url), "utf8"));
  const found = document.cases.find((one: any) => one.id === id);
  assert.ok(found, id);
  return found.input;
}

function claimsOf(compact: string): any {
  return JSON.parse(Buffer.from(compact.split(".")[1], "base64url").toString());
}

test("receipt context types use invalid_type", () => {
  const receipt = fixture("receipt-verify", "receipt-signed-governing-match");
  for (const context of [null, 42, [], ["x"], {}, true]) {
    assert.deepEqual(api.verifyReceipt(receipt.compact, context as any), { ok: false, code: "invalid_type" });
  }
});

test("set-aware producers and refusal checks preserve the set error", () => {
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  const acceptance = { ...claimsOf(view.acceptances[0]), protocol_revision: 2 };
  const termination = { ...claimsOf(fixture("termination-verify", "termination-valid").compact), protocol_revision: 2 };
  const broken = { ...view, descriptors: ["garbage"] };
  assert.deepEqual(api.verifyChain(broken), { ok: false, code: "compact_invalid" });
  for (const result of [api.acceptanceRefusal(acceptance, broken), api.terminationRefusal(termination, broken),
    api.acceptanceSigningInput("k", acceptance, broken), api.terminationSigningInput("k", termination, broken)]) {
    assert.deepEqual(result, { ok: false, code: "compact_invalid" });
  }
});

function generatedInputs(): any[] {
  let seed = 0x7051;
  const random = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  const atoms = [null, undefined, false, 42, "x", [], {}, ["x"], [null], { lineage: null }];
  const values: any[] = [...atoms];
  const fields = ["lineage", "digest", "descriptor_digest", "claims", "revisions", "acceptances", "descriptors", "terminations", "limits", "profile", "algorithms", "revisions"];
  for (let i = 0; i < 250; i++) {
    const value: any = {};
    for (let j = 0; j < 1 + random() % 5; j++) value[fields[random() % fields.length]] = atoms[random() % atoms.length];
    values.push(value);
  }
  return values;
}

test("public verify functions return typed results for generated malformed inputs", () => {
  const descriptor = fixture("party_descriptor-verify", "party-descriptor-genesis-valid").compact;
  const acceptance = fixture("acceptance-verify", "acceptance-valid");
  const receipt = fixture("receipt-verify", "receipt-signed-governing-match");
  const calls = (value: any) => [
    () => api.verifyDescriptor(value), () => api.verifyDescriptor(descriptor, value), () => api.verifyDescriptor(descriptor, null, value),
    () => api.verifyDescriptorChain(value), () => api.verifyDescriptorChain([descriptor], value),
    () => api.verifyAcceptance(value, acceptance.revision_text, acceptance.descriptor_compacts),
    () => api.verifyAcceptance(acceptance.compact, value, acceptance.descriptor_compacts),
    () => api.verifyAcceptance(acceptance.compact, acceptance.revision_text, value),
    () => api.verifyAcceptance(acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts, value),
    () => api.verifyTermination(value, acceptance.revision_text, acceptance.descriptor_compacts),
    () => api.verifyTermination(acceptance.compact, value, acceptance.descriptor_compacts),
    () => api.verifyTermination(acceptance.compact, acceptance.revision_text, value),
    () => api.verifyTermination(acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts, value),
    () => api.verifyChain(value), () => api.verifyChain(receipt.chain, value),
    () => api.verifyReceipt(value, receipt.chain), () => api.verifyReceipt(receipt.compact, value), () => api.verifyReceipt(receipt.compact, receipt.chain, value),
    () => api.verifySignature(value, Buffer.alloc(64), "x", "Ed25519"),
    () => api.verifySignature(Buffer.alloc(1), value, "x", "Ed25519"),
    () => api.verifySignature(Buffer.alloc(1), Buffer.alloc(64), value, "Ed25519"),
    () => api.verifySignature(Buffer.alloc(1), Buffer.alloc(64), "x", value),
    () => api.verifySignature(Buffer.alloc(1), Buffer.alloc(64), "x", "Ed25519", value),
  ];
  for (const value of generatedInputs()) for (const call of calls(value)) {
    const result = call();
    if (typeof result === "boolean") continue;
    assert.equal(typeof result.ok, "boolean");
    if (!result.ok) assert.equal(typeof result.code, "string");
  }
});

test("signature guard requires canonical base64url", () => {
  const compact = fixture("party_descriptor-verify", "party-descriptor-genesis-valid").compact;
  const [header, payload, signature] = compact.split(".");
  const key = claimsOf(compact).verification_keys[0].public_key;
  const message = Buffer.from(`${header}.${payload}`);
  const bytes = Buffer.from(signature, "base64url");
  assert.equal(api.verifySignature(message, bytes, key, "EdDSA"), true);
  assert.equal(api.verifySignature(message, bytes, key + "=", "EdDSA"), false);
});

test("runtime support checks declared types and known answers once per key algorithm", async () => {
  const { Session } = await import("node:inspector/promises");
  const fresh = await import(new URL("./core.ts?support-check", import.meta.url).href);
  const session = new Session();
  session.connect();
  try {
    await session.post("Profiler.enable");
    await session.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
    fresh.capabilities();
    fresh.capabilities();
    const { result } = await session.post("Profiler.takePreciseCoverage");
    const core = result.find((script) => script.url.endsWith("core.ts?support-check"));
    assert.ok(core);
    const count = core.functions.filter((fn) => fn.functionName === "katVerifies").reduce((sum, fn) => sum + fn.ranges[0].count, 0);
    assert.equal(count, 8);
  } finally {
    await session.post("Profiler.stopPreciseCoverage");
    session.disconnect();
  }
});
