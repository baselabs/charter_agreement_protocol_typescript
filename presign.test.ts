import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";
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

function keyPair(algorithm = "Ed25519") {
  const pair = algorithm === "ML-DSA-65" ? generateKeyPairSync("ml-dsa-65") : generateKeyPairSync("ed25519");
  const raw = pair.publicKey.export({ format: "der", type: "spki" }).subarray(algorithm === "ML-DSA-65" ? 22 : 12);
  return { privateKey: pair.privateKey, publicKey: raw.toString("base64url") };
}

function signed(input: api.SigningInput, privateKey: KeyObject): string {
  const compact = api.assembleCompact(input, sign(null, input.message, privateKey));
  assert.ok(compact.ok, JSON.stringify(compact));
  return compact.compact;
}

function mintedSet(algorithm = "Ed25519", counterpartyAlgorithm = algorithm, counterpartyPad = "") {
  const base = fixture("chain-verify", "chain-dual-acceptance-valid");
  const revisionNumber = algorithm === "ML-DSA-65" ? 3 : 2;
  const parties = [keyPair(algorithm), keyPair(counterpartyAlgorithm)].map((pair, index) => {
    const alg = index === 0 ? algorithm : counterpartyAlgorithm;
    const claims = { ...claimsOf(base.descriptors[index]), protocol_revision: alg === "ML-DSA-65" ? 3 : alg === "EdDSA" ? 1 : 2,
      verification_keys: [{ key_id: "k", algorithm: alg === "EdDSA" ? "Ed25519" : alg, public_key: pair.publicKey, status: "active" }] };
    if (index === 1 && counterpartyPad) claims.extensions = { critical: {}, optional: { "com.example/pad": counterpartyPad } };
    // EdDSA is accepted but is not emitted by the build-only producers.
    const compact = alg === "EdDSA" ? rawCompact("descriptor", "k", claims, alg, pair.privateKey) : (() => {
      const built = api.descriptorSigningInput("k", claims, alg);
      assert.ok(built.ok, JSON.stringify(built));
      return signed(built.input, pair.privateKey);
    })();
    const digest = api.descriptorDigest(compact);
    assert.ok(digest.ok);
    return { ...pair, claims, compact, digest: digest.digest };
  });
  const revision = { ...JSON.parse(base.revisions[0]), protocol_revision: 2,
    parties: ["issuer", "acceptor"].map((role, index) => ({ role, party_descriptor_digest: parties[index].digest })) };
  const revisionText = api.canonical(revision);
  const digest = api.revisionDigest(revisionText);
  assert.ok(digest.ok, JSON.stringify(digest));
  const acceptance = (index: number) => ({ ...claimsOf(base.acceptances[index]), protocol_revision: revisionNumber,
    charter_id: digest.digest, revision_digest: digest.digest, party_descriptor_digest: parties[index].digest });
  const acceptances = parties.map((pair, index) => rawCompact("acceptance", "k", acceptance(index), index === 1 ? counterpartyAlgorithm : algorithm, pair.privateKey));
  const chain: api.ChainInput = { revisions: [revisionText], acceptances, descriptors: parties.map((pair) => pair.compact), terminations: [] };
  assert.ok(api.verifyChain(chain).ok);
  const termination = { ...claimsOf(fixture("termination-verify", "termination-valid").compact), protocol_revision: revisionNumber,
    charter_id: digest.digest, governing_revision_digest: digest.digest, party_descriptor_digest: parties[0].digest };
  const receipt = { ...claimsOf(fixture("receipt-verify", "receipt-signed-governing-match").compact), protocol_revision: revisionNumber,
    charter_id: digest.digest, revision_digest: digest.digest };
  return { parties, revision, revisionText, digest: digest.digest, chain, acceptance: acceptance(0), termination, receipt, algorithm };
}

function rawCompact(kind: string, kid: string, claims: any, algorithm: string, privateKey: KeyObject): string {
  const typ = { descriptor: "cap+party", acceptance: "cap+acceptance", termination: "cap+termination", receipt: "cap+receipt" }[kind];
  assert.ok(typ);
  const message = Buffer.from(`${Buffer.from(api.canonical({ alg: algorithm, kid, typ })).toString("base64url")}.${Buffer.from(api.canonical(claims)).toString("base64url")}`);
  return `${message}.${sign(null, message, privateKey).toString("base64url")}`;
}

for (const algorithm of ["Ed25519", "ML-DSA-65"]) test(`prepare and real finish for every kind with ${algorithm}`, () => {
  const set = mintedSet(algorithm);
  for (const [kind, claims, context] of [
    ["descriptor", set.parties[0].claims, null], ["acceptance", set.acceptance, set.chain],
    ["termination", set.termination, set.chain], ["receipt", set.receipt, set.chain], ["receipt", set.receipt, set.revisionText],
  ] as const) {
    const prepared = api.prepareSigning(kind, "k", claims, set.parties[0].publicKey, context, { algorithm });
    assert.ok(prepared.ok, JSON.stringify(prepared));
    assert.ok(prepared.plan instanceof api.SigningPlan);
    assert.equal(prepared.plan.kind, kind);
    assert.equal(prepared.plan.key, typeof context === "string" ? "unnamed" : "matched");
    const finished = api.finishSigning(prepared.plan, new Uint8Array(sign(null, prepared.plan.input.message, set.parties[0].privateKey)));
    assert.ok(finished.ok, JSON.stringify(finished));
    assert.equal(api.decodeArtifact(finished.compact).ok, true);
  }
});

test("prepare orders limits profile context build key shape context claims membership", () => {
  const set = mintedSet();
  const prepare = (changes: any = {}) => api.prepareSigning(changes.kind ?? "descriptor", changes.kid ?? "k", changes.claims ?? set.parties[0].claims,
    changes.publicKey ?? set.parties[0].publicKey, Object.hasOwn(changes, "context") ? changes.context : null, changes.options);
  for (const [changes, code] of [
    [{ context: 42, claims: {}, publicKey: "x", options: { limits: { max_bytes: -1 }, profile: null } }, "invalid_limits"],
    [{ context: 42, claims: {}, publicKey: "x", options: { profile: null } }, "invalid_profile"],
    [{ context: 42, claims: {}, publicKey: "x" }, "invalid_type"], [{ claims: {}, publicKey: "x" }, "signing_input_invalid"],
    [{ publicKey: "x", context: {} }, "signing_key_invalid"], [{ publicKey: set.parties[0].publicKey + "=" }, "signing_key_invalid"],
    [{ publicKey: keyPair().publicKey }, "signing_key_mismatch"], [{ kid: "missing" }, "signing_key_mismatch"],
    [{ options: { profile: { algorithms: ["EdDSA"] } }, kid: "missing" }, "algorithm_outside_profile"],
    [{ kind: "acceptance", claims: set.acceptance, context: { ...set.chain, descriptors: ["garbage"] } }, "compact_invalid"],
    [{ kind: "acceptance", claims: { ...set.acceptance, revision_digest: "sha-256:" + "A".repeat(43) }, context: set.chain }, "signing_refused"],
  ] as const) assert.deepEqual(prepare(changes), { ok: false, code });
  for (const kind of ["descriptor", "acceptance", "termination", "receipt", "other"] as const) {
    for (const context of [null, 42, [], ["x"], false, "x"]) {
      if (kind === "descriptor" && context === null || kind === "receipt" && typeof context === "string") continue;
      assert.deepEqual(prepare({ kind, context }), { ok: false, code: "invalid_type" });
    }
  }
  for (const value of [null, {}, [], 42, Object.create(api.SigningPlan.prototype)]) {
    assert.deepEqual(api.finishSigning(value as any, Buffer.alloc(64)), { ok: false, code: "invalid_type" });
  }
});

test("small-order descriptor key is refused by prepare", () => {
  const set = mintedSet();
  const publicKey = Buffer.from("01" + "00".repeat(31), "hex").toString("base64url");
  const claims = { ...set.parties[0].claims, verification_keys: [{ ...set.parties[0].claims.verification_keys[0], public_key: publicKey }] };
  assert.equal(api.descriptorSigningInput("k", claims).ok, true);
  assert.deepEqual(api.prepareSigning("descriptor", "k", claims, publicKey, null), { ok: false, code: "signing_key_invalid" });
});

test("successor requires a verified predecessor and uses its active key", () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"]) {
    const set = mintedSet(algorithm);
    const previous = api.verifyDescriptor(set.parties[0].compact);
    assert.ok(previous.ok);
    const claims = { ...set.parties[0].claims, descriptor_number: 2, party_id: set.parties[0].digest, prev_descriptor_digest: set.parties[0].digest };
    assert.equal(api.descriptorSigningInput("k", claims, algorithm).ok, true);
    assert.deepEqual(api.prepareSigning("descriptor", "k", claims, set.parties[0].publicKey, null, { algorithm }), { ok: false, code: "descriptor_chain_invalid" });
    const prepared = api.prepareSigning("descriptor", "k", claims, set.parties[0].publicKey, previous.facts, { algorithm });
    assert.ok(prepared.ok, JSON.stringify(prepared));
    assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, set.parties[0].privateKey)).ok);
    const wrong = api.verifyDescriptor(set.parties[1].compact);
    assert.ok(wrong.ok);
    assert.deepEqual(api.prepareSigning("descriptor", "k", claims, set.parties[0].publicKey, wrong.facts, { algorithm }), { ok: false, code: "descriptor_chain_invalid" });
  }
});

test("prepare keeps the retained context and signing input private", () => {
  const set = mintedSet();
  const options: api.VerificationOptions = { profile: { algorithms: ["Ed25519"] } };
  const prepared = api.prepareSigning("acceptance", "k", set.acceptance, set.parties[0].publicKey, set.chain, options);
  assert.ok(prepared.ok);
  const message = Buffer.from(prepared.plan.input.message);
  for (const array of Object.values(set.chain)) array.splice(0);
  options.profile!.algorithms!.splice(0);
  prepared.plan.input.message.fill(0);
  set.acceptance.party_role = "changed";
  assert.deepEqual(prepared.plan.input.message, message);
  assert.ok(api.finishSigning(prepared.plan, sign(null, message, set.parties[0].privateKey)).ok);
  assert.deepEqual(Object.keys(prepared.plan).sort(), ["key", "kind"]);
  assert.deepEqual(api.finishSigning(prepared.plan, "x" as any), { ok: false, code: "invalid_type" });
  assert.deepEqual(api.finishSigning(prepared.plan, Buffer.alloc(63)), { ok: false, code: "signature_invalid" });
  assert.deepEqual(api.finishSigning(prepared.plan, sign(null, message, set.parties[1].privateKey)), { ok: false, code: "signature_invalid" });
});

test("prepare returns typed results for generated malformed inputs in every position", () => {
  const set = mintedSet();
  for (const value of generatedInputs()) for (const kind of ["descriptor", "acceptance", "termination", "receipt"] as const) {
    const claims = kind === "descriptor" ? set.parties[0].claims : set[kind];
    const context = kind === "descriptor" ? null : set.chain;
    for (const args of [[value, "k", claims, set.parties[0].publicKey, context], [kind, value, claims, set.parties[0].publicKey, context],
      [kind, "k", value, set.parties[0].publicKey, context], [kind, "k", claims, value, context],
      [kind, "k", claims, set.parties[0].publicKey, value], [kind, "k", claims, set.parties[0].publicKey, context, value]]) {
      const result = (api.prepareSigning as Function)(...args);
      assert.equal(typeof result.ok, "boolean");
      if (!result.ok) assert.equal(typeof result.code, "string");
    }
  }
});
