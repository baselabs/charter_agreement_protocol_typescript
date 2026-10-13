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
    [{ publicKey: "x", context: {} }, "invalid_type"],
    [{ publicKey: "x", context: { descriptor_digest: set.parties[0].digest, lineage: ["garbage"] } }, "signing_key_invalid"],
    [{ publicKey: set.parties[0].publicKey + "=" }, "signing_key_invalid"],
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

test("malformed predecessor history returns invalid_type", () => {
  const set = mintedSet();
  for (const predecessor of [{ lineage: [42] }, { lineage: null }, {},
    { descriptor_digest: set.parties[0].digest, lineage: [42] },
    { descriptor_digest: set.parties[0].digest, lineage: null },
    { descriptor_digest: set.parties[0].digest, lineage: [] }]) {
    assert.deepEqual(api.verifyDescriptor(set.parties[0].compact, predecessor as any), { ok: false, code: "invalid_type" });
    assert.deepEqual(api.prepareSigning("descriptor", "k", set.parties[0].claims, set.parties[0].publicKey,
      predecessor as any), { ok: false, code: "invalid_type" });
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

function rotatedSet(holdSuccessor = true) {
  const set = mintedSet();
  const nextKey = keyPair();
  const descriptorClaims = { ...set.parties[0].claims, descriptor_number: 2, party_id: set.parties[0].digest, prev_descriptor_digest: set.parties[0].digest,
    verification_keys: [{ key_id: "k", algorithm: "Ed25519", public_key: nextKey.publicKey, status: "active" }] };
  const descriptorCompact = rawCompact("descriptor", "k", descriptorClaims, "Ed25519", set.parties[0].privateKey);
  const descriptorDigest = api.descriptorDigest(descriptorCompact);
  assert.ok(descriptorDigest.ok);
  const revision = { ...set.revision, revision_number: 2, charter_id: set.digest, prev_revision_digest: set.digest,
    parties: [{ role: "issuer", party_descriptor_digest: descriptorDigest.digest }, set.revision.parties[1]] };
  const revisionText = api.canonical(revision);
  const revisionDigest = api.revisionDigest(revisionText);
  assert.ok(revisionDigest.ok);
  const acceptance = { ...set.acceptance, revision_digest: revisionDigest.digest, revision_number: 2, prev_revision_digest: set.digest,
    party_descriptor_digest: descriptorDigest.digest };
  const chain = { ...set.chain, revisions: [...set.chain.revisions, revisionText],
    descriptors: holdSuccessor ? [...set.chain.descriptors, descriptorCompact] : [...set.chain.descriptors],
    acceptances: [...set.chain.acceptances, ...(holdSuccessor ? [rawCompact("acceptance", "k", acceptance, "Ed25519", nextKey.privateKey),
      rawCompact("acceptance", "k", { ...acceptance, party_role: "acceptor", party_descriptor_digest: set.parties[1].digest }, "Ed25519", set.parties[1].privateKey)] : [])] };
  assert.ok(api.verifyChain(chain).ok);
  return { ...set, chain, nextKey, acceptance, nextRevisionText: revisionText };
}

test("receipt prepare accepts both same-kid keys in the retained view", () => {
  const set = rotatedSet();
  const claims = { ...set.receipt, revision_number: 3, revision_digest: "sha-256:" + "A".repeat(43) };
  for (const pair of [set.parties[0], set.nextKey]) {
    const compact = rawCompact("receipt", "k", claims, "Ed25519", pair.privateKey);
    assert.ok(api.verifyReceipt(compact, set.chain).ok);
    const prepared = api.prepareSigning("receipt", "k", claims, pair.publicKey, set.chain);
    assert.ok(prepared.ok, JSON.stringify(prepared));
    const finished = api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, pair.privateKey));
    assert.ok(finished.ok);
    assert.equal(finished.compact, compact);
  }
  assert.deepEqual(api.prepareSigning("receipt", "k", claims, keyPair().publicKey, set.chain), { ok: false, code: "signing_key_mismatch" });
  assert.deepEqual(api.prepareSigning("receipt", "absent", claims, set.parties[0].publicKey, set.chain), { ok: false, code: "signing_key_mismatch" });
});

test("an unheld successor descriptor reports acceptance_claims_mismatch", () => {
  const set = rotatedSet(false);
  assert.equal(api.acceptanceSigningInput("k", set.acceptance, set.chain).ok, true);
  const compact = rawCompact("acceptance", "k", set.acceptance, "Ed25519", set.nextKey.privateKey);
  assert.deepEqual(api.verifyAcceptance(compact, set.nextRevisionText, [set.parties[0].compact]), { ok: false, code: "acceptance_claims_mismatch" });
  assert.deepEqual(api.prepareSigning("acceptance", "k", set.acceptance, set.nextKey.publicKey, set.chain), { ok: false, code: "acceptance_claims_mismatch" });
});

test("acceptance and termination profiles cover the routed context and artifact", () => {
  const set = mintedSet("Ed25519", "EdDSA");
  const options = { profile: { algorithms: ["Ed25519"], revisions: { min: 2, max: 2 } } };
  assert.deepEqual(api.verifyChain(set.chain, options), { ok: false, code: "algorithm_outside_profile" });
  for (const kind of ["acceptance", "termination"] as const) {
    const prepared = api.prepareSigning(kind, "k", set[kind], set.parties[0].publicKey, set.chain, options);
    assert.ok(prepared.ok, JSON.stringify(prepared));
    assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, set.parties[0].privateKey)).ok);
    assert.deepEqual(api.prepareSigning(kind, "k", set[kind], set.parties[0].publicKey, set.chain, { profile: { algorithms: ["EdDSA"] } }), { ok: false, code: "algorithm_outside_profile" });
    assert.deepEqual(api.prepareSigning(kind, "k", set[kind], set.parties[0].publicKey, set.chain, { profile: { revisions: { min: 1, max: 1 } } }), { ok: false, code: "revision_outside_profile" });
  }
  assert.deepEqual(api.prepareSigning("receipt", "k", set.receipt, set.parties[0].publicKey, set.chain, options), { ok: false, code: "algorithm_outside_profile" });
});

test("limits cover the whole set including the counterparty descriptor", () => {
  const set = mintedSet("Ed25519", "Ed25519", "x".repeat(5000));
  for (const kind of ["acceptance", "termination"] as const) {
    const compact = rawCompact(kind, "k", set[kind], "Ed25519", set.parties[0].privateKey);
    const options = { limits: { max_bytes: 4000 } };
    const verify = kind === "acceptance" ? api.verifyAcceptance : api.verifyTermination;
    assert.ok(verify(compact, set.revisionText, [set.parties[0].compact], options).ok);
    assert.deepEqual(api.prepareSigning(kind, "k", set[kind], set.parties[0].publicKey, set.chain, options), { ok: false, code: "limit_exceeded" });
  }
});

test("raised limits build and finish a 1601202-byte receipt", () => {
  const set = mintedSet();
  const claims = { ...set.receipt, extensions: { critical: {}, optional: { "com.example/pad": "" } } };
  // Keep every padding string below the default string bound.
  claims.extensions.optional = Object.fromEntries(Array.from({ length: 24 }, (_, i) => [`com.example/pad${i}`, "x".repeat(49900)]));
  let compact = rawCompact("receipt", "k", claims, "Ed25519", set.parties[0].privateKey);
  const difference = 1_601_202 - Buffer.byteLength(compact);
  claims.extensions.optional["com.example/pad0"] += "x".repeat(Math.floor(difference * 3 / 4));
  compact = rawCompact("receipt", "k", claims, "Ed25519", set.parties[0].privateKey);
  assert.equal(Buffer.byteLength(compact), 1_601_202);
  assert.deepEqual(api.receiptSigningInput("k", claims), { ok: false, code: "signing_input_invalid" });
  const options = { limits: { max_bytes: 4 * 1024 * 1024 } };
  assert.ok(api.verifyReceipt(compact, set.revisionText, options).ok);
  const prepared = api.prepareSigning("receipt", "k", claims, set.parties[0].publicKey, set.revisionText, options);
  assert.ok(prepared.ok, JSON.stringify(prepared));
  assert.deepEqual(api.assembleCompact(prepared.plan.input, sign(null, prepared.plan.input.message, set.parties[0].privateKey)), { ok: false, code: "signing_input_invalid" });
  const finished = api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, set.parties[0].privateKey));
  assert.ok(finished.ok, JSON.stringify(finished));
  assert.equal(finished.compact, compact);
});

test("max_bytes counts the final signature segment at the exact bound", () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"]) {
    const set = mintedSet(algorithm);
    for (const kind of ["descriptor", "receipt"] as const) {
      const claims = kind === "descriptor" ? set.parties[0].claims : set.receipt;
      const context = kind === "descriptor" ? null : set.revisionText;
      const compact = rawCompact(kind, "k", claims, algorithm, set.parties[0].privateKey);
      const max_bytes = Buffer.byteLength(compact);
      const prepared = api.prepareSigning(kind, "k", claims, set.parties[0].publicKey, context, { algorithm, limits: { max_bytes } });
      assert.ok(prepared.ok, JSON.stringify(prepared));
      assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, set.parties[0].privateKey)).ok);
      assert.deepEqual(api.prepareSigning(kind, "k", claims, set.parties[0].publicKey, context, { algorithm, limits: { max_bytes: max_bytes - 1 } }), { ok: false, code: "signing_input_invalid" });
    }
  }
});

test("raised string and depth limits apply to the build and set reads", () => {
  const set = mintedSet();
  let nested: any = "x";
  for (let i = 0; i < 70; i++) nested = { child: nested };
  const receipt = { ...set.receipt, extensions: { critical: {}, optional: { "com.example/deep": nested } } };
  assert.equal(api.receiptSigningInput("k", receipt).ok, false);
  assert.ok(api.prepareSigning("receipt", "k", receipt, set.parties[0].publicKey, set.revisionText, { limits: { max_depth: 128 } }).ok);
  const revision = { ...set.revision, extensions: { critical: {}, optional: { "com.example/pad": "x".repeat(70000) } } };
  const revisionText = api.canonical(revision);
  const digest = api.taggedDigest("charter_revision_content", Buffer.from(revisionText));
  const chain = { ...set.chain, revisions: [revisionText], acceptances: [] };
  const acceptance = { ...set.acceptance, charter_id: digest, revision_digest: digest };
  assert.deepEqual(api.acceptanceSigningInput("k", acceptance, chain), { ok: false, code: "limit_exceeded" });
  const prepared = api.prepareSigning("acceptance", "k", acceptance, set.parties[0].publicKey, chain, { limits: { max_string_bytes: 100000 } });
  assert.ok(prepared.ok, JSON.stringify(prepared));
  assert.ok(api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, set.parties[0].privateKey)).ok);
});

test("browser shim refuses ML-DSA prepare including a bare-revision receipt", async () => {
  const set = mintedSet("ML-DSA-65");
  const scratch = mkdtempSync(join(tmpdir(), "cap-presign-browser-"));
  try {
    const outfile = join(scratch, "verifier.mjs");
    await build({ entryPoints: ["index.ts"], bundle: true, outfile, format: "esm", platform: "browser", target: "es2022",
      alias: { "node:crypto": "./web/shim/node-crypto.ts", "node:fs": "./web/shim/node-fs.ts", "node:path": "./web/shim/node-path.ts" }, inject: ["./web/shim/buffer-global.ts"] });
    const browser = await import(pathToFileURL(outfile).href);
    for (const [kind, claims, context] of [["descriptor", set.parties[0].claims, null], ["receipt", set.receipt, set.revisionText],
      ["acceptance", set.acceptance, set.chain], ["termination", set.termination, set.chain], ["receipt", set.receipt, set.chain]]) {
      assert.deepEqual(browser.prepareSigning(kind, "k", claims, set.parties[0].publicKey, context, { algorithm: "ML-DSA-65" }), { ok: false, code: "algorithm_unsupported_on_substrate" });
    }
    const ed = mintedSet();
    const prepared = browser.prepareSigning("descriptor", "k", ed.parties[0].claims, ed.parties[0].publicKey, null);
    assert.ok(prepared.ok, JSON.stringify(prepared));
    assert.ok(browser.finishSigning(prepared.plan, sign(null, Buffer.from(prepared.plan.input.message), ed.parties[0].privateKey)).ok);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("prepare shares descriptor and receipt checks up to the signature step", () => {
  const set = mintedSet();
  const pair = set.parties[0];
  for (const [kind, claims, context, options, verify] of [
    ["descriptor", pair.claims, null, {}, (c: string) => api.verifyDescriptor(c)],
    ["descriptor", pair.claims, null, { profile: { algorithms: ["EdDSA"] } }, (c: string) => api.verifyDescriptor(c, null, { profile: { algorithms: ["EdDSA"] } })],
    ["descriptor", { ...pair.claims, descriptor_number: 2, party_id: pair.digest, prev_descriptor_digest: pair.digest }, null, {}, (c: string) => api.verifyDescriptor(c)],
    ["receipt", set.receipt, set.chain, {}, (c: string) => api.verifyReceipt(c, set.chain)],
    ["receipt", set.receipt, set.revisionText, {}, (c: string) => api.verifyReceipt(c, set.revisionText)],
    ["receipt", { ...set.receipt, deployment_digest: "sha-256:" + "A".repeat(43) }, set.chain, {}, (c: string) => api.verifyReceipt(c, set.chain)],
    ["receipt", { ...set.receipt, revision_digest: "sha-256:" + "A".repeat(43) }, set.revisionText, {}, (c: string) => api.verifyReceipt(c, set.revisionText)],
    ["receipt", set.receipt, set.chain, { profile: { algorithms: ["EdDSA"] } }, (c: string) => api.verifyReceipt(c, set.chain, { profile: { algorithms: ["EdDSA"] } })],
  ] as const) {
    const compact = rawCompact(kind, "k", claims, "Ed25519", pair.privateKey);
    const result = verify(compact);
    const prepared = api.prepareSigning(kind, "k", claims, pair.publicKey, context, options as api.VerificationOptions);
    if (result.ok) {
      assert.ok(prepared.ok, JSON.stringify(prepared));
      assert.equal(prepared.plan.input.message.toString(), compact.split(".").slice(0, 2).join("."));
      const signatureOnly = verify(compact.split(".").slice(0, 2).join(".") + "." + Buffer.alloc(64).toString("base64url"));
      if (typeof context !== "string") assert.deepEqual(signatureOnly, { ok: false, code: "signature_invalid" });
      const other = api.prepareSigning(kind, "k", claims, keyPair().publicKey, context, options as api.VerificationOptions);
      if (typeof context === "string") assert.ok(other.ok && other.plan.key === "unnamed");
      else assert.deepEqual(other, { ok: false, code: "signing_key_mismatch" });
    } else {
      assert.deepEqual(prepared, { ok: false, code: result.code });
    }
  }
});

test("snapshot key algorithm and bytes must match an active descriptor key", () => {
  const set = mintedSet();
  const publicKey = keyPair("ML-DSA-65").publicKey;
  const claims = { ...set.parties[0].claims, protocol_revision: 3 };
  assert.equal(api.descriptorSigningInput("k", claims, "ML-DSA-65").ok, true);
  assert.deepEqual(api.prepareSigning("descriptor", "k", claims, publicKey, null, { algorithm: "ML-DSA-65" }), { ok: false, code: "signing_key_mismatch" });
  const retired = { ...set.parties[0].claims, verification_keys: [{ ...set.parties[0].claims.verification_keys[0], status: "retired" },
    { ...set.parties[0].claims.verification_keys[0], key_id: "other" }] };
  assert.deepEqual(api.prepareSigning("descriptor", "k", retired, set.parties[0].publicKey, null), { ok: false, code: "signing_key_mismatch" });
});

test("verify context fields tolerate generated wrong shapes", () => {
  const set = mintedSet();
  const compact = rawCompact("receipt", "k", set.receipt, "Ed25519", set.parties[0].privateKey);
  const previous = api.verifyDescriptor(set.parties[0].compact);
  assert.ok(previous.ok);
  for (const value of generatedInputs()) {
    for (const field of ["revisions", "acceptances", "descriptors", "terminations"] as const) for (const replacement of [value, [value]]) {
      const context = { ...set.chain, [field]: replacement };
      for (const result of [api.verifyChain(context as any), api.verifyReceipt(compact, context),
        api.prepareSigning("receipt", "k", set.receipt, set.parties[0].publicKey, context as any),
        api.prepareSigning("acceptance", "k", set.acceptance, set.parties[0].publicKey, context as any),
        api.prepareSigning("termination", "k", set.termination, set.parties[0].publicKey, context as any)]) {
        assert.equal(typeof result.ok, "boolean");
        if (!result.ok) assert.equal(typeof result.code, "string");
      }
    }
    const predecessor = { ...previous.facts, lineage: value };
    const result = api.prepareSigning("descriptor", "k", set.parties[0].claims, set.parties[0].publicKey, predecessor);
    assert.equal(typeof result.ok, "boolean");
    if (!result.ok) assert.equal(typeof result.code, "string");
  }
});

test("prepare rejects cyclic and invalid JSON claims without throwing", () => {
  const set = mintedSet();
  const cycle: any = {};
  cycle.child = cycle;
  for (const value of [cycle, 9007199254740992, 9007199254740993n, () => 1]) {
    const claims = { ...set.receipt, extensions: { critical: {}, optional: { "com.example/value": value } } };
    assert.deepEqual(api.prepareSigning("receipt", "k", claims, set.parties[0].publicKey, set.revisionText), { ok: false, code: "signing_input_invalid" });
  }
});
