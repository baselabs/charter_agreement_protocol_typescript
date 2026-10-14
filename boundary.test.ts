import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import * as api from "./index.ts";

function fixture(file: string, id: string): any {
  return JSON.parse(readFileSync(new URL(`./conformance/cases/${file}.json`, import.meta.url), "utf8"))
    .cases.find((one: any) => one.id === id).input;
}

const descriptor = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
const acceptance = fixture("acceptance-verify", "acceptance-valid");
const termination = fixture("termination-verify", "termination-valid");
const chain = fixture("chain-verify", "chain-dual-acceptance-valid");
const receipt = fixture("receipt-verify", "receipt-signed-governing-match");
const signing = fixture("signing-prepare", "signing-ed25519-party_descriptor");
const [header, payload, encodedSignature] = descriptor.compact.split(".");
const message = Buffer.from(`${header}.${payload}`);
const signature = Buffer.from(encodedSignature, "base64url");
const publicKey = JSON.parse(Buffer.from(payload, "base64url").toString()).verification_keys[0].public_key;
const calls: Record<string, (options: any) => any> = {
  verifyDescriptor: (o) => api.verifyDescriptor(descriptor.compact, null, o),
  verifyDescriptorChain: (o) => api.verifyDescriptorChain([descriptor.compact], o),
  verifyAcceptance: (o) => api.verifyAcceptance(acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts, o),
  verifyTermination: (o) => api.verifyTermination(termination.compact, termination.revision_text, termination.descriptor_compacts, o),
  verifyChain: (o) => api.verifyChain(chain, o),
  verifyReceipt: (o) => api.verifyReceipt(receipt.compact, receipt.chain, o),
  prepareSigning: (o) => api.prepareSigning("descriptor", signing.kid, signing.claims, signing.public_key, null, o),
  verifySignature: (o) => api.verifySignature(message, signature, publicKey, "EdDSA", o),
};

test("chain entry points ignore unread members", () => {
  for (const note of ["x".repeat(70_000_000), Array(5000).fill(1), new Int8Array(20_000_000)]) {
    assert.ok(api.verifyChain({ ...chain, note }).ok);
    assert.ok(api.verifyReceipt(receipt.compact, { ...receipt.chain, note }).ok);
  }
  const view = { ...chain, get note() { throw new Error("unread member"); } };
  assert.ok(api.verifyChain(view).ok);
  assert.ok(api.governingRevision(view, "2026-09-01T00:00:00Z").ok);
  const candidate = fixture("signing-prepare", "signing-ed25519-acceptance");
  assert.ok(api.prepareSigning("acceptance", candidate.kid, candidate.claims, candidate.public_key,
    { ...candidate.context.set, get note() { throw new Error("unread member"); } }).ok);
  const previous = api.verifyDescriptor(descriptor.compact);
  assert.ok(previous.ok);
  assert.deepEqual(api.verifyDescriptor(descriptor.compact, { ...previous.facts, lineage: previous.facts.lineage,
    get note() { throw new Error("unread member"); } }), api.verifyDescriptor(descriptor.compact, previous.facts));
});

test("chain entry points check every list type before bounds", () => {
  const options = { limits: { max_artifact_set_bytes: 100, max_bytes: 100 } };
  for (const member of ["revisions", "acceptances", "descriptors", "terminations"]) {
    const view = { ...chain, [member]: "x".repeat(300) };
    assert.deepEqual(api.verifyChain(view, options), { ok: false, code: "invalid_type" });
    assert.deepEqual(api.verifyReceipt(receipt.compact, view, options), { ok: false, code: "invalid_type" });
    assert.deepEqual(api.governingRevision(view, "2026-09-01T00:00:00Z", options), { ok: false, code: "invalid_type" });
  }
  const candidate = fixture("signing-prepare", "signing-ed25519-acceptance");
  for (const member of ["revisions", "acceptances", "descriptors", "terminations"]) {
    const view = { ...candidate.context.set, [member]: "x".repeat(30000) };
    assert.deepEqual(api.prepareSigning("acceptance", candidate.kid, candidate.claims, candidate.public_key,
      view, { limits: { max_artifact_set_bytes: 100 } }), { ok: false, code: "invalid_type" });
  }
});

test("malformed array lengths have one error code", () => {
  for (const length of [2 ** 40, 2 ** 60, -1, "5", 1.5, NaN, Infinity]) {
    const revisions = new Proxy([], { get(target, key) { return key === "length" ? length : Reflect.get(target, key); } });
    assert.deepEqual(api.verifyChain({ ...chain, revisions }), { ok: false, code: "invalid_type" });
  }
  for (const length of [2 ** 32 - 1]) {
    const revisions = new Proxy([], { get(target, key) { return key === "length" ? length : Reflect.get(target, key); } });
    assert.deepEqual(api.verifyChain({ ...chain, revisions }), { ok: false, code: "limit_exceeded" });
  }
});

test("integer claims reject float tokens before canonical encoding", () => {
  for (const [input, verify, names] of [
    [descriptor, (compact: string) => api.verifyDescriptor(compact), ["protocol_revision", "descriptor_number"]],
    [acceptance, (compact: string) => api.verifyAcceptance(compact, acceptance.revision_text, acceptance.descriptor_compacts), ["protocol_revision", "revision_number"]],
    [termination, (compact: string) => api.verifyTermination(compact, termination.revision_text, termination.descriptor_compacts), ["protocol_revision"]],
    [receipt, (compact: string) => api.verifyReceipt(compact, receipt.chain), ["protocol_revision", "revision_number"]],
  ] as const) {
    const [header, payload, signature] = input.compact.split(".");
    const text = Buffer.from(payload, "base64url").toString();
    for (const name of names) for (const suffix of [".0", "e0"]) {
      const altered = text.replace(new RegExp(`("${name}":)([0-9]+)`), `$1$2${suffix}`);
      assert.notEqual(altered, text);
      const compact = `${header}.${Buffer.from(altered).toString("base64url")}.${signature}`;
      assert.deepEqual(verify(compact), { ok: false, code: "invalid_type" });
    }
  }
  const text = acceptance.revision_text;
  for (const name of ["protocol_revision", "revision_number", "release_number"]) {
    const altered = text.replace(new RegExp(`("${name}":)([0-9]+)`), "$1$2.0");
    assert.notEqual(altered, text);
    assert.deepEqual(api.decodeCharterRevision(altered), { ok: false, code: "invalid_type" });
  }
});

test("entry points honor inherited and getter options", async (t) => {
  const narrow = { algorithms: ["ML-DSA-65"] };
  for (const [name, call] of Object.entries(calls)) {
    assert.ok(name === "verifySignature" ? call({}) : call({}).ok, name);
    for (const shape of ["inherited profile", "class getter profile", "inherited limits"]) {
      await t.test(`${name} ${shape}`, () => {
        let reads = 0;
        class Options { get profile() { reads++; return narrow; } }
        const options = shape === "inherited profile" ? Object.create({ profile: narrow }) :
          shape === "class getter profile" ? new Options() : Object.create({ limits: { max_bytes: 10 } });
        const result = call(options);
        if (name === "verifySignature") assert.equal(result, false);
        else assert.deepEqual(result, { ok: false, code: shape === "inherited limits" ?
          name === "prepareSigning" ? "signing_input_invalid" : name === "verifyDescriptorChain" ? "descriptor_chain_invalid" : "limit_exceeded" : "algorithm_outside_profile" });
        if (shape === "class getter profile") assert.equal(reads, 1);
      });
    }
    await t.test(`${name} throwing inherited getter`, () => {
      const options = Object.create({ get limits() { throw new Error("unreadable"); } });
      assert.deepEqual(call(options), name === "verifySignature" ? false : { ok: false, code: "invalid_type" });
    });
  }
});

test("nested option members are read once with ordinary property reads", () => {
  const reads: Record<string, number> = {};
  const getter = (key: string, value: any) => ({ get() { reads[key] = (reads[key] ?? 0) + 1; return value; } });
  const range = Object.create(Object.defineProperties({}, { min: getter("min", 1), max: getter("max", 3) }));
  const profile = Object.create(Object.defineProperties({}, { algorithms: getter("algorithms", ["ML-DSA-65"]), revisions: getter("revisions", range) }));
  const options = Object.create(Object.defineProperties({}, { profile: getter("profile", profile) }));
  assert.deepEqual(api.verifyDescriptor(descriptor.compact, null, options), { ok: false, code: "algorithm_outside_profile" });
  assert.deepEqual(reads, { profile: 1, algorithms: 1, revisions: 1, min: 1, max: 1 });
  assert.deepEqual(api.verifyChain(chain, { limits: Object.create({ max_bytes: 10 }) }), { ok: false, code: "limit_exceeded" });
});

test("claims use own enumerable members", () => {
  const claims = { ...signing.claims };
  Object.defineProperty(claims, "hidden", { get() { throw new Error("hidden"); } });
  assert.ok(api.prepareSigning("descriptor", signing.kid, claims, signing.public_key, null).ok);
});

test("empty revisions read descriptors before topology checks", () => {
  const [protectedSegment, payloadSegment, signatureSegment] = descriptor.compact.split(".");
  const header = JSON.parse(Buffer.from(protectedSegment, "base64url").toString());
  const compactWithHeader = (text: string) => `${Buffer.from(text).toString("base64url")}.${payloadSegment}.${signatureSegment}`;
  for (const [compact, code] of [
    ["broken", "compact_invalid"],
    [compactWithHeader(JSON.stringify({ ...header, typ: "cap+receipt" })), "protected_header_invalid"],
    [`${protectedSegment}.${Buffer.from(" " + Buffer.from(payloadSegment, "base64url").toString()).toString("base64url")}.${signatureSegment}`, "non_canonical_bytes"],
  ]) {
    assert.deepEqual(api.verifyChain({ revisions: [], acceptances: [], descriptors: [compact], terminations: [] }), { ok: false, code });
  }
  assert.deepEqual(api.verifyChain({ revisions: [], acceptances: [], descriptors: [descriptor.compact], terminations: [] }, { limits: { max_bytes: 10 } }), { ok: false, code: "limit_exceeded" });
});

test("all public verdict functions return typed results for hostile reads", async (t) => {
  const prepared = api.prepareSigning("descriptor", signing.kid, signing.claims, signing.public_key, null);
  assert.ok(prepared.ok);
  const framed = api.descriptorSigningInput(signing.kid, signing.claims);
  assert.ok(framed.ok);
  const calls: Record<string, [(...args: any[]) => any, any[]]> = {
    governingRevision: [api.governingRevision, [chain, "2026-09-01T00:00:00Z", {}]],
    decodeCharterRevision: [api.decodeCharterRevision, [acceptance.revision_text, {}]],
    revisionDigest: [api.revisionDigest, [acceptance.revision_text, {}]],
    decodePartyDescriptor: [api.decodePartyDescriptor, [descriptor.compact]],
    descriptorDigest: [api.descriptorDigest, [descriptor.compact]],
    decodeArtifact: [api.decodeArtifact, [descriptor.compact]],
    checkSigningClaims: [api.checkSigningClaims, ["descriptor", signing.claims]],
    acceptanceRefusal: [api.acceptanceRefusal, [signing.claims, chain]],
    terminationRefusal: [api.terminationRefusal, [signing.claims, chain]],
    descriptorSigningInput: [api.descriptorSigningInput, [signing.kid, signing.claims, "Ed25519"]],
    receiptSigningInput: [api.receiptSigningInput, [signing.kid, signing.claims, "Ed25519"]],
    acceptanceSigningInput: [api.acceptanceSigningInput, [signing.kid, signing.claims, chain, "Ed25519"]],
    terminationSigningInput: [api.terminationSigningInput, [signing.kid, signing.claims, chain, "Ed25519"]],
    assembleCompact: [api.assembleCompact, [framed.input, signature]],
    finishSigning: [api.finishSigning, [prepared.plan, signature]],
    decodeJsonText: [api.decodeJsonText, ["{}", {}]],
  };
  const unreadable = () => { throw new Error("unreadable"); };
  const revoked = Proxy.revocable([], {});
  revoked.revoke();
  const hostile = [
    new Proxy({}, { get: unreadable, ownKeys: unreadable, getPrototypeOf: unreadable, has: unreadable }),
    revoked.proxy,
    { get revisions() { return unreadable(); } },
    new Proxy([], { get(target, key) { return key === "length" ? unreadable() : Reflect.get(target, key); } }),
  ];
  for (const [name, [call, args]] of Object.entries(calls)) await t.test(name, () => {
    for (let position = 0; position < args.length; position++) for (const value of hostile) {
      const result = call(...args.map((arg, i) => position === i ? value : arg));
      assert.equal(typeof result.ok, "boolean");
      if (!result.ok) assert.equal(typeof result.code, "string");
    }
  });
});

test("bounded copies preserve preparation error order", () => {
  assert.deepEqual(api.prepareSigning("receipt", "k", signing.claims, signing.public_key, null, { limits: { max_bytes: 0 } }),
    { ok: false, code: "invalid_type" });
  const context = { ...chain, revisions: new Array(2000).fill("x") };
  assert.deepEqual(api.prepareSigning("acceptance", "k", {}, signing.public_key, context),
    { ok: false, code: "signing_input_invalid" });
  const acceptanceClaims = fixture("signing-prepare", "signing-ed25519-acceptance").claims;
  assert.deepEqual(api.prepareSigning("acceptance", "k", acceptanceClaims, "AAAA", context),
    { ok: false, code: "signing_key_invalid" });
});

test("predecessor history does not consume artifact set limits", () => {
  const successor = fixture("signing-prepare", "signing-successor-with-predecessor");
  let previous: any = null;
  for (const compact of successor.context.predecessor_compacts) {
    const verified = api.verifyDescriptor(compact, previous);
    assert.ok(verified.ok);
    previous = verified.facts;
  }
  const options = { limits: { max_artifact_set_items: 0, max_artifact_set_bytes: 0 } };
  const prepared = api.prepareSigning("descriptor", successor.kid, successor.claims, successor.public_key, previous, options);
  assert.ok(prepared.ok);
  const privateKey = Array.from({ length: 9 }, (_, i) => createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, i + 1)]),
    format: "der", type: "pkcs8",
  })).find((key) => createPublicKey(key).export({ format: "jwk" }).x === successor.public_key);
  assert.ok(privateKey);
  const finished = api.finishSigning(prepared.plan, sign(null, prepared.plan.input.message, privateKey));
  assert.ok(finished.ok);
  assert.ok(api.verifyDescriptor(finished.compact, previous, options).ok);
});

test("a reported array length rejects before reading its items", () => {
  let lengths = 0;
  let items = 0;
  const list = new Proxy([], {
    get(target, key) {
      if (key === "length") { lengths++; return 2 ** 32 - 1; }
      if (key === "0") { items++; throw new Error("oversized item read"); }
      return Reflect.get(target, key);
    },
  });
  assert.deepEqual(api.verifyChain({ revisions: list, acceptances: [], descriptors: [], terminations: [] }), { ok: false, code: "limit_exceeded" });
  assert.equal(lengths, 1);
  assert.equal(items, 0);
});
