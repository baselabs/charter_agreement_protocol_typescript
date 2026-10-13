import test from "node:test";
import { build } from "esbuild";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign } from "node:crypto";
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

function changeClaims(compact: string, change: (claims: any) => any): string {
  const [header, , signature] = compact.split(".");
  return `${header}.${Buffer.from(api.canonical(change(claimsOf(compact)))).toString("base64url")}.${signature}`;
}

test("browser bundle verifies signed descriptors and a dual acceptance chain", async () => {
  const bundle = await build({
    entryPoints: ["index.ts"], bundle: true, write: false, format: "esm", platform: "browser", target: "es2022",
    alias: { "node:crypto": "./web/shim/node-crypto.ts", "node:fs": "./web/shim/node-fs.ts", "node:path": "./web/shim/node-path.ts" },
    inject: ["./web/shim/buffer-global.ts"],
  });
  const browser = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);
  const genesis = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  assert.equal(browser.verifyDescriptor(genesis.compact).ok, true);
  assert.equal(browser.verifyChain(view).ok, true);
  const pq = fixture("party_descriptor-verify", "descriptor-mldsa65-rev3-valid");
  assert.deepEqual(browser.verifyDescriptor(pq.compact), { ok: false, code: "algorithm_unsupported_on_substrate" });
  assert.deepEqual(browser.verifyDescriptor(changeClaims(pq.compact, (c) => ({ ...c, extra: true }))), { ok: false, code: "unknown_member" });
  assert.deepEqual(browser.verifyDescriptor(pq.compact, null, { profile: { algorithms: ["Ed25519"] } }), { ok: false, code: "algorithm_outside_profile" });
});

const badDigest = "sha-256:" + "A".repeat(42) + "B";
const sampleDigest = "sha-256:" + "A".repeat(43);

test("S1 signed claims reject every noncanonical digest", async (t) => {
  for (const [file, id, verify, fields, code] of [
    ["acceptance-verify", "acceptance-valid", api.verifyAcceptance, ["charter_id", "revision_digest", "prev_revision_digest", "party_descriptor_digest"], "acceptance_invalid"],
    ["termination-verify", "termination-valid", api.verifyTermination, ["charter_id", "governing_revision_digest", "party_descriptor_digest", "detail_digest"], "termination_invalid"],
  ] as const) {
    const f = fixture(file, id);
    for (const field of fields) await t.test(`${file} ${field}`, () => {
      const compact = changeClaims(f.compact, (claims) => ({ ...claims, [field]: badDigest }));
      assert.deepEqual(verify(compact, f.revision_text, f.descriptor_compacts), { ok: false, code });
    });
  }
  const f = fixture("receipt-verify", "receipt-signed-governing-match");
  for (const field of ["charter_id", "revision_digest", "deployment_digest"]) await t.test(`receipt ${field}`, () => {
    assert.deepEqual(api.verifyReceipt(changeClaims(f.compact, (claims) => ({ ...claims, [field]: badDigest })), f.chain), { ok: false, code: "receipt_invalid" });
  });
  const pinned = fixture("receipt-verify", "receipt-revision-digest-noncanonical");
  await t.test("real receipt signature cannot admit a noncanonical revision digest", () => {
    assert.deepEqual(api.verifyReceipt(pinned.compact, pinned.chain), { ok: false, code: "receipt_invalid" });
  });
});

test("B1 revision parties and supplied histories are distinct and named", async (t) => {
  const repeated = fixture("charter_revision-decode", "charter-revision-shared-descriptor");
  await t.test("revision repeats a descriptor", () => {
    assert.deepEqual(api.decodeCharterRevision(repeated.text), { ok: false, code: "revision_invalid" });
  });
  const sameHistory = fixture("chain-verify", "chain-one-party-both-roles");
  await t.test("different descriptors in one history cannot fill both roles", () => {
    assert.deepEqual(api.verifyChain(sameHistory), { ok: false, code: "chain_invalid" });
  });
  const base = fixture("chain-verify", "chain-dual-acceptance-valid");
  const root = JSON.parse(base.revisions[0]);
  root.parties[1].party_descriptor_digest = sampleDigest;
  const text = api.canonical(root);
  await t.test("an unnamed supplied history cannot replace a missing party", () => {
    assert.deepEqual(api.verifyChain({ ...base, revisions: [text], acceptances: [] }), { ok: false, code: "chain_invalid" });
  });
  await t.test("unresolvable digests are skipped and other revisions can name histories", () => {
    const decoded = api.decodeCharterRevision(text);
    assert.ok(decoded.ok);
    const next = { ...JSON.parse(base.revisions[0]), revision_number: 2, charter_id: decoded.digest, prev_revision_digest: decoded.digest };
    assert.ok(api.verifyChain({ ...base, revisions: [text, api.canonical(next)], acceptances: [] }).ok);
  });
});

test("S2 malformed signed timestamps keep the parser code and ordering", async (t) => {
  for (const [file, id, verify, fields] of [
    ["termination-verify", "termination-valid", api.verifyTermination, ["effective_at", "issued_at"]],
    ["receipt-verify", "receipt-signed-governing-match", api.verifyReceipt, ["occurred_at", "recorded_at"]],
  ] as const) {
    const f = fixture(file, id);
    for (const field of fields) await t.test(field, () => {
      const compact = changeClaims(f.compact, (claims) => ({ ...claims, [field]: "2026-13-01T00:00:00Z" }));
      const result = verify === api.verifyReceipt ? api.verifyReceipt(compact, f.chain) : api.verifyTermination(compact, f.revision_text, f.descriptor_compacts);
      assert.deepEqual(result, { ok: false, code: "timestamp_invalid" });
    });
  }
  await t.test("acceptance time precedes predecessor shape", () => {
    const f = fixture("acceptance-verify", "acceptance-valid");
    const compact = changeClaims(f.compact, (claims) => ({ ...claims, prev_revision_digest: sampleDigest, accepted_at: "bad-time" }));
    assert.deepEqual(api.verifyAcceptance(compact, f.revision_text, f.descriptor_compacts), { ok: false, code: "timestamp_invalid" });
  });
});

test("S3 year 0000 and its leap day pass every timestamp surface", async (t) => {
  const f = fixture("charter_revision-decode", "charter-revision-effective-from-year-zero");
  await t.test("revision decode", () => assert.ok(api.decodeCharterRevision(f.text).ok));
  await t.test("year zero leap day", () => {
    const revision = JSON.parse(f.text);
    assert.ok(api.decodeCharterRevision(api.canonical({ ...revision, effective_from: "0000-02-29T00:00:00Z" })).ok);
    assert.deepEqual(api.decodeCharterRevision(api.canonical({ ...revision, effective_from: "0000-02-30T00:00:00Z" })), { ok: false, code: "timestamp_invalid" });
  });
  for (const [kind, file, id, field] of [
    ["descriptor", "party_descriptor-verify", "party-descriptor-genesis-valid", "effective_from"],
    ["acceptance", "acceptance-verify", "acceptance-valid", "accepted_at"],
    ["termination", "termination-verify", "termination-valid", "issued_at"],
    ["receipt", "receipt-verify", "receipt-signed-governing-match", "occurred_at"],
  ] as const) await t.test(kind, () => {
    const claims = claimsOf(fixture(file, id).compact);
    assert.deepEqual(api.checkSigningClaims(kind, { ...claims, [field]: "0000-01-01T00:00:00Z" }), { ok: true });
  });
  await t.test("indexed observation", () => {
    const claims = claimsOf(fixture("receipt-verify", "receipt-indexed-price-observation-quarantine").compact);
    claims.extensions.optional["com.example/pricing-indexed-observation"].observation_instant = "0000-02-29T00:00:00Z";
    assert.deepEqual(api.checkSigningClaims("receipt", claims), { ok: true });
  });
  await t.test("governing instant", () => {
    assert.deepEqual(api.governingRevision(fixture("chain-verify", "chain-dual-acceptance-valid"), "0000-01-01T00:00:00Z"), { ok: true, governing: "none" });
  });
});

test("S4 producers and assembly reject malformed artifact claims", async (t) => {
  const f = fixture("termination-verify", "termination-valid");
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  const coordinates = claimsOf(view.acceptances[0]);
  const claims = { ...claimsOf(f.compact), protocol_revision: 2, charter_id: coordinates.charter_id, governing_revision_digest: coordinates.revision_digest, party_descriptor_digest: coordinates.party_descriptor_digest, party_role: coordinates.party_role };
  for (const extensions of [5, { critical: {}, optional: {} }]) await t.test("termination extra member " + typeof extensions, () => {
    assert.deepEqual(api.terminationSigningInput("k", { ...claims, extensions }, view), { ok: false, code: "unknown_member" });
  });
  for (const [file, id, field, value] of [
    ["party_descriptor-verify", "party-descriptor-genesis-valid", "extra", true],
    ["acceptance-verify", "acceptance-valid", "accepted_at", "bad-time"],
    ["termination-verify", "termination-valid", "extensions", 5],
    ["receipt-verify", "receipt-signed-governing-match", "revision_digest", badDigest],
  ] as const) await t.test("assembly " + file, () => {
    const original = fixture(file, id).compact;
    const [protectedSegment, payloadSegment] = changeClaims(original, (c) => ({ ...c, [field]: value })).split(".");
    const header = JSON.parse(Buffer.from(protectedSegment, "base64url").toString());
    const input = { alg: header.alg, protectedSegment, payloadSegment, message: Buffer.from(`${protectedSegment}.${payloadSegment}`) };
    assert.deepEqual(api.assembleCompact(input, Buffer.alloc(64)), { ok: false, code: "signing_input_invalid" });
  });
});

test("S7 revision timestamps precede binding digest extraction", () => {
  const base = JSON.parse(fixture("charter_revision-decode", "charter-revision-genesis-valid").text);
  base.abp_bindings[0].content_digest = badDigest;
  base.effective_from = "bad-time";
  assert.deepEqual(api.decodeCharterRevision(api.canonical(base)), { ok: false, code: "timestamp_invalid" });
  base.effective_from = "2026-08-25T12:00:00Z";
  assert.deepEqual(api.decodeCharterRevision(api.canonical(base)), { ok: false, code: "revision_invalid" });
});

test("revision optional digests and supersession uniqueness stay strict", () => {
  const base = JSON.parse(fixture("charter_revision-decode", "charter-revision-genesis-valid").text);
  assert.deepEqual(api.decodeCharterRevision(api.canonical({ ...base, revision_number: 2, charter_id: sampleDigest, prev_revision_digest: sampleDigest, supersedes: [sampleDigest, sampleDigest] })), { ok: false, code: "revision_invalid" });
  assert.deepEqual(api.decodeCharterRevision(api.canonical({ ...base, attribution_declaration: { ...base.attribution_declaration, detail_digest: badDigest } })), { ok: false, code: "revision_invalid" });
});

test("S8 descriptor key extraction uses codec errors before times and extensions", async (t) => {
  const f = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  const base = claimsOf(f.compact);
  const key = base.verification_keys[0];
  for (const [label, change] of [
    ["another algorithm key length", (c: any) => ({ ...c, verification_keys: [{ ...key, public_key: Buffer.alloc(1312).toString("base64url") }] })],
    ["noncanonical key encoding", (c: any) => ({ ...c, verification_keys: [{ ...key, public_key: key.public_key.slice(0, -1) + "B" }] })],
    ["duplicate key with bad time", (c: any) => ({ ...c, verification_keys: [key, key], effective_from: "bad-time" })],
    ["duplicate key with unknown critical extension", (c: any) => ({ ...c, verification_keys: [key, key], extensions: { critical: { "sample/unknown": {} }, optional: {} } })],
    ["no active key with bad time", (c: any) => ({ ...c, verification_keys: [{ ...key, status: "retired" }], effective_from: "bad-time" })],
  ] as const) await t.test(label, () => {
    assert.deepEqual(api.verifyDescriptor(changeClaims(f.compact, change)), { ok: false, code: "descriptor_invalid" });
  });
});

test("S9 chain routing checks the envelope and both routing coordinates first", async (t) => {
  const base = fixture("chain-verify", "chain-dual-acceptance-valid");
  for (const [kind, list, original, revisionField] of [
    ["acceptance", "acceptances", base.acceptances[0], "revision_digest"],
    ["termination", "terminations", fixture("termination-verify", "termination-valid").compact, "governing_revision_digest"],
  ]) {
    for (const [label, change] of [
      ["absent signer", (claims: any) => ({ ...claims, [revisionField]: claimsOf(base.acceptances[0]).revision_digest, party_descriptor_digest: sampleDigest })],
      ["missing signer coordinate", (claims: any) => { const { party_descriptor_digest, ...rest } = claims; return { ...rest, [revisionField]: claimsOf(base.acceptances[0]).revision_digest }; }],
    ] as const) await t.test(`${kind} ${label}`, () => {
      assert.deepEqual(api.verifyChain({ ...base, [list]: [changeClaims(original, change)] }), { ok: false, code: "chain_invalid" });
    });
    await t.test(`${kind} wrong type and unknown revision`, () => {
      const [, payload, signature] = changeClaims(original, (claims) => ({ ...claims, [revisionField]: sampleDigest })).split(".");
      const header = JSON.parse(Buffer.from(original.split(".")[0], "base64url").toString());
      const compact = `${Buffer.from(api.canonical({ ...header, typ: "cap+party" })).toString("base64url")}.${payload}.${signature}`;
      assert.deepEqual(api.verifyChain({ ...base, [list]: [compact] }), { ok: false, code: "protected_header_invalid" });
    });
  }
});

test("chain artifact lists must be supplied explicitly", () => {
  const base = fixture("chain-verify", "chain-dual-acceptance-valid");
  for (const list of ["acceptances", "terminations"]) {
    const view = { ...base };
    delete view[list];
    assert.deepEqual(api.verifyChain(view), { ok: false, code: "invalid_type" });
  }
});

test("S10 successor links are checked before selecting a key", () => {
  const [root, child] = fixture("descriptor_chain-verify", "descriptor-chain-superseded-position").compacts;
  const previous = api.decodePartyDescriptor(root);
  assert.ok(previous.ok);
  const predecessor = { digest: previous.digest, claims: previous.claims, lineage: [root] };
  const [header, payload, signature] = changeClaims(child, (c) => ({ ...c, prev_descriptor_digest: sampleDigest })).split(".");
  const protectedValue = JSON.parse(Buffer.from(header, "base64url").toString());
  const compact = `${Buffer.from(api.canonical({ ...protectedValue, kid: "unknown-key" })).toString("base64url")}.${payload}.${signature}`;
  assert.deepEqual(api.verifyDescriptor(compact, predecessor), { ok: false, code: "descriptor_chain_invalid" });
});

test("S11 JSON limits count every parsed member and parse over-limit values first", async (t) => {
  await t.test("duplicate members count toward the object limit", () => {
    assert.deepEqual(api.decodeJsonText('{"a":1,"a":2,"b":3}', { max_object_members: 2 }), { ok: false, code: "limit_exceeded" });
  });
  await t.test("invalid array value precedes item limit", () => {
    assert.deepEqual(api.decodeJsonText('[1,2,1e400]', { max_array_items: 2 }), { ok: false, code: "invalid_number" });
  });
  await t.test("invalid object value precedes member limit", () => {
    assert.deepEqual(api.decodeJsonText('{"a":1,"b":2,"c":1e400}', { max_object_members: 2 }), { ok: false, code: "invalid_number" });
  });
  assert.deepEqual(api.decodeJsonText('[1,2,3]', { max_array_items: 2 }), { ok: false, code: "limit_exceeded" });
  assert.deepEqual(api.decodeJsonText('{"a":1,"a":2}', { max_object_members: 2 }), { ok: false, code: "duplicate_member" });
});

test("S12 revision decoding requires text", () => {
  for (const value of [5, null, {}, [], true]) {
    assert.deepEqual(api.decodeCharterRevision(value), { ok: false, code: "invalid_type" });
  }
});

test("S13 descriptor predecessors are reverified from their signed lineage", async (t) => {
  const [root, child] = fixture("descriptor_chain-verify", "descriptor-chain-superseded-position").compacts;
  const previous = api.decodePartyDescriptor(root);
  assert.ok(previous.ok);
  const pair = generateKeyPairSync("ed25519");
  const attackerKey = pair.publicKey.export({ format: "jwk" }).x!;
  const spoofed = { ...previous.claims, verification_keys: previous.claims.verification_keys.map((key: any) => ({ ...key, public_key: attackerKey })) };
  const [header, payload] = child.split(".");
  const message = Buffer.from(`${header}.${payload}`);
  const forged = `${message}.${sign(null, message, pair.privateKey).toString("base64url")}`;
  await t.test("claims without lineage cannot supply a predecessor", () => {
    assert.deepEqual(api.verifyDescriptor(forged, { digest: previous.digest, claims: spoofed }), { ok: false, code: "descriptor_chain_invalid" });
  });
  await t.test("signed lineage replaces caller key claims", () => {
    const predecessor = { digest: previous.digest, claims: spoofed, lineage: [root] };
    assert.deepEqual(api.verifyDescriptor(forged, predecessor), { ok: false, code: "signature_invalid" });
  });
  await t.test("null claims produce a typed result", () => {
    assert.deepEqual(api.verifyDescriptor(child, { digest: previous.digest, claims: null } as never), { ok: false, code: "descriptor_chain_invalid" });
  });
  await t.test("honest successors use retained facts", () => {
    const genesis = api.verifyDescriptor(root);
    assert.ok(genesis.ok);
    assert.deepEqual(genesis.facts.lineage, [root]);
    const next = api.verifyDescriptor(child, genesis.facts);
    assert.ok(next.ok);
    assert.deepEqual(next.facts.lineage, [child, root]);
  });
  await t.test("lineage digest must equal the supplied digest", () => {
    const predecessor = { digest: sampleDigest, claims: previous.claims, lineage: [root] };
    assert.deepEqual(api.verifyDescriptor(child, predecessor), { ok: false, code: "descriptor_chain_invalid" });
  });
  await t.test("every retained signature is reverified", () => {
    const predecessor = { digest: previous.digest, claims: previous.claims, lineage: [changeClaims(root, (claims) => ({ ...claims, effective_from: "2026-08-25T09:00:00Z" }))] };
    assert.deepEqual(api.verifyDescriptor(child, predecessor), { ok: false, code: "descriptor_chain_invalid" });
  });
});

test("S5 file imports cannot alter source or built signature verdicts", async (t) => {
  const input = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  const [header, payload, signature] = input.compact.split(".");
  const bytes = Buffer.from(signature, "base64url");
  bytes[40] ^= 1;
  const forged = `${header}.${payload}.${bytes.toString("base64url")}`;
  for (const [entry, seam] of [["./index.ts", "./internal/capability-probe.ts"], ["./dist/index.js", "./dist/internal/capability-probe.js"]]) await t.test(entry, async () => {
    const verifier = await import(new URL(entry, import.meta.url).href);
    let probe: any;
    try { probe = (await import(new URL(seam, import.meta.url).href)).capabilityProbe; }
    catch (error: any) { assert.equal(error.code, "ERR_MODULE_NOT_FOUND"); }
    const savedVerify = probe?.verify;
    const savedRun = probe?.run;
    try {
      if (probe) {
        try { probe.run = () => false; } catch (error) { assert.ok(error instanceof TypeError); }
      }
      const genuine = verifier.verifyDescriptor(input.compact);
      if (probe) {
        try { probe.run = () => true; probe.verify = () => true; } catch (error) { assert.ok(error instanceof TypeError); }
      }
      const changed = verifier.verifyDescriptor(forged);
      assert.deepEqual([genuine.ok, changed.ok], [true, false]);
      assert.deepEqual(changed, { ok: false, code: "signature_invalid" });
    } finally {
      if (probe && !Object.isFrozen(probe)) { probe.verify = savedVerify; probe.run = savedRun; }
    }
  });
});

test("partial profile types match the public verification behavior", () => {
  const algorithms: api.Profile = { algorithms: ["EdDSA"] };
  const algorithmsOnly: api.VerificationOptions = { profile: algorithms };
  const revisions: api.Profile = { revisions: { min: 1, max: 1 } };
  const revisionsOnly: api.VerificationOptions = { profile: revisions };
  const f = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  assert.ok(api.verifyDescriptor(f.compact, null, algorithmsOnly).ok);
  assert.ok(api.verifyDescriptor(f.compact, null, revisionsOnly).ok);
});

test("signature message limits and null artifact lists retain their public behavior", () => {
  const pair = generateKeyPairSync("ed25519");
  const message = Buffer.alloc(1_048_577, 7);
  const signature = sign(null, message, pair.privateKey);
  const publicKey = pair.publicKey.export({ format: "jwk" }).x!;
  assert.equal(api.verifySignature(message, signature, publicKey, "EdDSA"), false);
  assert.equal(api.verifySignature(message, signature, publicKey, "EdDSA", { limits: { max_bytes: message.length } }), true);
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  for (const list of ["acceptances", "terminations"]) {
    assert.deepEqual(api.verifyChain({ ...view, [list]: null }), { ok: false, code: "invalid_type" });
  }
});


test("unsigned revision profile bounds and optional termination digest grammar stay strict", () => {
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  const revision = { ...JSON.parse(view.revisions[0]), protocol_revision: 2 };
  assert.deepEqual(api.verifyChain({ ...view, revisions: [api.canonical(revision)], acceptances: [] }, { profile: { revisions: { min: 1, max: 1 } } }), { ok: false, code: "revision_outside_profile" });
  const f = fixture("termination-verify", "termination-valid");
  assert.deepEqual(api.verifyTermination(changeClaims(f.compact, (claims) => ({ ...claims, detail_digest: "bad" })), f.revision_text, f.descriptor_compacts), { ok: false, code: "constraint_violation" });
});
