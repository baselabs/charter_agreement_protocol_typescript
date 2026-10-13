import test from "node:test";
import { build } from "esbuild";
import { Session } from "node:inspector/promises";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { generateKeyPairSync, sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createContext, runInContext } from "node:vm";
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

async function bundledVerifier(platform: "browser" | "node" = "browser") {
  const scratch = mkdtempSync(join(tmpdir(), "cap-bundle-"));
  try {
    const outfile = join(scratch, "verifier.mjs");
    await build({
      entryPoints: ["index.ts"], bundle: true, outfile, format: "esm", platform, target: "es2022",
      alias: platform === "browser" ? { "node:crypto": "./web/shim/node-crypto.ts", "node:fs": "./web/shim/node-fs.ts", "node:path": "./web/shim/node-path.ts" } : { "node:crypto": "./web/shim/node-crypto.ts" },
      inject: ["./web/shim/buffer-global.ts"],
    });
    return await import(pathToFileURL(outfile).href);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

test("browser bundle verifies signed descriptors and a dual acceptance chain", async () => {
  const browser = await bundledVerifier();
  const genesis = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  assert.equal(browser.verifyDescriptor(genesis.compact).ok, true);
  assert.equal(browser.verifyChain(view).ok, true);
  const pq = fixture("party_descriptor-verify", "descriptor-mldsa65-rev3-valid");
  assert.deepEqual(browser.verifyDescriptor(pq.compact), { ok: false, code: "algorithm_unsupported_on_substrate" });
  assert.deepEqual(browser.verifyDescriptor(changeClaims(pq.compact, (c) => ({ ...c, extra: true }))), { ok: false, code: "unknown_member" });
  assert.deepEqual(browser.verifyDescriptor(pq.compact, null, { profile: { algorithms: ["Ed25519"] } }), { ok: false, code: "algorithm_outside_profile" });
});

test("real web crypto diagnostics stay outside corpus verdict reports", async () => {
  const verifier = await bundledVerifier("node");
  assert.throws(() => verifier.reportFor("conformance"), /algorithm_unsupported_on_substrate/);
});

test("real signature verification skips signature vectors on its normal path", async () => {
  const session = new Session();
  session.connect();
  try {
    await session.post("Profiler.enable");
    await session.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
    const genesis = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
    const view = fixture("chain-verify", "chain-dual-acceptance-valid");
    assert.ok(api.verifyDescriptor(genesis.compact).ok);
    assert.ok(api.verifyChain(view).ok);
    assert.ok(api.verifyChain(view).ok);
    const { result } = await session.post("Profiler.takePreciseCoverage");
    const core = result.find((script) => script.url.endsWith("/core.ts"));
    assert.ok(core);
    const calls = (name: string) => core.functions.filter((fn) => fn.functionName === name).reduce((sum, fn) => sum + fn.ranges[0].count, 0);
    assert.ok(calls("runtimeSupportsAlgorithm") > 0);
    assert.equal(calls("katVerifies"), 0);
  } finally {
    await session.post("Profiler.stopPreciseCoverage");
    session.disconnect();
  }
});

const badDigest = "sha-256:" + "A".repeat(42) + "B";
const sampleDigest = "sha-256:" + "A".repeat(43);

test("signed claims reject every noncanonical digest", async (t) => {
  for (const [file, id, verify, fields, code] of [
    ["acceptance-verify", "acceptance-valid", api.verifyAcceptance, ["charter_id", "revision_digest", "prev_revision_digest", "party_descriptor_digest"], "acceptance_invalid"],
    ["termination-verify", "termination-valid", api.verifyTermination, ["charter_id", "governing_revision_digest", "party_descriptor_digest", "detail_digest"], "termination_invalid"],
  ] as const) {
    for (const field of fields) await t.test(`${file} ${field}`, () => {
      const f = fixture(file, id);
      if (field === "prev_revision_digest") {
        const first = api.decodeCharterRevision(f.revision_text);
        assert.ok(first.ok);
        f.revision_text = api.canonical({ ...JSON.parse(f.revision_text), revision_number: 2, charter_id: first.digest, prev_revision_digest: first.digest });
        const second = api.decodeCharterRevision(f.revision_text);
        assert.ok(second.ok);
        f.compact = changeClaims(f.compact, (c) => ({ ...c, revision_number: 2, charter_id: first.digest, prev_revision_digest: first.digest, revision_digest: second.digest }));
        assert.deepEqual(api.checkSigningClaims("acceptance", claimsOf(f.compact)), { ok: true });
        assert.deepEqual(api.verifyAcceptance(f.compact, f.revision_text, f.descriptor_compacts), { ok: false, code: "signature_invalid" });
      }
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

test("revision parties and supplied histories are distinct and named", async (t) => {
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
  await t.test("a successor revision cannot use two descriptors from one history", () => {
    const [root, child] = fixture("descriptor_chain-verify", "descriptor-chain-superseded-position").compacts;
    const first = api.decodeCharterRevision(base.revisions[0]);
    const older = api.descriptorDigest(root);
    const newer = api.descriptorDigest(child);
    assert.ok(first.ok && older.ok && newer.ok);
    const next = { ...JSON.parse(base.revisions[0]), revision_number: 2, charter_id: first.digest, prev_revision_digest: first.digest, parties: [{ role: "issuer", party_descriptor_digest: older.digest }, { role: "acceptor", party_descriptor_digest: newer.digest }] };
    const view = { ...base, descriptors: [...new Set([...base.descriptors, root, child])], revisions: [...base.revisions, api.canonical(next)], acceptances: [] };
    assert.deepEqual(api.verifyChain(view), { ok: false, code: "chain_invalid" });
  });
});

test("malformed signed timestamps keep the parser code and ordering", async (t) => {
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

test("year 0000 and its leap day pass every timestamp surface", async (t) => {
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

test("producers and assembly reject malformed artifact claims", async (t) => {
  const f = fixture("termination-verify", "termination-valid");
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  const coordinates = claimsOf(view.acceptances[0]);
  const claims = { ...claimsOf(f.compact), protocol_revision: 2, charter_id: coordinates.charter_id, governing_revision_digest: coordinates.revision_digest, party_descriptor_digest: coordinates.party_descriptor_digest, party_role: coordinates.party_role };
  for (const extensions of [5, { critical: {}, optional: {} }]) await t.test("termination extra member " + typeof extensions, () => {
    assert.deepEqual(api.terminationSigningInput("k", { ...claims, extensions }, view), { ok: false, code: "signing_input_invalid" });
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

test("producer build failures always return signing_input_invalid", async (t) => {
  const view = fixture("chain-verify", "chain-dual-acceptance-valid");
  const acceptance = { ...claimsOf(view.acceptances[0]), protocol_revision: 2 };
  const termination = { ...claimsOf(fixture("termination-verify", "termination-valid").compact), protocol_revision: 2, charter_id: acceptance.charter_id, governing_revision_digest: acceptance.revision_digest, party_descriptor_digest: acceptance.party_descriptor_digest, party_role: acceptance.party_role };
  const descriptor = { ...claimsOf(fixture("party_descriptor-verify", "party-descriptor-genesis-valid").compact), protocol_revision: 2 };
  const receipt = { ...claimsOf(fixture("receipt-verify", "receipt-signed-governing-match").compact), protocol_revision: 2 };
  for (const [kind, claims, produce, time] of [
    ["descriptor", descriptor, (c: any, alg?: any) => api.descriptorSigningInput("k", c, alg), "effective_from"],
    ["acceptance", acceptance, (c: any, alg?: any) => api.acceptanceSigningInput("k", c, view, alg), "accepted_at"],
    ["termination", termination, (c: any, alg?: any) => api.terminationSigningInput("k", c, view, alg), "issued_at"],
    ["receipt", receipt, (c: any, alg?: any) => api.receiptSigningInput("k", c, alg), "occurred_at"],
  ] as const) {
    assert.ok(produce(claims).ok, kind);
    for (const [label, run] of [
      ["extra member", () => produce({ ...claims, extra: true })],
      ["timestamp", () => produce({ ...claims, [time]: "bad-time" })],
      ["claims type", () => produce(null)],
      ["algorithm", () => produce(claims, "EdDSA")],
      ["null algorithm", () => produce(claims, null)],
    ] as const) await t.test(`${kind} ${label}`, () => assert.deepEqual(run(), { ok: false, code: "signing_input_invalid" }));
  }
});

test("revision timestamps precede binding digest extraction", () => {
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

test("descriptor key extraction uses codec errors before times and extensions", async (t) => {
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

test("chain routing checks the envelope and both routing coordinates first", async (t) => {
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

test("every set consuming API rejects omitted or non-list artifact lists with invalid_type", async (t) => {
  const base = fixture("chain-verify", "chain-dual-acceptance-valid");
  const acceptance = { ...claimsOf(base.acceptances[0]), protocol_revision: 2 };
  const termination = { ...claimsOf(fixture("termination-verify", "termination-valid").compact), protocol_revision: 2, charter_id: acceptance.charter_id, governing_revision_digest: acceptance.revision_digest, party_descriptor_digest: acceptance.party_descriptor_digest, party_role: acceptance.party_role };
  const omitted = Symbol("omitted");
  for (const list of ["revisions", "descriptors", "acceptances", "terminations"]) for (const bad of [omitted, null, "x", {}, [5]] as const) {
    const view: any = { ...base };
    if (bad === omitted) delete view[list];
    else view[list] = bad;
    const label = bad === omitted ? "omitted" : JSON.stringify(bad);
    for (const [name, run] of [
      ["verifyChain", () => api.verifyChain(view)],
      ["verifyReceipt", () => api.verifyReceipt("broken", view)],
      ["governingRevision", () => api.governingRevision(view, "2026-08-25T12:00:00Z")],
      ["acceptanceRefusal", () => api.acceptanceRefusal(acceptance, view)],
      ["terminationRefusal", () => api.terminationRefusal(termination, view)],
      ["acceptanceSigningInput", () => api.acceptanceSigningInput("k", acceptance, view)],
      ["terminationSigningInput", () => api.terminationSigningInput("k", termination, view)],
    ] as const) await t.test(`${name} ${list} ${label}`, () => assert.deepEqual(run(), { ok: false, code: "invalid_type" }));
  }
});

test("successor links are checked before selecting a key", () => {
  const [root, child] = fixture("descriptor_chain-verify", "descriptor-chain-superseded-position").compacts;
  const previous = api.decodePartyDescriptor(root);
  assert.ok(previous.ok);
  const predecessor = { digest: previous.digest, claims: previous.claims, lineage: [root] };
  const [header, payload, signature] = changeClaims(child, (c) => ({ ...c, prev_descriptor_digest: sampleDigest })).split(".");
  const protectedValue = JSON.parse(Buffer.from(header, "base64url").toString());
  const compact = `${Buffer.from(api.canonical({ ...protectedValue, kid: "unknown-key" })).toString("base64url")}.${payload}.${signature}`;
  assert.deepEqual(api.verifyDescriptor(compact, predecessor), { ok: false, code: "descriptor_chain_invalid" });
});

test("JSON limits count every parsed member and parse over-limit values first", async (t) => {
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

test("JSON separators precede container counts and number conversion", async (t) => {
  for (const text of ['[1,2,3}', '[1,2,"x"', '[1,2,true ', '[1,2,{}', '{"a":1,"b":2,"c":3]', '{"a":1,"b":2,"a":3']) {
    await t.test(text, () => assert.deepEqual(api.decodeJsonText(text, { max_array_items: 2, max_object_members: 2 }), { ok: false, code: "invalid_syntax" }));
  }
  for (const literal of ["1e400", "12345678901234567", "12345678901234567890123"]) {
    for (const text of [`[${literal}`, `[${literal}x`, `[${literal}}`, `{"a":${literal}`, `{"a":${literal}]`]) {
      await t.test(text, () => assert.deepEqual(api.decodeJsonText(text), { ok: false, code: "invalid_syntax" }));
    }
  }
  assert.deepEqual(api.decodeJsonText('[1,2,3,', { max_array_items: 2 }), { ok: false, code: "limit_exceeded" });
  assert.deepEqual(api.decodeJsonText('[1e400]'), { ok: false, code: "invalid_number" });
  assert.deepEqual(api.decodeJsonText('[12345678901234567]'), { ok: false, code: "number_not_double_expressible" });
});

test("revision decoding requires text", () => {
  for (const value of [5, null, {}, [], true]) {
    assert.deepEqual(api.decodeCharterRevision(value), { ok: false, code: "invalid_type" });
  }
});

test("descriptor predecessors are reverified from their signed lineage", async (t) => {
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
  await t.test("lineage digest must equal descriptor_digest too", () => {
    const predecessor: api.DescriptorPredecessor = { descriptor_digest: sampleDigest, lineage: [root] };
    assert.deepEqual(api.verifyDescriptor(child, predecessor), { ok: false, code: "descriptor_chain_invalid" });
  });
  await t.test("genesis rejects a verified predecessor", () => {
    const genesis = api.verifyDescriptor(root);
    assert.ok(genesis.ok);
    assert.deepEqual(api.verifyDescriptor(root, genesis.facts), { ok: false, code: "descriptor_chain_invalid" });
  });
  await t.test("a lone successor checks identity digests before its missing predecessor", () => {
    assert.deepEqual(api.verifyDescriptor(child), { ok: false, code: "descriptor_chain_invalid" });
    for (const name of ["party_id", "prev_descriptor_digest"]) {
      assert.deepEqual(api.verifyDescriptor(changeClaims(child, (c) => ({ ...c, [name]: badDigest }))), { ok: false, code: "descriptor_invalid" });
    }
  });
  await t.test("every retained signature is reverified", () => {
    const predecessor = { digest: previous.digest, claims: previous.claims, lineage: [changeClaims(root, (claims) => ({ ...claims, effective_from: "2026-08-25T09:00:00Z" }))] };
    assert.deepEqual(api.verifyDescriptor(child, predecessor), { ok: false, code: "descriptor_chain_invalid" });
  });
});

test("file imports cannot alter source or built signature verdicts", async (t) => {
  const input = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
  const [header, payload, signature] = input.compact.split(".");
  const bytes = Buffer.from(signature, "base64url");
  bytes[40] ^= 1;
  const forged = `${header}.${payload}.${bytes.toString("base64url")}`;
  for (const [entry, seam] of [["./index.ts", "./internal/capability-probe.ts"], ["./dist/index.js", "./dist/internal/capability-probe.js"]]) await t.test(entry, async () => {
    const verifier = await import(new URL(entry, import.meta.url).href);
    await assert.rejects(import(new URL(seam, import.meta.url).href), { code: "ERR_MODULE_NOT_FOUND" });
    assert.equal(verifier.verifyDescriptor(input.compact).ok, true);
    assert.deepEqual(verifier.verifyDescriptor(forged), { ok: false, code: "signature_invalid" });
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

test("standalone profiles reach their reverified context in order", async (t) => {
  for (const [file, stem, verify] of [
    ["acceptance-verify", "acceptance", api.verifyAcceptance],
    ["termination-verify", "termination", api.verifyTermination],
  ] as const) {
    for (const [suffix, code] of [["narrow-valid", null], ["context-algorithm-outside", "algorithm_outside_profile"], ["context-revision-outside", "revision_outside_profile"]] as const) {
      await t.test(`${stem} ${suffix}`, () => {
        const f = fixture(file, `${stem}-profile-${suffix}`);
        const result = verify(f.compact, f.revision_text, f.descriptor_compacts, { profile: f.profile });
        if (code) assert.deepEqual(result, { ok: false, code });
        else assert.ok(result.ok);
      });
    }
    await t.test(`${stem} revision admission precedes history and artifact decoding`, () => {
      const f = fixture(file, `${stem}-profile-context-revision-outside`);
      assert.deepEqual(verify("broken", f.revision_text, ["broken"], { profile: f.profile }), { ok: false, code: "revision_outside_profile" });
    });
    await t.test(`${stem} history admission precedes artifact decoding`, () => {
      const f = fixture(file, `${stem}-profile-context-algorithm-outside`);
      assert.deepEqual(verify("broken", f.revision_text, f.descriptor_compacts, { profile: f.profile }), { ok: false, code: "algorithm_outside_profile" });
    });
    await t.test(`${stem} history revision is admitted separately`, () => {
      const f = fixture(file, `${stem}-profile-narrow-valid`);
      const revisionText = api.canonical({ ...JSON.parse(f.revision_text), protocol_revision: 2 });
      assert.deepEqual(verify("broken", revisionText, f.descriptor_compacts, { profile: { revisions: { min: 2, max: 3 } } }), { ok: false, code: "revision_outside_profile" });
    });
  }
  for (const [suffix, code] of [["narrow-valid", null], ["context-algorithm-outside", "algorithm_outside_profile"], ["revision-only-algorithm-outside", "algorithm_outside_profile"], ["revision-only-revision-outside", "revision_outside_profile"]] as const) {
    await t.test(`receipt ${suffix}`, () => {
      const f = fixture("receipt-verify", `receipt-profile-${suffix}`);
      const result = api.verifyReceipt(f.compact, f.revision_text ?? f.chain, { profile: f.profile });
      if (code) assert.deepEqual(result, { ok: false, code });
      else assert.ok(result.ok);
    });
  }
  await t.test("receipt revision context leaves signatures unchecked", () => {
    const f = fixture("receipt-verify", "receipt-profile-revision-only-algorithm-outside");
    const [header, payload] = f.compact.split(".");
    const compact = `${header}.${payload}.${Buffer.alloc(64).toString("base64url")}`;
    const result = api.verifyReceipt(compact, f.revision_text);
    assert.ok(result.ok);
    assert.equal(result.facts.governing_match, "undetermined");
    assert.deepEqual(api.verifyReceipt(compact, f.revision_text, { profile: f.profile }), { ok: false, code: "algorithm_outside_profile" });
    assert.deepEqual(api.verifyReceipt("broken", f.revision_text, { profile: { revisions: { min: 2, max: 3 } } }), { ok: false, code: "revision_outside_profile" });
    assert.ok(result.facts.not_verified.includes("signature"));
    const laterEnvelope = changeClaims(compact, (c) => ({ ...c, protocol_revision: 3 }));
    assert.ok(api.verifyReceipt(laterEnvelope, f.revision_text).ok);
    assert.deepEqual(api.verifyReceipt(laterEnvelope, f.revision_text, { profile: { revisions: { min: 1, max: 2 } } }), { ok: false, code: "revision_outside_profile" });
    assert.deepEqual(api.verifyReceipt(changeClaims(compact, (c) => ({ ...c, revision_digest: sampleDigest })), f.revision_text, { profile: f.profile }), { ok: false, code: "receipt_claims_mismatch" });
    assert.deepEqual(api.verifyReceipt(changeClaims(compact, (c) => ({ ...c, extra: true })), f.revision_text, { profile: f.profile }), { ok: false, code: "unknown_member" });
  });
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

test("root numbers report the reference code for a cut-off fraction or exponent", () => {
  // Codes recorded from the Elixir reference's Json.decode on each text.
  const expected: Array<[string, string]> = [
    ["1e", "invalid_syntax"], ["1.", "invalid_syntax"], ["-0.", "invalid_syntax"], ["1e+", "invalid_syntax"],
    ["1ex", "invalid_syntax"], ["1.e5", "invalid_syntax"], ["1.5e", "invalid_syntax"], ["1.5E+", "invalid_syntax"],
    ["0.", "invalid_syntax"], ["0e", "invalid_syntax"], ["-1.x", "invalid_syntax"], ["1E", "invalid_syntax"],
    ["1e5.", "trailing_bytes"], ["1.5.", "trailing_bytes"], ["1e5e", "trailing_bytes"], ["1.5x", "trailing_bytes"],
    ["0x", "trailing_bytes"], ["01", "trailing_bytes"], ["1 .", "trailing_bytes"], ["1 e", "trailing_bytes"],
    ["1e5x", "trailing_bytes"], ["[1e]", "invalid_syntax"], ["[1.]", "invalid_syntax"], ["[01]", "invalid_syntax"],
  ];
  for (const [text, code] of expected) assert.deepEqual(api.decodeJsonText(text), { ok: false, code }, text);
});

test("trailing bytes outrank a deferred number error at the root", () => {
  assert.deepEqual(api.decodeJsonText("9007199254740993}"), { ok: false, code: "trailing_bytes" });
  assert.deepEqual(api.decodeJsonText("1e400 x"), { ok: false, code: "trailing_bytes" });
  assert.deepEqual(api.decodeJsonText("1e400"), { ok: false, code: "invalid_number" });
  assert.deepEqual(api.decodeJsonText("9007199254740993"), { ok: false, code: "number_not_double_expressible" });
});

test("browser bundle rejects every forged signature the corpus carries", async () => {
  const browser = await bundledVerifier();
  const one = (file: string, id: string) => fixture(file, id);
  const descriptor = one("party_descriptor-verify", "party-descriptor-wrong-signature");
  const chain = one("descriptor_chain-verify", "descriptor-chain-wrong-signer");
  const acceptance = one("acceptance-verify", "acceptance-wrong-signature");
  const termination = one("termination-verify", "termination-wrong-signature");
  const receipt = one("receipt-verify", "receipt-signature-invalid");
  const pairs: Array<[string, (v: any) => unknown, unknown]> = [
    ["descriptor", (v) => v.verifyDescriptor(descriptor.compact), { ok: false, code: "signature_invalid" }],
    ["descriptor chain", (v) => v.verifyDescriptorChain(chain.compacts), { ok: false, code: "descriptor_chain_invalid" }],
    ["acceptance", (v) => v.verifyAcceptance(acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts), { ok: false, code: "signature_invalid" }],
    ["termination", (v) => v.verifyTermination(termination.compact, termination.revision_text, termination.descriptor_compacts), { ok: false, code: "signature_invalid" }],
    ["receipt", (v) => v.verifyReceipt(receipt.compact, receipt.chain), { ok: false, code: "signature_invalid" }],
  ];
  for (const [name, call, expected] of pairs) {
    assert.deepEqual(call(api), expected, `node ${name}`);
    assert.deepEqual(call(browser), expected, `browser ${name}`);
  }
});

test("the browser bundle runs in a page that has no process object", async () => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-page-"));
  try {
    const outfile = join(scratch, "page.js");
    await build({
      entryPoints: ["index.ts"], bundle: true, outfile, format: "iife", globalName: "CAP", platform: "browser", target: "es2022",
      alias: { "node:crypto": "./web/shim/node-crypto.ts", "node:fs": "./web/shim/node-fs.ts", "node:path": "./web/shim/node-path.ts" },
      inject: ["./web/shim/buffer-global.ts"],
    });
    const page = createContext({ TextEncoder, TextDecoder, atob, btoa });
    runInContext(`${readFileSync(outfile, "utf8")}\nglobalThis.CAP = CAP;`, page);
    assert.equal(runInContext("typeof process", page), "undefined");
    const verifier = (page as any).CAP;
    const capabilities = verifier.capabilities();
    assert.equal(capabilities.linkedCrypto, "");
    // Values from the page's realm carry its own prototypes; compare plain copies.
    const verifiable = JSON.parse(JSON.stringify(capabilities.algorithms.filter((row: any) => row.verifiable).map((row: any) => row.name)));
    assert.deepEqual(verifiable, ["EdDSA", "Ed25519"]);
    const genesis = fixture("party_descriptor-verify", "party-descriptor-genesis-valid");
    assert.equal(verifier.verifyDescriptor(genesis.compact).ok, true);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("a runtime whose ML-DSA keys report no type still verifies ML-DSA", (t) => {
  // Bun imports ML-DSA keys without setting asymmetricKeyType. Run the
  // source verifier on a real Bun when one is installed.
  const bun = spawnSync("bun", ["--version"], { encoding: "utf8" });
  if (bun.status !== 0) {
    // CI installs Bun and sets CAP_REQUIRE_BUN, so a missing Bun fails there.
    assert.notEqual(process.env.CAP_REQUIRE_BUN, "1", "CAP_REQUIRE_BUN is set but bun is not on PATH");
    t.skip("bun is not installed");
    return;
  }
  const script = [
    `const core = await import(${JSON.stringify(new URL("./core.ts", import.meta.url).pathname)});`,
    `const doc = JSON.parse(await Bun.file(${JSON.stringify(new URL("./conformance/cases/party_descriptor-verify.json", import.meta.url).pathname)}).text());`,
    `const compact = doc.cases.find((c) => c.id === "descriptor-mldsa65-rev3-valid").input.compact;`,
    `const parts = compact.split(".");`,
    `const signature = Buffer.from(parts[2], "base64url"); signature[10] ^= 1;`,
    `const forged = parts[0] + "." + parts[1] + "." + signature.toString("base64url");`,
    `console.log(JSON.stringify([core.verifyDescriptor(compact).ok, core.verifyDescriptor(forged)]));`,
  ].join("\n");
  const run = spawnSync("bun", ["-e", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout.trim()), [true, { ok: false, code: "signature_invalid" }]);
});
