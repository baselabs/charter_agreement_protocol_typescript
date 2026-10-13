import test from "node:test";
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
