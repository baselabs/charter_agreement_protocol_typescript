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
