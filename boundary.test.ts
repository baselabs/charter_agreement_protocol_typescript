import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
