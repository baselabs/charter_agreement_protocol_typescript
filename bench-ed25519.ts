import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { canonical, taggedDigest, verifyChain, verifySignature } from "./index.ts";
import { loadEd25519Predicate } from "./ed25519-inputs.ts";

const predicate = await loadEd25519Predicate();
const fixture = JSON.parse(readFileSync(new URL("./conformance/cases/chain-verify.json", import.meta.url), "utf8"))
  .cases.find((one: any) => one.id === "chain-dual-acceptance-valid").input;
const view = { descriptors: [] as string[], revisions: [] as string[], acceptances: [] as string[], terminations: [] as string[] };
const descriptorTemplate = JSON.parse(Buffer.from(fixture.descriptors[0].split(".")[1], "base64url").toString());
const revisionTemplate = JSON.parse(fixture.revisions[0]);
const acceptanceTemplate = JSON.parse(Buffer.from(fixture.acceptances[0].split(".")[1], "base64url").toString());
const pairs = [1, 2].map((seed) => {
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, seed)]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  return { privateKey, publicKey, encoded: publicKey.export({ format: "jwk" }).x! };
});
const compact = (typ: string, claims: any, pair: typeof pairs[number]) => {
  const input = Buffer.from(`${Buffer.from(canonical({ alg: "Ed25519", kid: "k", typ })).toString("base64url")}.${Buffer.from(canonical(claims)).toString("base64url")}`);
  return `${input.toString()}.${sign(null, input, pair.privateKey).toString("base64url")}`;
};
const parties = pairs.map((pair, index) => {
  let root = "";
  let previous = "";
  for (let number = 1; number <= 40; number++) {
    const claims = { ...descriptorTemplate, protocol_revision: 2, descriptor_number: number,
      verification_keys: [{ algorithm: "Ed25519", key_id: "k", public_key: pair.encoded, status: "active" }],
      ...(number > 1 ? { party_id: root, prev_descriptor_digest: previous } : {}) };
    view.descriptors.push(compact("cap+party", claims, pair));
    previous = taggedDigest("party_descriptor_content", Buffer.from(canonical(claims)));
    if (number === 1) root = previous;
  }
  return { role: index === 0 ? "issuer" : "acceptor", party_descriptor_digest: previous };
});
let charterId = "";
let previous = "";
for (let number = 1; number <= 200; number++) {
  const claims = { ...revisionTemplate, protocol_revision: 2, revision_number: number, parties,
    ...(number > 1 ? { charter_id: charterId, prev_revision_digest: previous } : {}) };
  const text = canonical(claims);
  const digest = taggedDigest("charter_revision_content", Buffer.from(text));
  if (number === 1) charterId = digest;
  view.revisions.push(text);
  parties.forEach((party, index) => view.acceptances.push(compact("cap+acceptance", {
    ...acceptanceTemplate, party_descriptor_digest: party.party_descriptor_digest, party_role: party.role, protocol_revision: 2, charter_id: charterId,
    revision_number: number, revision_digest: digest,
    ...(number > 1 ? { prev_revision_digest: previous } : {}),
  }, pairs[index])));
  previous = digest;
}
assert.equal(view.descriptors.length, 80);
assert.equal(view.acceptances.length, 400);
const checked = verifyChain(view);
assert.ok(checked.ok, JSON.stringify(checked));
assert.equal(checked.facts.acceptedDigests.length, 200);
const message = Buffer.from("CAP Ed25519 cost check");
const signature = sign(null, message, pairs[0].privateKey);
const key = Buffer.from(pairs[0].encoded, "base64url");
const r = signature.subarray(0, 32);

function measure(label: string, count: number, call: () => boolean): number {
  for (let i = 0; i < Math.min(count, 100); i++) assert.ok(call());
  const samples = Array.from({ length: 5 }, () => {
    const start = performance.now();
    for (let i = 0; i < count; i++) assert.ok(call());
    return (performance.now() - start) * 1000 / count;
  }).sort((a, b) => a - b);
  console.log(`${label}: ${samples[2].toFixed(3)} us/call (median of 5, ${count} calls/sample)`);
  return samples[2];
}
console.log(`Node ${process.version}; real signatures; 80 descriptors, 200 revisions, 400 acceptances`);
const keyCost = measure("key point admission", 2500, () => predicate(key));
const rCost = measure("R point admission", 2500, () => predicate(r));
const nativeCost = measure("native signature check with retained KeyObject", 2500, () => verify(null, message, pairs[0].publicKey, signature));
measure("native signature check including SPKI import", 2500, () => verify(null, message,
  createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), key]), format: "der", type: "spki" }), signature));
measure("public verifySignature", 1000, () => verifySignature(message, signature, pairs[0].encoded, "Ed25519"));
measure("verifyChain large set", 1, () => verifyChain(view).ok);
console.log(`key/native: ${(keyCost / nativeCost).toFixed(3)}x; R/native: ${(rCost / nativeCost).toFixed(3)}x; combined/native: ${((keyCost + rCost) / nativeCost).toFixed(3)}x`);
