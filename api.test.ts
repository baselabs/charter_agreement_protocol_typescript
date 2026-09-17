// CAP never authorizes.
//
// Artifact-level API tests (0.2.0): the corpus fixtures supply real signed
// artifacts; each verify function must go green on the valid fixture and
// red on a tampered one.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acceptanceRefusal,
  decodeArtifact,
  terminationRefusal,
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  verifySignature,
} from "./core.ts";

const here = dirname(fileURLToPath(import.meta.url));

function corpusCase(surfaceFile: string, id: string): Record<string, any> {
  const document = JSON.parse(readFileSync(join(here, "conformance", "cases", surfaceFile), "utf8"));
  return document.cases.find((one: any) => one.id === id);
}

test("verifyDescriptor: green on the certified genesis, red on tampering", () => {
  const valid = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid");
  const result = verifyDescriptor(valid.input.compact);
  assert.ok(result.ok);
  assert.equal(result.facts.descriptor_number, 1);
  assert.match(String(result.facts.descriptor_digest), /^sha-256:/);

  const [header, payload, signature] = valid.input.compact.split(".");
  const forged = header + "." + payload + "." + signature.slice(0, -2) + "AA";
  const tampered = verifyDescriptor(forged);
  assert.ok(tampered.ok === false);
});

test("decodeArtifact exposes the framing without verifying the signature", () => {
  const valid = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid");
  const decoded = decodeArtifact(valid.input.compact);
  assert.ok(decoded.ok);
  assert.equal(decoded.facts.typ, "cap+party");
  assert.equal(typeof decoded.facts.kid, "string");
});

test("verifySignature is the strict wrong-key guard primitive", () => {
  const valid = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid");
  const [header, payload] = valid.input.compact.split(".");
  const message = Buffer.from(`${header}.${payload}`);
  const descriptor = verifyDescriptor(valid.input.compact);
  assert.ok(descriptor.ok);

  // The corpus descriptor's own key verifies its own message; a random
  // public key must not.
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  const publicKey = claims.verification_keys[0].public_key;
  const signature = Buffer.from(valid.input.compact.split(".")[2], "base64url");
  assert.equal(verifySignature(message, signature, publicKey, "EdDSA"), true);
  const wrongKey = Buffer.alloc(32, 7).toString("base64url");
  assert.equal(verifySignature(message, signature, wrongKey, "EdDSA"), false);
});

test("verifyAcceptance and verifyChain go green on the certified chain view", () => {
  const acceptance = corpusCase("acceptance-verify.json", "acceptance-valid");
  const verified = verifyAcceptance(
    acceptance.input.compact,
    acceptance.input.revision_text,
    acceptance.input.descriptor_compacts,
  );
  assert.ok(verified.ok);
  assert.match(String(verified.facts.acceptance_digest), /^sha-256:/);

  const chain = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const chainResult = verifyChain(chain.input);
  assert.ok(chainResult.ok);
  assert.equal(chainResult.facts.topology, "linear");
});

test("verifyReceipt goes green on the certified governing match", () => {
  const receipt = corpusCase("receipt-verify.json", "receipt-signed-governing-match");
  const verified = verifyReceipt(receipt.input.compact, receipt.input.chain);
  assert.ok(verified.ok);
  assert.equal(verified.facts.governing_match, "match");
  assert.equal(verified.facts.chain_conflict, "none");
});

// ---------------------------------------------------------------------------
// Honest-signer refusal surface (R1-R3): set-aware gates over the caller's
// own verified view, mirroring the reference producers. Fixtures are the
// certified corpus topologies; refusal claims are decoded from the real
// signed acceptances where the rule needs an occupied coordinate.
// ---------------------------------------------------------------------------

function acceptanceClaims(chainCase: Record<string, any>, index: number): Record<string, any> {
  const compact = chainCase.input.acceptances[index];
  return JSON.parse(Buffer.from(compact.split(".")[1], "base64url").toString("utf8"));
}

test("acceptanceRefusal: green replaying the certified dual acceptance", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const refusal = acceptanceRefusal(acceptanceClaims(view, 0), view.input);
  assert.ok(refusal.ok);
});

test("acceptanceRefusal: R1 false revision coordinates are refused", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const claims = { ...acceptanceClaims(view, 0), revision_digest: "sha-256:" + "0".repeat(43) };
  const refusal = acceptanceRefusal(claims, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("acceptanceRefusal: R2 equivocation at an occupied revision number is refused", () => {
  // The forked view holds accepted revisions at n=2 for BOTH sibling digests;
  // signing for either one occupies a coordinate the other already holds.
  const view = corpusCase("chain-verify.json", "chain-accepted-sibling-fork");
  const claims = acceptanceClaims(view, 2); // issuer acceptance of sibling kkvNA6mM
  const refusal = acceptanceRefusal(claims, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("acceptanceRefusal: R3 re-accepting genesis on a forked view is refused (uncovered head)", () => {
  // Same digest as the set's own genesis acceptances (R2 clean), but the
  // maximum accepted heads are the n=2 siblings and genesis supersedes
  // neither nor ancestors them.
  const view = corpusCase("chain-verify.json", "chain-accepted-sibling-fork");
  const claims = acceptanceClaims(view, 0); // issuer acceptance of genesis
  const refusal = acceptanceRefusal(claims, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("acceptanceRefusal: a malformed chain view keeps the typed code", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const broken = { ...view.input, acceptances: ["not-a-compact-jws"] };
  const refusal = acceptanceRefusal(acceptanceClaims(view, 0), broken);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "chain_invalid");
});

test("acceptanceRefusal: malformed consumed fields keep the producer code", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const refusal = acceptanceRefusal({ ...acceptanceClaims(view, 0), revision_digest: 123 }, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_input_invalid");
});

test("terminationRefusal: green at the certified governing instants (start-inclusive)", () => {
  const view = corpusCase("governing_revision.json", "governing-revision-start-inclusive-precedence");
  const issuer = { party_role: "issuer", party_descriptor_digest: "sha-256:1ynn3VZQs_pAZVjrnDn-DzEUMc8gJV0FMFV3SFONZIU" };
  const genesisDigest = "sha-256:j9vaSLLwxMwF1zzLniUdZwUUAB6aTGEvwMRzP526s3o";
  const successorDigest = "sha-256:kkvNA6mMTl4q91lBYkjT3lIhMfbNeyuMKh5CePdOmWI";
  const base = { charter_id: genesisDigest, reason_code: "mutual", ...issuer };
  assert.ok(terminationRefusal({ ...base, governing_revision_digest: genesisDigest, effective_at: "2026-08-25T12:00:00Z" }, view.input).ok);
  assert.ok(terminationRefusal({ ...base, governing_revision_digest: successorDigest, effective_at: "2026-08-25T12:00:01Z" }, view.input).ok);
});

test("terminationRefusal: a stale termination (non-governing revision) is refused", () => {
  const view = corpusCase("governing_revision.json", "governing-revision-start-inclusive-precedence");
  const refusal = terminationRefusal({
    charter_id: "sha-256:j9vaSLLwxMwF1zzLniUdZwUUAB6aTGEvwMRzP526s3o",
    governing_revision_digest: "sha-256:j9vaSLLwxMwF1zzLniUdZwUUAB6aTGEvwMRzP526s3o",
    party_role: "issuer",
    party_descriptor_digest: "sha-256:1ynn3VZQs_pAZVjrnDn-DzEUMc8gJV0FMFV3SFONZIU",
    reason_code: "mutual",
    effective_at: "2026-08-25T12:00:01Z", // the successor governs now
  }, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("terminationRefusal: an unlisted reason is refused", () => {
  const view = corpusCase("governing_revision.json", "governing-revision-start-inclusive-precedence");
  const refusal = terminationRefusal({
    charter_id: "sha-256:kkvNA6mMTl4q91lBYkjT3lIhMfbNeyuMKh5CePdOmWI",
    governing_revision_digest: "sha-256:kkvNA6mMTl4q91lBYkjT3lIhMfbNeyuMKh5CePdOmWI",
    party_role: "issuer",
    party_descriptor_digest: "sha-256:1ynn3VZQs_pAZVjrnDn-DzEUMc8gJV0FMFV3SFONZIU",
    reason_code: "not-in-charter",
    effective_at: "2026-08-25T12:00:01Z",
  }, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("terminationRefusal: malformed effective_at keeps the producer code", () => {
  const view = corpusCase("governing_revision.json", "governing-revision-start-inclusive-precedence");
  const refusal = terminationRefusal({
    charter_id: "sha-256:kkvNA6mMTl4q91lBYkjT3lIhMfbNeyuMKh5CePdOmWI",
    governing_revision_digest: "sha-256:kkvNA6mMTl4q91lBYkjT3lIhMfbNeyuMKh5CePdOmWI",
    party_role: "issuer",
    party_descriptor_digest: "sha-256:1ynn3VZQs_pAZVjrnDn-DzEUMc8gJV0FMFV3SFONZIU",
    reason_code: "mutual",
    effective_at: "not-a-timestamp",
  }, view.input);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_input_invalid");
});

test("acceptanceRefusal: R2 fires even when ancestry coverage would hold", () => {
  // Same fork view with sibling bcE's acceptor acceptance removed: kkvNA6mM
  // is now the unique covered head (R3 clean), but bcE's issuer acceptance
  // still occupies the (charter, n=2) coordinate with a different digest.
  const view = corpusCase("chain-verify.json", "chain-accepted-sibling-fork");
  const pruned = { ...view.input, acceptances: view.input.acceptances.filter((_: any, index: number) => index !== 5) };
  const claims = acceptanceClaims(view, 2);
  const refusal = acceptanceRefusal(claims, pruned);
  assert.ok(refusal.ok === false);
  assert.equal(refusal.code, "signing_refused");
});

test("acceptanceRefusal: the first acceptance into an empty view is clean", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const empty = { ...view.input, acceptances: [] };
  const refusal = acceptanceRefusal(acceptanceClaims(view, 0), empty);
  assert.ok(refusal.ok);
});
