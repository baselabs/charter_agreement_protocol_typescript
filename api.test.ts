// CAP never authorizes.
//
// Artifact-level API tests (0.2.0): the corpus fixtures supply real signed
// artifacts; each verify function must go green on the valid fixture and
// red on a tampered one.
import test from "node:test";
import * as publicApi from "./index.ts";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acceptanceRefusal,
  algorithmRegistryDigest,
  capabilities,
  acceptanceSigningInput,
  assembleCompact,
  canonical,
  checkSigningClaims,
  decodeArtifact,
  decodeCharterRevision,
  verifyDescriptorChain,
  decodePartyDescriptor,
  descriptorSigningInput,
  encodeBase64url,
  governingRevision,
  receiptSigningInput,
  reportFor,
  revisionDigest,
  terminationRefusal,
  terminationSigningInput,
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  verifySignature,
  verifyTermination,
  type SigningInput,
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

test("the refusal surface fails closed on a non-object view", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const claims = acceptanceClaims(view, 0);
  for (const bad of [undefined, null, "not-an-object", 42]) {
    const acceptance = acceptanceRefusal(claims, bad as any);
    assert.ok(acceptance.ok === false);
    assert.equal(acceptance.code, "signing_input_invalid");
    const termination = terminationRefusal({
      charter_id: claims.charter_id,
      governing_revision_digest: claims.revision_digest,
      party_descriptor_digest: claims.party_descriptor_digest,
      party_role: claims.party_role,
      reason_code: "mutual",
      effective_at: "2026-08-25T12:00:00Z",
    }, bad as any);
    assert.ok(termination.ok === false);
    assert.equal(termination.code, "signing_input_invalid");
  }
});

// ---------------------------------------------------------------------------
// The producer build gate's claims half (the reference decode_for_signing):
// the schema checks that depend only on the claims, shared with the verify
// paths. Holder-side signers run this before any key is used so malformed
// claims never burn a key operation.
// ---------------------------------------------------------------------------

const receiptFixture = {
  protocol_revision: 2,
  charter_id: "sha-256:" + "A".repeat(43),
  revision_number: 2,
  revision_digest: "sha-256:" + Buffer.alloc(32, 1).toString("base64url"),
  issuing_party_role: "issuer",
  agent_party_role: "agent",
  deployment_digest: "sha-256:" + Buffer.alloc(32, 2).toString("base64url"),
  grant: { scheme: "bap", id: "g-1", grant_digest: "sha-256:" + Buffer.alloc(32, 3).toString("base64url") },
  invocation_id: "inv-1",
  decision: "accepted",
  outcome: "effect_committed",
  occurred_at: "2026-08-25T12:00:01Z",
  recorded_at: "2026-08-25T12:00:02Z",
  extensions: { critical: {}, optional: {} },
};

const gateCode = (result: { ok: true } | { ok: false; code: string }): string => {
  if (result.ok) throw new Error("expected a rejected claims gate");
  return result.code;
};

test("checkSigningClaims: each kind green on well-formed claims", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const acceptance = acceptanceClaims(view, 0);
  assert.ok(checkSigningClaims("acceptance", acceptance).ok);
  assert.ok(checkSigningClaims("receipt", receiptFixture).ok);
  assert.ok(checkSigningClaims("termination", {
    protocol_revision: 2,
    charter_id: acceptance.charter_id,
    governing_revision_digest: acceptance.revision_digest,
    party_descriptor_digest: acceptance.party_descriptor_digest,
    party_role: acceptance.party_role,
    reason_code: "mutual",
    issued_at: "2026-08-25T14:00:00Z",
    effective_at: "2026-08-25T15:00:00Z",
  }).ok);
});

test("checkSigningClaims: descriptor schema reds keep the codec codes", () => {
  const genesis = JSON.parse(Buffer.from(
    corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input.compact.split(".")[1], "base64url",
  ).toString("utf8"));
  assert.ok(checkSigningClaims("descriptor", genesis).ok);
  assert.equal(gateCode(checkSigningClaims("descriptor", { ...genesis, prev_descriptor_digest: "sha-256:x" })), "descriptor_invalid");
  assert.equal(gateCode(checkSigningClaims("descriptor", { ...genesis, effective_from: "not-a-timestamp" })), "timestamp_invalid");
  assert.equal(gateCode(checkSigningClaims("descriptor", { ...genesis, verification_keys: [] })), "nested_invalid");
});

test("checkSigningClaims: acceptance and termination schema reds keep the codec codes", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const acceptance = acceptanceClaims(view, 0);
  // n>1 without a predecessor digest
  assert.equal(gateCode(checkSigningClaims("acceptance", { ...acceptance, revision_number: 2 })), "acceptance_invalid");
  assert.equal(gateCode(checkSigningClaims("acceptance", { ...acceptance, accepted_at: "yesterday" })), "timestamp_invalid");
  assert.equal(gateCode(checkSigningClaims("termination", {
    protocol_revision: 2, charter_id: acceptance.charter_id,
    governing_revision_digest: acceptance.revision_digest,
    party_descriptor_digest: acceptance.party_descriptor_digest, party_role: "issuer",
    reason_code: "mutual", issued_at: "2026-08-25T16:00:00Z",
    effective_at: "2026-08-25T15:00:00Z",
  })), "termination_invalid");
});

test("checkSigningClaims: receipt schema reds keep the codec codes", () => {
  assert.equal(gateCode(checkSigningClaims("receipt", { ...receiptFixture, grant: { scheme: "bap", id: "g-1" } })), "receipt_invalid");
  assert.equal(gateCode(checkSigningClaims("receipt", { ...receiptFixture, recorded_at: "2026-08-25T12:00:00Z", occurred_at: "2026-08-25T12:00:01Z" })), "receipt_invalid");
  assert.equal(gateCode(checkSigningClaims("receipt", { ...receiptFixture, decision: "rejected", outcome: "effect_committed" })), "cross_field_invalid");
  assert.equal(gateCode(checkSigningClaims("receipt", "not-an-object" as never)), "invalid_type");
  assert.equal(gateCode(checkSigningClaims("unknown-kind" as never, receiptFixture)), "invalid_type");
});

test("the refusal boundary never throws on partial object views", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const claims = acceptanceClaims(view, 0);
  // Missing artifact lists fail with a typed result.
  const partial = { revisions: view.input.revisions, descriptors: view.input.descriptors };
  assert.deepEqual(acceptanceRefusal(claims, partial), { ok: false, code: "invalid_type" });
  // A revision text that is valid JSON but not an object: typed failure.
  const notObject = { ...view.input, revisions: ["null"] };
  const acceptance = acceptanceRefusal(claims, notObject);
  assert.ok(acceptance.ok === false);
  assert.equal(acceptance.code, "invalid_type");
  const termination = terminationRefusal({
    charter_id: claims.charter_id,
    governing_revision_digest: claims.revision_digest,
    party_descriptor_digest: claims.party_descriptor_digest,
    party_role: claims.party_role,
    reason_code: "mutual",
    effective_at: "2026-08-25T12:00:00Z",
  }, notObject);
  assert.ok(termination.ok === false);
  assert.equal(termination.code, "invalid_type");
});

test("checkSigningClaims never throws on malformed verification key entries", () => {
  const genesis = JSON.parse(Buffer.from(
    corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input.compact.split(".")[1], "base64url",
  ).toString("utf8"));
  assert.equal(gateCode(checkSigningClaims("descriptor", { ...genesis, verification_keys: [null] })), "nested_invalid");
  assert.equal(gateCode(checkSigningClaims("descriptor", { ...genesis, verification_keys: [{ algorithm: "Ed25519", public_key: 123 }] })), "nested_invalid");
});

// ---------------------------------------------------------------------------
// The producer surface: byte-exact signing inputs from the public canonical
// primitives, the reference build ordering, assemble, and the query/decode
// exports cross-checked against the certified corpus through independent
// paths.
// ---------------------------------------------------------------------------

const KID = "producer-key-001";

function expectedSegments(typ: string, alg: string, kid: string, claims: Record<string, any>) {
  const payloadSegment = encodeBase64url(Buffer.from(canonical(claims as never), "utf8"));
  const protectedSegment = encodeBase64url(
    Buffer.from(canonical({ alg, kid, typ } as never), "utf8"),
  );
  return { payloadSegment, protectedSegment };
}

test("producers mint byte-exact segments for both emission pairs", () => {
  const descriptorClaims = {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [{ key_id: KID, algorithm: "Ed25519", public_key: Buffer.alloc(32, 3).toString("base64url"), status: "active" }],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };
  const receiptClaims = {
    protocol_revision: 3,
    charter_id: "sha-256:" + "A".repeat(43),
    revision_number: 1,
    revision_digest: "sha-256:" + Buffer.alloc(32, 1).toString("base64url"),
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: "sha-256:" + Buffer.alloc(32, 2).toString("base64url"),
    grant: { scheme: "bap", id: "g", grant_digest: "sha-256:" + Buffer.alloc(32, 3).toString("base64url") },
    invocation_id: "inv",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T12:00:01Z",
    recorded_at: "2026-08-25T12:00:02Z",
    extensions: { critical: {}, optional: {} },
  };

  const descriptor = descriptorSigningInput(KID, descriptorClaims);
  assert.ok(descriptor.ok);
  const expectedDescriptor = expectedSegments("cap+party", "Ed25519", KID, descriptorClaims);
  assert.equal(descriptor.input.protectedSegment, expectedDescriptor.protectedSegment);
  assert.equal(descriptor.input.payloadSegment, expectedDescriptor.payloadSegment);
  assert.equal(descriptor.input.message.toString("utf8"), `${expectedDescriptor.protectedSegment}.${expectedDescriptor.payloadSegment}`);

  const receipt = receiptSigningInput(KID, receiptClaims, "ML-DSA-65");
  assert.ok(receipt.ok);
  assert.equal(receipt.input.alg, "ML-DSA-65");
  const expectedReceipt = expectedSegments("cap+receipt", "ML-DSA-65", KID, receiptClaims);
  assert.equal(receipt.input.protectedSegment, expectedReceipt.protectedSegment);
  assert.equal(receipt.input.payloadSegment, expectedReceipt.payloadSegment);
});

test("producers reject bad input at the reference precedence", () => {
  const claims = { protocol_revision: 2 };
  const producerCode = (result: { ok: true; input: SigningInput } | { ok: false; code: string }): string => {
    if (result.ok) throw new Error("expected a producer rejection");
    return result.code;
  };
  assert.equal(producerCode(descriptorSigningInput(KID, "not-an-object" as never)), "signing_input_invalid");
  assert.equal(producerCode(descriptorSigningInput(KID, { protocol_revision: 3 })), "signing_input_invalid");
  assert.equal(producerCode(descriptorSigningInput(KID, claims, "EdDSA")), "signing_input_invalid");
  assert.equal(producerCode(descriptorSigningInput("bad kid!", claims)), "signing_input_invalid");
});

test("assembleCompact enforces the registry row and re-decodes the framing", () => {
  const claims = {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [{ key_id: KID, algorithm: "Ed25519", public_key: Buffer.alloc(32, 3).toString("base64url"), status: "active" }],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };
  const producer = descriptorSigningInput(KID, claims);
  assert.ok(producer.ok);
  const input = (producer as { input: SigningInput }).input;
  const short = assembleCompact(input, Buffer.alloc(63));
  assert.ok(short.ok === false && short.code === "signature_invalid");
  const assembled = assembleCompact(input, Buffer.alloc(64, 7));
  assert.ok(assembled.ok);
  const decoded = decodeArtifact(assembled.compact);
  assert.ok(decoded.ok);
  assert.equal(decoded.facts.typ, "cap+party");
});

test("governingRevision matches the certified precedence surface", () => {
  const view = corpusCase("governing_revision.json", "governing-revision-start-inclusive-precedence");
  for (const query of view.input.queries) {
    const result = governingRevision(view.input, query.at);
    assert.ok(result.ok, JSON.stringify(result));
    assert.equal(result.governing, query.governing_revision);
  }
  const badAt = governingRevision(view.input, "not-a-timestamp");
  assert.ok(badAt.ok === false);
  const badView = governingRevision({}, "2026-08-25T12:00:00Z");
  assert.ok(badView.ok === false);
  if (!badAt.ok && !badView.ok) {
    assert.equal(badAt.code, "invalid_type");
    assert.equal(badView.code, "invalid_type");
  }
});

test("revision and descriptor digests cross-check through independent paths", () => {
  const chain = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const chainFacts = verifyChain(chain.input);
  assert.ok(chainFacts.ok);
  const revisions = chainFacts.facts.revisions as { digest: string; bytes: Buffer }[];
  for (const one of revisions) {
    const digest = revisionDigest(one.bytes.toString("utf8"));
    assert.ok(digest.ok);
    assert.equal(digest.digest, one.digest);
  }

  const descriptor = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid");
  const verified = verifyDescriptor(descriptor.input.compact);
  assert.ok(verified.ok);
  const decoded = decodePartyDescriptor(descriptor.input.compact);
  assert.ok(decoded.ok);
  assert.equal(decoded.digest, verified.facts.descriptor_digest);
  assert.deepEqual(decoded.claims.verification_keys, JSON.parse(
    Buffer.from(descriptor.input.compact.split(".")[1], "base64url").toString("utf8"),
  ).verification_keys);
});

test("the set-aware producers: build first, then R1-R3 at the reference ordering", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const chainFacts = verifyChain(view.input);
  assert.ok(chainFacts.ok);
  const revision = (chainFacts.facts.revisions as { digest: string; value: AnyRecordAtLeast }[])[0];
  const acceptance = acceptanceClaims(view, 0);
  // A claims set bound to the view's genesis at the emission revision.
  const bound = {
    protocol_revision: 2,
    accepted_at: acceptance.accepted_at,
    charter_id: revision.digest,
    party_descriptor_digest: acceptance.party_descriptor_digest,
    party_role: acceptance.party_role,
    revision_digest: revision.digest,
    revision_number: revision.value.revision_number,
  };
  const produced = acceptanceSigningInput("producer-key-001", bound, view.input);
  assert.ok(produced.ok, JSON.stringify(produced));
  assert.ok(produced.input.message.toString("utf8").startsWith(produced.input.protectedSegment));

  // R1 red: an unbound digest refuses AFTER a successful build.
  const refused = acceptanceSigningInput("producer-key-001", { ...bound, revision_digest: "sha-256:" + "0".repeat(43) }, view.input);
  assert.ok(refused.ok === false && refused.code === "signing_refused");

  // Build-before-set ordering: claims schema defect + broken view reports
  // the PRODUCER code, not the chain code.
  const both = acceptanceSigningInput("producer-key-001", { ...bound, revision_number: 2 }, { ...view.input, acceptances: ["not-a-jws"] });
  assert.ok(both.ok === false && both.code === "signing_input_invalid");

  // Malformed view alone: the typed chain code.
  const badView = acceptanceSigningInput("producer-key-001", bound, { ...view.input, acceptances: ["not-a-jws"] });
  assert.ok(badView.ok === false && badView.code === "chain_invalid");

  const termination = terminationSigningInput("producer-key-001", {
    protocol_revision: 2,
    charter_id: revision.digest,
    governing_revision_digest: revision.digest,
    party_descriptor_digest: acceptance.party_descriptor_digest,
    party_role: acceptance.party_role,
    reason_code: "mutual",
    issued_at: "2026-08-25T14:00:00Z",
    effective_at: "2026-08-25T15:00:00Z",
  }, view.input);
  assert.ok(termination.ok, JSON.stringify(termination));
  const stale = terminationSigningInput("producer-key-001", {
    protocol_revision: 2,
    charter_id: revision.digest,
    governing_revision_digest: "sha-256:" + "0".repeat(43),
    party_descriptor_digest: acceptance.party_descriptor_digest,
    party_role: acceptance.party_role,
    reason_code: "mutual",
    issued_at: "2026-08-25T14:00:00Z",
    effective_at: "2026-08-25T15:00:00Z",
  }, view.input);
  assert.ok(stale.ok === false && stale.code === "signing_refused");
});

type AnyRecordAtLeast = Record<string, any>;

test("the new surface never throws: a malformed-input sweep", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const acceptance = acceptanceClaims(view, 0);
  const battery: [string, () => { ok: true } | { ok: false; code: string }][] = [
    ["descriptor claims NaN", () => descriptorSigningInput("k", { ...acceptance, revision_number: NaN })],
    ["descriptor claims undefined member", () => descriptorSigningInput("k", { ...acceptance, extra: undefined })],
    ["descriptor claims Infinity", () => descriptorSigningInput("k", { ...acceptance, accepted_at: Infinity })],
    ["governing null view", () => governingRevision(null as never, "2026-08-25T12:00:00Z")],
    ["governing undefined view", () => governingRevision(undefined as never, "2026-08-25T12:00:00Z")],
    ["governing bad instant", () => governingRevision(view.input, 42 as never)],
    ["assemble no message", () => assembleCompact({ alg: "Ed25519", protectedSegment: "a", payloadSegment: "b", message: undefined as never }, Buffer.alloc(64))],
    ["assemble tampered segments", () => assembleCompact({ alg: "Ed25519", protectedSegment: "tampered", payloadSegment: "b", message: descriptorSigningInput("k", acceptance).ok ? (descriptorSigningInput("k", acceptance) as { input: { message: Buffer } }).input.message : Buffer.alloc(0) }, Buffer.alloc(64))],
    ["decode descriptor wrong typ", () => decodePartyDescriptor(view.input.acceptances[0])],
    ["decode descriptor null", () => decodePartyDescriptor(null)],
    ["revision digest null", () => revisionDigest(null)],
    ["set-aware null view", () => acceptanceSigningInput("k", acceptance, null as never)],
  ];
  for (const [name, probe] of battery) {
    const result = probe();
    assert.ok(result.ok === false, name + " should reject");
    assert.ok(typeof result.code === "string", name + " carries the typed code");
  }
});

test("decodePartyDescriptor binds the protected header typ", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid");
  const wrongKind = decodePartyDescriptor(view.input.acceptances[0]);
  assert.ok(wrongKind.ok === false);
  assert.equal(wrongKind.code, "descriptor_invalid");
});

test("capabilities reports a verifiable verdict per registry row", () => {
  const report = capabilities();
  const names = new Set(report.algorithms.map((row) => row.name));
  for (const expected of ["EdDSA", "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) {
    assert.ok(names.has(expected), `missing ${expected}`);
  }
  // This suite runs on a capable Node (>= 24.8): every row verifies.
  for (const row of report.algorithms) {
    assert.equal(row.verifiable, true, `${row.name} should verify on this runtime`);
  }
  assert.ok(typeof report.linkedCrypto === "string");
});

test("algorithmRegistryDigest equals the reference identity", () => {
  assert.equal(
    algorithmRegistryDigest(),
    "sha-256:bPZY8aw4NCp3kMt4bZAACFZIcBctGGuTSa6avESQlrM",
  );
});

test("T1 termination closes governing at its instant and later", () => {
  const fixture = corpusCase("governing_revision.json", "governing-revision-closed-by-termination");
  for (const [i, query] of fixture.input.queries.entries()) {
    const actual = governingRevision(fixture.input, query.at);
    assert.ok(actual.ok);
    assert.equal(actual.governing, fixture.expect.output.governing_revisions[i]);
  }
  const chain = verifyChain(fixture.input);
  assert.ok(chain.ok);
  assert.equal(chain.facts.terminations.length, 1);
});

test("T1 receipt after termination reports a governing mismatch", () => {
  const fixture = corpusCase("receipt-verify.json", "receipt-after-termination-mismatch");
  const actual = verifyReceipt(fixture.input.compact, fixture.input.chain);
  assert.ok(actual.ok);
  assert.equal(actual.facts.governing_match, "mismatch");
});


function copyWithPath(source: Record<string, any>, path: string, value: unknown, remove = false) {
  const copy = structuredClone(source);
  const parts = path.split(".");
  let parent = copy;
  for (const part of parts.slice(0, -1)) parent = parent[part];
  if (remove) delete parent[parts.at(-1)!];
  else parent[parts.at(-1)!] = value;
  return copy;
}

const sampleDigest = "sha-256:" + "A".repeat(43);
const revisionRules: [string, unknown, unknown][] = [
  ["protocol_revision", "1", 3], ["charter_id", 1, "bad"],
  ["revision_number", "1", 0], ["prev_revision_digest", 1, "bad"],
  ["parties", {}, undefined], ["legal_text", 1, undefined],
  ["precedence_declaration", 1, "unlisted"], ["attribution_declaration", 1, undefined],
  ["effective_from", 1, ""], ["effective_until", 1, "x".repeat(65)],
  ["termination_rules", 1, undefined], ["abp_bindings", {}, undefined],
  ["receipt_profile", 1, "bad"], ["supersedes", {}, undefined], ["extensions", 1, undefined],
  ["parties.0.party_descriptor_digest", 1, "bad"], ["parties.0.role", 1, ""],
  ["legal_text.content_digest", 1, "bad"], ["legal_text.media_type", 1, ""],
  ["legal_text.uri_hint", 1, "x".repeat(2049)],
  ["attribution_declaration.basis", 1, "unlisted"], ["attribution_declaration.detail_digest", 1, "bad"],
  ["termination_rules.reason_codes", {}, undefined],
  ["abp_bindings.0.party_role", 1, ""], ["abp_bindings.0.blueprint_id", 1, "bad"],
  ["abp_bindings.0.release_number", "1", 0], ["abp_bindings.0.content_digest", 1, "bad"],
  ["abp_bindings.0.deployment_digest", 1, "bad"],
];

test("T2 revision decode uses strict JSON and exact canonical bytes", () => {
  const text = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input.revisions[0];
  assert.deepEqual(decodeCharterRevision(" " + text), { ok: false, code: "non_canonical_bytes" });
  assert.deepEqual(decodeCharterRevision(text.replace('"protocol_revision":1', '"protocol_revision":1,"protocol_revision":1')), { ok: false, code: "duplicate_member" });
});

test("T2 revision schema covers every declared member rule", async (t) => {
  const base = JSON.parse(corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input.revisions[0]);
  for (const [path, wrongType, wrongConstraint] of revisionRules) {
    const nested = path.includes(".");
    await t.test(path + " type", () => {
      assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, wrongType))), { ok: false, code: nested ? "nested_invalid" : "invalid_type" });
    });
    if (wrongConstraint !== undefined) await t.test(path + " constraint", () => {
      assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, wrongConstraint))), { ok: false, code: nested ? "nested_invalid" : "constraint_violation" });
    });
  }
  const required = ["protocol_revision", "revision_number", "parties", "legal_text", "precedence_declaration", "attribution_declaration", "effective_from", "termination_rules", "abp_bindings", "receipt_profile", "extensions", "parties.0.party_descriptor_digest", "parties.0.role", "legal_text.content_digest", "legal_text.media_type", "attribution_declaration.basis", "termination_rules.reason_codes", "abp_bindings.0.party_role", "abp_bindings.0.blueprint_id", "abp_bindings.0.release_number", "abp_bindings.0.content_digest", "abp_bindings.0.deployment_digest"];
  for (const path of required) await t.test(path + " required", () => {
    assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, undefined, true))), { ok: false, code: path.includes(".") ? "nested_invalid" : "missing_required" });
  });
  const probes: [string, unknown, string][] = [
    ["parties", base.parties.slice(0, 1), "cardinality_violation"],
    ["parties", [...base.parties, base.parties[0]], "cardinality_violation"],
    ["abp_bindings", Array(65).fill(base.abp_bindings[0]), "cardinality_violation"],
    ["supersedes", Array(9).fill(sampleDigest), "cardinality_violation"],
    ["termination_rules.reason_codes", [], "nested_invalid"],
    ["termination_rules.reason_codes", Array(65).fill("x"), "nested_invalid"],
    ["termination_rules.reason_codes", ["x", "x"], "revision_invalid"],
    ["termination_rules.reason_codes", [1], "revision_invalid"],
    ["termination_rules.reason_codes", ["x".repeat(129)], "revision_invalid"],
    ["effective_from", "2026-02-30T12:00:00Z", "timestamp_invalid"],
    ["effective_until", base.effective_from, "revision_invalid"],
    ["parties.1.role", base.parties[0].role, "revision_invalid"],
    ["abp_bindings.0.party_role", "unlisted", "revision_invalid"],
    ["receipt_profile", "unlisted/profile", "revision_invalid"],
    ["supersedes", [1], "revision_invalid"],
    ["revision_number", 1.5, "invalid_type"],
  ];
  for (const [path, value, code] of probes) await t.test(path + " local rule " + code, () => {
    assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, value))), { ok: false, code });
  });
  for (const path of ["extra", "parties.0.extra", "legal_text.extra", "attribution_declaration.extra", "termination_rules.extra", "abp_bindings.0.extra"]) await t.test(path + " closed", () => {
    assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, true))), { ok: false, code: path.includes(".") ? "nested_invalid" : "unknown_member" });
  });
  assert.ok(decodeCharterRevision(canonical(base)).ok);
});

test("T4 descriptor histories reject mixed parties and unbound successors", () => {
  for (const id of ["descriptor-chain-two-party-set", "descriptor-chain-successor-without-party"]) {
    const fixture = corpusCase("descriptor_chain-verify.json", id);
    assert.deepEqual(verifyDescriptorChain(fixture.input.compacts), { ok: false, code: "descriptor_chain_invalid" });
  }
});

test("T4 a descriptor fork only contests its own party", () => {
  const base = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  const fork = corpusCase("descriptor_chain-verify.json", "descriptor-chain-signed-sibling-fork").input.compacts;
  const forkRoot = JSON.parse(Buffer.from(fork[0].split(".")[1], "base64url").toString());
  const rootDigest = decodePartyDescriptor(fork[0]);
  assert.ok(rootDigest.ok);
  const others = base.descriptors.filter((compact: string) => {
    const descriptor = decodePartyDescriptor(compact);
    return descriptor.ok && descriptor.digest !== rootDigest.digest;
  });
  const view = verifyChain({ ...base, descriptors: [...fork, ...others] });
  assert.ok(view.ok, JSON.stringify(view));
  for (const compact of others) {
    const descriptor = decodePartyDescriptor(compact);
    assert.ok(descriptor.ok);
    assert.equal(view.facts.descriptors.positions[descriptor.digest], "head");
  }
  assert.equal(forkRoot.descriptor_number, 1);
});

test("T4 a chain view requires exactly the two revision party histories", () => {
  const base = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  assert.deepEqual(verifyChain({ ...base, acceptances: [], descriptors: base.descriptors.slice(0, 1) }), { ok: false, code: "chain_invalid" });
  const revision = JSON.parse(base.revisions[0]);
  revision.parties[1].party_descriptor_digest = sampleDigest;
  assert.deepEqual(verifyChain({ ...base, revisions: [canonical(revision)], acceptances: [] }), { ok: false, code: "chain_invalid" });
});

function replaceClaims(compact: string, change: (claims: Record<string, any>) => Record<string, any>): string {
  const [header, payload, signature] = compact.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  return `${header}.${Buffer.from(canonical(change(claims))).toString("base64url")}.${signature}`;
}

test("T3 signed claims reject unknown top-level members in all four kinds", async (t) => {
  await t.test("descriptor", () => {
    const f = corpusCase("party_descriptor-verify.json", "descriptor-claims-unknown-member");
    assert.deepEqual(verifyDescriptor(f.input.compact), { ok: false, code: "unknown_member" });
  });
  for (const [kind, file, id, verify] of [
    ["acceptance", "acceptance-verify.json", "acceptance-claims-unknown-member", verifyAcceptance],
    ["termination", "termination-verify.json", "termination-claims-unknown-member", verifyTermination],
  ] as const) await t.test(kind, () => {
    const f = corpusCase(file, id);
    assert.deepEqual(verify(f.input.compact, f.input.revision_text, f.input.descriptor_compacts), { ok: false, code: "unknown_member" });
  });
  await t.test("receipt", () => {
    const f = corpusCase("receipt-verify.json", "receipt-claims-unknown-member");
    assert.deepEqual(verifyReceipt(f.input.compact, f.input.chain), { ok: false, code: "unknown_member" });
  });
});

test("T3 every closed nested claims object rejects extra members", async (t) => {
  const descriptor = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input.compact;
  for (const [name, change, code] of [
    ["verification key", (c: Record<string, any>) => copyWithPath(c, "verification_keys.0.extra", true), "nested_invalid"],
    ["attestation hint", (c: Record<string, any>) => ({ ...c, attestation_hints: [{ kind: "sample", uri: "https://example.test", extra: true }] }), "nested_invalid"],
    ["descriptor extensions", (c: Record<string, any>) => copyWithPath(c, "extensions.extra", true), "unknown_member"],
  ] as const) await t.test(name, () => {
    assert.deepEqual(verifyDescriptor(replaceClaims(descriptor, change)), { ok: false, code });
  });
  const receipt = corpusCase("receipt-verify.json", "receipt-signed-governing-match");
  for (const [path, code] of [["grant.extra", "nested_invalid"], ["extensions.extra", "unknown_member"]]) await t.test("receipt " + path.split(".")[1] + " object " + code, () => {
    assert.deepEqual(verifyReceipt(replaceClaims(receipt.input.compact, (c) => copyWithPath(c, path, true)), receipt.input.chain), { ok: false, code });
  });
});

test("T8 indexed revision terms validate all fields and nested rules", async (t) => {
  const revision = JSON.parse(corpusCase("charter_revision-decode.json", "revision-indexed-price-valid").input.text);
  const body = revision.extensions.critical["com.example/pricing-indexed"];
  const rules: [string, unknown, unknown][] = [
    ["currency", 1, "ZZZ"], ["base_amount_minor", "1", -1], ["index", 1, undefined],
    ["formula", 1, "unlisted"], ["spread_bps", "1", 10001],
    ["floor_amount_minor", "1", -1], ["cap_amount_minor", "1", -1], ["tolerance_bps", "1", 10001],
    ["index.series_document_digest", 1, "bad"], ["index.series_id", 1, ""], ["index.observation_lag_days", "1", 91],
  ];
  const verifyBody = (changed: Record<string, any>) => decodeCharterRevision(canonical({ ...revision, extensions: { critical: { "com.example/pricing-indexed": changed }, optional: {} } }));
  for (const [path, wrongType, wrongConstraint] of rules) {
    await t.test(path + " type", () => assert.deepEqual(verifyBody(copyWithPath(body, path, wrongType)), { ok: false, code: path.includes(".") ? "nested_invalid" : "invalid_type" }));
    if (wrongConstraint !== undefined) await t.test(path + " constraint", () => assert.deepEqual(verifyBody(copyWithPath(body, path, wrongConstraint)), { ok: false, code: path.includes(".") ? "nested_invalid" : "constraint_violation" }));
    if (!["floor_amount_minor", "cap_amount_minor"].includes(path)) await t.test(path + " required", () => assert.deepEqual(verifyBody(copyWithPath(body, path, undefined, true)), { ok: false, code: path.includes(".") ? "nested_invalid" : "missing_required" }));
  }
  await t.test("ordered bounds", () => assert.deepEqual(verifyBody({ ...body, floor_amount_minor: 2, cap_amount_minor: 1 }), { ok: false, code: "cross_field_invalid" }));
  await t.test("closed terms", () => assert.deepEqual(verifyBody({ ...body, extra: true }), { ok: false, code: "unknown_member" }));
  await t.test("closed index", () => assert.deepEqual(verifyBody(copyWithPath(body, "index.extra", true)), { ok: false, code: "nested_invalid" }));
  assert.ok(verifyBody(body).ok);
});

test("T8 indexed receipt observation validates its full closed body", async (t) => {
  const fixture = corpusCase("receipt-verify.json", "receipt-indexed-price-observation-quarantine");
  const claims = JSON.parse(Buffer.from(fixture.input.compact.split(".")[1], "base64url").toString());
  const body = claims.extensions.optional["com.example/pricing-indexed-observation"];
  const verifyBody = (changed: Record<string, any>) => verifyReceipt(replaceClaims(fixture.input.compact, (c) => ({ ...c, extensions: { ...c.extensions, optional: { ...c.extensions.optional, "com.example/pricing-indexed-observation": changed } } })), fixture.input.chain);
  for (const [name, value, code] of [
    ["observed_index_digest", 1, "invalid_type"], ["observed_index_digest", "bad", "constraint_violation"],
    ["observation_instant", 1, "invalid_type"], ["observation_instant", "yesterday", "constraint_violation"],
    ["computed_amount_minor", "1", "invalid_type"], ["computed_amount_minor", -1, "constraint_violation"],
    ["extra", true, "unknown_member"],
  ] as const) await t.test(name + " " + code, () => assert.deepEqual(verifyBody({ ...body, [name]: value }), { ok: false, code }));
  for (const name of ["observed_index_digest", "observation_instant", "computed_amount_minor"]) await t.test(name + " required", () => assert.deepEqual(verifyBody(copyWithPath(body, name, undefined, true)), { ok: false, code: "missing_required" }));
  assert.ok(verifyReceipt(fixture.input.compact, fixture.input.chain).ok);
});

const withOptions = (fn: Function, args: unknown[], options: unknown) => fn(...args, options);
const classicalProfile = { algorithms: ["Ed25519"], revisions: { min: 1, max: 3 } };

function optionProbes(): [string, Function, unknown[]][] {
  const descriptor = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input;
  const acceptance = corpusCase("acceptance-verify.json", "acceptance-valid").input;
  const termination = corpusCase("termination-verify.json", "termination-valid").input;
  const receipt = corpusCase("receipt-verify.json", "receipt-signed-governing-match").input;
  const chain = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  return [
    ["descriptor", verifyDescriptor, [descriptor.compact, null]],
    ["descriptor history", verifyDescriptorChain, [[descriptor.compact]]],
    ["acceptance", verifyAcceptance, [acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts]],
    ["termination", verifyTermination, [termination.compact, termination.revision_text, termination.descriptor_compacts]],
    ["receipt", verifyReceipt, [receipt.compact, receipt.chain]],
    ["chain", verifyChain, [chain]],
  ];
}

test("T5 all public artifact verifiers apply trailing profiles", async (t) => {
  for (const [name, fn, args] of optionProbes()) await t.test(name, () => {
    assert.deepEqual(withOptions(fn, args, { profile: classicalProfile }), { ok: false, code: "algorithm_outside_profile" });
    assert.deepEqual(withOptions(fn, args, { profile: { algorithms: [], revisions: { min: 1, max: 3 } } }), { ok: false, code: "invalid_profile" });
    assert.ok(withOptions(fn, args, {}).ok);
  });
});

test("T5 profile validation is closed and admission follows local checks", () => {
  const descriptor = optionProbes()[0][2][0] as string;
  for (const profile of [null, [], { algorithms: ["EdDSA", "EdDSA"] }, { algorithms: ["unlisted"] }, { algorithms: 1 }, { revisions: { min: 3, max: 1 } }, { revisions: { min: 0, max: 3 } }, { extra: true }]) {
    assert.deepEqual(withOptions(verifyDescriptor, [descriptor, null], { profile }), { ok: false, code: "invalid_profile" });
  }
  const badSchema = replaceClaims(descriptor, (c) => ({ ...c, extra: true }));
  assert.deepEqual(withOptions(verifyDescriptor, [badSchema, null], { profile: classicalProfile }), { ok: false, code: "unknown_member" });
  assert.deepEqual(withOptions(verifyDescriptor, [descriptor, null], { profile: { algorithms: ["EdDSA"], revisions: { min: 2, max: 3 } } }), { ok: false, code: "revision_outside_profile" });
  const acceptance = corpusCase("acceptance-verify.json", "acceptance-claim-mismatch").input;
  assert.deepEqual(withOptions(verifyAcceptance, [acceptance.compact, acceptance.revision_text, acceptance.descriptor_compacts], { profile: classicalProfile }), { ok: false, code: "algorithm_outside_profile" });
});

test("T6 all public artifact verifiers validate and enforce limits", async (t) => {
  for (const [name, fn, args] of optionProbes()) await t.test(name, () => {
    assert.deepEqual(withOptions(fn, args, { limits: { max_bytes: 0 } }), { ok: false, code: name === "descriptor history" ? "descriptor_chain_invalid" : "limit_exceeded" });
    for (const limits of [null, [], { extra: 1 }, { max_depth: -1 }, { max_depth: 1.5 }, { max_depth: 129 }, { max_bytes: Infinity }]) {
      assert.deepEqual(withOptions(fn, args, { limits }), { ok: false, code: "invalid_limits" });
    }
  });
});

test("T6 item ceilings apply per list and byte ceilings span the entire view", () => {
  const base = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  const bytes = [base.revisions, base.acceptances, base.descriptors, base.terminations].flat().reduce((sum: number, item: string) => sum + Buffer.byteLength(item), 0);
  assert.ok(withOptions(verifyChain, [base], { limits: { max_artifact_set_items: 2, max_artifact_set_bytes: bytes } }).ok);
  assert.deepEqual(withOptions(verifyChain, [base], { limits: { max_artifact_set_items: 1 } }), { ok: false, code: "limit_exceeded" });
  assert.deepEqual(withOptions(verifyChain, [base], { limits: { max_artifact_set_bytes: bytes - 1 } }), { ok: false, code: "limit_exceeded" });
  assert.deepEqual(withOptions(verifyChain, [{ ...base, revisions: ["broken"] }], { limits: { max_artifact_set_items: 0 } }), { ok: false, code: "limit_exceeded" });
  for (const limits of [{ max_depth: 0 }, { max_object_members: 0 }, { max_array_items: 0 }, { max_string_bytes: 0 }]) {
    const result = withOptions(verifyChain, [base], { limits });
    assert.equal(result.ok, false);
  }
});


test("T5 raw signature primitive accepts options without changing its boolean result", () => {
  const compact = optionProbes()[0][2][0] as string;
  const [header, payload, signature] = compact.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
  const args = [Buffer.from(`${header}.${payload}`), Buffer.from(signature, "base64url"), claims.verification_keys[0].public_key, "EdDSA"];
  assert.equal(withOptions(verifySignature, args, { profile: classicalProfile }), false);
  assert.equal(withOptions(verifySignature, args, { limits: { max_bytes: 0 } }), false);
  assert.equal(withOptions(verifySignature, args, {}), true);
});

test("T6 limits expose the reference defaults and compiled maximums", () => {
  assert.deepEqual(publicApi.DEFAULT_LIMITS, { max_bytes: 1048576, max_depth: 64, max_object_members: 1024, max_array_items: 4096, max_string_bytes: 65536, max_artifact_set_items: 1024, max_artifact_set_bytes: 67108864 });
  assert.deepEqual(publicApi.MAXIMUM_LIMITS, { max_bytes: 16777216, max_depth: 128, max_object_members: 65536, max_array_items: 65536, max_string_bytes: 1048576, max_artifact_set_items: 4096, max_artifact_set_bytes: 1073741824 });
  const compact = optionProbes()[0][2][0] as string;
  for (const [key, max] of Object.entries(publicApi.MAXIMUM_LIMITS)) {
    assert.deepEqual(withOptions(verifyDescriptor, [compact, null], { limits: { [key]: max + 1 } }), { ok: false, code: "invalid_limits" });
  }
  assert.deepEqual(withOptions(verifyDescriptor, [compact, null], { limits: { max_depth: -1 }, profile: { algorithms: [] } }), { ok: false, code: "invalid_limits" });
});

test("T6 every artifact list is bounded before any artifact decode", () => {
  for (const name of ["revisions", "acceptances", "descriptors", "terminations"]) {
    const view = { revisions: [], acceptances: [], descriptors: [], terminations: [], [name]: ["broken", "broken"] };
    assert.deepEqual(withOptions(verifyChain, [view], { limits: { max_artifact_set_items: 1 } }), { ok: false, code: "limit_exceeded" });
  }
  assert.deepEqual(withOptions(verifyChain, [{ revisions: ["é"], acceptances: [], descriptors: [], terminations: [] }], { limits: { max_artifact_set_bytes: 1 } }), { ok: false, code: "limit_exceeded" });
});


function cryptoScenario(script: string): any {
  const setup = `
    import { mock } from "node:test";
    import { createHash, createPublicKey, verify as runtimeVerify } from "node:crypto";
    const input = ${JSON.stringify(corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input)};
    const entry = ${JSON.stringify(new URL("./index.ts", import.meta.url).href)};
    const corpus = ${JSON.stringify(join(here, "conformance"))};
  `;
  return JSON.parse(execFileSync(process.execPath, ["--experimental-test-module-mocks", "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", setup + script], { encoding: "utf8" }));
}

test("T7 unavailable substrate has a distinct artifact result after deterministic checks", () => {
  const results = cryptoScenario(`
    mock.module("node:crypto", { namedExports: { createHash, createPublicKey: () => { throw Error("test substrate failure"); }, verify: runtimeVerify } });
    const api = await import(entry);
    const [header, payload] = input.compact.split(".");
    const claims = JSON.parse(Buffer.from(payload, "base64url"));
    const malformed = header + "." + Buffer.from(api.canonical({ ...claims, extra: true })).toString("base64url") + "." + input.compact.split(".")[2];
    console.log(JSON.stringify([
      api.verifyDescriptor(input.compact),
      api.verifyDescriptor(malformed),
      api.verifyDescriptor(header + "." + payload + "." + Buffer.alloc(64).toString("base64url")),
      api.verifyDescriptor(input.compact, null, { profile: { algorithms: ["Ed25519"] } }),
    ]));
  `);
  assert.deepEqual(results, [
    { ok: false, code: "algorithm_unsupported_on_substrate" },
    { ok: false, code: "unknown_member" },
    { ok: false, code: "signature_invalid" },
    { ok: false, code: "algorithm_outside_profile" },
  ]);
  assert.equal("capabilityProbe" in publicApi, false);
});

test("T7 a capable substrate still reports bad signatures as signature_invalid", () => {
  const input = corpusCase("party_descriptor-verify.json", "party-descriptor-genesis-valid").input;
  const [header, payload, signature] = input.compact.split(".");
  const changed = Buffer.from(signature, "base64url");
  changed[40] ^= 1;
  assert.deepEqual(verifyDescriptor(`${header}.${payload}.${changed.toString("base64url")}`), { ok: false, code: "signature_invalid" });
});


test("T7 crypto exceptions rerun the known-answer probe", () => {
  for (const [rerun, code] of [[false, "algorithm_unsupported_on_substrate"], [true, "signature_invalid"]] as const) {
    const result = cryptoScenario(`
      let calls = 0;
      let vectorCalls = 0;
      let before = 0;
      mock.module("node:crypto", { namedExports: { createHash, createPublicKey, verify: (_alg, message) => {
        if (message.toString() === "charter-agreement-protocol capability known-answer") {
          vectorCalls++;
          return calls === 0 || ${rerun};
        }
        calls++;
        before = vectorCalls;
        throw Error("test substrate failure");
      } } });
      const api = await import(entry);
      const verdict = api.verifyDescriptor(input.compact);
      console.log(JSON.stringify({ verdict, calls, reruns: vectorCalls - before }));
    `);
    assert.deepEqual(result.verdict, { ok: false, code });
    assert.equal(result.calls, 1);
    assert.equal(result.reruns, 1);
  }
});


test("T7 substrate diagnostics stay outside corpus verdict reports", () => {
  const result = cryptoScenario(`
    mock.module("node:crypto", { namedExports: { createHash, createPublicKey: () => { throw Error("test substrate failure"); }, verify: runtimeVerify } });
    const api = await import(entry);
    try { api.reportFor(corpus); console.log(JSON.stringify("no error")); }
    catch (error) { console.log(JSON.stringify(error.message)); }
  `);
  assert.match(result, /algorithm_unsupported_on_substrate/);
});

const REFERENCE_FLOOR = ["tenancy", "live_policy", "authority", "effect_ownership", "execution", "billing", "evaluation_truth", "legal_validity", "term_satisfaction", "view_completeness", "counterparty_view", "wall_clock"];

function factSamples(): [string, Record<string, any>][] {
  const samples: [string, Record<string, any>][] = [];
  for (const [name, fn, args] of optionProbes()) {
    const result = withOptions(fn, args, {});
    assert.ok(result.ok);
    samples.push([name, result.facts]);
  }
  const chain = verifyChain(corpusCase("governing_revision.json", "governing-revision-closed-by-termination").input);
  assert.ok(chain.ok);
  for (const name of ["revisions", "acceptances", "terminations"]) for (const record of chain.facts[name]) samples.push(["chain " + name, record]);
  for (const history of chain.facts.descriptors.histories) {
    samples.push(["nested history", history]);
    for (const record of history.descriptors) samples.push(["nested descriptor", record]);
  }
  return samples;
}

test("T9 every facts record contains the reference floor", () => {
  const floor = REFERENCE_FLOOR;
  for (const [name, facts] of factSamples()) assert.deepEqual(facts.not_verified, floor, name);
});

test("T9 framing facts accumulate the unverified signature addition", () => {
  const compact = optionProbes()[0][2][0] as string;
  const decoded = decodeArtifact(compact);
  assert.ok(decoded.ok);
  assert.deepEqual(decoded.facts.not_verified, [...REFERENCE_FLOOR, "signature"]);
});

test("T10 facts retain protocol revision and signed algorithm names", () => {
  for (const [name, facts] of factSamples()) {
    assert.ok(Object.hasOwn(facts, "protocol_revision"), name);
    if (facts.claims || facts.payload) {
      assert.equal(facts.protocol_revision, (facts.claims ?? facts.payload).protocol_revision, name);
      assert.equal(facts.alg, facts.header?.alg ?? "EdDSA", name);
    }
  }
  for (const [file, id, verify] of [
    ["party_descriptor-verify.json", "party-descriptor-genesis-valid", verifyDescriptor],
    ["receipt-verify.json", "receipt-mldsa65-rev3-valid", verifyReceipt],
  ] as const) {
    const f = corpusCase(file, id).input;
    const result = verify === verifyDescriptor ? verifyDescriptor(f.compact) : verifyReceipt(f.compact, f.chain);
    assert.ok(result.ok);
    const header = JSON.parse(Buffer.from(f.compact.split(".")[0], "base64url").toString());
    const claims = JSON.parse(Buffer.from(f.compact.split(".")[1], "base64url").toString());
    assert.equal(result.facts.alg, header.alg);
    assert.equal(result.facts.protocol_revision, claims.protocol_revision);
  }
});

test("T2 revision integer members reject double-resolved large literals", () => {
  const text = corpusCase("charter_revision-decode.json", "charter-revision-genesis-valid").input.text;
  assert.deepEqual(decodeCharterRevision(text.replace('"revision_number":1', '"revision_number":9007199254740992')), { ok: false, code: "invalid_type" });
});

test("T2 revision timestamps support early and late four-digit years", () => {
  const base = JSON.parse(corpusCase("charter_revision-decode.json", "charter-revision-genesis-valid").input.text);
  for (const year of ["0001", "0099", "0100", "9999"]) {
    const result = decodeCharterRevision(canonical({ ...base, effective_from: year + "-01-01T00:00:00Z" }));
    assert.ok(result.ok, year + " " + JSON.stringify(result));
  }
});

test("T2 revision string rules use byte bounds and exact whole-string matches", () => {
  const base = JSON.parse(corpusCase("charter_revision-decode.json", "charter-revision-genesis-valid").input.text);
  for (const [path, max, nested] of [
    ["parties.0.role", 128, true], ["legal_text.media_type", 255, true], ["legal_text.uri_hint", 2048, true],
    ["abp_bindings.0.party_role", 128, true], ["effective_from", 64, false], ["effective_until", 64, false],
    ["abp_bindings.0.blueprint_id", 512, true], ["receipt_profile", 512, false],
  ] as const) {
    assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, "é".repeat(Math.floor(max / 2) + 1)))), { ok: false, code: nested ? "nested_invalid" : "constraint_violation" });
  }
  for (const [path, value, code] of [
    ["charter_id", sampleDigest + "\n", "constraint_violation"],
    ["receipt_profile", base.receipt_profile + "\n", "constraint_violation"],
    ["abp_bindings.0.blueprint_id", base.abp_bindings[0].blueprint_id + "\n", "nested_invalid"],
    ["effective_from", base.effective_from + "\n", "timestamp_invalid"],
  ]) assert.deepEqual(decodeCharterRevision(canonical(copyWithPath(base, path, value))), { ok: false, code });
});

test("T4 an individual successor must retain its predecessor party", () => {
  const [root, child] = corpusCase("descriptor_chain-verify.json", "descriptor-chain-superseded-position").input.compacts;
  const previous = decodePartyDescriptor(root);
  assert.ok(previous.ok);
  assert.deepEqual(verifyDescriptor(replaceClaims(child, (c) => ({ ...c, party_id: sampleDigest })), { digest: previous.digest, claims: previous.claims, lineage: [root] }), { ok: false, code: "descriptor_chain_invalid" });
});


test("T2 strict numeric decode follows reference tagging and lexeme bounds", () => {
  const decoded = publicApi.decodeJsonText("9007199254740992");
  assert.ok(decoded.ok);
  assert.deepEqual(publicApi.jsonProjection(decoded.value), { tag: "float", value: 9007199254740992 });
  assert.deepEqual(publicApi.decodeJsonText("9".repeat(400)), { ok: false, code: "number_not_double_expressible" });
  assert.deepEqual(publicApi.decodeJsonText("0." + "0".repeat(33)), { ok: false, code: "number_not_double_expressible" });
});

test("T6 explicit null artifact lists reject instead of using omitted defaults", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  for (const name of ["acceptances", "terminations"]) assert.deepEqual(verifyChain({ ...view, [name]: null }), { ok: false, code: "invalid_type" });
});

function replaceHeader(compact: string, changes: Record<string, unknown>): string {
  const [header, payload, signature] = compact.split(".");
  return `${Buffer.from(canonical({ ...JSON.parse(Buffer.from(header, "base64url").toString()), ...changes })).toString("base64url")}.${payload}.${signature}`;
}

test("T5 profile checks follow key resolution in signed artifact context", () => {
  for (const [file, id, fn, code] of [
    ["acceptance-verify.json", "acceptance-profile-narrow-valid", verifyAcceptance, "acceptance_invalid"],
    ["termination-verify.json", "termination-profile-narrow-valid", verifyTermination, "termination_invalid"],
  ] as const) {
    const input = corpusCase(file, id).input;
    assert.deepEqual(withOptions(fn, [replaceHeader(input.compact, { kid: "missing-key" }), input.revision_text, input.descriptor_compacts], { profile: { algorithms: ["EdDSA"] } }), { ok: false, code });
  }
  const receipt = corpusCase("receipt-verify.json", "receipt-signed-governing-match").input;
  assert.deepEqual(verifyReceipt(replaceHeader(receipt.compact, { kid: "missing-key" }), receipt.chain, { profile: { algorithms: ["EdDSA"] } }), { ok: false, code: "signature_invalid" });
});

test("S6 normal verification skips signature vectors even when a vector would fail", () => {
  const result = cryptoScenario(`
    let vectors = 0;
    let signatures = 0;
    mock.module("node:crypto", { namedExports: { createHash, createPublicKey, verify: (...args) => {
      if (args[1].toString() === "charter-agreement-protocol capability known-answer") { vectors++; return false; }
      signatures++;
      return runtimeVerify(...args);
    } } });
    const api = await import(entry);
    const verdict = api.verifyDescriptor(input.compact);
    console.log(JSON.stringify({ ok: verdict.ok, vectors, signatures }));
  `);
  assert.deepEqual(result, { ok: true, vectors: 0, signatures: 1 });
});

test("S6 repeated chain verification never runs normal-path signature vectors", () => {
  const view = corpusCase("chain-verify.json", "chain-dual-acceptance-valid").input;
  const result = cryptoScenario(`
    let vectors = 0;
    let signatures = 0;
    mock.module("node:crypto", { namedExports: { createHash, createPublicKey, verify: (...args) => {
      if (args[1].toString() === "charter-agreement-protocol capability known-answer") vectors++;
      else signatures++;
      return runtimeVerify(...args);
    } } });
    const api = await import(entry);
    const view = ${JSON.stringify(view)};
    const outcomes = [api.verifyChain(view).ok, api.verifyChain(view).ok];
    console.log(JSON.stringify({ outcomes, vectors, signatures }));
  `);
  assert.deepEqual(result, { outcomes: [true, true], vectors: 0, signatures: 8 });
});
