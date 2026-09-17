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
  acceptanceSigningInput,
  assembleCompact,
  canonical,
  checkSigningClaims,
  decodeArtifact,
  decodePartyDescriptor,
  descriptorSigningInput,
  encodeBase64url,
  governingRevision,
  receiptSigningInput,
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
  revision_digest: "sha-256:" + "B".repeat(43),
  issuing_party_role: "issuer",
  agent_party_role: "agent",
  deployment_digest: "sha-256:" + "C".repeat(43),
  grant: { scheme: "bap", id: "g-1", grant_digest: "sha-256:" + "D".repeat(43) },
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
    extensions: { critical: {}, optional: {} },
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
    effective_at: "2026-08-25T15:00:00Z", extensions: { critical: {}, optional: {} },
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
  // No acceptances member at all: behaves as the empty acceptance view.
  const partial = { revisions: view.input.revisions, descriptors: view.input.descriptors };
  assert.ok(acceptanceRefusal(claims, partial).ok);
  // A revision text that is valid JSON but not an object: typed failure.
  const notObject = { ...partial, revisions: ["null"] };
  const acceptance = acceptanceRefusal(claims, notObject);
  assert.ok(acceptance.ok === false);
  assert.equal(acceptance.code, "chain_invalid");
  const termination = terminationRefusal({
    charter_id: claims.charter_id,
    governing_revision_digest: claims.revision_digest,
    party_descriptor_digest: claims.party_descriptor_digest,
    party_role: claims.party_role,
    reason_code: "mutual",
    effective_at: "2026-08-25T12:00:00Z",
  }, notObject);
  assert.ok(termination.ok === false);
  assert.equal(termination.code, "chain_invalid");
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
    revision_digest: "sha-256:" + "B".repeat(43),
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: "sha-256:" + "C".repeat(43),
    grant: { scheme: "bap", id: "g", grant_digest: "sha-256:" + "D".repeat(43) },
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
  assert.equal(producerCode(descriptorSigningInput(KID, "not-an-object" as never)), "invalid_type");
  assert.equal(producerCode(descriptorSigningInput(KID, { protocol_revision: 3 })), "signing_input_invalid");
  assert.equal(producerCode(descriptorSigningInput(KID, claims, "EdDSA")), "algorithm_unsupported");
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
    assert.equal(badView.code, "chain_invalid");
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
  assert.ok(both.ok === false && both.code === "acceptance_invalid");

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
