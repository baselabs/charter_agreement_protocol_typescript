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
  decodeArtifact,
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
