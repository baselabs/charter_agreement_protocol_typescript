import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import * as candidate from "../dist/index.js";

const PACKAGE = "@charter-agreement-protocol/verifier";
const VERSION = "1.0.0";
const BASELINE = `npm:${VERSION}`;

const verdict = ({ status, error_code }) => status === "valid" ? "valid" : error_code;
const outcome = (result) => result.ok ? "valid" : result.code;

export async function checkReverseDifferential(root, scratch, metadata) {
  writeFileSync(join(scratch, "package.json"), JSON.stringify({ private: true }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", `${PACKAGE}@${VERSION}`], {
    cwd: scratch, stdio: "ignore", timeout: 120_000,
  });
  const installed = createRequire(join(scratch, "package.json"));
  const packageFile = installed.resolve(`${PACKAGE}/package.json`);
  assert.equal(JSON.parse(readFileSync(packageFile)).version, VERSION);
  const published = await import(pathToFileURL(installed.resolve(PACKAGE)).href);
  assert.ok(published.capabilities().algorithms.some((row) => row.name === "ML-DSA-65" && row.verifiable),
    "published verifier requires ML-DSA-65");

  const frozen = join(dirname(packageFile), "conformance");
  const frozenCases = published.loadCorpus(frozen).cases;
  const frozenReport = JSON.parse(published.reportFor(frozen).bytes);
  assert.equal(frozenReport.exit_status, 0, "published corpus does not agree");
  const prior = new Map(frozenCases.map((one) => [one.id, one]));
  const results = new Map(frozenReport.results.map((one) => [one.id, verdict(one.actual)]));
  const { index, cases } = candidate.loadCorpus(join(root, "conformance"));
  const row = metadata.compatibility.find((entry) => entry.package_versions.includes(metadata.package_version));
  assert.equal(row.census_digest, index.corpus_digest);
  const checked = new Map(cases.map((one) => [one.id, verdict(one.expect)]));
  const observed = new Map(cases.map((one) => [one.id, publishedOutcome(published, one, prior, results)]));

  const example = cases.find((one) => one.id === "signing-ed25519-party_descriptor").input;
  checked.set("api-assemble-missing-alg", missingAlgorithm(candidate, example));
  observed.set("api-assemble-missing-alg", missingAlgorithm(published, example));
  const count = compare(row, observed, checked);
  console.log(`reverse differential ${BASELINE}: ${checked.size} inputs, ${count} transitions`);
}

function publishedOutcome(api, one, prior, results) {
  if (prior.has(one.id)) {
    // The published runner pins its own index. Replay the identical input
    // through that runner for its existing IDs, with the numeric tokens
    // retained by both loaders.
    const frozen = prior.get(one.id);
    assert.equal(one.surface, frozen.surface, one.id);
    assert.deepEqual(one.input, frozen.input, one.id);
    return results.get(one.id);
  }

  return publicOutcome(api, one);
}

function publicOutcome(api, { surface, input }) {
  const { compact, descriptor_compacts, profile, limits, revision_text } = input;
  switch (surface) {
    case "charter_revision.decode": return outcome(api.decodeCharterRevision(input.text));
    case "party_descriptor.verify": return descriptorOutcome(api, input);
    case "descriptor_chain.verify": return outcome(api.verifyDescriptorChain(input.compacts));
    case "acceptance.verify": return outcome(api.verifyAcceptance(compact, revision_text, descriptor_compacts, { profile }));
    case "termination.verify": return outcome(api.verifyTermination(compact, revision_text, descriptor_compacts, { profile }));
    case "chain.verify": return outcome(api.verifyChain(input, { limits }));
    case "chain.verify_profile": return outcome(api.verifyChain(input, { profile }));
    case "governing_revision": return governingOutcome(api, input);
    case "receipt.verify": return outcome(api.verifyReceipt(compact, revision_text ?? input.chain, { limits, profile }));
    case "signing.prepare": return signingOutcome(api, input);
    default: return "unsupported";
  }
}

function descriptorOutcome(api, input) {
  let previous = null;
  for (const compact of input.predecessor_compacts ?? []) {
    const result = api.verifyDescriptor(compact, previous);
    if (!result.ok) return result.code;
    previous = result.facts;
  }
  return outcome(api.verifyDescriptor(input.compact, previous, { profile: input.profile }));
}

function governingOutcome(api, input) {
  const options = { limits: input.limits };
  const verified = api.verifyChain(input, options);
  if (!verified.ok) return verified.code;
  for (const { at } of input.queries) {
    const result = api.governingRevision(input, at, options);
    if (!result.ok) return result.code === "invalid_type" ? "timestamp_invalid" : result.code;
  }
  return "valid";
}

function signingOutcome(api, input) {
  if (input.kind === "party_replacement") return "unsupported";
  const { context, limits, profile, algorithm } = input;
  let retained = context?.set ?? context?.chain ?? context?.revision_text ?? context;
  if (context?.chain) {
    const parsed = api.verifyChain(context.chain, { limits });
    if (!parsed.ok) return parsed.code;
  } else if (context?.revision_text !== undefined) {
    const parsed = api.decodeCharterRevision(context.revision_text);
    if (!parsed.ok) return parsed.code;
  } else if (context?.predecessor_compacts) {
    retained = null;
    for (const compact of context.predecessor_compacts) {
      const parsed = api.verifyDescriptor(compact, retained);
      if (!parsed.ok) return parsed.code;
      retained = parsed.facts;
    }
  }
  const kind = input.kind === "party_descriptor" ? "descriptor" : input.kind;
  return outcome(api.prepareSigning(kind, input.kid, input.claims, input.public_key, retained, { algorithm, limits, profile }));
}

function missingAlgorithm(api, example) {
  const framed = api.descriptorSigningInput(example.kid, example.claims, example.algorithm);
  assert.ok(framed.ok);
  const input = { ...framed.input };
  delete input.alg;
  return outcome(api.assembleCompact(input, Buffer.alloc(64)));
}

function compare(row, observed, checked) {
  assert.deepEqual([...observed.keys()].sort(), [...checked.keys()].sort());
  const expected = new Map();
  for (const transition of row.transitions) {
    assert.ok(transition.witnesses.length > 0, transition.description);
    for (const { baselines, cases, from, to } of transition.witnesses) {
      assert.ok(cases.length > 0 && baselines.length > 0 && baselines.every((name) => [BASELINE, "hex:1.0.0"].includes(name)));
      if (!baselines.includes(BASELINE)) continue;
      for (const id of cases) {
        assert.ok(!expected.has(id), `duplicate witness ${id}`);
        expected.set(id, [from, to]);
      }
    }
  }
  const differences = new Map([...observed].flatMap(([id, before]) => {
    const after = checked.get(id);
    return before === after ? [] : [[id, [before, after]]];
  }));
  const drift = [...new Set([...differences.keys(), ...expected.keys()])].sort().flatMap((id) => {
    const actual = differences.get(id);
    const recorded = expected.get(id);
    return actual?.[0] === recorded?.[0] && actual?.[1] === recorded?.[1] ? [] : [{ id, recorded, actual }];
  });
  assert.equal(drift.length, 0, `reverse differential ${BASELINE}\n${JSON.stringify(drift, null, 2)}`);
  return differences.size;
}
