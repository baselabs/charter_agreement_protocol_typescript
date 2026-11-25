// Corpus witnesses run the actual corpus dispatcher in both versions.
// The published package keeps it private, so expose its shipped execute
// function in a temporary copy without changing its body. Public API
// probes use the same public call in both versions.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import * as candidate from "../index.ts";

const PACKAGE = "@charter-agreement-protocol/verifier";
const VERSION = "1.0.0";
const BASELINE = "npm:" + VERSION;
const INTEGRITY = "sha512-fjiqnSgXzCFM1cYMWmIurcLc7OObwpQzmd9TNy8uzoPS4cxMKZ3o4kXcH90DRv9WYtOn/PLu3ffkjOa8bJe3GA==";
const ENTRY_POINTS = ["corpus_runner", "public_api"];

const qualified = (entryPoint, id) => entryPoint + "/" + id;
const observation = (operation, value) => ({ operation, value });
const observedCase = ({ status, error_code, output }) => status === "valid" ? valid(output) : error_code;
const valid = (output) => ({ status: "valid", output });
const isValid = (value) => value?.status === "valid";
const same = (left, right) => candidate.canonical(left) === candidate.canonical(right);

export async function checkReverseDifferential(root, scratch, metadata) {
  const { api: published, frozenRoot, runCase } = await installBaseline(scratch);
  assert.ok(published.capabilities().algorithms.some((row) => row.name === "ML-DSA-65" && row.verifiable),
    "published verifier requires ML-DSA-65");

  const frozen = published.loadCorpus(frozenRoot);
  const fresh = frozen.cases.map((one) => ({ ...one, id: "dispatch-" + one.id }));
  checkedCorpus(published, fresh, runCase);

  const { index, cases } = candidate.loadCorpus(join(root, "conformance"));
  const row = metadata.compatibility.find((entry) => entry.package_versions.includes(metadata.package_version));
  assert.equal(row.census_digest, index.corpus_digest);
  const checked = checkedCorpus(candidate, cases, candidate.runConformanceCase);
  const observed = new Map(cases.map((one) => [
    qualified("corpus_runner", one.id),
    observation(one.surface, observedCase(runCase(one))),
  ]));
  recordPublicProbes(checked, candidate, cases);
  recordPublicProbes(observed, published, cases);
  const count = compare(row, observed, checked);
  console.log("reverse differential " + BASELINE + ": " + checked.size + " inputs, " + count + " transitions");
}

async function installBaseline(scratch) {
  const url = "https://registry.npmjs.org/" + PACKAGE + "/-/verifier-" + VERSION + ".tgz";
  const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, "published verifier download");
  const archive = Buffer.from(await response.arrayBuffer());
  const digest = createHash("sha512").update(archive).digest("base64");
  assert.equal("sha512-" + digest, INTEGRITY, "published verifier integrity");

  const tarball = join(scratch, "verifier-" + VERSION + ".tgz");
  writeFileSync(tarball, archive);
  writeFileSync(join(scratch, "package.json"), JSON.stringify({ private: true }));
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", tarball], {
    cwd: scratch, stdio: "ignore", timeout: 120_000,
  });

  const installed = createRequire(join(scratch, "package.json"));
  const packageFile = installed.resolve(PACKAGE + "/package.json");
  assert.equal(JSON.parse(readFileSync(packageFile)).version, VERSION);
  const packageRoot = dirname(packageFile);
  const shipped = readFileSync(join(packageRoot, "dist", "core.js"), "utf8");
  assert.match(shipped, /^function execute\(one\) \{/m, "published corpus dispatcher");
  const exposed = join(packageRoot, "dist", "reverse-corpus.mjs");
  writeFileSync(exposed, shipped + "\nexport { execute };\n");
  const { execute } = await import(pathToFileURL(exposed).href);
  return {
    api: await import(pathToFileURL(installed.resolve(PACKAGE)).href),
    frozenRoot: join(packageRoot, "conformance"),
    runCase: execute,
  };
}

function checkedCorpus(api, cases, runCase) {
  return new Map(cases.map((one) => {
    const actual = runCase(one);
    assert.equal(api.canonical(actual), api.canonical(one.expect), one.id);
    return [qualified("corpus_runner", one.id), observation(one.surface, observedCase(actual))];
  }));
}

function recordPublicProbes(observed, api, cases) {
  const inputFor = (id) => cases.find((one) => one.id === id).input;
  const example = inputFor("signing-ed25519-party_descriptor");
  observed.set(qualified("public_api", "api-assemble-missing-alg"),
    observation("assemble_compact", missingAlgorithm(api, example)));

  for (const id of ["chain-item-type-before-item-limit", "chain-item-type-before-list-byte-limit"]) {
    const input = inputFor(id);
    const result = api.verifyChain(input, { limits: input.limits });
    observed.set(qualified("public_api", id), observation("verify_chain", chainOutcome(result)));
  }
}

function missingAlgorithm(api, example) {
  const framed = api.descriptorSigningInput(example.kid, example.claims, example.algorithm);
  assert.ok(framed.ok);
  const input = { ...framed.input };
  delete input.alg;
  const result = api.assembleCompact(input, Buffer.alloc(64));
  return result.ok ? valid({ compact: result.compact }) : result.code;
}

function chainOutcome(result) {
  if (!result.ok) return result.code;
  const { charterId, topology, acceptedDigests, supersededDigests } = result.facts;
  return valid({
    charter_id: charterId, topology,
    accepted_revision_digests: acceptedDigests, superseded_revision_digests: supersededDigests,
  });
}

function direction(from, to, outputs) {
  if (outputs !== undefined) {
    if (from === "valid" && to === "valid" && outputs && Object.keys(outputs).length === 2 &&
        Object.hasOwn(outputs, "before") && Object.hasOwn(outputs, "after") &&
        !same(outputs.before, outputs.after)) return "green_to_green";
    return null;
  }
  const typed = (value) => typeof value === "string" && value.length > 0 &&
    !["valid", "raised", "unsupported"].includes(value);
  if (from === "raised" && typed(to)) return "crash_to_typed";
  if (from === "valid" && typed(to)) return "green_to_red";
  if (typed(from) && to === "valid") return "red_to_green";
  if (typed(from) && typed(to) && from !== to) return "red_to_red";
  return null;
}

function change(before, after) {
  if (isValid(before) && isValid(after)) {
    return ["valid", "valid", { before: before.output, after: after.output }];
  }
  return [isValid(before) ? "valid" : before, isValid(after) ? "valid" : after];
}

export function compare(row, observed, checked) {
  const operations = (entries) => [...entries].map(([id, { operation }]) => [id, operation]).sort();
  assert.deepEqual(operations(observed), operations(checked), "case IDs or operations do not match");
  const expected = new Map();
  for (const transition of row.transitions) {
    assert.ok(typeof transition.operation === "string" && transition.operation.length > 0);
    assert.ok(transition.witnesses.length > 0, transition.description);
    for (const { baselines, cases, entry_point, from, to, outputs } of transition.witnesses) {
      assert.ok(cases.length > 0 && baselines.length > 0 && baselines.every((name) => [BASELINE, "hex:1.0.0"].includes(name)));
      assert.ok(ENTRY_POINTS.includes(entry_point), "missing witness entry point");
      assert.equal(direction(from, to, outputs), transition.direction, transition.description);
      if (!baselines.includes(BASELINE)) continue;
      for (const id of cases) {
        const key = qualified(entry_point, id);
        assert.equal(checked.get(key)?.operation, transition.operation,
          "witness " + key + " does not name operation " + transition.operation);
        assert.ok(!expected.has(key), "duplicate witness " + key);
        expected.set(key, outputs === undefined ? [from, to] : [from, to, outputs]);
      }
    }
  }
  const differences = new Map([...observed].flatMap(([id, { value: before }]) => {
    const { value: after } = checked.get(id);
    return same(before, after) ? [] : [[id, change(before, after)]];
  }));
  const drift = [...new Set([...differences.keys(), ...expected.keys()])].sort().flatMap((id) => {
    const actual = differences.get(id);
    const recorded = expected.get(id);
    if (actual && recorded && same(actual, recorded)) return [];
    return [{
      id,
      reason: !recorded ? "unrecorded" : !actual ? "no longer firing" : "outcome drift",
      recorded: recorded ?? null,
      baseline: observed.get(id).value,
      candidate: checked.get(id).value,
    }];
  });
  assert.equal(drift.length, 0, "reverse differential " + BASELINE + "\n" + JSON.stringify(drift, null, 2));
  return differences.size;
}
