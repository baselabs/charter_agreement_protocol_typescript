import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const indexFormat = "charter-agreement-protocol-conformance-corpus-index";
const caseFormat = "charter-agreement-protocol-conformance-cases";
const separator = "charter-agreement-protocol/corpus-index";

const surfaces = [
  "base64url.decode",
  "json.decode",
  "canonicalization.encode",
  "digest.hash",
  "schema.validate",
  "party_descriptor.verify",
  "descriptor_chain.verify",
  "charter_revision.decode",
  "acceptance.verify",
  "acceptance.equivocation",
  "termination.verify",
  "chain.verify",
  "governing_revision",
];

const classes = [
  "valid",
  "boundary_near",
  "exact_bound",
  "maximum_plus_one",
  "invalid_encoding",
  "invalid_type",
  "invalid_constraint",
  "invalid_cardinality",
  "unknown_member",
  "missing_required",
  "non_canonical_bytes",
  "digest_mismatch",
  "signature_invalid",
  "chain_invalid",
  "descriptor_superseded",
  "descriptor_fork",
  "equivocation",
  "chain_fork",
  "supersession",
  "precedence_selection",
];

const required = {
  "base64url.decode": ["valid", "exact_bound", "invalid_encoding"],
  "json.decode": ["valid", "boundary_near", "exact_bound", "maximum_plus_one", "invalid_encoding", "invalid_type"],
  "canonicalization.encode": ["valid", "invalid_encoding", "non_canonical_bytes", "invalid_type"],
  "digest.hash": ["valid", "invalid_type", "digest_mismatch"],
  "schema.validate": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required", "maximum_plus_one"],
  "party_descriptor.verify": ["valid", "signature_invalid"],
  "descriptor_chain.verify": ["signature_invalid", "chain_invalid", "descriptor_superseded", "descriptor_fork"],
  "charter_revision.decode": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required"],
  "acceptance.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "acceptance.equivocation": ["equivocation"],
  "termination.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "chain.verify": ["valid", "chain_fork", "supersession"],
  "governing_revision": ["precedence_selection"],
};

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}

function corpusDigest(index) {
  const without = { ...index };
  delete without.corpus_digest;
  const preimage = Buffer.concat([Buffer.from(separator), Buffer.from([0]), Buffer.from(canonical(without))]);
  return `sha-256:${hash(preimage)}`;
}

function walk(root, directory = root) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? walk(root, path) : [relative(root, path).split(sep).join("/")];
  });
}

function exactKeys(object, keys) {
  return object && typeof object === "object" && !Array.isArray(object) &&
    JSON.stringify(Object.keys(object).sort()) === JSON.stringify([...keys].sort());
}

function check(root) {
  const indexBytes = readFileSync(join(root, "index.json"));
  const index = JSON.parse(indexBytes);
  if (canonical(index) !== indexBytes.toString()) throw new Error("non-canonical index");
  if (!exactKeys(index, ["applicability", "corpus_digest", "files", "format", "total_cases"])) throw new Error("index shape");
  if (index.format !== indexFormat || index.corpus_digest !== corpusDigest(index)) throw new Error("index identity");
  if (!Number.isInteger(index.total_cases) || index.total_cases < 1 || !Array.isArray(index.files)) throw new Error("empty corpus");

  const expectedFiles = ["index.json", ...index.files.map((entry) => entry.path)].sort();
  if (JSON.stringify(walk(root).sort()) !== JSON.stringify(expectedFiles)) throw new Error("file set");

  const allCases = [];
  for (const entry of index.files) {
    if (!exactKeys(entry, ["cases", "path", "sha256_base64url"])) throw new Error("file entry");
    const bytes = readFileSync(join(root, entry.path));
    if (hash(bytes) !== entry.sha256_base64url) throw new Error("file hash");
    const file = JSON.parse(bytes);
    if (canonical(file) !== bytes.toString() || !exactKeys(file, ["cases", "format"]) || file.format !== caseFormat || !Array.isArray(file.cases)) throw new Error("case file");
    if (entry.cases !== file.cases.length) throw new Error("file count");
    allCases.push(...file.cases);
  }

  if (allCases.length !== index.total_cases) throw new Error("total count");
  const ids = new Set();
  const observed = new Map();

  for (const one of allCases) {
    if (!exactKeys(one, ["class", "expect", "id", "input", "surface"]) || typeof one.id !== "string" || one.id === "") throw new Error("case shape");
    if (!surfaces.includes(one.surface) || !classes.includes(one.class)) throw new Error("unknown cell");
    if (ids.has(one.id)) throw new Error("duplicate id");
    ids.add(one.id);
    const valid = exactKeys(one.expect, ["output", "status"]) && one.expect.status === "valid";
    const invalid = exactKeys(one.expect, ["error_code", "status"]) && one.expect.status === "invalid" && typeof one.expect.error_code === "string" && one.expect.error_code !== "";
    if (!valid && !invalid) throw new Error("vacuous expectation");
    const cell = `${one.surface}\u0000${one.class}`;
    observed.set(cell, (observed.get(cell) || 0) + 1);
  }

  if (!exactKeys(index.applicability, surfaces)) throw new Error("applicability surfaces");
  for (const surface of surfaces) {
    const cells = index.applicability[surface];
    if (!exactKeys(cells, classes)) throw new Error("applicability classes");
    for (const name of classes) {
      const count = observed.get(`${surface}\u0000${name}`) || 0;
      if (required[surface].includes(name)) {
        if (!Number.isInteger(cells[name]) || cells[name] < 1 || cells[name] !== count) throw new Error("required cell");
      } else if (!exactKeys(cells[name], ["n_a"]) || typeof cells[name].n_a !== "string" || cells[name].n_a === "" || count !== 0) {
        throw new Error("not-applicable cell");
      }
    }
  }

  return index.corpus_digest;
}

try {
  console.log(check(process.argv[2] || "priv/conformance"));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
