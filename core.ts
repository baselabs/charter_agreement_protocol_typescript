import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const INDEX_FORMAT = "charter-agreement-protocol-conformance-corpus-index";
const CASE_FORMAT = "charter-agreement-protocol-conformance-cases";
const REPORT_FORMAT = "charter-agreement-protocol-conformance-report";
export const CERTIFIED_INDEX_SHA256_BASE64URL = "NiSzeS8F0SXS6ddeeQhOBdsG4BQn8jcxb8DSX1q-oLM";
export const CERTIFIED_REGISTRY_DIGEST = "sha-256:u754joyHGcLCTm1LYV2s6eHauUUdDfJDwwyhbAbxvzc";

const SEPARATORS = {
  party_descriptor_content: "charter-agreement-protocol/party-descriptor-content",
  charter_revision_content: "charter-agreement-protocol/charter-revision-content",
  acceptance_content: "charter-agreement-protocol/acceptance-content",
  termination_content: "charter-agreement-protocol/termination-content",
  receipt_content: "charter-agreement-protocol/receipt-content",
  legal_text: "charter-agreement-protocol/legal-text",
  signature: "charter-agreement-protocol/signature",
  extension_schema: "charter-agreement-protocol/extension-schema",
  extension_registry: "charter-agreement-protocol/extension-registry",
  conformance_report: "charter-agreement-protocol/conformance-report",
  corpus_index: "charter-agreement-protocol/corpus-index",
};

const SURFACES = [
  "base64url.decode", "json.decode", "canonicalization.encode", "digest.hash",
  "schema.validate", "party_descriptor.verify", "descriptor_chain.verify",
  "charter_revision.decode", "acceptance.verify", "acceptance.equivocation",
  "termination.verify", "chain.verify", "governing_revision", "receipt.verify",
];

const CLASSES = [
  "valid", "boundary_near", "exact_bound", "maximum_plus_one", "invalid_encoding",
  "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member",
  "missing_required", "non_canonical_bytes", "digest_mismatch", "signature_invalid",
  "chain_invalid", "descriptor_superseded", "descriptor_fork", "equivocation",
  "chain_fork", "supersession", "precedence_selection", "outcome_indeterminate",
  "extension_unknown_critical", "extension_optional_roundtrip",
];

const REQUIRED = {
  "base64url.decode": ["valid", "exact_bound", "invalid_encoding"],
  "json.decode": ["valid", "boundary_near", "exact_bound", "maximum_plus_one", "invalid_encoding", "invalid_type"],
  "canonicalization.encode": ["valid", "invalid_encoding", "invalid_type", "non_canonical_bytes"],
  "digest.hash": ["valid", "invalid_type", "digest_mismatch"],
  "schema.validate": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required", "maximum_plus_one"],
  "party_descriptor.verify": ["valid", "signature_invalid"],
  "descriptor_chain.verify": ["signature_invalid", "chain_invalid", "descriptor_superseded", "descriptor_fork"],
  "charter_revision.decode": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required", "extension_unknown_critical"],
  "acceptance.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "acceptance.equivocation": ["equivocation"],
  "termination.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "chain.verify": ["valid", "chain_fork", "supersession"],
  "governing_revision": ["precedence_selection"],
  "receipt.verify": ["valid", "invalid_constraint", "signature_invalid", "chain_fork", "outcome_indeterminate", "extension_optional_roundtrip"],
};

export function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function rawHash(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}

function taggedHash(domain, bytes) {
  const preimage = Buffer.concat([Buffer.from(SEPARATORS[domain]), Buffer.from([0]), Buffer.from(bytes)]);
  return `sha-256:${rawHash(preimage)}`;
}

function exactKeys(object, keys) {
  return object && typeof object === "object" && !Array.isArray(object) &&
    canonical(Object.keys(object).sort()) === canonical([...keys].sort());
}

function walk(root, directory = root) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? walk(root, path) : [relative(root, path).split(sep).join("/")];
  });
}

function strictBase64url(text) {
  if (typeof text !== "string") return fail("invalid_type");
  if (text.includes("=")) return fail("base64url_padded");
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return fail("base64url_invalid");
  const bytes = Buffer.from(text, "base64url");
  return bytes.toString("base64url") === text ? ok(bytes) : fail("base64url_invalid");
}

function ok(value) { return { ok: true, value }; }
function fail(code) { return { ok: false, code }; }
function valid(output) { return { status: "valid", output }; }
function invalid(code) { return { status: "invalid", error_code: code }; }
function project(result, projector) { return result.ok ? valid(projector(result.value)) : invalid(result.code); }

function parseJsonBytes(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return ok(JSON.parse(text));
  } catch (_error) {
    return fail("invalid_encoding");
  }
}

function jsonProjection(value) {
  if (value === null) return { tag: "null" };
  if (Number.isInteger(value)) return { tag: "integer", value };
  if (Array.isArray(value)) return { tag: "array", items: value.map(jsonProjection) };
  if (value && typeof value === "object") return { tag: "object", members: Object.entries(value).map(([key, item]) => [key, jsonProjection(item)]) };
  if (typeof value === "string") return { tag: "string", value };
  if (typeof value === "boolean") return { tag: "boolean", value };
  return { tag: "float", value };
}

function decodeJws(compact) {
  if (typeof compact !== "string") return fail("compact_invalid");
  const segments = compact.split(".");
  if (segments.length !== 3) return fail("compact_invalid");
  const decoded = segments.map(strictBase64url);
  if (decoded.some((one) => !one.ok)) return fail("compact_invalid");
  try {
    const headerBytes = decoded[0].value;
    const payloadBytes = decoded[1].value;
    const header = JSON.parse(headerBytes.toString("utf8"));
    const payload = JSON.parse(payloadBytes.toString("utf8"));
    if (canonical(header) !== headerBytes.toString() || canonical(payload) !== payloadBytes.toString()) return fail("non_canonical_bytes");
    return ok({ header, payload, payloadBytes, signature: decoded[2].value, signingInput: Buffer.from(`${segments[0]}.${segments[1]}`) });
  } catch (_error) {
    return fail("compact_invalid");
  }
}

function ed25519(rawKey, message, signature) {
  try {
    const prefix = Buffer.from("302a300506032b6570032100", "hex");
    const key = createPublicKey({ key: Buffer.concat([prefix, Buffer.from(rawKey, "base64url")]), format: "der", type: "spki" });
    return verifySignature(null, message, key, signature);
  } catch (_error) {
    return false;
  }
}

function verifyDecodedJws(decoded, typ, keys) {
  if (decoded.header.alg !== "EdDSA" || decoded.header.typ !== typ || typeof decoded.header.kid !== "string") return false;
  const key = keys.find((one) => one.key_id === decoded.header.kid && one.algorithm === "Ed25519" && one.status === "active");
  return Boolean(key && ed25519(key.public_key, decoded.signingInput, decoded.signature));
}

function descriptorFromCompact(compact, predecessor = null) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const payload = decoded.value.payload;
  const keys = predecessor ? predecessor.payload.verification_keys : payload.verification_keys;
  if (!Array.isArray(keys) || !verifyDecodedJws(decoded.value, "cap+party", keys)) return fail("signature_invalid");
  const digest = taggedHash("party_descriptor_content", decoded.value.payloadBytes);
  if (payload.descriptor_number === 1) {
    if (payload.prev_descriptor_digest !== undefined) return fail("descriptor_invalid");
  } else if (!predecessor || payload.prev_descriptor_digest !== predecessor.digest || payload.descriptor_number !== predecessor.payload.descriptor_number + 1) {
    return fail("descriptor_chain_invalid");
  }
  return ok({ ...decoded.value, digest, compact });
}

function descriptorChain(compacts) {
  if (!Array.isArray(compacts) || compacts.length === 0) return fail("descriptor_chain_invalid");
  const pending = [...compacts];
  const descriptors = [];
  while (pending.length > 0) {
    let progressed = false;
    for (let index = pending.length - 1; index >= 0; index -= 1) {
      const decoded = decodeJws(pending[index]);
      if (!decoded.ok) return fail("descriptor_chain_invalid");
      const prev = decoded.value.payload.prev_descriptor_digest;
      const predecessor = prev ? descriptors.find((one) => one.digest === prev) : null;
      if (prev && !predecessor) continue;
      const verified = descriptorFromCompact(pending[index], predecessor);
      if (!verified.ok) return fail("descriptor_chain_invalid");
      descriptors.push(verified.value);
      pending.splice(index, 1);
      progressed = true;
    }
    if (!progressed) return fail("descriptor_chain_invalid");
  }
  const children = new Map();
  for (const descriptor of descriptors) {
    const prev = descriptor.payload.prev_descriptor_digest;
    if (prev) children.set(prev, [...(children.get(prev) || []), descriptor.digest]);
  }
  const fork = [...children.values()].find((values) => values.length > 1);
  const positions = Object.fromEntries(descriptors.map((one) => [one.digest, fork ? "contested" : (children.has(one.digest) ? "superseded" : "head")]));
  return ok({ descriptors, topology: fork ? "forked" : "linear", positions, siblingDescriptors: fork ? [...fork].sort() : [] });
}

const REVISION_FIELDS = ["abp_bindings", "attribution_declaration", "charter_id", "effective_from", "extensions", "legal_text", "parties", "precedence_declaration", "prev_revision_digest", "protocol_revision", "receipt_profile", "revision_number", "supersedes", "termination_rules"];
const REVISION_REQUIRED = ["abp_bindings", "attribution_declaration", "effective_from", "extensions", "legal_text", "parties", "precedence_declaration", "protocol_revision", "receipt_profile", "revision_number", "termination_rules"];

function revisionFromText(text) {
  if (typeof text !== "string") return fail("revision_invalid");
  let value;
  try { value = JSON.parse(text); } catch (_error) { return fail("invalid_syntax"); }
  const unknown = Object.keys(value).find((key) => !REVISION_FIELDS.includes(key));
  if (unknown) return fail("unknown_member");
  const missing = REVISION_REQUIRED.find((key) => !(key in value));
  if (missing) return fail("missing_required");
  if (!Array.isArray(value.parties) || new Set(value.parties.map((one) => one.role)).size !== value.parties.length) return fail("revision_invalid");
  if (!Array.isArray(value.termination_rules.reason_codes) || value.termination_rules.reason_codes.length === 0) return fail("nested_invalid");
  if (value.revision_number === 1 && (value.supersedes !== undefined || value.prev_revision_digest !== undefined || value.charter_id !== undefined)) return fail("revision_invalid");
  if (value.supersedes !== undefined && (!Array.isArray(value.supersedes) || value.supersedes.some((one) => typeof one !== "string"))) return fail("revision_invalid");
  const critical = value.extensions?.critical || {};
  for (const namespace of Object.keys(critical)) {
    if (namespace !== "com.example/pricing-indexed") return fail("extension_unknown_critical");
    if (critical[namespace]?.formula !== "index_plus_spread") return fail("constraint_violation");
  }
  const bytes = Buffer.from(text);
  return ok({ value, bytes, digest: taggedHash("charter_revision_content", bytes) });
}

function acceptanceFromCompact(compact, revision, chain) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const descriptor = chain.descriptors.find((one) => one.digest === claims.party_descriptor_digest);
  if (!descriptor || !verifyDecodedJws(decoded.value, "cap+acceptance", descriptor.payload.verification_keys)) return fail("signature_invalid");
  const expectedCharter = revision.value.charter_id || revision.digest;
  const party = revision.value.parties.find((one) => one.party_descriptor_digest === claims.party_descriptor_digest);
  const mismatch = claims.protocol_revision !== revision.value.protocol_revision || claims.charter_id !== expectedCharter || claims.revision_number !== revision.value.revision_number || claims.revision_digest !== revision.digest || claims.party_role !== party?.role || (revision.value.prev_revision_digest || undefined) !== (claims.prev_revision_digest || undefined);
  if (mismatch) return fail("acceptance_claims_mismatch");
  return ok({ claims, digest: taggedHash("acceptance_content", decoded.value.payloadBytes), descriptorPosition: chain.positions[claims.party_descriptor_digest] });
}

function terminationFromCompact(compact, revision, chain) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const descriptor = chain.descriptors.find((one) => one.digest === claims.party_descriptor_digest);
  if (!descriptor || !verifyDecodedJws(decoded.value, "cap+termination", descriptor.payload.verification_keys)) return fail("signature_invalid");
  const expectedCharter = revision.value.charter_id || revision.digest;
  const party = revision.value.parties.find((one) => one.party_descriptor_digest === claims.party_descriptor_digest);
  if (claims.charter_id !== expectedCharter || claims.governing_revision_digest !== revision.digest || claims.party_role !== party?.role || !revision.value.termination_rules.reason_codes.includes(claims.reason_code)) return fail("termination_claims_mismatch");
  if (Date.parse(claims.issued_at) > Date.parse(claims.effective_at)) return fail("termination_invalid");
  return ok({ claims, digest: taggedHash("termination_content", decoded.value.payloadBytes), descriptorPosition: chain.positions[claims.party_descriptor_digest] });
}

function chainFromInput(input) {
  const descriptors = descriptorChain(input.descriptors);
  if (!descriptors.ok) return fail("chain_invalid");
  const revisions = [];
  for (const text of input.revisions) {
    const revision = revisionFromText(text);
    if (!revision.ok) return fail("chain_invalid");
    revisions.push(revision.value);
  }
  const byDigest = new Map(revisions.map((one) => [one.digest, one]));
  const acceptances = [];
  for (const compact of input.acceptances) {
    const decoded = decodeJws(compact);
    if (!decoded.ok) return fail("chain_invalid");
    const revision = byDigest.get(decoded.value.payload.revision_digest);
    if (!revision) return fail("chain_invalid");
    const verified = acceptanceFromCompact(compact, revision, descriptors.value);
    if (!verified.ok) return fail("chain_invalid");
    acceptances.push(verified.value);
  }
  const accepted = revisions.filter((revision) => {
    const roles = acceptances.filter((one) => one.claims.revision_digest === revision.digest).map((one) => one.claims.party_role);
    return roles.includes("issuer") && roles.includes("acceptor");
  });
  const superseded = new Set(accepted.flatMap((one) => one.value.supersedes || []));
  const children = new Map();
  for (const revision of accepted) {
    const prev = revision.value.prev_revision_digest;
    if (prev) children.set(prev, [...(children.get(prev) || []), revision.digest]);
  }
  const activeLeaves = accepted.filter((one) => !children.has(one.digest) && !superseded.has(one.digest));
  const topology = activeLeaves.length > 1 ? "forked" : "linear";
  const genesis = accepted.find((one) => one.value.revision_number === 1);
  return ok({ descriptors: descriptors.value, revisions, accepted, acceptedDigests: accepted.map((one) => one.digest).sort(), supersededDigests: [...superseded].sort(), activeLeaves, topology, charterId: genesis?.digest });
}

function governing(chain, at) {
  const applicable = chain.accepted.filter((one) => Date.parse(one.value.effective_from) <= at && !chain.supersededDigests.includes(one.digest));
  if (applicable.length === 0) return "none";
  const maximum = Math.max(...applicable.map((one) => one.value.revision_number));
  const finalists = applicable.filter((one) => one.value.revision_number === maximum);
  return finalists.length === 1 ? finalists[0].digest : "contested";
}

function receiptFromCompact(compact, chain) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const claimedRevision = chain.revisions.find((one) => one.digest === claims.revision_digest);
  const signingRevision = claimedRevision || chain.revisions.find((one) => one.value.revision_number === claims.revision_number) || chain.revisions[0];
  const party = signingRevision.value.parties.find((one) => one.role === claims.agent_party_role);
  const descriptor = chain.descriptors.descriptors.find((one) => one.digest === party?.party_descriptor_digest);
  if (!descriptor || !verifyDecodedJws(decoded.value, "cap+receipt", descriptor.payload.verification_keys)) return fail("signature_invalid");
  if (claims.decision === "rejected" && claims.outcome === "effect_committed") return fail("cross_field_invalid");
  const governingDigest = governing(chain, Date.parse(claims.occurred_at));
  const governingMatch = governingDigest === claims.revision_digest ? "match" : "mismatch";
  const chainConflict = claimedRevision ? (chain.topology === "forked" ? "fork_evidenced" : "none") : "fork_evidenced";
  const binding = claimedRevision?.value.abp_bindings.find((one) => one.party_role === claims.agent_party_role);
  const deploymentMatched = governingMatch === "match" && binding?.deployment_digest === claims.deployment_digest;
  return ok({ claims, digest: taggedHash("receipt_content", decoded.value.payloadBytes), governingMatch, chainConflict, deploymentMatched, optionalExtensions: Object.keys(claims.extensions?.optional || {}).sort() });
}

function execute(one) {
  const input = one.input;
  switch (one.surface) {
    case "base64url.decode":
      return project(strictBase64url(input.text), (bytes) => ({ bytes_base64url: bytes.toString("base64url") }));
    case "json.decode": {
      if (!("text" in input) && !("bytes_base64url" in input)) return invalid("invalid_type");
      const bytes = "text" in input ? Buffer.from(input.text) : Buffer.from(input.bytes_base64url, "base64url");
      if (input.limits?.max_bytes !== undefined && bytes.length > input.limits.max_bytes) return invalid("limit_exceeded");
      return project(parseJsonBytes(bytes), jsonProjection);
    }
    case "canonicalization.encode":
      if (input.tag === "object") return valid({ text: canonical(Object.fromEntries(input.members.map(([key, value]) => [key, value.value]))) });
      if (input.tag === "string_codepoint") return invalid("invalid_encoding");
      if (input.kind === "improper_object") return invalid("invalid_type");
      return canonical(JSON.parse(input.text)) === input.text ? valid({ text: input.text }) : invalid("non_canonical_bytes");
    case "digest.hash":
      if (!("bytes_base64url" in input)) return invalid("invalid_type");
      if (input.tagged && input.tagged !== taggedHash(input.domain || "charter_revision_content", Buffer.from(input.bytes_base64url, "base64url"))) return invalid("digest_mismatch");
      return valid({ algorithm: "sha-256" });
    case "schema.validate": {
      const members = input.members;
      if (Object.keys(members).some((key) => key !== "name")) return invalid("unknown_member");
      if (!("name" in members)) return invalid("missing_required");
      if (typeof members.name !== "string") return invalid("invalid_type");
      if (!/^[a-z]+$/.test(members.name)) return invalid("constraint_violation");
      if (Buffer.byteLength(members.name) < 2 || Buffer.byteLength(members.name) > 4) return invalid("cardinality_violation");
      return valid({ members });
    }
    case "party_descriptor.verify": {
      const descriptor = descriptorFromCompact(input.compact);
      return project(descriptor, (oneDescriptor) => ({ descriptor_digest: oneDescriptor.digest, party_id: oneDescriptor.digest, descriptor_number: oneDescriptor.payload.descriptor_number }));
    }
    case "descriptor_chain.verify": {
      const chain = descriptorChain(input.compacts);
      return project(chain, (value) => {
        return { topology: value.topology, positions: value.positions, sibling_descriptors: value.siblingDescriptors };
      });
    }
    case "charter_revision.decode":
      return project(revisionFromText(input.text), (revision) => ({ revision_digest: revision.digest, revision_number: revision.value.revision_number, precedence_declaration: revision.value.precedence_declaration, abp_binding: { blueprint_id: revision.value.abp_bindings[0].blueprint_id, release_number: revision.value.abp_bindings[0].release_number, content_digest: revision.value.abp_bindings[0].content_digest, deployment_digest: revision.value.abp_bindings[0].deployment_digest } }));
    case "acceptance.verify": {
      const revision = revisionFromText(input.revision_text);
      const chain = descriptorChain(input.descriptor_compacts);
      if (!revision.ok || !chain.ok) return invalid("acceptance_invalid");
      return project(acceptanceFromCompact(input.compact, revision.value, chain.value), (facts) => ({ acceptance_digest: facts.digest, revision_digest: facts.claims.revision_digest, party_descriptor_digest: facts.claims.party_descriptor_digest, descriptor_position: facts.descriptorPosition }));
    }
    case "acceptance.equivocation": {
      const chain = descriptorChain(input.descriptor_compacts);
      if (!chain.ok) return invalid("acceptance_equivocation_invalid");
      const facts = input.signed_revisions.map((signed) => {
        const revision = revisionFromText(signed.revision_text);
        return revision.ok ? acceptanceFromCompact(signed.compact, revision.value, chain.value) : revision;
      });
      if (facts.some((oneFact) => !oneFact.ok)) return invalid("acceptance_equivocation_invalid");
      return valid({ kind: "acceptance_equivocation", revision_number: facts[0].value.claims.revision_number, revision_digests: facts.map((oneFact) => oneFact.value.claims.revision_digest).sort(), winner: null });
    }
    case "termination.verify": {
      const revision = revisionFromText(input.revision_text);
      const chain = descriptorChain(input.descriptor_compacts);
      if (!revision.ok || !chain.ok) return invalid("termination_invalid");
      return project(terminationFromCompact(input.compact, revision.value, chain.value), (facts) => ({ termination_digest: facts.digest, governing_revision_digest: facts.claims.governing_revision_digest, party_descriptor_digest: facts.claims.party_descriptor_digest, reason_code: facts.claims.reason_code, descriptor_position: facts.descriptorPosition }));
    }
    case "chain.verify": {
      const chain = chainFromInput(input);
      return project(chain, (facts) => ({ charter_id: facts.charterId, topology: facts.topology, accepted_revision_digests: facts.acceptedDigests, superseded_revision_digests: facts.supersededDigests }));
    }
    case "governing_revision": {
      const chain = chainFromInput(input);
      if (!chain.ok) return invalid("governing_invalid");
      return valid({ governing_revisions: input.queries.map((query) => governing(chain.value, Date.parse(query.at))) });
    }
    case "receipt.verify": {
      const chain = chainFromInput(input.chain);
      if (!chain.ok) return invalid("receipt_invalid");
      return project(receiptFromCompact(input.compact, chain.value), (facts) => ({ receipt_digest: facts.digest, revision_number: facts.claims.revision_number, revision_digest: facts.claims.revision_digest, decision: facts.claims.decision, outcome: facts.claims.outcome, chain_conflict: facts.chainConflict, governing_match: facts.governingMatch, deployment_digest_matched: facts.deploymentMatched, optional_extensions_retained: facts.optionalExtensions }));
    }
    default:
      throw new Error("unsupported surface");
  }
}

function corpusDigest(index) {
  const without = { ...index };
  delete without.corpus_digest;
  return taggedHash("corpus_index", Buffer.from(canonical(without)));
}

export function loadCorpus(root) {
  const indexBytes = readFileSync(join(root, "index.json"));
  const index = JSON.parse(indexBytes);
  if (canonical(index) !== indexBytes.toString()) throw new Error("non-canonical index");
  if (!exactKeys(index, ["applicability", "corpus_digest", "files", "format", "registry_digest", "total_cases"])) throw new Error("index shape");
  if (index.format !== INDEX_FORMAT || index.corpus_digest !== corpusDigest(index)) throw new Error("index identity");
  if (index.registry_digest !== CERTIFIED_REGISTRY_DIGEST) throw new Error("registry identity");
  if (rawHash(indexBytes) !== CERTIFIED_INDEX_SHA256_BASE64URL) throw new Error("uncertified index");
  const expectedFiles = ["index.json", ...index.files.map((entry) => entry.path)].sort();
  if (canonical(walk(root).sort()) !== canonical(expectedFiles)) throw new Error("file set");
  const cases = [];
  for (const entry of index.files) {
    const bytes = readFileSync(join(root, entry.path));
    if (rawHash(bytes) !== entry.sha256_base64url) throw new Error("file hash");
    const file = JSON.parse(bytes);
    if (canonical(file) !== bytes.toString() || file.format !== CASE_FORMAT || file.cases.length !== entry.cases) throw new Error("case file");
    cases.push(...file.cases);
  }
  if (cases.length !== index.total_cases || cases.length === 0) throw new Error("case count");
  const ids = new Set();
  const observed = new Map();
  for (const one of cases) {
    if (ids.has(one.id) || !SURFACES.includes(one.surface) || !CLASSES.includes(one.class)) throw new Error("case shape");
    ids.add(one.id);
    const key = `${one.surface}\0${one.class}`;
    observed.set(key, (observed.get(key) || 0) + 1);
  }
  for (const surface of SURFACES) {
    for (const oneClass of CLASSES) {
      const count = observed.get(`${surface}\0${oneClass}`) || 0;
      const cell = index.applicability[surface][oneClass];
      if (REQUIRED[surface].includes(oneClass)) {
        if (cell !== count || count < 1) throw new Error("required cell");
      } else if (!exactKeys(cell, ["n_a"]) || cell.n_a === "" || count !== 0) throw new Error("not-applicable cell");
    }
  }
  return { index, indexBytes, cases };
}

export function reportFor(root) {
  const corpus = loadCorpus(root);
  const results = corpus.cases.map((one) => {
    const actual = execute(one);
    return { id: one.id, surface: one.surface, agree: canonical(actual) === canonical(one.expect), expected: one.expect, actual };
  });
  const agreed = results.filter((one) => one.agree).length;
  const total = results.length;
  const agreement = agreed === total && total > 0;
  const report = {
    format: REPORT_FORMAT,
    agreement,
    exit_status: agreement ? 0 : 1,
    total,
    agreed,
    disagreed: total - agreed,
    corpus_digest: corpus.index.corpus_digest,
    registry_digest: corpus.index.registry_digest,
    index_sha256_base64url: rawHash(corpus.indexBytes),
    results,
  };
  return { bytes: `${canonical(report)}\n`, exitStatus: report.exit_status };
}

export function selfChecks() {
  const vectors = [
    [Buffer.from(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    [Buffer.from("d3", "hex"), "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"],
    [Buffer.from("b4190e", "hex"), "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2"],
  ];
  for (const [message, expected] of vectors) {
    if (createHash("sha256").update(message).digest("hex") !== expected) throw new Error("SHA-256 KAT failed");
  }
  if (canonical({ b: 1, a: 2 }) !== "{\"a\":2,\"b\":1}") throw new Error("canonical ordering failed");
  if (strictBase64url("AQ==").code !== "base64url_padded") throw new Error("base64url strictness failed");
}
