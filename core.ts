import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const INDEX_FORMAT = "charter-agreement-protocol-conformance-corpus-index";
const CASE_FORMAT = "charter-agreement-protocol-conformance-cases";
const REPORT_FORMAT = "charter-agreement-protocol-conformance-report";
const MAXIMUM_CORPUS_FILES = 64;
const MAXIMUM_CORPUS_BYTES = 33_554_432;
export const CERTIFIED_INDEX_SHA256_BASE64URL = "YLaLsoOJQjHAY2qo1o5wqH-PHc4lpSGRPn0pwjiTRoU";
export const CERTIFIED_REGISTRY_DIGEST = "sha-256:u754joyHGcLCTm1LYV2s6eHauUUdDfJDwwyhbAbxvzc";
// The fourth certified identity — the specification digest over the spec
// set — is pinned in priv/release-metadata.json and enforced by the
// release-candidate gate; corpus verification does not consume it.

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
  "extension_unknown_critical", "extension_optional_roundtrip", "extension_invalid",
];

const REQUIRED = {
  "base64url.decode": ["valid", "exact_bound", "invalid_encoding"],
  "json.decode": ["valid", "boundary_near", "exact_bound", "maximum_plus_one", "invalid_encoding", "invalid_type"],
  "canonicalization.encode": ["valid", "invalid_encoding", "invalid_type", "non_canonical_bytes"],
  "digest.hash": ["valid", "invalid_type", "digest_mismatch"],
  "schema.validate": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required", "maximum_plus_one"],
  "party_descriptor.verify": ["valid", "signature_invalid", "invalid_encoding", "unknown_member", "invalid_constraint"],
  "descriptor_chain.verify": ["signature_invalid", "chain_invalid", "descriptor_superseded", "descriptor_fork"],
  "charter_revision.decode": ["valid", "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member", "missing_required", "extension_unknown_critical", "extension_invalid"],
  "acceptance.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "acceptance.equivocation": ["equivocation", "invalid_constraint"],
  "termination.verify": ["valid", "invalid_constraint", "signature_invalid"],
  "chain.verify": ["valid", "chain_fork", "supersession", "chain_invalid"],
  "governing_revision": ["precedence_selection"],
  "receipt.verify": ["valid", "invalid_constraint", "signature_invalid", "chain_fork", "outcome_indeterminate", "extension_optional_roundtrip", "invalid_encoding", "extension_invalid"],
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
    const stat = lstatSync(path);
    if (stat.isDirectory()) return walk(root, path);
    if (!stat.isFile()) throw new Error("non-regular corpus entry");
    return [{ path: relative(root, path).split(sep).join("/"), size: stat.size }];
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

// The I-JSON decoder mirror: duplicate member names, trailing
// non-whitespace, integer literals beyond the ECMAScript safe range, and
// numbers that cannot round-trip a double are rejected with the decoder's
// closed codes, in the decoder's own order.
const MAXIMUM_SAFE_INTEGER = 9007199254740991n;
const NUMBER_TOKEN = /(?:-?(?:0|[1-9][0-9]*))(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

function readJsonValue(text, index) {
  index = skipWhitespace(text, index);
  const char = text[index];
  if (char === undefined) return { status: "need-character" };
  if (char === "{") {
    const members = new Map();
    let cursor = skipWhitespace(text, index + 1);
    if (text[cursor] === "}") return { status: "ok", value: {}, index: cursor + 1 };
    for (;;) {
      if (text[cursor] !== '"') return { status: "syntax" };
      const key = readJsonString(text, cursor);
      if (key.status !== "ok") return key;
      cursor = skipWhitespace(text, key.index);
      if (text[cursor] !== ":") return { status: "syntax" };
      const item = readJsonValue(text, skipWhitespace(text, cursor + 1));
      if (item.status !== "ok") return item;
      const duplicate = members.has(key.value);
      members.set(key.value, item.value);
      cursor = skipWhitespace(text, item.index);
      if (text[cursor] === ",") { cursor = skipWhitespace(text, cursor + 1); continue; }
      if (text[cursor] === "}") {
        if (duplicate) return { status: "error", code: "duplicate_member" };
        return { status: "ok", value: Object.fromEntries(members), index: cursor + 1 };
      }
      return { status: "syntax" };
    }
  }
  if (char === "[") {
    const items = [];
    let cursor = skipWhitespace(text, index + 1);
    if (text[cursor] === "]") return { status: "ok", value: items, index: cursor + 1 };
    for (;;) {
      const item = readJsonValue(text, cursor);
      if (item.status !== "ok") return item;
      items.push(item.value);
      cursor = skipWhitespace(text, item.index);
      if (text[cursor] === ",") { cursor = skipWhitespace(text, cursor + 1); continue; }
      if (text[cursor] === "]") return { status: "ok", value: items, index: cursor + 1 };
      return { status: "syntax" };
    }
  }
  if (char === '"') {
    const string = readJsonString(text, index);
    return string.status === "ok" ? { status: "ok", value: string.value, index: string.index } : string;
  }
  for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
    if (text.startsWith(literal, index)) return { status: "ok", value, index: index + literal.length };
  }
  NUMBER_TOKEN.lastIndex = index;
  const token = NUMBER_TOKEN.exec(text);
  if (token) {
    const literal = token[0];
    if (/^-?[0-9]+$/.test(literal)) {
      const magnitude = BigInt(literal);
      if ((magnitude > MAXIMUM_SAFE_INTEGER || magnitude < -MAXIMUM_SAFE_INTEGER) &&
          magnitude !== BigInt(Number(literal))) {
        return { status: "error", code: "number_not_double_expressible" };
      }
    } else if (!Number.isFinite(Number(literal))) {
      return { status: "error", code: "invalid_number" };
    }
    return { status: "ok", value: Number(literal), index: NUMBER_TOKEN.lastIndex };
  }
  return { status: "syntax" };
}

function readJsonString(text, index) {
  if (text[index] !== '"') return { status: "syntax" };
  let end = index + 1;
  while (end < text.length) {
    if (text[end] === "\\") { end += 2; continue; }
    if (text[end] === '"') break;
    end += 1;
  }
  if (text[end] !== '"') return { status: "syntax" };
  try {
    const value = JSON.parse(text.slice(index, end + 1));
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) {
      return { status: "syntax" };
    }
    return { status: "ok", value, index: end + 1 };
  } catch (_error) {
    return { status: "syntax" };
  }
}

const JSON_WHITESPACE = /[ \t\n\r]/;

function skipWhitespace(text, index) {
  while (JSON_WHITESPACE.test(text[index])) index += 1;
  return index;
}

function decodeJsonText(text) {
  const value = readJsonValue(text, 0);
  if (value.status === "need-character" || value.status === "syntax") return fail("invalid_syntax");
  if (value.status === "error") return fail(value.code);
  if (skipWhitespace(text, value.index) !== text.length) return fail("trailing_bytes");
  return ok(value.value);
}

function decodeJsonBytes(bytes) {
  try {
    return decodeJsonText(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (_error) {
    return fail("invalid_encoding");
  }
}

const JSON_DEFAULT_LIMITS = {
  max_bytes: 1_048_576,
  max_depth: 64,
  max_object_members: 1_024,
  max_array_items: 4_096,
  max_string_bytes: 65_536,
};

const LIMIT_MAXIMUMS = {
  max_bytes: 1_048_576,
  max_depth: 64,
  max_object_members: 1_024,
  max_array_items: 4_096,
  max_string_bytes: 65_536,
  max_artifact_set_items: 1_024,
};

function validLimits(selected) {
  if (typeof selected !== "object" || selected === null) return false;
  return Object.entries(selected).every(([name, value]) =>
    name in LIMIT_MAXIMUMS && Number.isInteger(value) && value >= 0 && value <= LIMIT_MAXIMUMS[name]
  );
}

function jsonWithinLimits(value, bytes, selected = {}) {
  const limits = { ...JSON_DEFAULT_LIMITS, ...selected };
  if (bytes.length > limits.max_bytes) return fail("limit_exceeded");

  function visit(item, depth) {
    if (typeof item === "string") {
      if (Buffer.byteLength(item) > limits.max_string_bytes) throw new Error("limit");
      return;
    }
    if (Array.isArray(item)) {
      if (depth + 1 > limits.max_depth || item.length > limits.max_array_items) throw new Error("limit");
      item.forEach((child) => visit(child, depth + 1));
      return;
    }
    if (item && typeof item === "object") {
      const entries = Object.entries(item);
      if (depth + 1 > limits.max_depth || entries.length > limits.max_object_members) throw new Error("limit");
      entries.forEach(([key, child]) => {
        if (Buffer.byteLength(key) > limits.max_string_bytes) throw new Error("limit");
        visit(child, depth + 1);
      });
    }
  }

  try {
    visit(value, 0);
    return ok(value);
  } catch (_limit) {
    return fail("limit_exceeded");
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

const PROTECTED_MEMBERS = ["alg", "kid", "typ"];

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
    const headerKeys = Object.keys(header);
    if (headerKeys.length !== 3 || PROTECTED_MEMBERS.some((member) => !headerKeys.includes(member))) {
      return fail("protected_header_invalid");
    }
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

const TIMESTAMP_GRAMMAR = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function descriptorFromCompact(compact, predecessor = null) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const payload = decoded.value.payload;
  const keys = predecessor ? predecessor.payload.verification_keys : payload.verification_keys;
  const resolved = Array.isArray(keys) && keys.find((one) =>
    one.key_id === decoded.value.header.kid && one.algorithm === "Ed25519" && one.status === "active"
  );
  if (!resolved) return fail("descriptor_key_invalid");
  if (!verifyDecodedJws(decoded.value, "cap+party", keys)) return fail("signature_invalid");
  if (!TIMESTAMP_GRAMMAR.test(payload.effective_from) || Number.isNaN(Date.parse(payload.effective_from))) {
    return fail("timestamp_invalid");
  }
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
const EXTENSION_PROFILES = [
  { namespace: "com.example/pricing-indexed", owner: "Example Charter Profiles", criticality: "critical", state: "active", schema_digest: "sha-256:W88CU79l5r7YYCv2vuUTELifnM4GDKfbZPULSpDgQ2Y", a2a_uri: "https://example.com/charter-profiles/pricing-indexed", promoted_at_revision: null, surface: "charter_revision" },
  { namespace: "com.example/pricing-indexed-observation", owner: "Example Charter Profiles", criticality: "optional", state: "active", schema_digest: "sha-256:6e4emU-CATXhAVFi9XaIIZUzZbCAQBcGkVwJpkZzWk8", a2a_uri: "https://example.com/charter-profiles/pricing-indexed-observation", promoted_at_revision: null, surface: "receipt" },
  { namespace: "com.example.charter/default", owner: "Example Charter Profiles", criticality: "optional", state: "active", schema_digest: null, a2a_uri: "https://example.com/charter-profiles/com.example.charter/default", promoted_at_revision: null, surface: "receipt" },
  { namespace: "com.example/identity-vlei", owner: "Example Charter Profiles", criticality: "optional", state: "reserved", schema_digest: null, a2a_uri: "https://example.com/charter-profiles/identity-vlei", promoted_at_revision: null, surface: "party_descriptor" },
  { namespace: "com.example/identity-eidas-qeaa", owner: "Example Charter Profiles", criticality: "optional", state: "reserved", schema_digest: null, a2a_uri: "https://example.com/charter-profiles/identity-eidas-qeaa", promoted_at_revision: null, surface: "party_descriptor" },
  { namespace: "com.example/retired-profile", owner: "Example Charter Profiles", criticality: "critical", state: "retired", schema_digest: null, a2a_uri: "https://example.com/charter-profiles/retired-profile", promoted_at_revision: 1, surface: "charter_revision" },
];

function criticalRevisionProfile(namespace) {
  return EXTENSION_PROFILES.find((profile) =>
    profile.namespace === namespace && profile.criticality === "critical" &&
    profile.state === "active" && profile.surface === "charter_revision"
  ) || null;
}

function extensionRegistryDigest() {
  const document = Object.fromEntries(EXTENSION_PROFILES.map((profile) => [
    profile.namespace,
    {
      namespace: profile.namespace,
      owner: profile.owner,
      criticality: profile.criticality,
      state: profile.state,
      schema_digest: profile.schema_digest,
      a2a_uri: profile.a2a_uri,
      promoted_at_revision: profile.promoted_at_revision,
    },
  ]));
  return taggedHash("extension_registry", Buffer.from(canonical(document)));
}

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
  const optional = value.extensions?.optional || {};
  const names = [...Object.keys(critical), ...Object.keys(optional)];
  if (names.some((namespace) => Buffer.byteLength(namespace) > 512 || !/^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9.-]*$/.test(namespace))) {
    return fail("extension_namespace_invalid");
  }
  if (new Set(names).size !== names.length) return fail("extension_duplicate");
  for (const namespace of Object.keys(critical)) {
    const profile = EXTENSION_PROFILES.find((entry) => entry.namespace === namespace);
    if (!profile || profile.state === "reserved") return fail("extension_unknown_critical");
    if (profile.state === "retired") return fail("extension_retired");
    if (profile.criticality !== "critical") return fail("extension_criticality_conflict");
    if (profile.surface !== "charter_revision") return fail("extension_scope_invalid");
    if (profile.schema_digest === null) return fail("extension_schema_unavailable");
    if (namespace === "com.example/pricing-indexed" && critical[namespace]?.formula !== "index_plus_spread") return fail("constraint_violation");
  }
  for (const namespace of Object.keys(optional)) {
    const profile = EXTENSION_PROFILES.find((entry) => entry.namespace === namespace);
    if (!profile || profile.state === "reserved" || profile.state === "retired") continue;
    if (profile.surface !== "charter_revision") return fail("extension_scope_invalid");
    if (profile.schema_digest === null) return fail("extension_schema_unavailable");
  }
  const bytes = Buffer.from(text);
  return ok({ value, bytes, digest: taggedHash("charter_revision_content", bytes) });
}

function acceptanceFromCompact(compact, revision, chain) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  if ((claims.revision_number === 1) !== (claims.prev_revision_digest === undefined)) return fail("acceptance_invalid");
  if (!TIMESTAMP_GRAMMAR.test(claims.accepted_at) || Number.isNaN(Date.parse(claims.accepted_at))) return fail("timestamp_invalid");
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
  if (!Array.isArray(input.revisions) || input.revisions.length === 0) return fail("chain_invalid");
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

function projectReceipt(claims, chain, governingDigest) {
  const claimedRevision = chain.accepted.find((one) => one.digest === claims.revision_digest);
  const governingMatch = governingDigest === "contested" ? "undetermined" :
    (governingDigest === claims.revision_digest ? "match" : "mismatch");

  if (claimedRevision) {
    const revision = claimedRevision.value;
    const charterId = revision.charter_id || claimedRevision.digest;
    const roles = new Set(revision.parties.map((one) => one.role));
    const deploymentMatched = revision.abp_bindings.some((binding) =>
      binding.party_role === claims.agent_party_role &&
      binding.deployment_digest === claims.deployment_digest
    );
    const recognized = claims.charter_id === charterId &&
      claims.revision_number === revision.revision_number &&
      roles.has(claims.issuing_party_role) && roles.has(claims.agent_party_role) &&
      deploymentMatched;

    return recognized ? ok({ governingMatch, chainConflict: "none", deploymentMatched: true }) :
      fail("receipt_claims_mismatch");
  }

  const roles = new Set(chain.accepted.flatMap((one) => one.value.parties.map((party) => party.role)));
  const recognized = claims.charter_id === chain.charterId &&
    roles.has(claims.issuing_party_role) && roles.has(claims.agent_party_role);
  if (!recognized) return fail("receipt_claims_mismatch");

  const acceptedHead = Math.max(0, ...chain.accepted.map((one) => one.value.revision_number));
  const chainConflict = claims.revision_number <= acceptedHead ? "fork_evidenced" : "none";
  return ok({ governingMatch, chainConflict, deploymentMatched: false });
}

function receiptSigningKeys(chain, claimedRevision, role) {
  const revisions = claimedRevision ? [claimedRevision] : chain.accepted;
  const keys = revisions.flatMap((revision) =>
    revision.value.parties
      .filter((party) => party.role === role)
      .flatMap((party) => {
        const descriptor = chain.descriptors.descriptors.find((one) =>
          one.digest === party.party_descriptor_digest
        );
        return descriptor?.payload.verification_keys || [];
      })
  );
  return [...new Map(keys.map((key) => [canonical(key), key])).values()];
}

function receiptFromCompact(compact, chain) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  if (claims.grant?.scheme === "bap" && claims.grant?.grant_digest === undefined) return fail("receipt_invalid");
  const optional = claims.extensions?.optional || {};
  for (const namespace of Object.keys(optional)) {
    const profile = EXTENSION_PROFILES.find((entry) => entry.namespace === namespace);
    if (!profile || profile.state === "reserved" || profile.state === "retired") continue;
    if (profile.surface !== "receipt") return fail("extension_scope_invalid");
    if (profile.schema_digest === null) return fail("extension_schema_unavailable");
  }
  const claimedRevision = chain.accepted.find((one) => one.digest === claims.revision_digest);
  const verifiedPublicKeys = new Set(
    receiptSigningKeys(chain, claimedRevision, claims.issuing_party_role)
      .filter((key) => verifyDecodedJws(decoded.value, "cap+receipt", [key]))
      .map((key) => key.public_key)
  );
  if (verifiedPublicKeys.size !== 1) return fail("signature_invalid");
  if (claims.decision === "rejected" && claims.outcome === "effect_committed") return fail("cross_field_invalid");
  const governingDigest = governing(chain, Date.parse(claims.occurred_at));
  const projection = projectReceipt(claims, chain, governingDigest);
  if (!projection.ok) return projection;
  return ok({ claims, digest: taggedHash("receipt_content", decoded.value.payloadBytes), ...projection.value, optionalExtensions: Object.keys(claims.extensions?.optional || {}).sort() });
}

function execute(one) {
  const input = one.input;
  switch (one.surface) {
    case "base64url.decode":
      return project(strictBase64url(input.text), (bytes) => ({ bytes_base64url: bytes.toString("base64url") }));
    case "json.decode": {
      if (!("text" in input) && !("bytes_base64url" in input)) return invalid("invalid_type");
      if (input.limits !== undefined && !validLimits(input.limits)) return invalid("invalid_limits");
      const bytes = "text" in input ? Buffer.from(input.text) : Buffer.from(input.bytes_base64url, "base64url");
      const decoded = decodeJsonBytes(bytes);
      if (!decoded.ok) return invalid(decoded.code);
      return project(jsonWithinLimits(decoded.value, bytes, input.limits), jsonProjection);
    }
    case "canonicalization.encode":
      if (input.tag === "integer") {
        const literal = input.text_value !== undefined ? input.text_value : String(input.value);
        if (/^-?[0-9]+$/.test(literal) && (BigInt(literal) > MAXIMUM_SAFE_INTEGER || BigInt(literal) < -MAXIMUM_SAFE_INTEGER)) return invalid("integer_magnitude");
        return valid({ text: literal });
      }
      if (input.tag === "object") {
        const names = input.members.map(([key]) => key);
        if (new Set(names).size !== names.length) return invalid("duplicate_member");
        return valid({ text: canonical(Object.fromEntries(input.members.map(([key, value]) => [key, value.value]))) });
      }
      if (input.tag === "string_codepoint") return invalid("invalid_encoding");
      if (input.kind === "improper_object") return invalid("invalid_type");
      return canonical(JSON.parse(input.text)) === input.text ? valid({ text: input.text }) : invalid("non_canonical_bytes");
    case "digest.hash":
      if (!("bytes_base64url" in input)) return invalid("invalid_type");
      if (input.tagged !== undefined) {
        if (typeof input.tagged !== "string") return invalid("invalid_type");
        const separator = input.tagged.indexOf(":");
        if (separator < 1) return invalid("digest_encoding_invalid");
        if (input.tagged.slice(0, separator) !== "sha-256") return invalid("digest_algorithm_unsupported");
        if (!/^[A-Za-z0-9_-]{43}$/.test(input.tagged.slice(separator + 1))) return invalid("digest_encoding_invalid");
        if (input.tagged !== taggedHash(input.domain || "charter_revision_content", Buffer.from(input.bytes_base64url, "base64url"))) return invalid("digest_mismatch");
      }
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
      if (!chain.ok || !Array.isArray(input.signed_revisions) || input.signed_revisions.length !== 2) {
        return invalid("acceptance_equivocation_invalid");
      }
      const facts = input.signed_revisions.map((signed) => {
        const revision = revisionFromText(signed.revision_text);
        return revision.ok ? acceptanceFromCompact(signed.compact, revision.value, chain.value) : revision;
      });
      if (facts.length !== 2 || facts.some((oneFact) => !oneFact.ok)) return invalid("acceptance_equivocation_invalid");
      const [left, right] = facts.map((oneFact) => oneFact.value.claims);
      const pairable = left.charter_id === right.charter_id && left.revision_number === right.revision_number &&
        left.party_descriptor_digest === right.party_descriptor_digest && left.party_role === right.party_role &&
        left.revision_digest !== right.revision_digest;
      if (!pairable) return invalid("acceptance_equivocation_invalid");
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
  const observedEntries = walk(root);
  if (observedEntries.length === 0 || observedEntries.length > MAXIMUM_CORPUS_FILES ||
      observedEntries.reduce((total, entry) => total + entry.size, 0) > MAXIMUM_CORPUS_BYTES) {
    throw new Error("corpus filesystem bounds");
  }
  const observedSizes = new Map(observedEntries.map((entry) => [entry.path, entry.size]));
  const indexBytes = readFileSync(join(root, "index.json"));
  if (indexBytes.length !== observedSizes.get("index.json")) throw new Error("index changed during read");
  const index = JSON.parse(indexBytes);
  if (canonical(index) !== indexBytes.toString()) throw new Error("non-canonical index");
  if (!exactKeys(index, ["applicability", "corpus_digest", "files", "format", "registry_digest", "total_cases"])) throw new Error("index shape");
  if (index.format !== INDEX_FORMAT || index.corpus_digest !== corpusDigest(index)) throw new Error("index identity");
  if (index.registry_digest !== CERTIFIED_REGISTRY_DIGEST) throw new Error("registry identity");
  if (rawHash(indexBytes) !== CERTIFIED_INDEX_SHA256_BASE64URL) throw new Error("uncertified index");
  const expectedFiles = ["index.json", ...index.files.map((entry) => entry.path)].sort();
  if (canonical(observedEntries.map((entry) => entry.path).sort()) !== canonical(expectedFiles)) throw new Error("file set");
  const cases = [];
  for (const entry of index.files) {
    const bytes = readFileSync(join(root, entry.path));
    if (bytes.length !== observedSizes.get(entry.path)) throw new Error("case file changed during read");
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

  const acceptedRevision = {
    digest: "known-revision",
    value: {
      abp_bindings: [{ party_role: "agent", deployment_digest: "known-deployment" }],
      charter_id: "known-charter",
      effective_from: "2026-01-01T00:00:00Z",
      parties: [
        { role: "issuer", party_descriptor_digest: "issuer-descriptor" },
        { role: "agent", party_descriptor_digest: "agent-descriptor" },
      ],
      revision_number: 2,
    },
  };
  const projectionChain = {
    accepted: [acceptedRevision],
    descriptors: {
      descriptors: [
        { digest: "issuer-descriptor", payload: { verification_keys: [{ key_id: "issuer", public_key: "issuer-key" }] } },
        { digest: "agent-descriptor", payload: { verification_keys: [{ key_id: "agent", public_key: "agent-key" }] } },
      ],
    },
    supersededDigests: [],
    charterId: "known-charter",
  };
  const knownClaims = {
    charter_id: "known-charter",
    revision_digest: "known-revision",
    revision_number: 2,
    issuing_party_role: "issuer",
    agent_party_role: "agent",
    deployment_digest: "known-deployment",
  };
  const knownProjection = projectReceipt(knownClaims, projectionChain, "contested");
  if (!knownProjection.ok || knownProjection.value.chainConflict !== "none" ||
      knownProjection.value.governingMatch !== "undetermined" || !knownProjection.value.deploymentMatched) {
    throw new Error("known receipt projection drifted");
  }
  const unknownProjection = projectReceipt(
    { ...knownClaims, revision_digest: "unknown-revision", revision_number: 2 },
    projectionChain,
    "known-revision",
  );
  if (!unknownProjection.ok || unknownProjection.value.chainConflict !== "fork_evidenced" || unknownProjection.value.deploymentMatched) {
    throw new Error("unknown receipt projection drifted");
  }
  const futureProjection = projectReceipt(
    { ...knownClaims, revision_digest: "future-revision", revision_number: 3 },
    projectionChain,
    "known-revision",
  );
  if (!futureProjection.ok || futureProjection.value.chainConflict !== "none") {
    throw new Error("future receipt projection drifted");
  }
  if (projectReceipt({ ...knownClaims, deployment_digest: "wrong" }, projectionChain, "known-revision").ok) {
    throw new Error("recognized receipt claim validation drifted");
  }
  const issuerKeys = receiptSigningKeys(projectionChain, acceptedRevision, "issuer");
  if (issuerKeys.length !== 1 || issuerKeys[0].public_key !== "issuer-key") {
    throw new Error("receipt issuer-key selection drifted");
  }
  if (jsonWithinLimits({ nested: [["xx"]] }, Buffer.from('{"nested":[["xx"]]}'), { max_depth: 2 }).ok) {
    throw new Error("JSON depth limit drifted");
  }
  if (jsonWithinLimits({ a: 1, b: 2 }, Buffer.from('{"a":1,"b":2}'), { max_object_members: 1 }).ok ||
      jsonWithinLimits([1, 2], Buffer.from("[1,2]"), { max_array_items: 1 }).ok ||
      jsonWithinLimits("é", Buffer.from('"é"'), { max_string_bytes: 1 }).ok) {
    throw new Error("JSON structural limit drifted");
  }
  if (criticalRevisionProfile("com.example/pricing-indexed") === null ||
      criticalRevisionProfile("com.example/retired-profile") !== null) {
    throw new Error("critical extension registry drifted");
  }
  if (extensionRegistryDigest() !== CERTIFIED_REGISTRY_DIGEST) {
    throw new Error("compiled extension registry identity drifted");
  }
}
