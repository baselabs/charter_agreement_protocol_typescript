import { createHash, createPublicKey, verify as nodeVerifySignature } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const INDEX_FORMAT = "charter-agreement-protocol-conformance-corpus-index";
const CASE_FORMAT = "charter-agreement-protocol-conformance-cases";
const REPORT_FORMAT = "charter-agreement-protocol-conformance-report";
const MAXIMUM_CORPUS_FILES = 64;
const MAXIMUM_CORPUS_BYTES = 33_554_432;
export const CERTIFIED_INDEX_SHA256_BASE64URL = "f--8DXp39J4wJkrpkD8ZTQpHkMlduX43Xvnz0HeObeA";
export const CERTIFIED_REGISTRY_DIGEST = "sha-256:u754joyHGcLCTm1LYV2s6eHauUUdDfJDwwyhbAbxvzc";
// The fourth certified identity — the specification digest over the spec
// set — is pinned in priv/release-metadata.json and enforced by the
// release-candidate gate; corpus verification does not consume it.

// The closed algorithm registry (docs/adr/algorithm-name-agility.md) — the
// TypeScript mirror of CharterAgreementProtocol.Algorithm: one row per
// accepted alg name, the minimum protocol_revision it is legal at, and the
// key algorithm it verifies with. RFC 9864's fully-specified Ed25519 names
// exactly the EdDSA-with-Ed25519-key operation, so both rows verify Ed25519.
const ALG_ROWS = [
  { name: "EdDSA", minProtocolRevision: 1, keyAlgorithm: "Ed25519", publicKeyBytes: 32, signatureBytes: 64 },
  { name: "Ed25519", minProtocolRevision: 2, keyAlgorithm: "Ed25519", publicKeyBytes: 32, signatureBytes: 64 },
  { name: "ML-DSA-44", minProtocolRevision: 3, keyAlgorithm: "ML-DSA-44", publicKeyBytes: 1312, signatureBytes: 2420 },
  { name: "ML-DSA-65", minProtocolRevision: 3, keyAlgorithm: "ML-DSA-65", publicKeyBytes: 1952, signatureBytes: 3309 },
  { name: "ML-DSA-87", minProtocolRevision: 3, keyAlgorithm: "ML-DSA-87", publicKeyBytes: 2592, signatureBytes: 4627 },
];
const ACCEPTED_PROTOCOL_REVISIONS = [1, 2, 3];

// The per-artifact binding rule: EdDSA at any accepted revision, Ed25519
// from revision 2, unknown revisions fail closed. Views mix revisions
// freely; the rule binds within one artifact.
function algBinds(alg: string, protocolRevision: number): boolean {
  const row = ALG_ROWS.find((one) => one.name === alg);
  return row !== undefined && ACCEPTED_PROTOCOL_REVISIONS.includes(protocolRevision) && protocolRevision >= row.minProtocolRevision;
}

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
  signature_registry: "charter-agreement-protocol/signature-registry",
  conformance_report: "charter-agreement-protocol/conformance-report",
  corpus_index: "charter-agreement-protocol/corpus-index",
};

const SURFACES = [
  "base64url.decode", "json.decode", "canonicalization.encode", "digest.hash",
  "schema.validate", "party_descriptor.verify", "descriptor_chain.verify",
  "charter_revision.decode", "acceptance.verify", "acceptance.equivocation",
  "termination.verify", "chain.verify", "chain.verify_profile", "governing_revision", "receipt.verify",
];

const CLASSES = [
  "valid", "boundary_near", "exact_bound", "maximum_plus_one", "invalid_encoding",
  "invalid_type", "invalid_constraint", "invalid_cardinality", "unknown_member",
  "missing_required", "non_canonical_bytes", "digest_mismatch", "signature_invalid",
  "chain_invalid", "descriptor_superseded", "descriptor_fork", "equivocation",
  "chain_fork", "profile_algorithm_outside", "profile_revision_outside", "profile_narrow_valid",
  "supersession", "precedence_selection", "outcome_indeterminate",
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
  "chain.verify_profile": ["profile_algorithm_outside", "profile_revision_outside", "profile_narrow_valid"],
  "governing_revision": ["precedence_selection"],
  "receipt.verify": ["valid", "invalid_constraint", "signature_invalid", "chain_fork", "outcome_indeterminate", "extension_optional_roundtrip", "invalid_encoding", "extension_invalid"],
};

// ---------------------------------------------------------------------------
// Public typed shapes
// ---------------------------------------------------------------------------

export type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | CanonicalValue[]
  | { [key: string]: CanonicalValue }
  // Boxed numbers carry float-ness through the reader when the lexeme had a
  // fraction or exponent; canonical() unwraps them before serialization.
  | Number;

export type Projection =
  | { tag: "null" }
  | { tag: "boolean"; value: boolean }
  | { tag: "integer"; value: number }
  | { tag: "float"; value: number }
  | { tag: "string"; value: string }
  | { tag: "array"; items: Projection[] }
  | { tag: "object"; members: [string, Projection][] };

export type DecodeResult = { ok: true; value: CanonicalValue } | { ok: false; code: string };
export type CaseResult = { status: "valid"; output: unknown } | { status: "invalid"; error_code: string };
export type CorpusFile = { path: string; sha256_base64url: string; cases: number };
export type CorpusIndex = {
  format: string;
  corpus_digest: string;
  registry_digest: string;
  total_cases: number;
  files: CorpusFile[];
  applicability: Record<string, Record<string, unknown>>;
};
export type ConformanceCase = {
  id: string;
  surface: string;
  class: string;
  input: Record<string, any>;
  expect: CaseResult;
};
export type LoadedCorpus = { index: CorpusIndex; indexBytes: Buffer; cases: ConformanceCase[] };
export type CaseOutcome = { id: string; surface: string; agree: boolean; expected: CaseResult; actual: CaseResult };
export type ConformanceReport = {
  format: string;
  agreement: boolean;
  exit_status: number;
  total: number;
  agreed: number;
  disagreed: number;
  corpus_digest: string;
  registry_digest: string;
  index_sha256_base64url: string;
  results: CaseOutcome[];
};
export type ReportOutput = { bytes: string; exitStatus: number };

type Result<T> = { ok: true; value: T } | { ok: false; code: string };
const ok = <T,>(value: T): { ok: true; value: T } => ({ ok: true, value });
const fail = (code: string): { ok: false; code: string } => ({ ok: false, code });
const valid = (output: unknown): CaseResult => ({ status: "valid", output });
const invalid = (code: string): CaseResult => ({ status: "invalid", error_code: code });
const project = <T,>(result: { ok: true; value: T } | { ok: false; code: string }, projector: (value: T) => unknown): CaseResult =>
  result.ok ? valid(projector(result.value)) : invalid(result.code);

// ---------------------------------------------------------------------------
// Internal working types — payload views are any-valued records: the JSON
// surfaces are validated at runtime by the closed grammar checks, and the
// exported API above stays strictly typed.
// ---------------------------------------------------------------------------

type AnyRecord = Record<string, any>;

interface JsonReader {
  status: string;
  value?: unknown;
  index?: number;
  code?: string;
}

interface CorpusEntry { path: string; size: number; }

type Domain = keyof typeof SEPARATORS;

export function canonical(value: CanonicalValue): string {
  if (value instanceof Number) return JSON.stringify(value.valueOf());
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("unsupported JSON value");
}

function rawHash(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("base64url");
}

function taggedHash(domain: Domain, bytes: Buffer): string {
  const preimage = Buffer.concat([Buffer.from(SEPARATORS[domain]), Buffer.from([0]), Buffer.from(bytes)]);
  return `sha-256:${rawHash(preimage)}`;
}

function exactKeys(object: unknown, keys: string[]): boolean {
  if (!object || typeof object !== "object" || Array.isArray(object)) return false;
  return canonical(Object.keys(object).sort() as string[]) === canonical([...keys].sort());
}

function walk(root: string, directory: string = root): CorpusEntry[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    const stat = lstatSync(path);
    if (stat.isDirectory()) return walk(root, path);
    if (!stat.isFile()) throw new Error("non-regular corpus entry");
    return [{ path: relative(root, path).split(sep).join("/"), size: stat.size }];
  });
}

function strictBase64url(text: unknown): Result<Buffer> {
  if (typeof text !== "string") return fail("invalid_type");
  if (text.includes("=")) return fail("base64url_padded");
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return fail("base64url_invalid");
  const bytes = Buffer.from(text, "base64url");
  return bytes.toString("base64url") === text ? ok(bytes) : fail("base64url_invalid");
}

// The I-JSON decoder mirror: duplicate member names, trailing
// non-whitespace, integer literals beyond the ECMAScript safe range, and
// numbers that cannot round-trip a double are rejected with the decoder's
// closed codes, in the decoder's own order.
const MAXIMUM_SAFE_INTEGER = 9007199254740991n;
const NUMBER_TOKEN = /(?:-?(?:0|[1-9][0-9]*))(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

function readJsonValue(text: string, index: number): JsonReader {
  index = skipWhitespace(text, index);
  const char = text[index];
  if (char === undefined) return { status: "need-character" };
  if (char === "{") {
    const members = new Map<string, unknown>();
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
    const items: unknown[] = [];
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
  for (const [literal, value] of [["true", true], ["false", false], ["null", null]] as [string, boolean | null][]) {
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
    // Float-ness follows the lexeme (fraction or exponent), never the value:
    // "0.0" and "2e0" are floats even though their double is integral, so the
    // tagged projection matches the reference decoder instead of collapsing.
    const boxed: CanonicalValue = /[.eE]/.test(literal) ? new Number(Number(literal)) : Number(literal);
    return { status: "ok", value: boxed, index: NUMBER_TOKEN.lastIndex };
  }
  return { status: "syntax" };
}

function readJsonString(text: any, index: any) {
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
    for (const codepoint of value) {
      const unit = codepoint.codePointAt(0);
      if ((unit >= 0xfdd0 && unit <= 0xfdef) || (unit & 0xfffe) === 0xfffe) {
        return { status: "error", code: "invalid_encoding" };
      }
    }
    return { status: "ok", value, index: end + 1 };
  } catch (_error) {
    return { status: "syntax" };
  }
}

const JSON_WHITESPACE = /[ \t\n\r]/;

function skipWhitespace(text: any, index: any) {
  while (JSON_WHITESPACE.test(text[index])) index += 1;
  return index;
}

export function decodeJsonText(text: string): Result<CanonicalValue> {
  const value = readJsonValue(text, 0);
  if (value.status === "need-character" || value.status === "syntax") return fail("invalid_syntax");
  if (value.status === "error") return fail(value.code as string);
  if (value.index === undefined || skipWhitespace(text, value.index) !== text.length) return fail("trailing_bytes");
  return ok(value.value as CanonicalValue);
}

function decodeJsonBytes(bytes: Buffer): Result<CanonicalValue> {
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
  max_artifact_set_items: 1_024,
  max_artifact_set_bytes: 67_108_864,
};

// The compiled maximums mirror lib/charter_agreement_protocol/limits.ex: the
// greatest caller-selectable value per field, not the defaults.
const LIMIT_MAXIMUMS = {
  max_bytes: 16_777_216,
  max_depth: 128,
  max_object_members: 65_536,
  max_array_items: 65_536,
  max_string_bytes: 1_048_576,
  max_artifact_set_items: 4_096,
  max_artifact_set_bytes: 1_073_741_824,
};

function validLimits(selected: AnyRecord): boolean {
  if (typeof selected !== "object" || selected === null) return false;
  const maximums: Record<string, number> = LIMIT_MAXIMUMS;
  return Object.entries(selected).every(([name, value]) =>
    name in maximums && Number.isInteger(value) && value >= 0 && value <= maximums[name]
  );
}

function jsonWithinLimits(value: any, bytes: Buffer, selected: AnyRecord = {}): Result<unknown> {
  const limits: Record<string, number> = { ...JSON_DEFAULT_LIMITS, ...selected };
  if (bytes.length > limits.max_bytes) return fail("limit_exceeded");

  function visit(item: any, depth: any) {
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

export function jsonProjection(value: any): Projection {
  if (value === null) return { tag: "null" };
  if (value instanceof Number) return { tag: "float", value: value.valueOf() };
  if (Number.isInteger(value)) return { tag: "integer", value };
  if (Array.isArray(value)) return { tag: "array", items: value.map(jsonProjection) };
  if (value && typeof value === "object") return { tag: "object", members: Object.entries(value).map(([key, item]) => [key, jsonProjection(item)]) };
  if (typeof value === "string") return { tag: "string", value };
  if (typeof value === "boolean") return { tag: "boolean", value };
  return { tag: "float", value };
}

const PROTECTED_MEMBERS = ["alg", "kid", "typ"];

function decodeJws(compact: unknown): Result<{ header: Record<string, string>; payload: AnyRecord; payloadBytes: Buffer; signature: Buffer; signingInput: Buffer }> {
  if (typeof compact !== "string") return fail("compact_invalid");
  if (Buffer.byteLength(compact) > JSON_DEFAULT_LIMITS.max_bytes) return fail("limit_exceeded");
  const segments = compact.split(".");
  if (segments.length !== 3) return fail("compact_invalid");
  const decoded = segments.map(strictBase64url);
  if (decoded.some((one) => !one.ok)) return fail("compact_invalid");
  const headerBytes = (decoded[0] as { ok: true; value: Buffer }).value;
  const payloadBytes = (decoded[1] as { ok: true; value: Buffer }).value;
  // Strict I-JSON decode under the default ceilings — the reference verifier
  // never hands raw JSON.parse bytes; every header/payload failure maps to the
  // framing-layer code the reference decoder emits for that segment.
  const headerValue = decodeJsonBytes(headerBytes);
  if (!headerValue.ok) return fail("protected_header_invalid");
  const payloadValue = decodeJsonBytes(payloadBytes);
  if (!payloadValue.ok) return fail("non_canonical_bytes");
  const header = headerValue.value as Record<string, string>;
  const payload = payloadValue.value as Record<string, unknown>;
  const headerKeys = Object.keys(header);
  if (headerKeys.length !== 3 || PROTECTED_MEMBERS.some((member) => !headerKeys.includes(member))) {
    return fail("protected_header_invalid");
  }
  if (canonical(header as unknown as CanonicalValue) !== headerBytes.toString() || canonical(payload as unknown as CanonicalValue) !== payloadBytes.toString()) return fail("non_canonical_bytes");
  const revision: unknown = payload.protocol_revision;
  if (typeof revision !== "number" || !Number.isInteger(revision) || !algBinds(header.alg, revision)) return fail("protected_header_invalid");
  // Per-row signature length: checked only after the header names the
  // algorithm (64 for the classical rows, 2420/3309/4627 for ML-DSA).
  const row = ALG_ROWS.find((one) => one.name === header.alg);
  const signature = (decoded[2] as { ok: true; value: Buffer }).value;
  if (!row || signature.length !== row.signatureBytes) return fail("signature_invalid");
  return ok({ header, payload, payloadBytes, signature, signingInput: Buffer.from(`${segments[0]}.${segments[1]}`) });
}

const ED25519_FIELD_PRIME = 2n ** 255n - 19n;
const ED25519_SUBGROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const ED25519_SMALL_ORDER_POINTS = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
].map((hex) => Buffer.from(hex, "hex"));

function decodeLittleEndian(buffer: Buffer): bigint {
  let value = 0n;
  for (let index = buffer.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(buffer[index]);
  return value;
}

// Strict point check mirroring Signature.strict_point?/1: the y coordinate is
// canonical, the negative-zero spelling is rejected, and the complete
// eight-point torsion set is refused before OpenSSL sees the key or R.
function strictEd25519Point(point: Buffer): boolean {
  if (point.length !== 32) return false;
  if (ED25519_SMALL_ORDER_POINTS.some((one) => one.equals(point))) return false;
  const prefix = point.subarray(0, 31);
  const last = point[31];
  const y = decodeLittleEndian(Buffer.concat([prefix, Buffer.from([last & 0x7f])]));
  const negativeZero = (last & 0x80) !== 0 && (y === 1n || y === ED25519_FIELD_PRIME - 1n);
  return y < ED25519_FIELD_PRIME && !negativeZero;
}

function ed25519(rawKey: string, message: Buffer, signature: Buffer): boolean {
  try {
    const key = Buffer.from(rawKey, "base64url");
    if (signature.length !== 64 || key.length !== 32) return false;
    if (!strictEd25519Point(key)) return false;
    const r = signature.subarray(0, 32);
    const s = signature.subarray(32);
    if (!strictEd25519Point(r)) return false;
    if (decodeLittleEndian(s) >= ED25519_SUBGROUP_ORDER) return false;
    const prefix = Buffer.from("302a300506032b6570032100", "hex");
    const spki = createPublicKey({ key: Buffer.concat([prefix, key]), format: "der", type: "spki" });
    return nodeVerifySignature(null, message, spki, signature);
  } catch (_error) {
    return false;
  }
}

const ML_DSA_SPKI_PREFIXES = {
  "ML-DSA-44": Buffer.from("30820532300b06096086480165030403110382052100", "hex"),
  "ML-DSA-65": Buffer.from("308207b2300b0609608648016503040312038207a100", "hex"),
  "ML-DSA-87": Buffer.from("30820a32300b060960864801650304031303820a2100", "hex"),
};

function mldsa(keyAlgorithm: string, rawKey: string, message: Buffer, signature: Buffer): boolean {
  try {
    const key = Buffer.from(rawKey, "base64url");
    const prefixes: Record<string, Buffer> = ML_DSA_SPKI_PREFIXES;
    const prefix = prefixes[keyAlgorithm];
    if (!prefix || !signature || signature.length === 0) return false;
    const spki = createPublicKey({ key: Buffer.concat([prefix, key]), format: "der", type: "spki" });
    return nodeVerifySignature(null, message, spki, signature);
  } catch (_error) {
    return false;
  }
}

// Key resolution follows the registry: the kid-resolved active key's
// algorithm must equal the envelope row's keyAlgorithm, and its decoded
// byte length must equal the row's exact value.
function keyMatchesRow(key: AnyRecord | undefined, row: any): boolean {
  if (!key || key.algorithm !== row.keyAlgorithm || key.status !== "active") return false;
  const bytes = Buffer.from(key.public_key, "base64url");
  return bytes.length === row.publicKeyBytes && bytes.toString("base64url") === key.public_key;
}

function verifyDecodedJws(decoded: { header: Record<string, string>; signingInput: Buffer; signature: Buffer }, typ: string, keys: any[]): boolean {
  const row = ALG_ROWS.find((one) => one.name === decoded.header.alg);
  if (!row || decoded.header.typ !== typ || typeof decoded.header.kid !== "string") return false;
  const key = keys.find((one) => one.key_id === decoded.header.kid && keyMatchesRow(one, row));
  if (!key) return false;
  return row.keyAlgorithm === "Ed25519" ?
    ed25519(key.public_key, decoded.signingInput, decoded.signature) :
    mldsa(row.keyAlgorithm, key.public_key, decoded.signingInput, decoded.signature);
}

const TIMESTAMP_GRAMMAR = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/;

// Exact RFC 3339 UTC parse mirroring Timestamp.ex: real calendar date, hour
// 0..23, minute 0..59, second 0..59 with :60 reserved for 23:59 on June 30 and
// December 31, fractions kept as trimmed decimal strings. The tick coordinate
// preserves the leap-second slot; fraction comparison pads to equal width, so
// sub-millisecond precision never truncates the way Date.parse does.
function parseTimestamp(value: unknown): { ticks: number; fraction: string } | null {
  if (typeof value !== "string") return null;
  const match = TIMESTAMP_GRAMMAR.exec(value);
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year < 1) return null;
  const utc = Date.UTC(year, month - 1, day);
  const date = new Date(utc);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
  if (hour > 23 || minute > 59 || second > 60) return null;
  if (second === 60 && !(hour === 23 && minute === 59 && ((month === 6 && day === 30) || (month === 12 && day === 31)))) return null;
  const days = Math.floor(utc / 86400000);
  const base = days * 86400 + hour * 3600 + minute * 60 + Math.min(second, 59);
  return { ticks: base * 2 + (second === 60 ? 1 : 0), fraction: (match[7] || "").replace(/0+$/, "") };
}

function compareTimestamps(left: { ticks: number; fraction: string }, right: { ticks: number; fraction: string }): number {
  if (left.ticks !== right.ticks) return left.ticks < right.ticks ? -1 : 1;
  const width = Math.max(left.fraction.length, right.fraction.length);
  const paddedLeft = left.fraction.padEnd(width, "0");
  const paddedRight = right.fraction.padEnd(width, "0");
  if (paddedLeft === paddedRight) return 0;
  return paddedLeft < paddedRight ? -1 : 1;
}

function descriptorFromCompact(compact: string, predecessor: { digest: string; payload: AnyRecord } | null = null) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const payload = decoded.value.payload;
  const keys = predecessor ? predecessor.payload.verification_keys : payload.verification_keys;
  const descriptorRow = ALG_ROWS.find((one) => one.name === decoded.value.header.alg);
  const grammar = keyGrammarError(payload);
  if (grammar) return fail(grammar);
  // The descriptor timestamp floor mirrors the reference SCHEMA-stage
  // constraint (checked before key resolution and signature work there):
  // a spelling outside 1..64 BYTES is not a legal member value — the same
  // floor the seven sibling timestamp members carry. Byte length, not
  // UTF-16 units.
  if (typeof payload.effective_from !== "string" ||
      Buffer.byteLength(payload.effective_from, "utf8") < 1 ||
      Buffer.byteLength(payload.effective_from, "utf8") > 64) {
    return fail("constraint_violation");
  }
  const resolved = Array.isArray(keys) && keys.find((one) =>
    one.key_id === decoded.value.header.kid && keyMatchesRow(one, descriptorRow)
  );
  if (!resolved) return fail("descriptor_key_invalid");
  if (!verifyDecodedJws(decoded.value, "cap+party", keys)) return fail("signature_invalid");
  if (!parseTimestamp(payload.effective_from)) {
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

// The key-grammar gate mirrors the reference codec's two stages: an unknown
// key algorithm or a wrong-length encoding fails the nested schema constraint
// (nested_invalid), while an ML-DSA key inside a revision-1 or revision-2
// descriptor passes the schema and rejects at the codec's revision gate
// (descriptor_invalid) — no honest producer could have minted it.
function keyGrammarError(payload: AnyRecord): string | null {
  if (!Array.isArray(payload.verification_keys) || payload.verification_keys.length === 0) {
    return "nested_invalid";
  }
  for (const one of payload.verification_keys) {
    // Malformed entries carry the typed code, never a dereference throw -
    // the pre-sign claims gate and the verify path share this walk.
    if (!one || typeof one !== "object" || typeof one.algorithm !== "string" || typeof one.public_key !== "string") {
      return "nested_invalid";
    }
    const row = ALG_ROWS.find((candidate) => candidate.keyAlgorithm === one.algorithm);
    if (!row) return "nested_invalid";
    const bytes = Buffer.from(one.public_key, "base64url");
    if (bytes.length !== row.publicKeyBytes || bytes.toString("base64url") !== one.public_key) {
      return "nested_invalid";
    }
    if (one.algorithm !== "Ed25519" &&
        !(Number.isInteger(payload.protocol_revision) && payload.protocol_revision >= 3)) {
      return "descriptor_invalid";
    }
  }
  return null;
}

function descriptorChain(compacts: string[]) {
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

function criticalRevisionProfile(namespace: string) {
  return EXTENSION_PROFILES.find((profile) =>
    profile.namespace === namespace && profile.criticality === "critical" &&
    profile.state === "active" && profile.surface === "charter_revision"
  ) || null;
}

function extensionRegistryDigest(): string {
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

function revisionFromText(text: unknown): Result<{ value: AnyRecord; bytes: Buffer; digest: string }> {
  if (typeof text !== "string") return fail("revision_invalid");
  let value;
  try { value = JSON.parse(text); } catch (_error) { return fail("invalid_syntax"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail("revision_invalid");
  const unknown = Object.keys(value).find((key) => !REVISION_FIELDS.includes(key));
  if (unknown) return fail("unknown_member");
  const missing = REVISION_REQUIRED.find((key) => !(key in value));
  if (missing) return fail("missing_required");
  if (!Array.isArray(value.parties) || new Set(value.parties.map((one: any) => one.role)).size !== value.parties.length) return fail("revision_invalid");
  if (!Array.isArray(value.termination_rules.reason_codes) || value.termination_rules.reason_codes.length === 0) return fail("nested_invalid");
  if (value.revision_number === 1 && (value.supersedes !== undefined || value.prev_revision_digest !== undefined || value.charter_id !== undefined)) return fail("revision_invalid");
  if (value.supersedes !== undefined && (!Array.isArray(value.supersedes) || value.supersedes.some((one: any) => typeof one !== "string"))) return fail("revision_invalid");
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

function acceptanceFromCompact(compact: string, revision: { value: AnyRecord; digest: string }, chain: { descriptors: { digest: string; payload: AnyRecord }[]; positions: Record<string, string> }) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const acceptanceShape = acceptanceClaimsError(claims);
  if (acceptanceShape) return fail(acceptanceShape);
  const descriptor = chain.descriptors.find((one) => one.digest === claims.party_descriptor_digest);
  if (!descriptor || !verifyDecodedJws(decoded.value, "cap+acceptance", descriptor.payload.verification_keys)) return fail("signature_invalid");
  const expectedCharter = revision.value.charter_id || revision.digest;
  const party = revision.value.parties.find((one: any) => one.party_descriptor_digest === claims.party_descriptor_digest);
  const mismatch = claims.charter_id !== expectedCharter || claims.revision_number !== revision.value.revision_number || claims.revision_digest !== revision.digest || claims.party_role !== party?.role || (revision.value.prev_revision_digest || undefined) !== (claims.prev_revision_digest || undefined);
  if (mismatch) return fail("acceptance_claims_mismatch");
  return ok({ claims, digest: taggedHash("acceptance_content", decoded.value.payloadBytes), descriptorPosition: chain.positions[claims.party_descriptor_digest] });
}

function terminationFromCompact(compact: string, revision: { value: AnyRecord; digest: string }, chain: { descriptors: { digest: string; payload: AnyRecord }[]; positions: Record<string, string> }) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const descriptor = chain.descriptors.find((one) => one.digest === claims.party_descriptor_digest);
  if (!descriptor || !verifyDecodedJws(decoded.value, "cap+termination", descriptor.payload.verification_keys)) return fail("signature_invalid");
  const expectedCharter = revision.value.charter_id || revision.digest;
  const party = revision.value.parties.find((one: any) => one.party_descriptor_digest === claims.party_descriptor_digest);
  if (claims.charter_id !== expectedCharter || claims.governing_revision_digest !== revision.digest || claims.party_role !== party?.role || !revision.value.termination_rules.reason_codes.includes(claims.reason_code)) return fail("termination_claims_mismatch");
  const terminationShape = terminationClaimsError(claims);
  if (terminationShape) return fail(terminationShape);
  return ok({ claims, digest: taggedHash("termination_content", decoded.value.payloadBytes), descriptorPosition: chain.positions[claims.party_descriptor_digest] });
}

// Chain-level structural checks mirroring Chain.verify: unique revision
// digests, exactly one genesis defining one charter identity, exact
// predecessor linkage, well-formed supersession targets, unique acceptance
// coordinates, dual acceptance against the revision's actual party pairs (any
// two roles — never hardcoded names), verified termination notices, and the
// reference topology/governing semantics with ancestry coverage.
// The capability probe mirror: one verifiable verdict per registry row,
// derived from the SAME pinned known-answer vectors as the reference
// implementation (identical bytes; a capable runtime must verify each
// triple). Linked-crypto identity is informational only — it never decides
// a verdict.
const KNOWN_ANSWER_MESSAGE = Buffer.from("charter-agreement-protocol capability known-answer");

const KNOWN_ANSWERS: Record<string, { publicKey: string; signature: string }> = {
  "Ed25519": {
    publicKey: "GzQZjEZ9YYJWL3R3uwR0owiJSd55-Dl33NgTbuWBewc",
    signature: "-H0dvAgkit6g5XUHSeemuI_1BQK2ZZaip-cskYhB6Jv2YNBAASg3B57dXW30ezxbH9YVPgWc3TA3qx74TN5UDA",
  },
  "ML-DSA-44": {
    publicKey: "eZXohjF26xlaoAtC8VRJ1q3BslIgF8E7VmFo-eakCL6nkVT5WNKGnswbF-MpIn-5dushxTjsPHGpJ--TRc3PIUTXc48LRWsrR5oaTIPNicT-dIFInl9geCmg_-2QFYvT7-gHjQWz2EhUbCxRt3lHIyRRyYRadtkRL6c8LV6eTnhYo9rJjhmwPl9eVvYfgF-LCY-Qe3ZUUYGiwoh5K0KAZmH5ttDV8Y78xyFwWwB24nNNqTGgo5nc-G35yWKwHY9CI_xSkZ5XtdGjLY0R2zmYYMEvubfdxVyFM38_oG7qglm-4W92j4kmXhX4_rR-UKQD4_GjBK57jtHMjE9ClmrPjn4ACjP1XeSVED71VAhbuRKvE_h1t746u_GkdoPTWZfLToJTiTRFOlQ1NDHxSo8MkbRwRuqTYolxl9M-Ndoc_RxFoXVjQTheib6Q3Xpt_JP0mt9i1keuVWOf5ufirUg6pox-M_uZ5gySLbARLeUx-HXAYtxbGAQuWhG8cALf2unHOVwBVHvvO3n9Fss5Zf39Ib4v_XoBtI7rMnVooTLfWqm2__PofD03vlOELeErYRdtxumwZOpHPCbO9fH9TOEJqTW42xL4e84cftGHBEORxi99cHynTnzf1IZbK3jRALPlMrpmXwO-UXUr_MMb2E3udaIa43Egn-A54RJfAu8kg27a2tjSGlpyX4JMu44lGHgZdFDtlqTsejhuK1JjqvCAYMcqKhaZxdiqrvR3doUcSOj0isrSEAoalwF1WJlU0ke3OnYVJC6MslpW_4O6iJHTPDLv_9rzVLp5BsQBuQT-9vbsRm7YaHkO043yACmWXmcC__DKGXAGkBlbMNM9kidMfOXjTjXcHeKWn1kc1BgCm2sBMtqajV8qs-0689RwNXCcIUWVUDc2VUx-P7lVcsxXKwiOBrT472nQo7E28Rl6rSQsy3MBE38U1puQpHAh9BVBddxV1d9Nt7zuRH1ha8yPBN-RckdvZEeMpcG_p89NW-jz31uDXqMfOB_wseNre9vwFW4H4BcUlUrhWmTgqbuOZI_-Bl62GvQPLxP4AvlfDcROaL2h-srGCJRdKPTtExqhwfrKsi2Aa8QY0QZps3F35xK2Cv4Y0eHtCZ6ZzbmM6BUJlEI7cby9Hn5A1-usebldtChzNnRcaoBN2oqYxgYlPAPrzvNx862pox9MayFoEsjQZrM7xZEyvxvisXyz87Ow2UPMdv_D_qPfu3sW9WDaT0Jck_JVV08nrbmdwhfTctROu3Jv5UhzgdyrkXIgTRKXcePaY5ppW6ILOWeug1QU8Ztdmbo-zCKBNr0B_bpNasATaPE1rBbektfIVDsxE_nWStrzSRm9YAgDs0tLKYxJCO6D0UggHRlo7Q8XzBmcGTxpEbws5Qg6FyhDQP-E364XIvcpHNhkLXdH4QTdla5OYBVqA46cE-gJwmhPGVVV0cTkgzXtkqwmt3g6UxNQuepeY9DfBosu4EAUnrb2PCX5ifmwaTFbd89omGZMrlS9BpJwCH0HCB8oQhcCVa4K9Kck1i2IEj0std5m53pNODVN2dBUg0X7OpUdyR5DDD2gjK1CCYT8qPCP6mHrRK0SA2ERZ5f391vg8rCrh9Q_t4UGPWW1RJB6t0ojwXuCdp_2-kvB4vciGiyTQIGVV77-WXUAZC6FOona-tpLbIfEURpwezhOC-ntE4bpxGlBnLoxNDe5xDs8PBlq6a3fspLWTEMcQSsnR-VtVKYHqwJFkB6n4w",
    signature: "4RmdiYiFwEgDeFnBEH8usSmDVeU8YAPB1q4d1rsOz0uYJPZfnAiHF5ZvUBe_ptbfsEAkamgZ_UwwsMV9ZF9ryITkQicTsTdmeT9a7r4EupC2RatHn7SUz5AGRbNoZSgDnfGkPyVFPIJcR73U-pW_RvVIyMfCPh7snUAZVuX-kGiUSQ0wr1RxNKpz4N0Ov2VeHfnojAo2VUD7e5z2NaP3EHhfkD50m2TnzNCrc8ov8i79uSac-YaqQQrtjcoe5Ka9UTgvB2FWjBCsTy7Zp-y21Jqh8LbUeO-kKmCxcmQ2cR167EJ2rLhz6NRYThxzD_YN6aBgGRhgZI_ndrYEtW2BOMewYxMeJzlHQQtKBzyWoWiFJPUVAId5b2ptO2Qx8RCEhbg2f9DcFSWL03JdKqJngeyCLmSKHMrU9hagRYJufrxQwRugYaIArJz69EIzf6yACI7iPQIIilfzBGeXzh2bErBL0wDsGNywkwgHQgzzbItg6KWUzwO8IbfTJfDqm40Xqcw4QGA4hBoFwRo2cxTZHbg3DKMxMhqNrqwzlajOYXcC2UZ7BmYeG27lJ6mJS2lgc8kTIFdSt-wIDAdNRZAPTXiAhZja99ZOB306nTnu-q4yclzVWqWEipH6L9_JlyGQiliBG1OJ9y-t7cGR-hTlvKtw4WWqwxEJz81Kx0AixAFd8590imXsxu705x4Wj6Uk5NyIEXgo4J4W7Jh20iA2u_wKV3tIFjHNciRC2SR0cAwyC486_pXCVV2tu-4rP16NVCfSM94k_iB3RJ24Kk9MwWaSRU0Uq7oGJpApyyM1t1qo1iedjlGMgboBSNZwxEpGjJ5SePq3n90QOmWVaNiECAz_P_wiNwn8yNrhaGgSuF-47baBX4-5oVSOea1MqdwBin6xnBY8bBeiFSolpwkys28zGJwIgs1XR_MTUcyiLl4TpHfYvtgZd58BboRSqi2oY4aCHycckJY-Z2RWV74Qma6lIBVw-iq2CUth0iX88p1BylzxV-3OFn20ZVBzT0eVgp-5Ivceo_VJeROUvCNmpShqA3XhAEBsQDP-kJm3C9rEyFA_4FtiDoxD2mO3kOp1Uwix5SLYiByN4Q8NwIRwhX3lMhks_scHVYdCQtIqRqDi3F1DWW_1BG0oH_T8VGEHiSveeKImR7rief4Hso1u7j8iWs_Qh06aIG1iyFkVLIg-XqMXBcwOU-aMtdNxaYlphLqeYRuUdWnaLUunZ12f4vPTVIhlOMZjBobs1_GEkCFSKJsw1Eb2dB93D2ivihT1PcLmnW6ZJfebp6a6uGQULYDBluoZCmjqcZhNQYvKxPP62sPfExse6bAI-3bZgCr7O-OW0N5Y0fgxIbNhWJ5S2bbPr-97nwI3PdZpn41F6jOsvfPkXeAUTPmOakiJZB42xnKJCzmeYUMDsuJfd4GkncyWJr1a0zGkFnzaurbYAa2t20BmpFqoXYM0v6DvdyAlreJUnVYcaUZdkt3MomcR3Vn9nck7Bi41umZRCfQ5Bsycf4zjsDB0gTboBS-s21_6lAyXuWHyvS0Mv_yy0x8zjnf6bhXdXyg9cMXqoiTIWoU6cmu1Z6tJNzHfw_zxQNE16xsVcIfm_iAJrHt2Qa_2V-98YojOYHgQ_XZ4Ef_lrqxA6Incd8qwRSzKGkZ8NO9d2tVoYf2vNbbuwMWtlDZYEkKFvfcMPu7dsLuiQ17j4BBjIoHEFRxdycJQscucHsnA0LAUFsXJ0Fa2EYZdRw-CoQ1RKXzSzKb1q7H2cM9mdZx2ULHzwrFXIPaBVACt_3UxA3ZjJnb7E6ZrI0DSYKLm2GpkGvg8EseRXix0a421KgqTFRXtDaFb8Y2N3_B2tp3kU8gobxfIYSX-KbEA9NcyoDkDphLwtHymCCuHbD01Nv5Hb2SoKcuiEUIbKDvDmOq-ODxHtpTyeH7yy4is05Nnru3vphyNd11GAWmF2Wp3aRBmZSdm5FDq6zgiTll3ytS7Bri3OyriUEJuGxaYLIfQn5QWonoY_4wVux2YMU7v8cbLAaPZnRYX2Gx5lvvxXPDnd9olnHLKEufFd5lXUrZJ5KD7zItEu_gTKyghrFDtnWqaryEfaQF5gXJTRQuIBGxcAw8mGWrzTru_lz3mvauXN3vTeIAy3r14zUl2oBR3LSFQm-0QY83EbQtdHY3DfuHojX5JD76sIac0FaNe_6yjL8PBw9VLQCDtEP9vp1MrDTWZt9WpurPOdBbE1ZLpflTuu3WD0Gpx9oIruHbSsUqXJcwTXnPavAmP9EBB1A_rOKplyoVUNuuqPtu-B0UX_DAKSVmphHJelL5dWrdm45w63_IkVttYX-drUeYPp32kIG-ij747SrIf-_fQEsRVnKDH9zhjxGX3lZ5N19ootgBrX2NMOQRwswHXM3_A4ahguBmfrS4ndVzLe5zA-IFlv74cjDJNaYJUwplYcdla1sdWjl38tvOTKfHMhI2yD-JhcE_0w3D7ZA7q1JOUcisippMeYxOBkFg8U65EUXQ4wHr5n_LuB6-oEOdx5Ry3MJgyflmUO1Aa6jEJ9RZ04t7zVqbaRhPQXb0MY3HyErSYDz-tzhO5kuVHhoTmALu1-tuXSHgk4l-XJTpT4DdKoVnGSA8j7jszVQd2W5AmeSjJ2BiC9TWlVo8orS6qMNQdgoOkE-lPIAWFl1Vgghv3PEgmiO0SvFX_Typ2XsKyMtVfD4GLkgrHNKQMO8NvzrtLMsH9TWhfg9qsgD8vqNDOM9wuCSZwlTHakl-3avFifsO4QmiBCfM9tFfHJdxyvPo5Xpo6xhSaT6yAVP6_x-8_8QU4Ymuw6YsK5L4VIwNabAX0xTo4-Fi9cGTUUrZoFNxKkaDM7pAij10EugkhOko0QuQqPPODRcuwoNTWshs3fqLYNMxO8cEKZma3oXAv06e_ktuPsW7PBZEynBVxK4yTVJmBKGG8EoCUXZ9MqPaLnLU58sQ3aDeinTE1JH8O3khJJePdTPENIkZ0a7NJmKmUwuOS1NL-9CJyuqHu8nsk2vWnWDS0joah21qqe_SJ-B_MBhepQkFL-fjp9oNg4kd46hEsTZgV80aaQXPwOUE-JzLvUA13nDW3aeziJWUEk9kbLoArlaw4PkJQcHmLo7bCxgQNESMlNUxOVmNzdYKQlqy4xOfzAg0PFzxFVoGRutPjLTE3QUJph4-0uLzb3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsfKzg",
  },
  "ML-DSA-65": {
    publicKey: "C4pFSZOaGQCePNdFL0X4fkl0J3TMtrkIxlz7cllPnPP85C94zKV91cQ-Us7OJO5acJHSCRO6_jcRqRfPqyyHXMDD2MOoS1vLPOGcLk1M-ECTVJtTa5K6eMrP_K2McyL_GbXS7qE6HK0VflbB6c9b2_HZGmCRseG784CkmhhuQ7hNs_RGlp1slfR431NtQ__ESCFc5GCemF_owXHOFHhGezOYJDqjLWCRcfSQ4zhMX4jaZbVRDEhxJesWQtL5NIRLX_sob5wPfiEtnowrfsSL2B6zBpuGkppLr6_Vs_ZFSwvr5ELMidcmStMOpA1uC91pXNj-qHE4uFO_DBIRZQmJa41q72elXg1phQ5yKgO_ORwuJBo2JvXBofyIeNc6pMqnbcXdsPMFfYPBBxNY7O7Ax6JuvHGmLCqMd5K6MhTtwy4xudZNwjMr5VEuIj6jMiCyuQ7XBePtgmJwqQU7FvWG1gxK0L3Zr2gf31QOL-ACWzIrC41oZZIJzteRsQaK5QFCos37leUnUSTFZx0UWRxihMINmpZyR2xDRRFtLbYTG2CyBRSORxr129gqackxexXeEwrRoKkzEJjnQIRQOSd0F1AHzbaATCte97scQ2ISlZsLg8P9Y-uGej_0QYibk0SJWRGldllZcTZm6gBDnipLjQFdHrnX0VNqD2o5sEWQWFILri-ropDD4ry_DSHqbFtVE20DL5KZuhA7Pkir9JQrNISbYtjjHLeyK0Q4wfiBbEuC-LXE_dwhzvkAabavhpRS9kbblKTj7Iew5h26MVNbSAIOFaLsSl-ivubTkreQmc2rP15J3dLAW7JMy6zpVRj4OaMGks8wMOnWnDQ4FU7tOfpDDIzRz8PVsbP1OMT3t1fUhPply90v4hd_d7W4kziSBah9M9YZZEouCt_yzJNSBZWOAgvoL059qbO8UHa6B4PqhtprIjgVrCWDXqpBFxe-0-9pdkDHsMBDaieF8cDe77w_ZbjvaQQNsqTdDNEaues8Q-zI0cJrsMwpfNjBZkNPvK3Jj1cFWUnJ7jzGDCpV7-0Ed3RPiXQt2lcjgMzw9O0TWNPnAlwIGih9OaC0LDXncxiPekbiunhzMUIjdDdnHnFzeVmlnXgud_6veQiux224SIBLGVGS6ve_UjxUgdctbMLnasip9ZXZjmkV5VkNeJYv2Z-5MNgwQYLSV_FWJFv4zwMLAR5CRFZnQVE2UK_tntVHl3p25bwAXf4JFQl3BLnAXpjRc5FWVV5BBJvhqHFfqbQEwxMDThoy2XgVwOuPZjzoFEqS0qbvWTSKJNNzoWC5TvqOHdC_psFPLHLSmfmn2dkhG1MmnfVw-EFdd8N-jvrhiQljwzBFiqtp4gOlKaCR6HN2exg65Bc3Zofeu-K_xviRRV3azBrhdQlWM5vj9SOTqEFYWHA5v0euWFrUgjQaL-w6Egt1A9Lk4FVVNvzb0idh7A21kDVIxk3Ufszq-CG0gr8qYQ4F-pHwNaKEgWaN3zLzhuECseRc0B5s7cias_TPi3rmpRJtTwu5t0oK2ujidnVJe5-fk5rkOhkhPxNoR8XXwejm8KvMZVe-vSkORZS7x-jsES_GYN-ywdToWfIE28D_PAv2WTnJgY2ZEv4GkPO3k6FFd7o7wEPS5yrtOsaAvIWj0mJw8_1Fsd1W9bj8fT0XHbJzGAPIpjrZTJYO-qkJbkimH3keuABkSS5zEyqgXYnuCtWy0UTXsVV8Pd9iOm4zjG2m0R-oPnCRJj0sDu9beko9dIjuWp8TqRQiJCwEVCaR_XV7ASvw82o992lPPfPoZ7k0nH0csnqeUUq3_olzu-zY94Z_ewKEatTNGdg-1kU6hIOdZ2nTjmwj36DDAo5ZhX9V8LKReF5GZKazg1yBuqabFg-5MErFtxHHdnoVPUFEgDI2FcvMd-m1MTJnayyxI6lsH7q27Xxh58s7JioiL4sEqLxKiErzPa3Fle-U7aXyg1KyN_z2Pik6ilETszadzT5UqQHueqFn1IKfNpib-7hXzIVqEU_y5yRvPp03ZrOfn8IyDSDb46xtxq5PPB1obcMuRSSkkEkmL2c-5guPkHuFzn2e1seYHWx2dKf6P2VJuM6OCb7qH3ALzYp9WoIPf5Usa3axhLSRcQWwXJu7VXDk5jQnDb1Tc7bcHtFcXQxxA1qiYUucn6vDtWbGp4sZPRMSZZE74Wd2U_BqJLNu9qE4AtGcw-GTha4Qs7lcxmDtzOl-B8EOtuAgDeqkyxRKXWWZr0zzH7zEUXnVo8cAvuSIDBKRt77CM9kd-_DiVTVXt4M3PmimijFNqlJj1HLRxa8Roih_umi7lsOSK9mpAiQOZNlIJfALHt50JLPeEnDpMp4URZtELex4hxTAOt70FwuSNg2-XXx3rIHjH40DWDrNhrMhscy4X534Gg4BszYcJx3JTGwA435UYfY7TUsNEso9xHwW8kKsnLgQS20IJk2TprItUwLj-7K4YjvKj3UajdZx9NjzOYZVYCZJdTn39q1PCRPG_2B-hAIIAx8s0bMTDcGd0h518FIGYoc4ysJY20qI0cX3AQNr5Bh2T65XPsmxD_Vmig_4m02Xp38d6J5SUEER6SAWOuY",
    signature: "KW6lNy_f9pipkduhncCIkDtDcAymQ7FXWAq53FfqGD-vHVlJGLB87lvUE7xPng7l2YZSrXcHfTHcnCIvxSRwTm40Prt9ul078UCcpceT1L2m5wR2Xfh3HoAEpwTHm4Poj16XtfecYjumxr6jL2MiTSxtQvodfZMsfRWHvrDLQUOSEhDnv3evJ2K_HPRpq5wR0wEA-drPtYcYHptBP0Jdp0VYxSuXNVoTTImIbIB6jLYzy0rI57XyS4m1Vg4aFyPBaBh3zLr5YLnERqqGERFP83AE8a_lx5VvBbbQJTCeVCdjP3Ajc3l3DJq8TcboQU5D5FqLdcMjiHb8cqAMw1UGINxIDr21DOZ5z27NN6cSHGN7AaIiaxV49GvINkIcLgI031BM4UY4BS_E7qvbLDTevBavCLypOakFbl7hoTAVNhOiPOKzDYUYLWhFdFU2cboYC8UOVCE0Ni1UZNPVAPHLLLcqAIGmLDw9K8XspCLprsSDriR3pLNdppCEzkDuUuEMX399Q3SEs7NgV8rA_1jZSR7oGA3JgEYs3-3Dt6cPmanbfkddqD2zpW8fyOaoUYKdhyCeVA8T7bqQEuKRpsqjpMZpri3jhcmLAywajeYiFPYJhb9PAWfVr82Uuk3aFo5XzDqAjbqt22TmZZiGCIZjtHLuRaQ4kAXNd7o4IfU58Vsg5euQP9Un7H3LBI-aVlkpi7YTzWsMkEXScRSkZFmmubnTQjtJFffp579cxji0XC57n4M04blxzOD_0W63ZqhIqflereoFmGgO3fFWlQ838RYwmiBNthKhR5psTYtPvIHThigfrxdPY3Z5ehUSHne1zNjevf-bgDXCD7qzk6gf7sNZ99nbp0ATtBD4QIswDTgSjsicw5IBDlaml-56uGm4tEX-5PN0GuPJ9cWd69BkMKbHpMEfpp8a4YSw1Aeotfc3XLZk1K0FqgxJqwFHf6uqqduMfUunrNhylKG05nsMQgnKma2DNrAR-eeKhMnB5R0bzbX1ZmHADCOstLtRfVY3CP2GTKJrDdOASWAkKjB9DCmnK-urxYb_v9NLa5hWhDilyktzd0NnbB1-V-V6BOwzze9MHS2TcgkMsnK7TLRV4LR3E_yV532mKzlIiWXR0oE7AAbYaWODuP8X2YxfGwciPn0txAN7ah8lbxeyhOey38OxklF8V0Kk6BDXpA-XtJKRAVCEx4x8-ytwF3Qrg7kQ467X5OoANegrxZ1IlZzmZhWzH9240q1J60fGCLAOZKOXpuL5T62jfUnYulRKBPCYu5PkujuN8q97udEcDUgSmOKFPa1q0PUmEdANhItYLcRqqdDtpXxPqKgVWPQFZycAHhpezJ9colM8hI3kyW7uMuZveVEmFk2gwGcaNBMympQpAWzwzdRF5cTSCKBhJzSimskj4R9D3L-TSepfyTdZd-q1TQq8ANhB70YP-pcMUKrfsTycegXUJ8FmVm4-mKlDYrQR3QIQK-7e_YV3tv5QRVCFrRICZzXBbpFY9cfh_FYTIB7ChxzJOPuOiSV1Ewi_v4vQi3L6cPit-pLJTVoJdntQZBCPZU71QvxcZ2-ZKjxMfu5W4c-TYCPLDdYncDbw_VJgMc8W-8_UA5mzfo7VCnyqH_HUOsY7P_vfmGzrrHNyq0m69_LdjvcL2dlvTRJd8cGjm5wsSwABGY8R9O0Ram7Dq_cuTrAR4d4LDKQ0D46cWKyoi5XqWMmF_seQdCeO1acHiecmOZAa8we7gnVrzCLqOH4MlB0rG99ksz_ky6paJhrkeLNjnjMRk8WUgqUD3UrBJk8kYy8Hu-pfYUolQMOMLtq8tyi0m-6-jllsdum4ecRe8Bj1iRb8Go5Neu6jtocCNggSukSpEJJBhrGUB2Ear-0DWJuOHypbFI8esWtdVqWnJoq73alRyeMVJWaUJ1-JvPl09M3qIq97DSuVJAUe0XBWPd4HAlp0d6AORq7P9B56jXVmR-vyq-PYSG4syBQAkuj1C07Zrn12rPKhcI4cQG64xfI0AWyJ-jbYmGFEQFlhNkV5K_90zeFsRZvT8jBhKp-18CgNJCGMjQzy4F03-PVZXY2i15EBh87SSmybdQI2FvyR7xh97tRmEvGlTrMlgHoi46t7GddR4_STVjvM3zlpPuYS6IrY2_u6utqi0v5qS5c3OJEAB-dVkl9iQm7EU4XkEx2b7FAYahMxTF1fEF8WQ_fg62-oHJ2XsDUQZTSB5b5A-sPxZsKIU5kdcHKSojmEcek9OAaiouF-SPqn9XcmqVvkhCk4UAvtvXkgbsTPHZRGgTrzGFc37m5a53QlpI34JvK_FkATQI5lTC7TCeWDMUXB32yciLW2I62PLP55_0D2Nisht6G0hH8qh6G765NAyqKhqPwvfHB4tyyif3g2iOeSGw7OjCWEgtF6ExS6L9FS5Rp2hEKiEvMvBqyxpDqBeWEb47X43w9gCLK2NRN3DUtMfpTe0981_qOrtuuTIBjvss53aSZ2qTxw-t5AbSvctIJzXI6VuR1gs7wiHgdec2lf3XlMgBa5ZMvk-cbIAdqzc4-T846EqerLQx_gpL-_JolARF44dt1zrEi2tKv3-xHaBBacruWsSwkMwfg6MwflE_OpkcBhunDLSJx9N4ij3NhmTsHIrmhcroSJTrvR2FEmmYge5qSPaAZVwk2BTSNfeuychHDu85OiiPFDqnbrZquuzJCCMe0a5CCgdH2YPT31KCrROW-d3FCpDnRfpl1oOO-styQoZvG51BOaMk09pio7anG3AhgeCtzGZVePEKptFihW-lKm1y49CeDeNTvOrO5ZvEJl7J1QAttoNRpbEmo4lFf-4TWvRaRmNTVXm1giHfFWmDJ42QEkfL9fkl3Ax8u1FDJmxqqVP8IKdSNSx5zLDFuGlWNvIKl7pqBEVNAjUSqneIje_2mxcqBoOQaQ0l6ljPebUR5veGSCOuvdL5dMax3ERMztcGBr__jA6mqZosY6o3nmRsFL18ma7FW1u4GD7aW4nuM9oyka839esMQjF3oDmMZLj_CIZzTQEQwiTHN_7vH8hV5kyko_VBbJENCMrqVF9NeO_MsLVB4YCXxpkhdxD7NRUxe_1XOst2YtLimCmmzNdia0IynFN28xfqu0A6KntJio9fewP-tUBGQxF-VWCl2nOFU7rGYbLfBs77cIqfL1fYL3nvUaolKwKy38P1ElqLvBdMpNLIFfEmu7rUhD95sJ92H4t9Hn8lwR2guS0R4ZNuVCAYwIv7oosVuGGDclLFPz_6Ah-HnXr7JyjWn9FOHcueoKAIws2vvZKvr_FmDhrTO6H3oATkS968lWXZDc27rn8RXlK1v0ctBNDBo9GgQmqs58z1mqNyp0wlk1EVBLrIRzg4yVopO1qIXhRkEgZOXcVtdlatc_-3hK7t6_OFc-M6cv1ev6-TVRCLoFeWqMtw3AlkaHMMv9VS1s351xzpGUTojaq4EzvbtLoYR8zLs9iBuwg0mhKlvJpEFK3tVsY3JYRM4qNIQxOYEPY8x1oRnn-lclMdClbIOtJb8b_-2zq_FvU2dc0khZvJk5oaMsd99jFkYxSw2exOwAyNMMKXBq5jypiJMpKymMVT4aSpoE5lg7nhIkJ4elVzw3cVfs7FIhslFybJj0o4f1XkXE2W5xKUKcGvOqYrRWC_zjOMRzqmovKS616CXqSMMhXSP_HLulTrItVP0V11fy73QqEFjXMZKyHoKnyTZ5w2VQ3crhhSDifbKd6EK3D90pYQbHs8jeJDEI5TkU7JxrQtwD7EYHBLeSg_6udaDztLRA02-YBv6CLLXcJzxUVliuSEGkr7cQSzFP8_sKJXkw1CLBmrhSoNyydptxZmdpWB-AUo5UCZTf-CqJ0xzA9LrsNDO3FrqIk9VvnF84YwZ5xFPw8uaRcBVOGHO81JzR9tzgkOtFV4xACrC2u1Lk3SPAWzdeRMyQsqUdoG7OeT18URaCII2EA5P366f2REiMBiPkYeOzxqgmWRogZIaTxymDK-69LShEdhtBv4oVaHYI7YQEDU37gTZv3l_-Ach1CSNQuMk0E8PBdRknn16mPPudqE_zNIka10w6hM2u2nHjwZoNKP9cd50keiCWzlCuz1cSmRoZmLHnwviilVT1vCDPaQDfDtgMVLedpYS5sR7xsHAZIAvHLvClYAPFyF7J-uZA_rXtcEuO5mLUE9c4ES2ATn89X6qn36MDsqoQff4jSF2L6Z6KFvIJQKzFvEzGt0XRW-YLRMSl5o4uqc7fDArxGEdYiHzVu0IDTyuG9Y67dPX-yHNCULIhxT6FOYMB4tlRYgmkdOlW1hwQuS6pPnK83YU4magYIVKL1tvoWY2WrLTuU3CfvkWzxd49ZYu0wQkzjrLNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABw0RFRof",
  },
  "ML-DSA-87": {
    publicKey: "_DRTNRDPJMvz9rQfPB2gOnF52qnYuUpJU8ZvlwT6S7JrCUjoNkp7A0OXE5WhUyQ_KrA8iiWQybt9Hp0R2E_v90pvm3Cw7M-TB8XtP_Qmob6RdnJ6OjZESDn8ldVpgavNDRoc98cVZPCKrbbsmRPm_FalrCIHt0THZwgpqBjCoWsZSd-UWF7T9A_02s6-bq8-dHofzyZKsQZ9rveolOIJ7JW5QZwkpfUrGReH4aGi5AY_QLNCl0Mw8kPoZKRVZuKRX7MiA6_BtkFF9tUR6cUX4-OdEwrZ8B2qdfZydyXiv4pZ5VX46qjx5eQFfSbu7zMf4AeeHMGMdeeko8fL1cd69ocs3TR3gJFN43FFhQw1bQLjpDn9f3VRYr4N2HASssaIwFyRk9m11mXA6JVscW_uaPnH1vjdPjnahU1PQqcjdvQoTcFRvojE-Kdq5_yNdD3jTdhnLeBmJCKAzSLPjpJs6o65WjFRJxgyQudlmtx8B7w8uDN-kcQhFf4ATkmVOAQquOR9e-KIDj-GlANxL_1Xh5xI0ctlLe2FZbgqrIp_fbWp2wgAeWqXU1QAd-QPxaLTruILJKm7GhJVWlb1-JfJs3d3Ya5-JJ8dJDIDsaMyOdhTtCVBa6c2ZUtuq6uMj1JoKUQhdq1wooyYXZdwPBCE0Qm6CXbj1GlXuwzLgX1gbs6cgxuOeqYExv3PXM9s5HSZX8jZT6-Bn1QyCv3nEHBGDtlhTEyC0KzMaII239PQhjsiXdE7VwoT3He_ov-MDkJ8CGV84njVq45yceWGHha4Tr93xu_ZkbUzyVC37CzWo7oW2wMjCE_nJML8gKmAYnKFQGPu8k0k2MCULQ6ZmoRvsTDpHl4rwsToMQVTfW88b5UrvaoB57fA3DfHi0UwsQI8Sg4wq-QHkN05YiBjrR313IEfgSmkP6J8mLQTD7N-Td2E4DqX5R0_V9xM-m40vNF5nw88FLCR4TLKQS__2JWo0T_LvqHzvbuicUp1kB6rhpmEvqXBQ7GPrdM6r2ZbjqI732mqTB7uwqz68zpUNFSo5mTQc431EgbItapQfSzrPBQ2DD2eeILE37cBjvSN9o6uKI9KAfXPBHPpuFbheo7LS6qJzkCoRe51skT9qTZ7V2OmvLIXj2Ao3v3zjFk5XgL3ofsxJBwwVgTTJFyFXTifPDN1AWYuKfjsGl-YlNVMjweP2lS5W0uUyLTQn8do9MO2FaKY2EnbRZsh0L8xdUJgf02ZR0tc1e3EAqSBM6xCXL8byidj47z2KnGKxFEA5SNJkbYRtlAeIGkrdUffmpc6j7jnd2iUcCZ9EuZ2t3WAqOsanHijtHor8akhmqOmD2J9YdDFn0OoXQVNZB8jfwTuTcvoWua63cyy0Cf0Wq3qPWTNG-P_hTDXju2Js71Ef0NpCvGTHy7htNu5HqhnOX9GcsMsz0Slq0rzMuwT3Laco2i-fRIEVmptOQSOP6YYnoQo5rbU9v83e-r1rkAgPhBOVR0n-NUR7RtmePMYk9IOcxxsVqE7e7mGh2OKnPkLnbAJONe-CJ__5nusJ5VI_LjdXXudrC5VkdxVpaf3zMLGVmXAK2CETAzgw6ODieE7XT2p5RRjZxi4c7RTZpGesuXkbzlU8jH5xQG7gMaFDh-rkdAss-s4dGQ6yxfWPKwTcpiAiJOGSa6zkTa_Zu4ccY9WXaoQjttMrnZ6WfMVOq1GN9wZjiQ2bwAu7m-5luIggDi4_j5_hFAVwPrgPgFrjYlhZjs02HNN9J6U_Oi8wzRGknOfMdrITWN5051WNqc_klyyJXT24pj47Ya-VYLmjI4NONFWiPuyLQ-iPBPnmVFhv0pOsw7ZqfIcF1WImc7BFijdhsHusug3Sx_4ZiizTIc-vK1WS9AjP6nW-gSNAUYJSrymkypGOk_iP8CeyzjqBdbPEhN-xbZNAF6Ckk9EoWumTmL8i43pYQorjJGQ_7mHq-5rK0EtxsDxHHvxyyGgMehudGdrPSTz_TpHTukwtzQhqhzgHHIemhZvPlQZseit4OQ9p-pmhPyKI_TGLSfd--fNtGZybA8Bi_Tsv1ZaRFlwWZUzNRFVRHbeXqlNY7pQDCf3L-g20Zl7cuR-1QmCjpcr6z8QZvMrC9BgXfs9QLC-Ei1-vBJZBFB7VRC4Ptj3TBy0gU9iWC1eSMO23NcGx6dZLZcfj8JFES8IZ-YTT-RcDGlEC8z2cTmqKivU5V0v0fAov336viBFD2D8DBQhiy_pXW7r7wlVrK0ry6JkYNlox1DVGO_UzuYhSXBHuTFTQVt66oPrj6G_1PZ2GrjwmixtLRQutZnVFuaPiYawRMgCaoTURfUw947tlWIj7DVnOC2fG-RN93gWmheZbk5UWgtEpu7OtihTNJNxMzpmKHmTUp2GPkXWGPMYGIuUcwrV6c6inW5SvWxTgqTnJbM_prY1jRIabyjNI3A-QKcS0T88fGvMYCPZ097OteTUm5dDKSWDSRchtJ-qy4Yv7nU4VHyUKnLxoYGnc7fnpNZ4uzet5GKMnbCCeMtXZSH9_Wjh9CBMO_Uh7NeKRdkil72JTX-VuZKy9NPS_KGUjTZxj-GW1qd61aJmWJaxG4Xy1ff5Nn2IRCnH_zzVlF9XRMB29Pz13PoHzrknp0laahJvc_pogmeMCh0n2uzz_E7eM5diRMcYYgkfy9AyXdIIrYLgcyHgz9qzgP18wkGL4MjAKgc-6tmeaUdt0ObrfoGjBfp3nTJ3Hr7xEf1QiDZk9vL6KlEoeUM2HOLZZS0AX_9tsH3TGQA25x8_-hISYb27sx76_WKEp4puhvKyyXZSw_u0vUEv1ZFzQxaf-0fSUZTzGaBnWNNRf48dCqa7LwvwYXjeeeQqoOiNPAfE8YfsLk3wDO-S51VXnkMcFfgEqDW7P-mfNfwEu48nHelXeFI32yM-cJd_rMUyUZKSXDBMsl29LfVq8joXtCG1LtqpNNLr0RiG9SlJswFJNKMzFi_dxoPN8Jju2SdtMi7S2KZrl9ReYh3pKqLSHmf6WnuDr9BdCxU0vE_6uzKsIM1YUvgEA12yG15OL7bhRDZxKpdcq6qq5BK98exSAqmyiXKnuVB8Ah_T1y2akXlJv-7rr4ENmpO4QFh_IWtUhAXq3Psh_rfLomYWqVXmhpOeEcNASi4xpx492SJE56lOaD6bEhBIY198bPUeYXq9mRxiN07f4MV3qiYBisrJHE8644aVAJoXMszefzdNHod8kgK4ihnhn_SOh1kqK542HpbrgDYX7UpzTOQNsCe7Pi378U76VadETppYRAzddHY3jvzAnBUuE6_gIP-bWnoMp2YAPLLtA-9hhrP1QKIDqI0McMTup6x5jP1OUX6eIklHgrvqQb_14LhXpq0MUGAHXRwCAnJVqQRgiKri-eUsYikobCHBNdAxuZEgA3tBnSOBTYi2lNvJx6BbQ62abXGuGGsJeGT9yTRzX_Cx",
    signature: "j-2qiavUPiB8LInhWxrc6J9StRzbPMtqB3qR44jMgb4bWaL1DNGlFx9C8EVuJivnvwC1zTmTbVwiJOTyskFgO_pUdaOtx0CNtTn3-zrTnoKO9aLNFYebPtij4oXt1BlIZWH9pIlELIUYBk3jjWaZWF0L8nq99J2_Khz7N_lp7n5WXjLJY4f3YQlUp-DOolf3ZuCIvP9A43st0OCK3CRlR8FWK3ODu_RUq-TYRRCDJ-1NBVU7fzGwICnjzp5HrDWHHXXwML2fgbUtWUul4bn8DquFtuibqSy8pejuWyZ7XfOr8RXPbkLgBBVum-SUzD--I35CeI9Q9itRosyuYjyZLQxJici_U3YUW3KmRolIiq1egZQwZCiN9U6Rw5NxqCJZdq5rvxS_DpmHNZrGf2WPKRjTgoW4hOdSqsJjnAHS49b7zOBeJiN_tJQeyz5ENEW_tmjPcfGGnIkKSR5rMpz5qZ-IEQNVstiAmHZBKTw_Um2_nSL10n40JhU67OUyjbb3A4PbBQTXesQlagkLaQD5KapPLfsadKfL299wsGvHKFfBw4zHcoZ_L878ceWVBKaGO0dlzUr6f2xrGG7n2Ck3Duyimz2BVGzWbUUsDk8AZwHJpuw_vQ8yKzusQUabOkX7j5ml03wDe9UVaW6MoZSghs_P5xuSokmhkpUFGxvgEvhCy9lMt97atPZBkpk_czeMaRbXy6f0Divr4ZVNKGOZxh67nszIPhzFeaLCz03MHm-KK6wHL2BKCCatGf6qEI7pOUywCSsRY7eyTLGinChHvwKLwd__87sOjrWAbB9-o5Cqgr7sauFwxJTdgBjOdWwFkiu9mq-Ulm8HuGXZr5CIMr1Kmq5PXAoIw4SBdrYs1Sbzp6GFcMOrttC4v4QDEnGUiZ47QnJrSVlzVXzPaE28hy3mMHgc7_8t_L1bgPrPr8GfYKsGyUcA0455FuLMonGC_Avbxxt-RbdUxoJlT0dWYOHAXWYXMHxaTbM83FmQi0wqs8miwQ090TCrhbVp69D-XfEBjTk8ghW6zM76KRrSQdG3dNHxN841zzOYY2OI4hgcsIOfB17EE-WbgHX_FRZubkKIbmcHvr0i3Ac78fr2Aojj4Cgk8wPp_s5Xg09R3Ta-H0qxlTwEpjDctyhAZhIhXsTN2lGHi67LE6Zi_RxMJUZCXH1BBzDlEnRAQy1_vkiQFYMquE0spBRzrZHwVCAwVwPNDE8rY4X0eoo4wrCcpUb9S7D8AFiVbFdjgaCdprJTbIUccascWKmvrKy9A4UHhlnuT2tnyjOKMETj_LafMgrGhOuhb9wAn0EpurT3-XKSY89GdLOa4Y1ORGXKM0PymYyzff1W26HOXO19oh2SP0ANMzQcC8Oea58ksvtJ2hAOTCyfVP1Ao_Sz3VIbOAF65Vvi3NRDBtRyx8atM3dL-T22AfhVMcD-fRpPuGw36k3T_h1EZ52-3XRuw93ykhsjSzZcgSJs9GWHIjBmzY5M0iAmi-L6xO7HoPYDj-9TJNasniOPXLbcdRPrdcbqL0jcslch6PGRQOQvkBsWcXLC1rdY4FFPz-PVbJ7gDArpmdviRwjVUEiUXFMHHsDmlUjPtUYfodbXdJDeFCTgwTwLADsJzUVxSC_8FW-B1UlTHGeVUu9O72GwiMWnA4sj0ddD2Z4Rsg78WXKrC8Sjfl1Ozw3MpFj5pWadCnrQmm2LFYUC1Km1uwPgWqPel-MvXJBiMIVTJkgT_5ASNGPXWXSeQqyCq1f-KhcY1wD_0or77TDBQkdbp4G0DqszWKKilPAmUSX1ak0ZkNh-7Oa984na4YgvXhZFsOQXU35kvgPXeHs4FYDYN39V807zM_6FlwMF7RBMBq9900RvNpLUEZS64ecvG_q0Wp91U0LNcmdSvXBxS040K2inHBoWWNrVODhFN51houdCh6Z59LjGJNcCJPvYRTX9susKPaNuBWRymvMqMa3NVjXNd0jJKrov06DJsRS4J3Qapql6s6KvjUwq0Dff5cPgMuTk6oW-SPETdbnqPs_8BqrYP6pClgBSNfAqt2FeaLLdT4SCW6j_nLZS9RTWpTV9Qf45MUJdKeYsQSb1cQ9_V7AEyCRRuaNJKKDPfYoU1FBfROTCHt2UyiSA2BStpRa9iRM0YHgSZVYYBpDLV9EF6WDJI7ishp3VDT3lmJed4R5hUbwnsgKh4zmjcapkllUxWs3S7zpBPtvbeVqOvywBovC5Rc01_K12eU45C7DKRMA0JTQxuFer1ZKq-IX0W1VfTo3oSAIhTk41PbgdJiVdUa2eN5YgaIwRwoR83JU1J-9WcsnKZ0vnH-kveePVdpOnLoZtF6gP4gLLMAy88KHoBFbtLsq7VFkiV-6HYWQYpdpnoTJflJ-E6NLq-stDf-eWHYsYw_uzU2vwAHQv5VZ8Be0ASWBrEpqeeVwfwVcAVne8WB-qJro7YEScBRd7o3GKIZA5DmClYtyQ46HUgcSQe-SBWrxE2PHP5KaZrljLqb28y8oDYaKtFXjAukKIibESHtE_106Hk8F1vUbkio_N3v2vHrpLc1CFauuxPoJZq70odCljjW7vDsl1qvelYaiFWF1yElCI9UxYUl8o0s-7EuiJgRLJQRw2AmLed9dlYBeFXnPrZBQw48ceoCLi0UuRS1MT78SC7YQzsgLHCqfsAiYuuDYlb8uIH3XTKvYYCRQMSdDQdHoCbUrEQGbF1mMarDDpHCwHCIWzbqLp9K_Rkwm2_QU91KhZlEGXyR-hhOV828atC-mTUM10XcrrOPt8zcyyu86uErMDgSNKFVd5Qx1H7z6ZOMWeI5QMJHOqih7Go-fwTWZWkIbk7h97Y98Ii3i7-Z3Ov2UHNjk02Dh6pQmAr2fvKZN5gz-nX8-raVgKQt3Du63cE6pPbb4BrcbwoL20X5hw8haQVhh6A-k0eZdPpSzR7RacpVZOKeuhDbzD6JMXM6CBmtyObvqGO7fcTeQNNm7OGyiAVY7HcZufSkXDA0Q8tZr8VftOFeYjGNaRBvDs6yTepx4JRSwtKbCfU-n5CHUHXSQzf1EKdnvfQOSUkvLA_cYr4hTIp9yRSexo49PYSZy6-HbTwI5vOO03M2jNmm1BqKI3WxzO6BmNtCFOsjC3bfjF2Ccgjt4uAoX2Vtp3amwR8h6EHe0wDgcQnC5nQWYEBXgVTPwVivOXLZaoyF1PtLBhOygsTyFUUNvsL1fJ05PyfLgbrCJgeZKZCB6wtLiZEAHC_umNh-go91Ig4sW7mM5F1xfiSHWfpnI12EFyUL8muqgjtjiPEvXjTtQzJDZ8zKuYZJ_q8C4oWGTFlU_dVJmzR3xBeLKwqIMqKgfUko73WjEYIalD6hFkUExhdkRQ2c7VPF2iz_3b11O4aK_wlrfOk9hpfmg7AOo-fJ8yOaHTn1rymp33osZ_bRWYmRnfSIMPFaTO7miRrInp2tXWkWrYXFOlIVFtuz-lR52cx-ukm9rPrAhKxohAZ1y9RowhmjPgI55t7L2Y-9i0K1ujjx-T2LRCOPZMpRBwIPDtFP65yCe0xS824g1vxnrzwBI82RsoutcMx7hYNnLoShqwp-rV-SAMOtQtb2euo2e5HPnP7esD5JnBjal2d_p5Mhnk0AOcZrYaF2MsAgGnPFSPLYsN00dlncP75kJ8m7x4f6bI13QvRRzeYDcftLuMcOtJxvQz6gTkQd0kSGGbPrAMJYnr1kPi_pOxLULV3bwyCs_zS-KMwkAAx9EsaGFvBKU3I9twipP52sJlw8cEN9NYLy5zREbpCRZMYluXlpUi3ArT4ql-sTh8unsNA6stT_tdJhS1SL-7gyT5g0KIWV_We2gEs5LFxaQpmNqKiUeIH-qXw8nMJqjqmvCi16nMh4DdzFHvtFHzeIS5PrzHw8k5XutgyfMkqiEvaBZfWNj0ayklwWoin-5ng9WpvjITN5A4TZzkERUTFh74qTofUMbk8xrNOdOv_d4rqETZHVhsHHcflnDTk7ARMiw8oJBVMD6qY5m1Oelt5fVgoVdGlJGiDK2Szv8jErmmCgGzrt771KLIkYJ3o0Og84rOdBVL4gj6XjoM7T3UvAI99LC69QVN7tU6oHK7QTzH1JYqdZdsZKwCAqzOY6unEBiiQUF8hM84SSLb7WJWDWqfKA5J7qXVooWGiwelFAnPyabcXxuEVK9STQCx7BGxlBjN6CVCyfJf5tjdXtgGrjBdYd44BsAq6pesLGNNh3p6rnfFy93vBhBaEWIlfQLI5c1DsFqeSrvFzNf8vTEBvlY3rdGn7sf41QAj-YNqIePeyQB5rLSRo7Y7Kxw7h4bC8paIg4EC8KGT7L-PjXcLDFfIQ3HJXBtngXgtSGhSK8yrTDyPxHrIvUs3mJKs0M_5hKFsbo0oSpGLBBAEYnAreh-elu4o0YCdRgSXo3ZFlu2HR2kGvaxs-0UOdH8F0IqxEIvy5GAAvjYVSMQI-6jR48QZAOk6CqJ7earG30_IVWq9OhhtFHN3zmddnfYGIlF-t253LDxqQ1VsncwtvaogKe-09_1V93s1UBM9dax8xBzmth8KKMpUQAqUbVn7mUr1bEFwGtcqLZZQ_L7l0rLYDE0gwFQKi951wQxkG9ERYp3YHksyOy1yNpuMtvdMtWgiS5mur-i2GGPHgjrN2vRCbrC3AkB_6sJmE9hvx3aSqsBNnlbKAtE2pmokWqr1aL8jCcfg7-5mr0fe2bJfKSWJXYdynwSBc08h2RfS43UkPlrn6dFBZdJk2auRuP3kxwFe-UaXAaQW-n3cA3hUqIGROnEmkpWj19Rb-u_T-eY5Ra0tZ_dg3Fq5aQsXthvOdktH8MxZ3MNWIG0fsL_VbHje_KW2fOLz0vSZnzGNa4V2xL3NjwRqBolto85T3AH5Ak88idXytIbnwD-IqMWoL2Fywr22M-Wp481HPHlCsVUj6IutIuSaDcX2_Hkytg4jjVU8eTnemMneB1NzL2eOlWphv-T062KwBnqLZabzpGjBURD-NcysF_9Taw52f_ue49hdvIZ3bXVSwQFotcTQmZ7mXtBGI3RRe3cZzt-8hJV99T-7PQ4q1UxViYpANPPHzBgxWGHMkPnoIObb6qz1GEaFDGGwywwyoYlnUB0rkmFCCv1ySWd1jVZrqltojW4aTjJmk_GeSGcEDza0-80nZROjCALgJBOCzZkOJOxnxK0sTduenwg5hvUBxVkx0k6VlaysboxmwTTg-cLDRPFdxoWDC1LN0foC55TP6JHROrBu7R5HsxtrshorWfMrEcZshvvrGBVNngVVYAFsVdzM6oC62i7HO7l4RhC-fXOipxPikMHflFVv6l5FDeaqxij7Cs-dH5xI1RULaKRMLNRb15Y2haRZpd8GmzgjvmOVYNcEKP8GDgh4Z7Z5TZpo_iUsM3s60zgBVyP7f5mR4xjTVo6egji5UjDcCusEVG8xEaezpuschogoRt6XRUuwFI8az6wqmFzoIz8GLbkvRYwp5vSyFLpg71xWB4JZSfqc-8OxWelhSt4dqJGZHSNh-VpiDDjnuLRZds2nVASDOk0f_8p2JO-UCHvtT5I_rP2ZFEVvzr0MIPt7x1SBVsiqRX17_h8XsvrGI0PDY0geoLtfP_3ZPF2PQ4MhsujUUKb7wc180S5TuKTLJeKa-WRu5s1oV4HviSDcd3-EWIYX0rJSdS0pSMQHTTm1BubGGXCjvoulSRNlKHnA4JjjiWTXrvkszmBC5ekHwr_AFwdy4UWXQ-XHhX99bDWOO5xSEnggqGIIriMYS2uhGpyOfDhaI4D7RM6PCheKpt7XwsTQDDJNc-OSwH_NoSxeaPMLtnew-KgT0_VGRtlvQPWn1o5NkaeKs3CUjW260yCsCHoVArVTeAsOSCtpTTtxyKRgHCPJ3VA1fNIpXGBPPeQgv30DHTMpHpsr-zsPNZ5PU7TlQb3AUI-UnP_0XLSY5-UyMKRPeGgf2fo8agKKbhIbRlcRRzfWPd3bSaNpdZ2AI-bbprJEnwkgbM4A0p7wBXuLHzhS4rC24QMQj92dxBrqzUmZfL-Ihj--5dgcvQqVZIq-9mMCYuhZZt4NHSidqLLoCRchOTuFqsno8iw3Ro-W7jVyAxMgMnmCzdHS8_gOGhwmlekEMEbE3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADChQaHCctMg",
  },
};

function katVerifies(keyAlgorithm: string): boolean {
  const vector = KNOWN_ANSWERS[keyAlgorithm];
  if (!vector) return false;
  const signature = Buffer.from(vector.signature, "base64url");
  if (keyAlgorithm === "Ed25519") {
    try {
      // Raw Ed25519 public key wrapped in its SPKI DER prefix.
      const spki = Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(vector.publicKey, "base64url"),
      ]);
      const key = createPublicKey({ key: spki, format: "der", type: "spki" });
      return nodeVerifySignature(null, KNOWN_ANSWER_MESSAGE, key, signature);
    } catch (_error) {
      return false;
    }
  }
  return mldsa(keyAlgorithm, vector.publicKey, KNOWN_ANSWER_MESSAGE, signature);
}

export function capabilities(): { linkedCrypto: string; algorithms: Array<{ name: string; keyAlgorithm: string; verifiable: boolean }> } {
  const algorithms = ALG_ROWS.map((row) => ({
    name: row.name,
    keyAlgorithm: row.keyAlgorithm,
    verifiable: katVerifies(row.keyAlgorithm),
  }));
  return { linkedCrypto: process.versions.openssl ?? "", algorithms };
}

// The signature registry's published identity, mirroring the reference
// Algorithm.registry_digest/0 byte for byte: the canonical object of every
// row under the signature-registry digest domain.
export function algorithmRegistryDigest(): string {
  const value: CanonicalValue = Object.fromEntries(
    ALG_ROWS.map((row) => [
      row.name,
      Object.fromEntries([
        ["name", row.name],
        ["min_protocol_revision", row.minProtocolRevision],
        ["key_algorithm", row.keyAlgorithm],
        ["public_key_bytes", row.publicKeyBytes],
        ["signature_bytes", row.signatureBytes],
      ]),
    ]),
  ) as CanonicalValue;

  return taggedDigest("signature_registry", Buffer.from(canonical(value), "utf8"));
}

// Strict like the reference Profile.new/1: shape errors report invalid_type;
// unknown names or out-of-accepted-range bounds report invalid_profile.
// Omitted members mean the full axis.
function parseProfile(spec: AnyRecord | undefined):
  { ok: true; algorithms: string[]; minRevision: number; maxRevision: number } |
  { ok: false; code: "invalid_type" | "invalid_profile" } {
  const registryNames = ALG_ROWS.map((row) => row.name);
  let algorithms = registryNames;
  if (spec !== undefined && spec.algorithms !== undefined) {
    if (!Array.isArray(spec.algorithms)) return { ok: false, code: "invalid_type" };
    const names = spec.algorithms as unknown[];
    if (names.length === 0 || new Set(names).size !== names.length) return { ok: false, code: "invalid_profile" };
    if (!names.every((name) => typeof name === "string" && registryNames.includes(name))) {
      return { ok: false, code: "invalid_profile" };
    }
    algorithms = names as string[];
  }

  let minRevision = Math.min(...ACCEPTED_PROTOCOL_REVISIONS);
  let maxRevision = Math.max(...ACCEPTED_PROTOCOL_REVISIONS);
  if (spec !== undefined && spec.revisions !== undefined) {
    const bounds = spec.revisions as AnyRecord;
    if (typeof bounds !== "object" || bounds === null ||
        typeof bounds.min !== "number" || typeof bounds.max !== "number") {
      return { ok: false, code: "invalid_type" };
    }
    if (!ACCEPTED_PROTOCOL_REVISIONS.includes(bounds.min) ||
        !ACCEPTED_PROTOCOL_REVISIONS.includes(bounds.max) || bounds.min > bounds.max) {
      return { ok: false, code: "invalid_profile" };
    }
    minRevision = bounds.min;
    maxRevision = bounds.max;
  }

  return { ok: true, algorithms, minRevision, maxRevision };
}

// "ok" | "algorithm" | "revision" | "invalid_type" | "invalid_profile" |
// "decode": the admission walk mirrors the reference Chain.verify STAGE
// order (descriptors, then revisions, then acceptances and terminations),
// so a view whose defects are in different stages reports the same stage
// in both implementations. Within one stage, admission defects are
// decided before signature work here exactly as there. A view with BOTH a
// structural defect and an admission defect in the SAME stage may differ
// (this mirror reports the admission code; the reference reports the
// structural one) — no certified corpus case carries that shape.
function admitView(input: AnyRecord):
  "ok" | "algorithm" | "revision" | "invalid_type" | "invalid_profile" | "decode" {
  const profile = parseProfile(input.profile);
  if (!profile.ok) return profile.code;

  const admitEnvelope = (compact: unknown): "ok" | "algorithm" | "revision" | "decode" => {
    const decoded = decodeJws(compact);
    if (!decoded.ok) return "decode";
    const revision = decoded.value.payload.protocol_revision;
    if (typeof revision !== "number") return "decode";
    if (!profile.algorithms.includes(decoded.value.header.alg)) return "algorithm";
    if (revision < profile.minRevision || revision > profile.maxRevision) return "revision";
    return "ok";
  };

  for (const compact of Array.isArray(input.descriptors) ? input.descriptors : []) {
    const outcome = admitEnvelope(compact);
    if (outcome !== "ok") return outcome;
  }

  for (const text of Array.isArray(input.revisions) ? input.revisions : []) {
    let parsed: unknown;
    try { parsed = JSON.parse(text as string); } catch (_error) { return "decode"; }
    if (typeof parsed !== "object" || parsed === null) return "decode";
    const revision = (parsed as AnyRecord).protocol_revision;
    if (typeof revision !== "number") return "decode";
    if (revision < profile.minRevision || revision > profile.maxRevision) return "revision";
  }

  for (const compact of [
    ...(Array.isArray(input.acceptances) ? input.acceptances : []),
    ...(Array.isArray(input.terminations) ? input.terminations : []),
  ]) {
    const outcome = admitEnvelope(compact);
    if (outcome !== "ok") return outcome;
  }

  return "ok";
}

function chainFromInput(input: AnyRecord): Result<{ descriptors: any; revisions: any[]; acceptances: any[]; accepted: any[]; acceptedDigests: string[]; supersededDigests: string[]; topology: string; charterId: string }> {
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
  if (byDigest.size !== revisions.length) return fail("chain_invalid");
  const genesisList = revisions.filter((one) => one.value.revision_number === 1);
  if (genesisList.length !== 1) return fail("chain_invalid");
  const charterId = genesisList[0].value.charter_id || genesisList[0].digest;
  for (const { digest, value } of revisions) {
    if ((value.charter_id || digest) !== charterId) return fail("chain_invalid");
    if (value.revision_number === 1) continue;
    const predecessor = byDigest.get(value.prev_revision_digest);
    if (!predecessor || predecessor.value.revision_number !== value.revision_number - 1 ||
        (predecessor.value.charter_id || value.prev_revision_digest) !== charterId) {
      return fail("chain_invalid");
    }
    for (const target of value.supersedes || []) {
      const supersededTarget = byDigest.get(target);
      if (!supersededTarget || supersededTarget.value.revision_number >= value.revision_number ||
          (supersededTarget.value.charter_id || target) !== charterId) {
        return fail("chain_invalid");
      }
    }
  }
  const acceptances: any[] = [];
  const coordinates = new Set();
  for (const compact of ((input.acceptances as string[]) || [])) {
    const decoded = decodeJws(compact);
    if (!decoded.ok) return fail("chain_invalid");
    const revision = byDigest.get(decoded.value.payload.revision_digest);
    if (!revision) return fail("chain_invalid");
    const verified = acceptanceFromCompact(compact, revision, descriptors.value);
    if (!verified.ok) return fail("chain_invalid");
    const coordinate = `${verified.value.claims.revision_digest}\0${verified.value.claims.party_descriptor_digest}\0${verified.value.claims.party_role}`;
    if (coordinates.has(coordinate)) return fail("chain_invalid");
    coordinates.add(coordinate);
    acceptances.push(verified.value);
  }
  for (const compact of ((input.terminations as string[]) || [])) {
    const decoded = decodeJws(compact);
    if (!decoded.ok) return fail("chain_invalid");
    const revision = byDigest.get(decoded.value.payload.governing_revision_digest);
    if (!revision) return fail("chain_invalid");
    const verified = terminationFromCompact(compact, revision, descriptors.value);
    if (!verified.ok) return fail("chain_invalid");
  }
  const accepted = revisions.filter((revision) => {
    const expected = new Set(revision.value.parties.map((party: any) => `${party.party_descriptor_digest}\0${party.role}`));
    const actual = new Set(acceptances
      .filter((one) => one.claims.revision_digest === revision.digest)
      .map((one) => `${one.claims.party_descriptor_digest}\0${one.claims.party_role}`));
    if (actual.size !== expected.size) return false;
    for (const entry of [...expected] as string[]) if (!actual.has(entry)) return false;
    return true;
  });
  const superseded = new Set(accepted.flatMap((one) => one.value.supersedes || []));
  const active = accepted.filter((one) => !superseded.has(one.digest));
  const maximum = Math.max(...active.map((one) => one.value.revision_number));
  const heads = active.filter((one) => one.value.revision_number === maximum);
  const acceptedByDigest = new Map(accepted.map((one) => [one.digest, one]));
  // Walk DOWN from the head along unbroken accepted prev links: the head and
  // everything on that chain is covered. A candidate outside the chain makes
  // the active view forked.
  const headAncestry = (head: any) => {
    const chain = new Set([head]);
    let current = acceptedByDigest.get(head);
    while (current && current.value.prev_revision_digest && acceptedByDigest.has(current.value.prev_revision_digest)) {
      chain.add(current.value.prev_revision_digest);
      current = acceptedByDigest.get(current.value.prev_revision_digest);
    }
    return chain;
  };
  const ancestryCovers = (head: any) => {
    const chain = headAncestry(head);
    return active.every((one) => chain.has(one.digest));
  };
  const linear = heads.length === 1 && ancestryCovers(heads[0].digest);
  const topology = active.length > 0 && !linear ? "forked" : "linear";
  return ok({ descriptors: descriptors.value, revisions, acceptances, accepted, acceptedDigests: accepted.map((one) => one.digest).sort(), supersededDigests: [...superseded].sort(), topology, charterId });
}

// Governing mirrors the reference semantics exactly: candidates are accepted,
// non-superseded, and effective at the instant (start-inclusive, end-exclusive
// via exact fraction comparison); a unique highest-numbered head governs only
// when every candidate is the head or an ancestor along an unbroken accepted
// chain — otherwise the view is contested, never silently resolved.
function effectiveAt(revision: { value: AnyRecord }, at: { ticks: number; fraction: string }): boolean {
  const from = parseTimestamp(revision.value.effective_from);
  if (!from || compareTimestamps(from, at) > 0) return false;
  if (revision.value.effective_until === undefined || revision.value.effective_until === null) return true;
  const until = parseTimestamp(revision.value.effective_until);
  return until !== null && compareTimestamps(at, until) < 0;
}

function governing(chain: any, at: { ticks: number; fraction: string }): string {
  const applicable = chain.accepted.filter((one: any) => !chain.supersededDigests.includes(one.digest) && effectiveAt(one, at));
  if (applicable.length === 0) return "none";
  const maximum = Math.max(...applicable.map((one: any) => one.value.revision_number));
  const finalists = applicable.filter((one: any) => one.value.revision_number === maximum);
  if (finalists.length !== 1) return "contested";
  const acceptedByDigest = new Map<string, any>(chain.accepted.map((one: any) => [one.digest, one]));
  const head = finalists[0].digest;
  const chainFromHead = new Set([head]);
  let walk: any = acceptedByDigest.get(head);
  while (walk && walk.value.prev_revision_digest && acceptedByDigest.has(walk.value.prev_revision_digest)) {
    chainFromHead.add(walk.value.prev_revision_digest);
    walk = acceptedByDigest.get(walk.value.prev_revision_digest);
  }
  const covers = applicable.every((one: any) => chainFromHead.has(one.digest));
  return covers ? head : "contested";
}

function projectReceipt(claims: AnyRecord, chain: any, governingDigest: string) {
  const claimedRevision = chain.accepted.find((one: any) => one.digest === claims.revision_digest);
  const governingMatch = governingDigest === "contested" ? "undetermined" :
    (governingDigest === claims.revision_digest ? "match" : "mismatch");

  if (claimedRevision) {
    const revision = claimedRevision.value;
    const charterId = revision.charter_id || claimedRevision.digest;
    const roles = new Set(revision.parties.map((one: any) => one.role));
    const deploymentMatched = revision.abp_bindings.some((binding: any) =>
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

  const roles = new Set(chain.accepted.flatMap((one: any) => one.value.parties.map((party: any) => party.role)));
  const recognized = claims.charter_id === chain.charterId &&
    roles.has(claims.issuing_party_role) && roles.has(claims.agent_party_role);
  if (!recognized) return fail("receipt_claims_mismatch");

  const acceptedHead = Math.max(0, ...chain.accepted.map((one: any) => one.value.revision_number));
  const chainConflict = claims.revision_number <= acceptedHead ? "fork_evidenced" : "none";
  return ok({ governingMatch, chainConflict, deploymentMatched: false });
}

function receiptSigningKeys(chain: any, claimedRevision: any, role: unknown) {
  const revisions = claimedRevision ? [claimedRevision] : chain.accepted;
  const keys = revisions.flatMap((revision: any) =>
    revision.value.parties
      .filter((party: any) => party.role === role)
      .flatMap((party: any) => {
        const descriptor = chain.descriptors.descriptors.find((one: any) =>
          one.digest === party.party_descriptor_digest
        );
        return descriptor?.payload.verification_keys || [];
      })
  );
  return [...new Map(keys.map((key: any) => [canonical(key), key])).values()];
}

function receiptFromCompact(compact: string, chain: any) {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return decoded;
  const claims = decoded.value.payload;
  const receiptShape = receiptGrantError(claims);
  if (receiptShape) return fail(receiptShape);
  const claimedRevision = chain.accepted.find((one: any) => one.digest === claims.revision_digest);
  const verifiedPublicKeys = new Set(
    receiptSigningKeys(chain, claimedRevision, claims.issuing_party_role)
      .filter((key: any) => verifyDecodedJws(decoded.value, "cap+receipt", [key]))
      .map((key: any) => key.public_key)
  );
  if (verifiedPublicKeys.size !== 1) return fail("signature_invalid");
  const receiptTiming = receiptTimingError(claims);
  if (receiptTiming) return fail(receiptTiming);
  const governingDigest = governing(chain, parseTimestamp(claims.occurred_at)!);
  const projection = projectReceipt(claims, chain, governingDigest);
  if (!projection.ok) return projection;
  return ok({ claims, digest: taggedHash("receipt_content", decoded.value.payloadBytes), ...projection.value, optionalExtensions: Object.keys(claims.extensions?.optional || {}).sort() });
}

function execute(one: ConformanceCase): CaseResult {
  const input = one.input;
  switch (one.surface) {
    case "base64url.decode":
      return project(strictBase64url(input.text), (bytes) => ({ bytes_base64url: bytes.toString("base64url") }));
    case "json.decode": {
      if (!("text" in input) && !("bytes_base64url" in input)) return invalid("invalid_type");
      if (input.limits !== undefined && !validLimits(input.limits)) return invalid("invalid_limits");
      const bytes = "text" in input ? Buffer.from(input.text as string) : Buffer.from(input.bytes_base64url as string, "base64url");
      const decoded = decodeJsonBytes(bytes);
      if (!decoded.ok) return invalid(decoded.code);
      return project(jsonWithinLimits(decoded.value, bytes, input.limits), jsonProjection);
    }
    case "canonicalization.encode":
      if (input.tag === "integer") {
        const literal = input.text_value !== undefined ? (input.text_value as string) : String(input.value);
        if (/^-?[0-9]+$/.test(literal) && (BigInt(literal) > MAXIMUM_SAFE_INTEGER || BigInt(literal) < -MAXIMUM_SAFE_INTEGER)) return invalid("integer_magnitude");
        return valid({ text: literal });
      }
      if (input.tag === "object") {
        const names = input.members.map(([key]: any) => key);
        if (new Set(names).size !== names.length) return invalid("duplicate_member");
        return valid({ text: canonical(Object.fromEntries(input.members.map(([key, value]: any) => [key, value.value])) as unknown as CanonicalValue) });
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
        if (input.tagged !== taggedHash((input.domain as Domain) || "charter_revision_content", Buffer.from(input.bytes_base64url as string, "base64url"))) return invalid("digest_mismatch");
      }
      return valid({ algorithm: "sha-256" });
    case "schema.validate": {
      const members = input.members as Record<string, any>;
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
      const [left, right] = facts.map((oneFact: any) => oneFact.value.claims);
      const pairable = left.charter_id === right.charter_id && left.revision_number === right.revision_number &&
        left.party_descriptor_digest === right.party_descriptor_digest && left.party_role === right.party_role &&
        left.revision_digest !== right.revision_digest;
      if (!pairable) return invalid("acceptance_equivocation_invalid");
      return valid({ kind: "acceptance_equivocation", revision_number: (facts[0] as any).value.claims.revision_number, revision_digests: facts.map((oneFact: any) => oneFact.value.claims.revision_digest).sort(), winner: null });
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
    case "chain.verify_profile": {
      // The capability-profile mirror. The admission walk mirrors the
      // reference Chain.verify STAGE order (descriptors, then revisions,
      // then acceptances and terminations), so a view whose defects are in
      // different stages reports the same stage in both implementations.
      // Within one stage, admission defects are decided before signature
      // work here exactly as there. A view with BOTH a structural defect
      // and an admission defect in the SAME stage may differ (this mirror
      // reports the admission code; the reference reports the structural
      // one) — no certified corpus case carries that shape.
      const admission = admitView(input);
      if (admission === "algorithm") return invalid("algorithm_outside_profile");
      if (admission === "revision") return invalid("revision_outside_profile");
      if (admission === "invalid_type") return invalid("invalid_type");
      if (admission === "invalid_profile") return invalid("invalid_profile");
      const chain = chainFromInput(input);
      return project(chain, (facts) => ({ charter_id: facts.charterId, topology: facts.topology }));
    }
    case "governing_revision": {
      const chain = chainFromInput(input);
      if (!chain.ok) return invalid("governing_invalid");
      return valid({
        governing_revisions: input.queries.map((query: any) => {
          const at = parseTimestamp(query.at);
          return at ? governing(chain.value, at) : "none";
        }),
      });
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

function corpusDigest(index: Record<string, unknown>): string {
  const without = { ...index };
  delete without.corpus_digest;
  return taggedHash("corpus_index", Buffer.from(canonical(without as unknown as CanonicalValue)));
}

export function loadCorpus(root: string): LoadedCorpus {
  const observedEntries = walk(root);
  if (observedEntries.length === 0 || observedEntries.length > MAXIMUM_CORPUS_FILES ||
      observedEntries.reduce((total, entry) => total + entry.size, 0) > MAXIMUM_CORPUS_BYTES) {
    throw new Error("corpus filesystem bounds");
  }
  const observedSizes = new Map(observedEntries.map((entry) => [entry.path, entry.size]));
  const indexBytes = readFileSync(join(root, "index.json"));
  if (indexBytes.length !== observedSizes.get("index.json")) throw new Error("index changed during read");
  const index = JSON.parse(indexBytes.toString("utf8"));
  if (canonical(index as CanonicalValue) !== indexBytes.toString("utf8")) throw new Error("non-canonical index");
  if (!exactKeys(index, ["applicability", "corpus_digest", "files", "format", "registry_digest", "total_cases"])) throw new Error("index shape");
  if (index.format !== INDEX_FORMAT || index.corpus_digest !== corpusDigest(index)) throw new Error("index identity");
  if (index.registry_digest !== CERTIFIED_REGISTRY_DIGEST) throw new Error("registry identity");
  if (rawHash(indexBytes) !== CERTIFIED_INDEX_SHA256_BASE64URL) throw new Error("uncertified index");
  const expectedFiles = ["index.json", ...index.files.map((entry: any) => entry.path)].sort();
  if (canonical(observedEntries.map((entry: CorpusEntry) => entry.path).sort() as unknown as CanonicalValue) !== canonical(expectedFiles as unknown as CanonicalValue)) throw new Error("file set");
  const cases = [];
  for (const entry of index.files) {
    const bytes = readFileSync(join(root, entry.path));
    if (bytes.length !== observedSizes.get(entry.path)) throw new Error("case file changed during read");
    if (rawHash(bytes) !== String(entry.sha256_base64url)) throw new Error("file hash");
    const file = JSON.parse(bytes.toString("utf8"));
    if (canonical(file as CanonicalValue) !== bytes.toString("utf8") || file.format !== CASE_FORMAT || file.cases.length !== entry.cases) throw new Error("case file");
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
      const applicability: Record<string, any> = index.applicability;
      const cell = applicability[surface][oneClass];
      if ((REQUIRED as Record<string, string[]>)[surface].includes(oneClass)) {
        if (cell !== count || count < 1) throw new Error("required cell");
      } else if (!exactKeys(cell, ["n_a"]) || cell.n_a === "" || count !== 0) throw new Error("not-applicable cell");
    }
  }
  return { index, indexBytes, cases };
}

export function reportFor(root: string): ReportOutput {
  const corpus = loadCorpus(root);
  const results = corpus.cases.map((one) => {
    const actual = execute(one);
    return { id: one.id, surface: one.surface, agree: canonical(actual as unknown as CanonicalValue) === canonical(one.expect as unknown as CanonicalValue), expected: one.expect, actual };
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
  return { bytes: `${canonical(report as unknown as CanonicalValue)}\n`, exitStatus: report.exit_status };
}

export function selfChecks(): void {
  const vectors = [
    [Buffer.from(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    [Buffer.from("d3", "hex"), "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"],
    [Buffer.from("b4190e", "hex"), "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2"],
  ];
  for (const [message, expected] of vectors) {
    if (createHash("sha256").update(message).digest("hex") !== expected) throw new Error("SHA-256 KAT failed");
  }
  if (canonical({ b: 1, a: 2 }) !== "{\"a\":2,\"b\":1}") throw new Error("canonical ordering failed");
  const strictPadded = strictBase64url("AQ==");
  if (strictPadded.ok || strictPadded.code !== "base64url_padded") throw new Error("base64url strictness failed");

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
  const issuerKey = issuerKeys[0] as AnyRecord;
  if (issuerKeys.length !== 1 || issuerKey.public_key !== "issuer-key") {
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

  // Parity invariants against the reference implementation.
  const floatDecoded = decodeJsonText('{"a":0.0,"b":2e0,"c":5}');
  if (!floatDecoded.ok) throw new Error("float decode drifted");
  const projected = jsonProjection(floatDecoded.value) as Extract<Projection, { tag: "object" }>;
  const member = (name: any) => projected.members.find(([key]: any) => key === name)?.[1].tag;
  if (!floatDecoded.ok || member("a") !== "float" || member("b") !== "float" || member("c") !== "integer") {
    throw new Error("number tagging drifted");
  }
  if (decodeJsonBytes(Buffer.from('"\\ufdd0"')).ok || decodeJsonBytes(Buffer.from('"\\uffff"')).ok) {
    throw new Error("I-JSON noncharacter rejection drifted");
  }
  if (parseTimestamp("2026-06-30T23:59:60Z") === null || parseTimestamp("2024-03-31T23:59:60Z") !== null) {
    throw new Error("leap-second window drifted");
  }
  if (parseTimestamp("2026-02-30T00:00:00Z") !== null || parseTimestamp("0000-01-01T00:00:00Z") !== null) {
    throw new Error("calendar validation drifted");
  }
  const halfMs = parseTimestamp("2026-01-01T00:00:00.0005Z");
  const whole = parseTimestamp("2026-01-01T00:00:00Z");
  if (!halfMs || !whole || compareTimestamps(halfMs, whole) <= 0) {
    throw new Error("sub-millisecond fraction comparison drifted");
  }
  const halfSecond = parseTimestamp("2026-01-01T00:00:00.5Z");
  const halfSecondPadded = parseTimestamp("2026-01-01T00:00:00.500Z");
  if (halfSecond === null || halfSecondPadded === null || compareTimestamps(halfSecond, halfSecondPadded) !== 0) {
    throw new Error("fraction padding drifted");
  }
  if (LIMIT_MAXIMUMS.max_bytes !== 16_777_216 || LIMIT_MAXIMUMS.max_artifact_set_items !== 4_096) {
    throw new Error("compiled limit maximums drifted");
  }
}

// ---------------------------------------------------------------------------
// Artifact-level verification API (added 0.2.0)
//
// The corpus surface above proves this implementation against certified
// expectations; the functions below expose the same verification over ONE
// caller-supplied artifact (or a small caller-supplied view), so layered
// tools — holder-side signers above all — reuse exactly one verification
// implementation instead of forking one. CAP never authorizes: every result
// is structural evidence, never permission.
// ---------------------------------------------------------------------------

export type AlgRow = { name: string; minProtocolRevision: number; keyAlgorithm: string; publicKeyBytes: number; signatureBytes: number };
export type VerifyResult = { ok: true; facts: AnyRecord } | { ok: false; code: string };

export function algorithmRegistry(): AlgRow[] {
  return ALG_ROWS.map((row) => ({ ...row }));
}

export function emissions(): Record<string, number> {
  return { Ed25519: 2, "ML-DSA-65": 3 };
}

export function encodeBase64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

export function taggedDigest(domain: string, bytes: Buffer): string {
  return taggedHash(domain as Domain, bytes);
}

export function defaultEmissionName(): string {
  return "Ed25519";
}

// Framing-level decode: canonical protected header and payload, registry
// binding, per-row signature length — everything about an artifact except
// its cryptographic verification. Holder-side producers use this as the
// provisional check on a zero-signature framing before any key is touched.
export function decodeArtifact(compact: string): VerifyResult {
  const decoded = decodeJws(compact);
  if (!decoded.ok) return { ok: false, code: decoded.code };
  const { header, payload } = decoded.value;
  return { ok: true, facts: { alg: header.alg, kid: header.kid, typ: header.typ, payload } };
}

// Strict signature verification over exact bytes with a base64url public
// key under the registry row for `alg` — the wrong-key guard primitive.
export function verifySignature(message: Buffer, signature: Buffer, publicKeyBase64url: string, alg: string): boolean {
  const row = ALG_ROWS.find((one) => one.name === alg);
  if (!row) return false;
  const key = Buffer.from(publicKeyBase64url, "base64url");
  if (key.length !== row.publicKeyBytes) return false;
  if (row.keyAlgorithm === "Ed25519") return ed25519(publicKeyBase64url, message, signature);
  return mldsa(row.keyAlgorithm, publicKeyBase64url, message, signature);
}

export function verifyDescriptor(
  compact: string,
  predecessor: { digest: string; claims: AnyRecord } | null = null,
): VerifyResult {
  const verified = descriptorFromCompact(compact, predecessor ? { digest: predecessor.digest, payload: predecessor.claims } : null);
  if (!verified.ok) return { ok: false, code: verified.code };
  const one = verified.value;
  return {
    ok: true,
    facts: {
      descriptor_digest: one.digest,
      party_id: one.digest,
      descriptor_number: one.payload.descriptor_number,
      protocol_revision: one.payload.protocol_revision,
    },
  };
}

export function verifyDescriptorChain(compacts: string[]): VerifyResult {
  const verified = descriptorChain(compacts);
  if (!verified.ok) return { ok: false, code: verified.code };
  return { ok: true, facts: verified.value };
}

export function verifyAcceptance(compact: string, revisionText: string, descriptorCompacts: string[]): VerifyResult {
  const revision = revisionFromText(revisionText);
  const chain = descriptorChain(descriptorCompacts);
  if (!revision.ok || !chain.ok) return { ok: false, code: "acceptance_invalid" };
  const verified = acceptanceFromCompact(compact, revision.value, chain.value);
  if (!verified.ok) return { ok: false, code: verified.code };
  return { ok: true, facts: { acceptance_digest: verified.value.digest, claims: verified.value.claims, descriptor_position: verified.value.descriptorPosition } };
}

export function verifyTermination(compact: string, revisionText: string, descriptorCompacts: string[]): VerifyResult {
  const revision = revisionFromText(revisionText);
  const chain = descriptorChain(descriptorCompacts);
  if (!revision.ok || !chain.ok) return { ok: false, code: "termination_invalid" };
  const verified = terminationFromCompact(compact, revision.value, chain.value);
  if (!verified.ok) return { ok: false, code: verified.code };
  return { ok: true, facts: { termination_digest: verified.value.digest, claims: verified.value.claims, descriptor_position: verified.value.descriptorPosition } };
}

export function verifyChain(chainInput: AnyRecord): VerifyResult {
  const verified = chainFromInput(chainInput);
  if (!verified.ok) return { ok: false, code: verified.code };
  return { ok: true, facts: verified.value };
}

export function verifyReceipt(compact: string, chainInput: AnyRecord): VerifyResult {
  const chain = chainFromInput(chainInput);
  if (!chain.ok) return { ok: false, code: "receipt_invalid" };
  const verified = receiptFromCompact(compact, chain.value);
  if (!verified.ok) return { ok: false, code: verified.code };
  return {
    ok: true,
    facts: {
      receipt_digest: verified.value.digest,
      claims: verified.value.claims,
      governing_match: verified.value.governingMatch,
      chain_conflict: verified.value.chainConflict,
    },
  };
}

// ---------------------------------------------------------------------------
// The producer build gate's claims half (the reference decode_for_signing):
// the schema checks that depend only on the claims, shared with the verify
// paths below so the pre-sign gate and the post-sign discipline are ONE
// implementation. Holder-side signers run checkSigningClaims before any key
// is used; malformed claims are a typed producer rejection, never a burned
// key operation.
// ---------------------------------------------------------------------------

export function checkSigningClaims(
  kind: "descriptor" | "acceptance" | "termination" | "receipt",
  claims: AnyRecord,
): { ok: true } | { ok: false; code: string } {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) return { ok: false, code: "invalid_type" };
  const error =
    kind === "descriptor" ? descriptorClaimsError(claims) :
    kind === "acceptance" ? acceptanceClaimsError(claims) :
    kind === "termination" ? terminationClaimsError(claims) :
    kind === "receipt" ? (receiptGrantError(claims) ?? receiptTimingError(claims)) :
    "invalid_type";
  return error ? { ok: false, code: error } : { ok: true };
}

function acceptanceClaimsError(claims: AnyRecord): string | null {
  if ((claims.revision_number === 1) !== (claims.prev_revision_digest === undefined)) return "acceptance_invalid";
  if (!parseTimestamp(claims.accepted_at)) return "timestamp_invalid";
  return null;
}

function terminationClaimsError(claims: AnyRecord): string | null {
  const issuedAt = parseTimestamp(claims.issued_at);
  const effectiveAt = parseTimestamp(claims.effective_at);
  if (!issuedAt || !effectiveAt || compareTimestamps(issuedAt, effectiveAt) > 0) return "termination_invalid";
  return null;
}

function receiptGrantError(claims: AnyRecord): string | null {
  if (claims.grant?.scheme === "bap" && claims.grant?.grant_digest === undefined) return "receipt_invalid";
  const optional = claims.extensions?.optional || {};
  for (const namespace of Object.keys(optional)) {
    const profile = EXTENSION_PROFILES.find((entry) => entry.namespace === namespace);
    if (!profile || profile.state === "reserved" || profile.state === "retired") continue;
    if (profile.surface !== "receipt") return "extension_scope_invalid";
    if (profile.schema_digest === null) return "extension_schema_unavailable";
  }
  return null;
}

function receiptTimingError(claims: AnyRecord): string | null {
  const occurredAt = parseTimestamp(claims.occurred_at);
  const recordedAt = parseTimestamp(claims.recorded_at);
  if (!occurredAt || !recordedAt || compareTimestamps(recordedAt, occurredAt) < 0) return "receipt_invalid";
  // The closed matrix mirrors the reference decoder: rejected requires
  // no_effect; accepted admits effect_committed, no_effect, or indeterminate.
  const outcomeAllowed = claims.decision === "rejected" ? claims.outcome === "no_effect" :
    (claims.outcome === "effect_committed" || claims.outcome === "no_effect" || claims.outcome === "indeterminate");
  if (!outcomeAllowed) return "cross_field_invalid";
  return null;
}

function descriptorClaimsError(payload: AnyRecord): string | null {
  const grammar = keyGrammarError(payload);
  if (grammar) return grammar;
  if (!parseTimestamp(payload.effective_from)) return "timestamp_invalid";
  if (payload.descriptor_number === 1 && payload.prev_descriptor_digest !== undefined) return "descriptor_invalid";
  return null;
}

// ---------------------------------------------------------------------------
// The query/decode surface: the reference's governing-revision computation
// and the revision/descriptor decode+digest pairs, over the same certified
// internals the verify paths use. Every export fails closed with typed
// codes; none of them verifies signatures.
// ---------------------------------------------------------------------------

// The unique governing revision in a verified view at one UTC instant -
// a digest, or "contested"/"none" (never silently resolved).
export function governingRevision(chainInput: AnyRecord, at: string): { ok: true; governing: string } | { ok: false; code: string } {
  const instant = typeof at === "string" ? parseTimestamp(at) : null;
  if (!instant) return { ok: false, code: "invalid_type" };
  if (!chainInput || typeof chainInput !== "object" || Array.isArray(chainInput)) {
    return { ok: false, code: "signing_input_invalid" };
  }
  const chain = chainFromInput(chainInput);
  if (!chain.ok) return { ok: false, code: "chain_invalid" };
  return { ok: true, governing: governing(chain.value, instant) };
}

// Decode one canonical unsigned Charter Revision: the parsed claims plus
// its content digest, computed over the exact text bytes.
export function decodeCharterRevision(text: unknown): { ok: true; revision: AnyRecord; digest: string } | { ok: false; code: string } {
  const revision = revisionFromText(text);
  if (!revision.ok) return { ok: false, code: revision.code };
  return { ok: true, revision: revision.value.value, digest: revision.value.digest };
}

export function revisionDigest(text: unknown): { ok: true; digest: string } | { ok: false; code: string } {
  const revision = decodeCharterRevision(text);
  if (!revision.ok) return revision;
  return { ok: true, digest: revision.digest };
}

// Decode one Party Descriptor's claims without verifying its signature -
// the framing, the descriptor schema, and the content digest.
export function decodePartyDescriptor(compact: unknown): { ok: true; claims: AnyRecord; digest: string } | { ok: false; code: string } {
  const decoded = decodeJws(compact as string);
  if (!decoded.ok) return { ok: false, code: decoded.code };
  if (decoded.value.header.typ !== "cap+party") return { ok: false, code: "descriptor_invalid" };
  const claimsError = descriptorClaimsError(decoded.value.payload);
  if (claimsError) return { ok: false, code: claimsError };
  return { ok: true, claims: decoded.value.payload, digest: taggedHash("party_descriptor_content", decoded.value.payloadBytes) };
}

export function descriptorDigest(compact: unknown): { ok: true; digest: string } | { ok: false; code: string } {
  const decoded = decodePartyDescriptor(compact);
  if (!decoded.ok) return decoded;
  return { ok: true, digest: decoded.digest };
}

// ---------------------------------------------------------------------------
// The producer surface (the reference SigningInput): build the exact RFC
// 7515 signing input per kind WITHOUT signing, compose the claims gate and
// the set-aware refusal checks at the reference ordering, and assemble a
// validated signature. Holder-side signers consume these instead of
// hand-rolling framing - exactly one producer implementation. The mint set
// is the emission map (Ed25519 at revision 2, ML-DSA-65 at revision 3);
// nothing here ever sees a key.
// ---------------------------------------------------------------------------

export type SigningInput = { alg: string; protectedSegment: string; payloadSegment: string; message: Buffer };
export type ProducerResult = { ok: true; input: SigningInput } | { ok: false; code: string };

const PRODUCER_TYPES: Record<"descriptor" | "acceptance" | "termination" | "receipt", string> = {
  descriptor: "cap+party",
  acceptance: "cap+acceptance",
  termination: "cap+termination",
  receipt: "cap+receipt",
};



// The reference producer's tagged/1: claims must be pure JSON values -
// undefined, functions, symbols, bigints, and non-finite numbers get the
// typed producer code, never a canonicalization throw.
function jsonValueError(value: unknown): boolean {
  if (value === null) return false;
  const type = typeof value;
  if (type === "string" || type === "boolean") return false;
  if (type === "number") return !Number.isFinite(value);
  if (type !== "object") return true;
  if (Array.isArray(value)) return value.some(jsonValueError);
  if (Buffer.isBuffer(value)) return true;
  return Object.values(value as AnyRecord).some(jsonValueError);
}

// The shared build path: algorithm -> claims shape/JSON values -> emission
// binding -> kid -> framing -> size gate -> claims schema -> provisional
// decode (the reference producer's exact ordering, so error precedence
// matches too).
function buildSigningInput(
  kind: keyof typeof PRODUCER_TYPES,
  kid: unknown,
  claims: unknown,
  algorithm: unknown,
): ProducerResult {
  if (typeof algorithm === "undefined" || algorithm === null) algorithm = defaultEmissionName();
  if (typeof algorithm !== "string" || !(algorithm in emissions())) {
    return { ok: false, code: "algorithm_unsupported" };
  }
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    return { ok: false, code: "invalid_type" };
  }
  const record = claims as AnyRecord;
  if (jsonValueError(record)) return { ok: false, code: "signing_input_invalid" };
  const revision = record.protocol_revision;
  if (typeof revision !== "number" || !Number.isInteger(revision) || revision !== emissions()[algorithm as string]) {
    return { ok: false, code: "signing_input_invalid" };
  }
  if (typeof kid !== "string" || kid.length === 0 || kid.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(kid)) {
    return { ok: false, code: "signing_input_invalid" };
  }
  const row = ALG_ROWS.find((one) => one.name === algorithm);
  if (!row) return { ok: false, code: "algorithm_unsupported" };

  const payloadSegment = encodeBase64url(Buffer.from(canonical(record as never), "utf8"));
  const protectedSegment = encodeBase64url(
    Buffer.from(canonical({ alg: algorithm, kid, typ: PRODUCER_TYPES[kind] } as never), "utf8"),
  );
  const message = Buffer.from(`${protectedSegment}.${payloadSegment}`, "utf8");
  const signatureSegmentLength = Math.ceil((row.signatureBytes * 4) / 3);
  if (message.length + 1 + signatureSegmentLength > JSON_DEFAULT_LIMITS.max_bytes) {
    return { ok: false, code: "signing_input_invalid" };
  }

  // The reference build's decode step: the claims schema gate runs inside
  // the producer, after framing and size - the same precedence as
  // decode_for_signing inside the Elixir build pipeline.
  const claimsGate = checkSigningClaims(kind, record);
  if (!claimsGate.ok) return { ok: false, code: claimsGate.code };

  // The provisional check: a zero signature at the row's exact length must
  // frame and bind.
  const zeroSignature = Buffer.alloc(row.signatureBytes);
  const provisional = `${protectedSegment}.${payloadSegment}.${encodeBase64url(zeroSignature)}`;
  const decoded = decodeArtifact(provisional);
  if (!decoded.ok) return { ok: false, code: "signing_input_invalid" };

  return { ok: true, input: { alg: algorithm as string, protectedSegment, payloadSegment, message } };
}

export function descriptorSigningInput(kid: string, claims: AnyRecord, algorithm?: string): ProducerResult {
  return buildSigningInput("descriptor", kid, claims, algorithm);
}

export function receiptSigningInput(kid: string, claims: AnyRecord, algorithm?: string): ProducerResult {
  return buildSigningInput("receipt", kid, claims, algorithm);
}

// The reference producer ordering: build (shape, emission binding, framing,
// claims schema) FIRST, then the set-aware R1-R3 refusal checks - so a
// claims defect reports the producer code even when the view is also bad.
export function acceptanceSigningInput(kid: string, claims: AnyRecord, chainInput: AnyRecord, algorithm?: string): ProducerResult {
  const built = buildSigningInput("acceptance", kid, claims, algorithm);
  if (!built.ok) return built;
  const refusal = acceptanceRefusal(claims, chainInput);
  if (!refusal.ok) return { ok: false, code: refusal.code };
  return built;
}

export function terminationSigningInput(kid: string, claims: AnyRecord, chainInput: AnyRecord, algorithm?: string): ProducerResult {
  const built = buildSigningInput("termination", kid, claims, algorithm);
  if (!built.ok) return built;
  const refusal = terminationRefusal(claims, chainInput);
  if (!refusal.ok) return { ok: false, code: refusal.code };
  return built;
}

// Assemble a validated signing input and its exact raw signature (the
// reference assemble): registry-row length, framing re-decode, size gate.
export function assembleCompact(input: SigningInput, signature: Buffer): { ok: true; compact: string } | { ok: false; code: string } {
  if (!input || typeof input !== "object" || !Buffer.isBuffer(signature)) return { ok: false, code: "invalid_type" };
  // The input is a struct the producer minted: the message must BE the
  // protected/payload framing (a caller-modified copy is invalid, never
  // silently assembled).
  if (typeof input.protectedSegment !== "string" || typeof input.payloadSegment !== "string" ||
      !Buffer.isBuffer(input.message) || input.message.toString("utf8") !== `${input.protectedSegment}.${input.payloadSegment}`) {
    return { ok: false, code: "signing_input_invalid" };
  }
  const row = ALG_ROWS.find((one) => one.name === input.alg);
  if (!row) return { ok: false, code: "algorithm_unsupported" };
  if (signature.length !== row.signatureBytes) return { ok: false, code: "signature_invalid" };
  const compact = `${input.message.toString("utf8")}.${encodeBase64url(signature)}`;
  if (Buffer.byteLength(compact) > JSON_DEFAULT_LIMITS.max_bytes) return { ok: false, code: "signing_input_invalid" };
  const decoded = decodeArtifact(compact);
  if (!decoded.ok) return { ok: false, code: "signing_input_invalid" };
  return { ok: true, compact };
}

// ---------------------------------------------------------------------------
// The honest-signer refusal boundary (R1-R3 from the reference producers).
// Pure set-aware gates over the caller's OWN verified view: the view must
// first pass the full chain discipline (a view that fails is invalid input,
// never a refusal), then the claims are bound against that verified chain.
// Holder-side signers run these BEFORE any key is used; a refusal means the
// claims contradict the caller's own evidence. The rule that fired is
// deliberately not surfaced — one opaque signing_refused code, mirroring the
// reference. These functions never verify signatures themselves and never
// authorize anything.
// ---------------------------------------------------------------------------

export type RefusalResult = { ok: true } | { ok: false; code: string };

function refused(): RefusalResult {
  return { ok: false, code: "signing_refused" };
}

// The producer build gate these checks assume already ran upstream in the
// reference: fields the refusal rules consume must be well-typed, or the
// caller gets the typed producer code instead of a refusal.
function refusalClaimsShape(claims: AnyRecord, stringFields: string[], integerFields: string[]): boolean {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) return false;
  return stringFields.every((field) => typeof claims[field] === "string") &&
    integerFields.every((field) => typeof claims[field] === "number" && Number.isInteger(claims[field]));
}

// A non-object view mirrors the reference producer's non-ArtifactSet arm
// (the typed producer code); an object that fails the chain discipline is
// the caller's invalid set. Neither may throw out of the refusal boundary.
function refusalChain(chainInput: AnyRecord): { chain: any } | { invalidSet: "signing_input_invalid" } | { invalidSet: "chain_invalid" } {
  if (!chainInput || typeof chainInput !== "object" || Array.isArray(chainInput)) return { invalidSet: "signing_input_invalid" };
  const chain = chainFromInput(chainInput);
  return chain.ok ? { chain: chain.value } : { invalidSet: "chain_invalid" };
}

function refusalPartyMatches(revision: { value: AnyRecord }, claims: AnyRecord): boolean {
  return (revision.value.parties as AnyRecord[]).some(
    (party) => party.role === claims.party_role && party.party_descriptor_digest === claims.party_descriptor_digest,
  );
}

// Walk up the candidate's prev links through the whole verified revision
// index; the verified chain guarantees strictly decreasing numbers, so the
// walk terminates. Identity is ancestry (re-accepting a head covers itself).
function refusalAncestorOf(candidate: string, target: string, byDigest: Map<string, any>): boolean {
  if (candidate === target) return true;
  const previous = byDigest.get(candidate)?.value.prev_revision_digest;
  return typeof previous === "string" ? refusalAncestorOf(previous, target, byDigest) : false;
}

export function acceptanceRefusal(claims: AnyRecord, chainInput: AnyRecord): RefusalResult {
  if (!refusalClaimsShape(claims, ["revision_digest", "charter_id", "party_role", "party_descriptor_digest"], ["revision_number"])) {
    return { ok: false, code: "signing_input_invalid" };
  }
  const resolved = refusalChain(chainInput);
  if ("invalidSet" in resolved) return { ok: false, code: resolved.invalidSet };
  const chain = resolved.chain;

  // R1 claims-truth: the named revision exists and every coordinate binds.
  const revision = chain.revisions.find((one: any) => one.digest === claims.revision_digest);
  if (!revision) return refused();
  const charterId = revision.value.charter_id || revision.digest;
  if (claims.charter_id !== charterId ||
      claims.revision_number !== revision.value.revision_number ||
      (revision.value.prev_revision_digest || undefined) !== (claims.prev_revision_digest || undefined) ||
      !refusalPartyMatches(revision, claims)) {
    return refused();
  }

  // R2 no-equivocation: no existing acceptance holds this charter/number
  // coordinate for a different revision.
  const equivocation = chain.acceptances.some((one: any) =>
    one.claims.charter_id === claims.charter_id &&
    one.claims.revision_number === claims.revision_number &&
    one.claims.revision_digest !== claims.revision_digest,
  );
  if (equivocation) return refused();

  // R3 ancestry coverage: every maximum accepted head is superseded by the
  // candidate or an ancestor of it (an empty accepted set covers trivially).
  const maximum = Math.max(...chain.accepted.map((one: any) => one.value.revision_number));
  const heads = chain.accepted.filter((one: any) => one.value.revision_number === maximum).map((one: any) => one.digest);
  const byDigest = new Map<string, any>(chain.revisions.map((one: any) => [one.digest, one] as [string, any]));
  const covered = heads.every((head: string) =>
    ((revision.value.supersedes as string[]) || []).includes(head) || refusalAncestorOf(revision.digest, head, byDigest),
  );
  if (!covered) return refused();

  return { ok: true };
}

export function terminationRefusal(claims: AnyRecord, chainInput: AnyRecord): RefusalResult {
  if (!refusalClaimsShape(claims, ["governing_revision_digest", "charter_id", "party_role", "party_descriptor_digest", "reason_code"], [])) {
    return { ok: false, code: "signing_input_invalid" };
  }
  const effectiveAt = parseTimestamp(claims.effective_at);
  if (!effectiveAt) return { ok: false, code: "signing_input_invalid" };
  const resolved = refusalChain(chainInput);
  if ("invalidSet" in resolved) return { ok: false, code: resolved.invalidSet };
  const chain = resolved.chain;

  // R1 claims-truth: the named revision exists, the reason is listed in its
  // termination rules, and the signing party is one of its parties.
  const revision = chain.revisions.find((one: any) => one.digest === claims.governing_revision_digest);
  if (!revision) return refused();
  const charterId = revision.value.charter_id || revision.digest;
  if (claims.charter_id !== charterId ||
      !(revision.value.termination_rules.reason_codes as string[]).includes(claims.reason_code) ||
      !refusalPartyMatches(revision, claims)) {
    return refused();
  }

  // R3 governing coverage: the named revision must be THE unique governing
  // revision at the notice's own effective instant — a stale or contested
  // view refuses.
  if (governing(chain, effectiveAt) !== revision.digest) return refused();

  return { ok: true };
}
