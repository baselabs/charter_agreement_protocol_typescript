import { createHash, createPublicKey, verify as nodeVerifySignature } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

const INDEX_FORMAT = "charter-agreement-protocol-conformance-corpus-index";
const CASE_FORMAT = "charter-agreement-protocol-conformance-cases";
const REPORT_FORMAT = "charter-agreement-protocol-conformance-report";
const MAXIMUM_CORPUS_FILES = 64;
const MAXIMUM_CORPUS_BYTES = 33_554_432;
export const CERTIFIED_INDEX_SHA256_BASE64URL = "SQYrs8WyUX4Bj_QlupjB_KYaMyjVjrnwvQ79sNkyIao";
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
  if (typeof at !== "string" || !parseTimestamp(at)) return { ok: false, code: "invalid_type" };
  const chain = chainFromInput(chainInput);
  if (!chain.ok) return { ok: false, code: "chain_invalid" };
  return { ok: true, governing: governing(chain.value, parseTimestamp(at)!) };
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

const MAX_SIGNING_INPUT_BYTES = 1_048_576;

// The shared build path: claims shape -> emission binding -> kid -> framing
// -> size gate -> claims schema -> provisional decode (the reference
// producer's exact ordering, so error precedence matches too).
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
  if (message.length + 1 + signatureSegmentLength > MAX_SIGNING_INPUT_BYTES) {
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
  const row = ALG_ROWS.find((one) => one.name === input.alg);
  if (!row) return { ok: false, code: "algorithm_unsupported" };
  if (signature.length !== row.signatureBytes) return { ok: false, code: "signature_invalid" };
  const compact = `${input.message.toString("utf8")}.${encodeBase64url(signature)}`;
  if (Buffer.byteLength(compact) > MAX_SIGNING_INPUT_BYTES) return { ok: false, code: "signing_input_invalid" };
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
