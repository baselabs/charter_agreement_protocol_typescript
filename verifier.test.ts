// CAP never authorizes.
//
// In-package unit tests: red-capable checks over the parser-layer closures
// this package owns (strict I-JSON, canonical bytes, exact timestamps,
// registry gating) plus a tamper-proof of the corpus loader. Run:
//   node --test --experimental-strip-types --no-warnings verifier.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonical, decodeJsonText, jsonProjection, reportFor, selfChecks } from "./core.ts";

const here = dirname(fileURLToPath(import.meta.url));

test("self-check battery passes", () => {
  selfChecks();
});

test("strict I-JSON: noncharacters and lone surrogates reject", () => {
  assert.equal(decodeJsonText('"\uffff"').ok, false);
  assert.equal(decodeJsonText('"\ud800"').ok, false);
  assert.equal(decodeJsonText('{"a":1,"a":2}').ok, false);
  assert.equal(decodeJsonText("1 2").ok, false);
});

test("number tagging follows the lexeme, never the value", () => {
  const decoded = decodeJsonText('{"a":0.0,"b":2e0,"c":5}');
  assert.ok(decoded.ok);
  const projected = jsonProjection(decoded.value) as { tag: string; members: [string, { tag: string }][] };
  const tag = (name: string) => projected.members.find(([key]) => key === name)?.[1].tag;
  assert.equal(tag("a"), "float");
  assert.equal(tag("b"), "float");
  assert.equal(tag("c"), "integer");
});

test("canonical bytes: member order by UTF-16 units, no whitespace", () => {
  assert.equal(canonical({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonical([1, "x", null, true]), '[1,"x",null,true]');
});

test("vendored certified corpus verifies green through the public API", () => {
  const report = reportFor(join(here, "conformance"));
  assert.equal(report.exitStatus, 0);
});

test("a tampered corpus case cannot verify green", () => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-verifier-tamper-"));
  cpSync(join(here, "conformance"), scratch, { recursive: true });
  const casePath = join(scratch, "cases", "base64url-decode.json");
  const document = JSON.parse(readFileSync(casePath, "utf8"));
  document.cases[0].expect = { status: "invalid", error_code: "base64url_invalid" };
  writeFileSync(casePath, canonical(document) + "\n");
  assert.throws(() => reportFor(scratch), /file hash|changed during read/);
  rmSync(scratch, { recursive: true, force: true });
});

test("a corpus whose index bytes are edited fails the certified pin", () => {
  const scratch = mkdtempSync(join(tmpdir(), "cap-verifier-pin-"));
  cpSync(join(here, "conformance"), scratch, { recursive: true });
  const indexPath = join(scratch, "index.json");
  const index = JSON.parse(readFileSync(indexPath, "utf8"));
  index.total_cases = 1;
  writeFileSync(indexPath, canonical(index) + "\n");
  assert.throws(() => reportFor(scratch), /uncertified index|identity|digest|file hash|shape|non-canonical/i);
  rmSync(scratch, { recursive: true, force: true });
});
