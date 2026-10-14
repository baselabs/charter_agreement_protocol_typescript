import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { Point } from "@noble/ed25519";
import { build } from "esbuild";
import { createContext, runInContext } from "node:vm";
import { browserBundleOptions } from "./web/bundle.ts";
import * as api from "./index.ts";
import { ED25519_EDGES, generatedEd25519Inputs, loadEd25519Predicate, loadEd25519Checks } from "./ed25519-inputs.ts";

const prime = 2n ** 255n - 19n;
const field = (value: bigint) => ((value % prime) + prime) % prime;

function inverse(value: bigint): bigint {
  let [a, b, x, y] = [prime, field(value), 0n, 1n];
  while (b !== 0n) {
    const quotient = a / b;
    [a, b] = [b, a - quotient * b];
    [x, y] = [y, x - quotient * y];
  }
  assert.equal(a, 1n);
  return field(x);
}

const d = field(-121665n * inverse(121666n));

function power(value: bigint, exponent: bigint): bigint {
  let result = 1n;
  for (const bit of exponent.toString(2)) {
    result = field(result * result);
    if (bit === "1") result = field(result * value);
  }
  return result;
}

// Euler's criterion checks the square before Tonelli-Shanks extracts a root.
function squareRoot(square: bigint): bigint | null {
  if (square === 0n) return 0n;
  if (power(square, (prime - 1n) / 2n) !== 1n) return null;
  let q = prime - 1n;
  let m = 0;
  while (q % 2n === 0n) { q /= 2n; m++; }
  let nonresidue = 2n;
  while (power(nonresidue, (prime - 1n) / 2n) === 1n) nonresidue++;
  let c = power(nonresidue, q);
  let root = power(square, (q + 1n) / 2n);
  let t = power(square, q);
  while (t !== 1n) {
    let i = 0;
    let squared = t;
    while (squared !== 1n) { squared = field(squared * squared); i++; }
    assert.ok(i < m);
    const factor = power(c, 1n << BigInt(m - i - 1));
    root = field(root * factor);
    c = field(factor * factor);
    t = field(t * c);
    m = i;
  }
  return root;
}

type ExtendedPoint = [bigint, bigint, bigint, bigint];

function doubleExtended([x, y, z]: ExtendedPoint): ExtendedPoint {
  const a = field(x * x);
  const b = field(y * y);
  const c = field(2n * z * z);
  const e = field((x + y) ** 2n - a - b);
  const g = field(b - a);
  const f = field(g - c);
  const h = field(-a - b);
  return [field(e * f), field(g * h), field(f * g), field(e * h)];
}

function referenceAdmits(bytes: Buffer): boolean {
  if (bytes.length !== 32) return false;
  const encoded = BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
  const y = encoded % (1n << 255n);
  const sign = encoded >> 255n;
  if (y >= prime) return false;
  const denominator = field(d * y * y + 1n);
  if (denominator === 0n) return false;
  let x = squareRoot(field((y * y - 1n) * inverse(denominator)));
  if (x === null || (x === 0n && sign === 1n)) return false;
  if (x % 2n !== sign) x = field(-x);
  let point: ExtendedPoint = [x, y, 1n, field(x * y)];
  for (let i = 0; i < 3; i++) point = doubleExtended(point);
  return !(point[0] === 0n && field(point[1] - point[2]) === 0n);
}

test("Ed25519 admission rejects y two without a curve point", async () => {
  const predicate = await loadEd25519Predicate();
  const bytes = Buffer.from("0200000000000000000000000000000000000000000000000000000000000000", "hex");
  assert.equal(referenceAdmits(bytes), false);
  assert.equal(predicate(bytes), false);
});

test("Ed25519 admission matches Euler and extended coordinates on seeded inputs", async () => {
  const { strictEd25519Point, strictEd25519Signature } = await loadEd25519Checks();
  const inputs = generatedEd25519Inputs();
  assert.equal(new Set(inputs.map((bytes) => bytes.toString("hex"))).size, 10_000);
  for (const bytes of inputs) {
    const admitted = referenceAdmits(bytes);
    assert.equal(strictEd25519Point(bytes), admitted, bytes.toString("hex"));
    assert.equal(strictEd25519Signature(Buffer.concat([bytes, Buffer.alloc(32)])), admitted, `R ${bytes.toString("hex")}`);
  }
});

test("Ed25519 signature R uses the key point rule and exact scalar bounds", async () => {
  const { strictEd25519Signature } = await loadEd25519Checks();
  for (const { name, bytes, admitted } of ED25519_EDGES) {
    assert.equal(strictEd25519Signature(Buffer.concat([bytes, Buffer.alloc(32)])), admitted, name);
  }
  for (const length of [0, 1, 32, 63, 65, 96]) assert.equal(strictEd25519Signature(Buffer.alloc(length)), false);
  const base = ED25519_EDGES.find((edge) => edge.name === "base point")!.bytes;
  const order = 2n ** 252n + 27742317777372353535851937790883648493n;
  for (const scalar of [0n, order - 1n, order, order + 1n, 2n ** 256n - 1n]) {
    const bytes = Buffer.from(scalar.toString(16).padStart(64, "0"), "hex").reverse();
    assert.equal(strictEd25519Signature(Buffer.concat([base, bytes])), scalar < order);
  }
});

test("Ed25519 R identity fails both public signature paths", async () => {
  const seed = Buffer.alloc(32, 1);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const encoded = publicKey.export({ format: "jwk" }).x!;
  const fixture = JSON.parse(readFileSync(new URL("./conformance/cases/party_descriptor-verify.json", import.meta.url), "utf8"));
  const compact = fixture.cases.find((one: any) => one.id === "party-descriptor-genesis-valid").input.compact;
  const claims = JSON.parse(Buffer.from(compact.split(".")[1], "base64url").toString());
  claims.protocol_revision = 2;
  claims.verification_keys = [{ key_id: "k", algorithm: "Ed25519", public_key: encoded, status: "active" }];
  const framed = api.descriptorSigningInput("k", claims);
  assert.ok(framed.ok);
  const secret = createHash("sha512").update(seed).digest().subarray(0, 32);
  secret[0] &= 248;
  secret[31] = (secret[31] & 63) | 64;
  const littleEndian = (bytes: Buffer) => BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
  const r = ED25519_EDGES.find((edge) => edge.name === "identity")!.bytes;
  const hash = createHash("sha512").update(r).update(Buffer.from(encoded, "base64url")).update(framed.input.message).digest();
  const scalar = littleEndian(hash) * littleEndian(secret) % (2n ** 252n + 27742317777372353535851937790883648493n);
  const signature = Buffer.concat([r, Buffer.from(scalar.toString(16).padStart(64, "0"), "hex").reverse()]);
  const order = 2n ** 252n + 27742317777372353535851937790883648493n;
  assert.ok(Point.BASE.multiply(scalar).equals(Point.fromBytes(r).add(Point.fromBytes(Buffer.from(encoded, "base64url")).multiply(littleEndian(hash) % order))));
  const bundle = await build({
    ...browserBundleOptions, entryPoints: ["index.ts"], bundle: true,
    format: "iife", globalName: "CAP", write: false,
  });
  const page = createContext({ TextEncoder, TextDecoder, atob, btoa });
  runInContext(bundle.outputFiles[0].text, page);
  const browser = page.CAP;
  const builtEntry = "./dist/index.js";
  const built: typeof api = await import(builtEntry);
  for (const verifier of [api, built, browser]) {
    for (const algorithm of ["EdDSA", "Ed25519"]) assert.equal(verifier.verifySignature(framed.input.message, signature, encoded, algorithm), false);
    assert.deepEqual(JSON.parse(JSON.stringify(verifier.verifyDescriptor(`${framed.input.message.toString()}.${signature.toString("base64url")}`))), { ok: false, code: "signature_invalid" });
    const prepared = verifier.prepareSigning("descriptor", "k", claims, encoded, null);
    assert.ok(prepared.ok);
    assert.equal(verifier.finishSigning(prepared.plan, signature).code, "signature_invalid");
  }
});

test("Ed25519 admission checks every named edge and exact byte length", async () => {
  const predicate = await loadEd25519Predicate();
  for (const { name, bytes, admitted } of ED25519_EDGES) {
    assert.equal(referenceAdmits(bytes), admitted, name);
    assert.equal(predicate(bytes), admitted, name);
  }
  for (const length of [0, 1, 31, 33, 64]) assert.equal(predicate(Buffer.alloc(length)), false);
});

test("Ed25519 key admission preserves public error codes and admits mixed order", () => {
  const fixture = JSON.parse(readFileSync(new URL("./conformance/cases/party_descriptor-verify.json", import.meta.url), "utf8"));
  const compact = fixture.cases.find((one: any) => one.id === "party-descriptor-genesis-valid").input.compact;
  const claims = JSON.parse(Buffer.from(compact.split(".")[1], "base64url").toString());
  for (const { name, bytes, admitted } of ED25519_EDGES) {
    const publicKey = bytes.toString("base64url");
    const changed = { ...claims, protocol_revision: 2, verification_keys: [{ key_id: "k", algorithm: "Ed25519", public_key: publicKey, status: "active" }] };
    const prepared = api.prepareSigning("descriptor", "k", changed, publicKey, null);
    if (admitted) {
      assert.ok(prepared.ok, name);
      assert.equal(prepared.plan.key, "matched", name);
    } else {
      assert.deepEqual(prepared, { ok: false, code: "signing_key_invalid" }, name);
      const framed = api.descriptorSigningInput("k", changed);
      assert.ok(framed.ok, name);
      const signature = Buffer.concat([ED25519_EDGES.find((edge) => edge.name === "base point")!.bytes, Buffer.from([1]), Buffer.alloc(31)]);
      const signed = `${framed.input.message.toString()}.${signature.toString("base64url")}`;
      assert.deepEqual(api.verifyDescriptor(signed), { ok: false, code: "signature_invalid" }, name);
    }
  }
});
