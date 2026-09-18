// The browser shim for the packages' entire node:crypto surface (verified by
// grep over both dist trees): createPublicKey, verify (Ed25519), createHash
// ("sha256"). Implemented over @noble (synchronous — checkEnvelope is a fully
// synchronous pipeline, so the shim must be too). Nothing here implements
// cryptography of its own; it only adapts shapes.
import { verify, hashes } from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

// noble/ed25519 3.x ships its SHA-512 as an injectable (tree-shakeable)
// dependency, unset by default — sign/verify/keygen throw until it is wired.
// Both the sync and async paths share the registry.
hashes.sha512 = sha512;

export interface ShimKeyObject {
  readonly kind: "shim-ed25519-public";
  readonly raw: Uint8Array;
}

const isUint8 = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

/** Accepts both construction shapes the packages use: JWK {kty,crv,x} and SPKI DER. */
export function createPublicKey(opts: {
  key: { kty?: string; crv?: string; x?: string } | Uint8Array;
  format?: string;
  type?: string;
}): ShimKeyObject {
  const k = opts.key;
  if (isUint8(k)) {
    // SPKI DER for Ed25519 is 44 bytes: 12-byte header + 32-byte raw key.
    if (k.length < 32) throw new Error("shim: SPKI too short for Ed25519");
    return { kind: "shim-ed25519-public", raw: new Uint8Array(k.subarray(k.length - 32)) };
  }
  if (k.kty !== "OKP" || k.crv !== "Ed25519" || typeof k.x !== "string") {
    throw new Error("shim: only Ed25519 OKP JWK supported");
  }
  const bin = atob(k.x.replace(/-/g, "+").replace(/_/g, "/"));
  const raw = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
  return { kind: "shim-ed25519-public", raw };
}

/** The packages always call verify(null, data, ed25519Key, sig). */
export function verifyEd25519(
  _alg: unknown,
  data: Uint8Array,
  key: ShimKeyObject,
  signature: Uint8Array,
): boolean {
  try {
    return verify(signature, data, key.raw);
  } catch {
    return false;
  }
}
export { verifyEd25519 as verify };

/** The packages always call createHash("sha256") with update/digest chaining. */
export function createHash(algo: string): { update(d: Uint8Array): unknown; digest(enc?: string): Uint8Array | string } {
  if (algo !== "sha256") throw new Error(`shim: hash ${algo} not supported`);
  let acc = new Uint8Array(0);
  return {
    update(d: Uint8Array) {
      const next = new Uint8Array(acc.length + d.length);
      next.set(acc);
      next.set(d, acc.length);
      acc = next;
      return this;
    },
    digest(enc?: string) {
      const out = sha256(acc);
      if (enc === "hex") {
        return Array.from(out, (b: number) => b.toString(16).padStart(2, "0")).join("");
      }
      return out;
    },
  };
}
