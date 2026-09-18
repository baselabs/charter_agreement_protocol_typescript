// esbuild --inject entry: the packages use the Node Buffer global (base64url
// and ed25519 modules). feross `buffer` is the standard pure-JS implementation,
// but it predates Node's "base64url" encoding name — the packages rely on it,
// so the gap is patched here: to/from base64url maps onto base64 with URL-safe
// alphabet translation and padding handling. Under real Node Buffer these
// patches are no-ops (native base64url short-circuits in origToString).
import { Buffer } from "buffer";

type AnyProto = {
  toString(enc?: string, ...rest: unknown[]): string;
} & Record<string, unknown>;

const proto = Buffer.prototype as unknown as AnyProto;
const origToString = proto.toString;
proto.toString = function (this: Uint8Array, enc?: string, ...rest: unknown[]): string {
  if (enc === "base64url") {
    return origToString.call(this, "base64", ...rest).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  return origToString.call(this, enc, ...rest);
} as AnyProto["toString"];

const origFrom = Buffer.from.bind(Buffer) as unknown as (v: unknown, e?: string) => Uint8Array;
const FromShim = function (this: unknown, value: unknown, encoding?: string): Uint8Array {
  if (typeof value === "string" && encoding === "base64url") {
    const b64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
    return origFrom(b64, "base64");
  }
  return origFrom(value, encoding);
} as unknown as typeof Buffer.from;
Buffer.from = FromShim;

const g = globalThis as unknown as { Buffer?: unknown };
if (g.Buffer === undefined) g.Buffer = Buffer;
export { Buffer };
