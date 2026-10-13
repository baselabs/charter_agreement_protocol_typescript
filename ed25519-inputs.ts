import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const ED25519_EDGES: Array<{ name: string; bytes: Buffer; admitted: boolean }> = [
  ["identity", "0100000000000000000000000000000000000000000000000000000000000000"],
  ["torsion c717 positive", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
  ["zero y negative", "0000000000000000000000000000000000000000000000000000000000000080"],
  ["torsion 26e8 positive", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
  ["order two", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"],
  ["torsion 26e8 negative", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"],
  ["zero y positive", "0000000000000000000000000000000000000000000000000000000000000000"],
  ["torsion c717 negative", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"],
  ["identity negative zero", "0100000000000000000000000000000000000000000000000000000000000080"],
  ["order two negative zero", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
  ["y two has no curve point", "0200000000000000000000000000000000000000000000000000000000000000"],
].map(([name, hex]) => ({ name, bytes: Buffer.from(hex, "hex"), admitted: false }));

for (let y = 2n ** 255n - 19n; y < 2n ** 255n; y++) {
  for (const sign of [0n, 1n]) {
    const encoded = (y + (sign << 255n)).toString(16).padStart(64, "0");
    ED25519_EDGES.push({ name: `noncanonical y ${y} sign ${sign}`, bytes: Buffer.from(encoded, "hex").reverse(), admitted: false });
  }
}
ED25519_EDGES.push(
  { name: "base point", bytes: Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex"), admitted: true },
  { name: "base point plus order two", bytes: Buffer.from("9599999999999999999999999999999999999999999999999999999999999999", "hex"), admitted: true },
);

export function generatedEd25519Inputs(count = 10_000, seed = 0x070ed255): Buffer[] {
  let state = seed >>> 0;
  if (state === 0) throw new Error("seed must be nonzero");
  const word = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  return Array.from({ length: count }, () => {
    const bytes = Buffer.alloc(32);
    for (let offset = 0; offset < bytes.length; offset += 4) bytes.writeUInt32LE(word(), offset);
    return bytes;
  });
}

export async function loadEd25519Predicate(built = false): Promise<(point: Buffer) => boolean> {
  return (await loadEd25519Checks(built)).strictEd25519Point;
}

export async function loadEd25519Checks(built = false): Promise<{
  strictEd25519Point: (point: Buffer) => boolean;
  strictEd25519Signature: (signature: Buffer) => boolean;
  validPublicKey: (key: unknown, row: { keyAlgorithm: string; publicKeyBytes: number }) => boolean;
}> {
  const scratch = mkdtempSync(join(tmpdir(), "cap-ed25519-"));
  try {
    const filename = built ? "core.js" : "core.ts";
    const source = readFileSync(new URL(built ? "./dist/core.js" : "./core.ts", import.meta.url), "utf8");
    const path = join(scratch, filename);
    // Import the complete real module with its private predicate exposed for checks.
    writeFileSync(path, source + "\nexport { strictEd25519Point, strictEd25519Signature, validPublicKey };\n");
    return await import(pathToFileURL(path).href);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
