import { createPrivateKey, createPublicKey } from "node:crypto";

const SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function ed25519Fixture(byte: number) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([SEED_PREFIX, Buffer.alloc(32, byte)]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey).export({ format: "jwk" }).x!;
  return { privateKey, publicKey };
}

const legacyFixtures = new Map(Array.from({ length: 9 }, (_, index) => {
  const fixture = ed25519Fixture(index + 1);
  return [fixture.publicKey, fixture.privateKey] as const;
}));

// The named scope fixture bytes are declared in CAP's conformance_fixture_keys.exs.
const scopeSeedBytes = new Map([["issuer", 1], ["restricted", 2], ["acceptor", 3], ["successor", 4]]);

export function corpusEd25519PrivateKey(publicKey: string, scopeKid?: string) {
  if (scopeKid === undefined) return legacyFixtures.get(publicKey);
  const byte = scopeSeedBytes.get(scopeKid);
  if (byte === undefined) return undefined;
  const fixture = ed25519Fixture(byte);
  return fixture.publicKey === publicKey ? fixture.privateKey : undefined;
}
