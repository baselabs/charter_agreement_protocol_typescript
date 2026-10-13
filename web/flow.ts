// The page and browser tests share the complete workshop signing flow.
import { keygen, sign as nobleSign } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import { signAcceptance, signDescriptor, signReceipt, type ChainView } from "@charter-agreement-protocol/signer";
import { verifyChain, verifyDescriptor } from "../index.js";

export interface CustodyKey {
  publicKeyB64: string;
  sign: (m: Uint8Array) => Promise<Uint8Array>;
  mode: "WebCrypto non-extractable" | "in-page (noble)";
}

export async function makeKey(): Promise<CustodyKey> {
  try {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as Algorithm, false, ["sign"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return {
      publicKeyB64: Buffer.from(raw).toString("base64url"),
      sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, m as BufferSource)),
      mode: "WebCrypto non-extractable",
    };
  } catch {
    const kp = keygen();
    return {
      publicKeyB64: Buffer.from(kp.publicKey).toString("base64url"),
      sign: async (m) => nobleSign(m, kp.secretKey),
      mode: "in-page (noble)",
    };
  }
}

export interface Party { key: CustodyKey; kid: string; descriptor?: string; pdd?: string; role: "issuer" | "acceptor" }

export type Step = { ok: true } | { ok: false; message: string };
export type World = { revisions: string[]; acceptances: string[]; descriptors: string[]; terminations: string[] };

// Deterministic fixture digests: hash the seed so every demo digest reads like
// a digest (43 base64url chars of real SHA-256 output).
export const dg = (seed: string): string =>
  "sha-256:" + Buffer.from(sha256(new TextEncoder().encode("demo:" + seed))).toString("base64url");

const failure = (label: string, r: { error: string; code?: string }): Step =>
  ({ ok: false, message: `${label} → ${r.error}${r.code ? " " + r.code : ""}` });

export class Workshop {
  issuer!: Party;
  acceptor!: Party;
  genesisText = "";
  genesisDigest = "";
  acceptanceIssuer = "";
  acceptanceAcceptor = "";
  receipt = "";

  async reset(): Promise<void> {
    const [ik, ak] = await Promise.all([makeKey(), makeKey()]);
    this.issuer = { key: ik, kid: "issuer-key-001", role: "issuer" };
    this.acceptor = { key: ak, kid: "acceptor-key-001", role: "acceptor" };
    this.genesisText = this.genesisDigest = this.acceptanceIssuer = this.acceptanceAcceptor = this.receipt = "";
  }

  revisionText(overrides: Record<string, unknown>): string {
    // The genesis revision carries no charter_id (successors stamp it).
    return JSON.stringify({
      abp_bindings: [{
        blueprint_id: "example.demo/echo",
        content_digest: dg("P"),
        deployment_digest: dg("Q"),
        party_role: "acceptor",
        release_number: 1,
      }],
      attribution_declaration: { basis: "bound_deployments" },
      effective_from: "2026-08-25T12:00:00Z",
      extensions: { critical: {}, optional: {} },
      legal_text: { content_digest: dg("L"), media_type: "text/plain" },
      parties: [
        { party_descriptor_digest: this.issuer.pdd as string, role: "issuer" },
        { party_descriptor_digest: this.acceptor.pdd as string, role: "acceptor" },
      ],
      precedence_declaration: "legal_text_governs",
      protocol_revision: 2,
      receipt_profile: "com.example.charter/default",
      revision_number: 1,
      termination_rules: { reason_codes: ["mutual", "breach"] },
      ...overrides,
    });
  }

  view(extra: Partial<ChainView> = {}): ChainView {
    return {
      revisions: [this.genesisText],
      acceptances: [this.acceptanceIssuer, this.acceptanceAcceptor],
      descriptors: [this.issuer.descriptor!, this.acceptor.descriptor!],
      terminations: [],
      ...extra,
    };
  }

  handle(p: Party) {
    return {
      keyIdentity: () => ({ kid: p.kid, publicKey: p.key.publicKeyB64 }),
      sign: (m: Uint8Array) => p.key.sign(m),
    };
  }

  private descriptorClaims(kid: string, publicKey: string) {
    return {
      protocol_revision: 2, descriptor_number: 1,
      verification_keys: [{ key_id: kid, algorithm: "Ed25519", public_key: publicKey, status: "active" }],
      attestation_hints: [], extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    };
  }

  // Step 1: each party signs its descriptor; the genesis revision names both.
  async form(): Promise<Step> {
    for (const p of [this.issuer, this.acceptor]) {
      const r = await signDescriptor(this.descriptorClaims(p.kid, p.key.publicKeyB64), this.handle(p));
      if (!r.ok) return failure("signDescriptor", r);
      p.descriptor = r.result.descriptor;
      const v = verifyDescriptor(p.descriptor);
      if (!v.ok) return { ok: false, message: "post-sign verify failed" };
      p.pdd = v.facts.descriptor_digest as string;
    }
    this.genesisText = this.revisionText({});
    const verified = verifyChain({ revisions: [this.genesisText], acceptances: [], descriptors: [this.issuer.descriptor!, this.acceptor.descriptor!], terminations: [] });
    if (!verified.ok) return { ok: false, message: "chain fixture failed: " + JSON.stringify(verified) };
    this.genesisDigest = (verified.facts.revisions as { digest: string }[])[0].digest;
    return { ok: true };
  }

  // Step 2: both parties accept the revision digest. Each acceptance is
  // checked against the signing party's own descriptor history only.
  async accept(): Promise<Step> {
    for (const p of [this.issuer, this.acceptor]) {
      const claims = {
        protocol_revision: 2,
        accepted_at: "2026-08-25T13:00:00Z",
        charter_id: this.genesisDigest,
        party_descriptor_digest: p.pdd!,
        party_role: p.role,
        revision_digest: this.genesisDigest,
        revision_number: 1,
      };
      const r = await signAcceptance(claims, this.handle(p), {
        revisionText: this.genesisText,
        descriptorCompacts: [p.descriptor!],
        chain: this.view({ acceptances: this.acceptanceIssuer ? [this.acceptanceIssuer] : [] }),
      });
      if (!r.ok) return failure(`signAcceptance (${p.role})`, r);
      if (p === this.issuer) this.acceptanceIssuer = r.result.acceptance; else this.acceptanceAcceptor = r.result.acceptance;
    }
    return { ok: true };
  }

  // Step 3: the issuing party signs a receipt for one action.
  async signActionReceipt(): Promise<Step> {
    const r = await signReceipt({
      protocol_revision: 2,
      charter_id: this.genesisDigest,
      revision_number: 1,
      revision_digest: this.genesisDigest,
      issuing_party_role: "issuer",
      agent_party_role: "acceptor",
      deployment_digest: dg("Q"),
      grant: { scheme: "bap", id: "grant-001", grant_digest: dg("E") },
      invocation_id: "inv-001",
      decision: "accepted",
      outcome: "effect_committed",
      occurred_at: "2026-08-25T13:30:00Z",
      recorded_at: "2026-08-25T13:30:01Z",
      extensions: { critical: {}, optional: {} },
    }, this.handle(this.issuer), this.view());
    if (!r.ok) return failure("signReceipt", r);
    this.receipt = r.result.receipt;
    return { ok: true };
  }

  // The evidence checks: each returns the world the page verifies.
  async tampered(kind: string): Promise<World | { error: string }> {
    const base = this.view();
    if (kind === "revision") {
      // The terms change after both parties accepted.
      const rewritten = this.revisionText({ legal_text: { content_digest: dg("S"), media_type: "text/plain" } });
      return { revisions: [rewritten], acceptances: base.acceptances, descriptors: base.descriptors, terminations: [] };
    }
    if (kind === "receipt") {
      return { revisions: [this.genesisText], acceptances: base.acceptances, descriptors: base.descriptors, terminations: [] };
    }
    // Re-form the issuer descriptor under a fresh key claiming the same seat.
    const impostor = await makeKey();
    const r = await signDescriptor(this.descriptorClaims(this.issuer.kid, impostor.publicKeyB64),
      { keyIdentity: () => ({ kid: this.issuer.kid, publicKey: impostor.publicKeyB64 }), sign: (m: Uint8Array) => impostor.sign(m) });
    if (!r.ok) return { error: `impostor descriptor → ${r.error}` };
    return { revisions: [this.genesisText], acceptances: base.acceptances, descriptors: [r.result.descriptor, this.acceptor.descriptor!], terminations: [] };
  }
}
