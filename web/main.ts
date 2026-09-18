// The bench — the CAP verifier package's live page. The REAL code runs here:
// this repository's verifier source (bundled) judges a charter set minted in
// the browser by the published @charter-agreement-protocol/signer package
// (dev-dependency for demo issuance only — this package itself has zero
// runtime dependencies).
import { keygen, sign as nobleSign } from "@noble/ed25519";
import { signAcceptance, signDescriptor, signReceipt, type ChainView } from "@charter-agreement-protocol/signer";
import {
  algorithmRegistry,
  CERTIFIED_INDEX_SHA256_BASE64URL,
  CERTIFIED_REGISTRY_DIGEST,
  decodeArtifact,
  verifyChain,
  verifyDescriptor,
} from "../index.js";

interface CustodyKey {
  publicKeyB64: string;
  sign: (m: Uint8Array) => Promise<Uint8Array>;
  mode: "WebCrypto non-extractable" | "in-page (noble)";
}

async function makeKey(): Promise<CustodyKey> {
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

interface Party { key: CustodyKey; kid: string; descriptor?: string; pdd?: string; role: "issuer" | "acceptor" }
let issuer: Party, acceptor: Party;
let genesisText = "", genesisDigest = "";
let acceptanceIssuer = "", acceptanceAcceptor = "", receipt = "";
let lastTamper: string | null = null;
const dg = (c: string) => "sha-256:" + c.repeat(43);

function revisionText(overrides: Record<string, unknown>): string {
  return JSON.stringify({
    abp_bindings: [{ blueprint_id: "example.demo/echo", content_digest: dg("P"), deployment_digest: dg("Q"), party_role: "acceptor", release_number: 1 }],
    attribution_declaration: { basis: "bound_deployments" },
    effective_from: "2026-08-25T12:00:00Z",
    extensions: { critical: {}, optional: {} },
    legal_text: { content_digest: dg("L"), media_type: "text/plain" },
    parties: [
      { party_descriptor_digest: issuer.pdd as string, role: "issuer" },
      { party_descriptor_digest: acceptor.pdd as string, role: "acceptor" },
    ],
    precedence_declaration: "legal_text_governs",
    protocol_revision: 2,
    receipt_profile: "com.example.charter/default",
    revision_number: 1,
    termination_rules: { reason_codes: ["mutual", "breach"] },
    ...overrides,
  });
}

const view = (): ChainView => ({
  revisions: [genesisText],
  acceptances: [acceptanceIssuer, acceptanceAcceptor],
  descriptors: [issuer.descriptor!, acceptor.descriptor!],
  terminations: [],
});

const handle = (p: Party) => ({ keyIdentity: () => ({ kid: p.kid, publicKey: p.key.publicKeyB64 }), sign: (m: Uint8Array) => p.key.sign(m) });

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const bMint = $<HTMLButtonElement>("btn-mint"), bVerify = $<HTMLButtonElement>("btn-verify");
const tamperBtns = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-tamper]"));

function setVerdict(state: "idle" | "ok" | "fail", html: string): void {
  const v = $("verdict");
  v.dataset.state = state;
  const icon = state === "ok" ? "#i-check" : state === "fail" ? "#i-x" : "#i-terminal";
  v.innerHTML = `<span class="verdict-mark"><svg class="ic"><use href="${icon}"/></svg></span><span class="verdict-text">${html}</span>`;
}

function replacer(_k: string, v: unknown): unknown {
  if (v instanceof Uint8Array) return `hex:${Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32)}…`;
  return v;
}

async function doMint(): Promise<void> {
  for (const p of [issuer, acceptor]) {
    const r = await signDescriptor({
      protocol_revision: 2, descriptor_number: 1,
      verification_keys: [{ key_id: p.kid, algorithm: "Ed25519", public_key: p.key.publicKeyB64, status: "active" }],
      attestation_hints: [], extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    }, handle(p));
    if (!r.ok) { setVerdict("fail", `mint: signDescriptor → ${r.error}`); return; }
    p.descriptor = r.result.descriptor;
    const v = verifyDescriptor(p.descriptor);
    if (!v.ok) { setVerdict("fail", "post-sign verify failed"); return; }
    p.pdd = v.facts.descriptor_digest as string;
  }
  genesisText = revisionText({});
  const chain = verifyChain({ revisions: [genesisText], acceptances: [], descriptors: [issuer.descriptor!, acceptor.descriptor!], terminations: [] });
  if (!chain.ok) { setVerdict("fail", "fixture chain: " + JSON.stringify(chain)); return; }
  genesisDigest = (chain.facts.revisions as { digest: string }[])[0].digest;

  for (const [p, other] of [[issuer, acceptor], [acceptor, issuer]] as const) {
    const claims = {
      protocol_revision: 2, accepted_at: "2026-08-25T13:00:00Z",
      charter_id: genesisDigest, party_descriptor_digest: p.pdd, party_role: p.role,
      revision_digest: genesisDigest, revision_number: 1,
    };
    const r = await signAcceptance(claims, handle(p), {
      revisionText: genesisText,
      descriptorCompacts: [p.descriptor!, other.descriptor!],
      chain: { ...view(), acceptances: acceptanceIssuer ? [acceptanceIssuer] : [] },
    });
    if (!r.ok) { setVerdict("fail", `mint: signAcceptance → ${r.error}`); return; }
    if (p === issuer) acceptanceIssuer = r.result.acceptance; else acceptanceAcceptor = r.result.acceptance;
  }

  const rec = await signReceipt({
    protocol_revision: 2, charter_id: genesisDigest, revision_number: 1, revision_digest: genesisDigest,
    issuing_party_role: "issuer", agent_party_role: "acceptor", deployment_digest: dg("Q"),
    grant: { scheme: "bap", id: "grant-001", grant_digest: dg("E") },
    invocation_id: "inv-001", decision: "accepted", outcome: "effect_committed",
    occurred_at: "2026-08-25T13:30:00Z", recorded_at: "2026-08-25T13:30:01Z",
    extensions: { critical: {}, optional: {} },
  }, handle(issuer), view());
  if (!rec.ok) { setVerdict("fail", `mint: signReceipt → ${rec.error}`); return; }
  receipt = rec.result.receipt;

  renderDecode();
  bVerify.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = false));
  setVerdict("idle", "a complete charter set, minted in your browser — now judge it");
}

function renderDecode(): void {
  const rows: string[] = [];
  for (const [label, compact] of [["party descriptor (A)", issuer.descriptor], ["acceptance (A)", acceptanceIssuer], ["receipt", receipt]] as const) {
    if (!compact) continue;
    const d = decodeArtifact(compact);
    rows.push(`// ${label} — decodeArtifact\n` + (d.ok ? JSON.stringify(d, replacer, 2) : JSON.stringify(d)));
  }
  $("decode-body").textContent = rows.join("\n\n");
}

function factsSummary(facts: Record<string, unknown>): string {
  return `revisions: ${(facts.revisions as unknown[] | undefined)?.length ?? 0} · acceptances: ${(facts.acceptances as unknown[] | undefined)?.length ?? 0} — full facts below (this package returns what it proves; the twelve-item omission floor is the protocol's facts-record contract, documented in the reference)`;
}

function verifySet(w: ChainView): void {
  const at = verifyChain(w);
  if (at.ok) {
    setVerdict("ok", "CHAIN VERIFIED — structural facts from raw bytes");
    $("facts-body").textContent = factsSummary(at.facts as Record<string, unknown>) + "\n\n" + JSON.stringify(at.facts, replacer, 2);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Now rewrite the past — the buttons below produce real refusals.";
  } else {
    setVerdict("fail", `VERIFICATION FAILED — <b>${(at as { code?: string }).code ?? "invalid"}</b>`);
    $("facts-body").textContent = JSON.stringify(at, replacer, 2);
    $("tamper-hint").className = "hint fail";
    const why: Record<string, string> = {
      revision: "the legal text changed after acceptance — digest bindings no longer match",
      descriptor: "a fresh key claims the issuer's seat — identity binding failed",
    };
    const w2 = lastTamper ? why[lastTamper] : undefined;
    $("tamper-hint").textContent = w2 ? `${w2} — closed refusal, code only.` : "closed refusal, code only.";
  }
}

function doVerify(): void { lastTamper = null; verifySet(view()); }

async function tamper(kind: string): Promise<void> {
  lastTamper = kind;
  if (kind === "revision") {
    verifySet({ ...view(), revisions: [revisionText({ legal_text: { content_digest: dg("S"), media_type: "text/plain" } })] });
    return;
  }
  if (kind === "descriptor") {
    const impostor = await makeKey();
    const r = await signDescriptor({
      protocol_revision: 2, descriptor_number: 1,
      verification_keys: [{ key_id: issuer.kid, algorithm: "Ed25519", public_key: impostor.publicKeyB64, status: "active" }],
      attestation_hints: [], extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    }, { keyIdentity: () => ({ kid: issuer.kid, publicKey: impostor.publicKeyB64 }), sign: (m: Uint8Array) => impostor.sign(m) });
    if (!r.ok) { setVerdict("fail", `impostor → ${r.error}`); return; }
    verifySet({ ...view(), descriptors: [r.result.descriptor, acceptor.descriptor!] });
  }
}

function renderRegistry(): void {
  const rows = algorithmRegistry();
  $("registry-body").textContent = JSON.stringify(rows, null, 2);
  $("corpus-digest").textContent = `certified index ${CERTIFIED_INDEX_SHA256_BASE64URL.slice(0, 22)}… · registry ${CERTIFIED_REGISTRY_DIGEST}`;
}

async function reset(): Promise<void> {
  const [ik, ak] = await Promise.all([makeKey(), makeKey()]);
  issuer = { key: ik, kid: "issuer-key-001", role: "issuer" };
  acceptor = { key: ak, kid: "acceptor-key-001", role: "acceptor" };
  genesisText = genesisDigest = acceptanceIssuer = acceptanceAcceptor = receipt = "";
  bVerify.disabled = true;
  tamperBtns.forEach((b) => (b.disabled = true));
  $("facts-body").textContent = "—";
  $("decode-body").textContent = "—";
  $("custody-mode").textContent = `demo issuance keys: ${issuer.key.mode}`;
  setVerdict("idle", "mint a charter set to judge it");
}

bMint.addEventListener("click", () => void doMint());
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", () => void reset());
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

renderRegistry();
void reset();
