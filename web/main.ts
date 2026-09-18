// The bench — the CAP verifier package's live page. The REAL code runs here:
// this repository's verifier source (bundled) judges a charter set minted in
// the browser by the published @charter-agreement-protocol/signer package
// (dev-dependency for demo issuance only — this package itself has zero
// runtime dependencies).
import { keygen, sign as nobleSign } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
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
// Deterministic fixture digests: hash the seed so every demo digest READS like
// a digest (43 base64url chars of real SHA-256 output) instead of a repeated
// letter — the shape the protocol's digest fields validate either way.
const dg = (seed: string): string =>
  "sha-256:" + Buffer.from(sha256(new TextEncoder().encode("demo:" + seed))).toString("base64url");

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


// ---------- artifact accordions: designed, animated disclosure ----------
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");


const humanize = (k: string): string =>
  k.replace(/[_-]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/\b\w/g, (c) => c.toUpperCase()).trim();

const isBinaryString2 = (s: string): boolean => /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff]/.test(s);
const toHex2 = (bytes: number[]): string => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

function valueChip(v: unknown): string | null {
  if (v instanceof Uint8Array) {
    const hex = toHex2(Array.from(v));
    return `<span class="chip mono" title="${esc(hex)}">${hex.slice(0, 20)}… · ${v.length}B</span>`;
  }
  if (typeof v === "string" && isBinaryString2(v)) {
    const m = v.match(/^([a-z0-9]+-?[a-z0-9]*:)/i);
    const prefix = m ? m[1] : "";
    const hex = toHex2(Array.from(v.slice(prefix.length), (c) => c.charCodeAt(0) & 0xff));
    return `<span class="chip mono" title="${esc(prefix + hex)}">${prefix}${hex.slice(0, 20)}… · ${v.length - prefix.length}B</span>`;
  }
  return null;
}

function fieldRows(obj: unknown, depth = 0): string {
  if (obj === null || typeof obj !== "object") {
    const chip = valueChip(obj);
    return chip ?? `<span class="val">${esc(String(obj))}</span>`;
  }
  const entries: [string, unknown][] = Array.isArray(obj)
    ? obj.map((v, i) => [`Item ${i + 1}`, v])
    : Object.entries(obj as Record<string, unknown>);
  return entries.map(([k, v]) => {
    if (v !== null && typeof v === "object" && !(v instanceof Uint8Array)) {
      return `<div class="field group"><div class="fl">${esc(humanize(k))}</div><div class="group-inner">${fieldRows(v, depth + 1)}</div></div>`;
    }
    const chip = valueChip(v);
    const s = String(v);
    const shown = chip ?? `<span class="val${/sha-256:|urn:|https:/.test(s) ? " mono" : ""}" title="${esc(s)}">${esc(s.length > 72 ? s.slice(0, 72) + "…" : s)}</span>`;
    return `<div class="field"><div class="fl">${esc(humanize(k))}</div><div class="fvs">${shown}</div></div>`;
  }).join("");
}

function accordion(title: string, chip: string | undefined, facts: unknown, open = false): string {
  return `<div class="acc${open ? " open" : ""}">
    <button type="button" class="acc-head" aria-expanded="${open}">
      <svg class="ic"><use href="#i-doc"/></svg>
      <span class="acc-title">${esc(title)}</span>
      ${chip ? `<span class="acc-chip mono">${esc(chip)}</span>` : ""}
      <svg class="ic acc-chev"><use href="#i-chev"/></svg>
    </button>
    <div class="acc-body"><div class="acc-inner">${fieldRows(facts)}</div></div>
  </div>`;
}


// Raw-JSON code box for the FACTS area (owner-directed: no formatted view) —
// defensively hex any string that still carries control/lossy characters.
function sanitize(v: unknown): unknown {
  // Byte arrays render as their base64url wire form — JSON.stringify on a
  // Uint8Array explodes into {"0":123,"1":34,…} index objects otherwise.
  if (v instanceof Uint8Array) {
    return Buffer.from(v).toString("base64url");
  }
  if (typeof v === "string" && /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff\ufffd]/.test(v)) {
    return "0x" + Array.from(v, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(v)) return v.map(sanitize);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = sanitize(val);
    return o;
  }
  return v;
}
function rawJsonBox(facts: unknown): string {
  return `<pre class="codebox">${esc(JSON.stringify(sanitize(facts), null, 2))}</pre>`;
}

// One delegated listener drives every accordion on the page, including ones
// injected later (artifacts after mint).
document.addEventListener("click", (e) => {
  const head = (e.target as HTMLElement).closest?.(".acc-head");
  if (!(head instanceof HTMLElement)) return;
  const acc = head.parentElement;
  if (!acc) return;
  const open = acc.classList.toggle("open");
  head.setAttribute("aria-expanded", String(open));
});

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

  const slot = $("slot-set");
  slot.textContent = "";
  const summary = document.createElement("div");
  summary.className = "set-summary";
  summary.innerHTML = [
    ["descriptors", 2], ["revision", 1], ["acceptances", 2], ["receipt", 1],
  ].map(([k, n]) => `<span class="chip mono">${n} × ${k}</span>`).join("")
    + `<div class="dim" style="font-size:.78rem;margin-top:8px">signed, post-verified, and decoded below ↓</div>`;
  slot.appendChild(summary);
  renderDecode();
  bVerify.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = false));
  setVerdict("idle", "a complete charter set, minted in your browser — now judge it");
}

function renderDecode(): void {
  const panels: string[] = [];
  for (const [label, compact] of [["party descriptor (A)", issuer.descriptor], ["acceptance (A)", acceptanceIssuer], ["receipt", receipt]] as const) {
    if (!compact) continue;
    const d = decodeArtifact(compact);
    panels.push(accordion(label, undefined, (d as { ok: boolean; facts?: unknown }).ok ? (d as { facts: unknown }).facts : d, false));
  }
  $("decode-body").innerHTML = panels.join("\n");
}

function factsSummary(facts: Record<string, unknown>): string {
  return `revisions: ${(facts.revisions as unknown[] | undefined)?.length ?? 0} · acceptances: ${(facts.acceptances as unknown[] | undefined)?.length ?? 0} — full facts below (this package returns what it proves; the twelve-item omission floor is the protocol's facts-record contract, documented in the reference)`;
}

function verifySet(w: ChainView): void {
  const at = verifyChain(w);
  if (at.ok) {
    setVerdict("ok", "CHAIN VERIFIED — structural facts from raw bytes");
    $("facts-body").innerHTML = rawJsonBox(at.facts);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Now rewrite the past — the buttons below produce real refusals.";
  } else {
    setVerdict("fail", `VERIFICATION FAILED — <b>${(at as { code?: string }).code ?? "invalid"}</b>`);
    $("facts-body").innerHTML = rawJsonBox(at);
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
  $("registry-body").innerHTML = accordion("Algorithm registry", "live", rows, false);
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
