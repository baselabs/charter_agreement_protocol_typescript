// The bench — the CAP verifier package's live page. The REAL code runs here:
// this repository's verifier source (bundled) judges a charter set minted in
// the browser by the published @charter-agreement-protocol/signer package
// (dev-dependency for demo issuance only — this package itself has zero
// runtime dependencies).
import { type ChainView } from "@charter-agreement-protocol/signer";
import {
  algorithmRegistry,
  CERTIFIED_INDEX_SHA256_BASE64URL,
  CERTIFIED_REGISTRY_DIGEST,
  decodeArtifact,
  verifyChain,
} from "../index.js";
import { Workshop } from "./flow.js";

const workshop = new Workshop();
let lastTamper: string | null = null;
const view = (): ChainView => workshop.view();

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
  for (const step of [() => workshop.form(), () => workshop.accept(), () => workshop.signActionReceipt()]) {
    const result = await step();
    if (!result.ok) { setVerdict("fail", `mint: ${esc(result.message)}`); return; }
  }

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
  for (const [label, compact] of [["party descriptor (A)", workshop.issuer.descriptor], ["acceptance (A)", workshop.acceptanceIssuer], ["receipt", workshop.receipt]] as const) {
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
  const changed = await workshop.tampered(kind);
  if ("error" in changed) { setVerdict("fail", esc(changed.error)); return; }
  verifySet(changed);
}

function renderRegistry(): void {
  const rows = algorithmRegistry();
  $("registry-body").innerHTML = accordion("Algorithm registry", "live", rows, false);
  $("corpus-digest").textContent = `certified index ${CERTIFIED_INDEX_SHA256_BASE64URL.slice(0, 22)}… · registry ${CERTIFIED_REGISTRY_DIGEST}`;
}

async function reset(): Promise<void> {
  await workshop.reset();
  bVerify.disabled = true;
  tamperBtns.forEach((b) => (b.disabled = true));
  $("facts-body").textContent = "—";
  $("decode-body").textContent = "—";
  $("custody-mode").textContent = `demo issuance keys: ${workshop.issuer.key.mode}`;
  setVerdict("idle", "mint a charter set to judge it");
}

bMint.addEventListener("click", () => void doMint());
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", () => void reset());
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

renderRegistry();
void reset();
