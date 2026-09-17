# @charter-agreement-protocol/verifier

Independent TypeScript verifier for the
[Charter Agreement Protocol](https://hex.pm/packages/charter_agreement_protocol) (CAP).

**CAP verifies. It never authorizes.** This package re-verifies signed,
byte-exact evidence of what two parties agreed — party descriptor key
histories (Ed25519 and, from `protocol_revision` 3, ML-DSA per RFC 9964),
charter revisions, bilateral acceptances, termination notices, and action
receipts — completely offline, with no network, no clock, and no central
authority. Every verification result carries a closed floor of what was
*not* verified: authority, execution, billing, legal validity, term
satisfaction, and more. Hosts read the evidence and decide.

## Install

```console
npm install @charter-agreement-protocol/verifier
```

Requires Node >= 24.8 (ML-DSA landed in the Node builtins across the
24.6–24.8 minors). Zero runtime dependencies — Node builtins only.

## Quickstart

Verify the certified conformance corpus shipped inside the package (the
fastest way to see the verifier work end-to-end):

```js
import { reportFor } from "@charter-agreement-protocol/verifier";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const corpusRoot = join(dirname(require.resolve("@charter-agreement-protocol/verifier/package.json")), "conformance");
const report = reportFor(corpusRoot);
console.log(report.bytes);   // canonical JSON report
process.exit(report.exitStatus); // 0 = all certified cases recomputed and agreed
```

Or from the shell:

```console
npx @charter-agreement-protocol/verifier        # the vendored certified corpus
npx @charter-agreement-protocol/verifier --corpus DIR  # any corpus directory
```

Exit `0` means every case recomputed and agreed with the certified
expectations. The loader refuses a newly self-consistent corpus whose index
SHA-256 does not equal the certified release pin, so a tampered corpus
cannot verify green.

## API

| Export | What it does |
|---|---|
| `reportFor(root)` | Load + integrity-check + recompute a corpus directory; returns the canonical report bytes and exit status |
| `loadCorpus(root)` | Integrity-checked corpus load (canonical index, digests, file set, applicability floor, certified index pin) |
| `selfChecks()` | The self-check battery: SHA-256 known answers, canonical ordering, strict base64url, timestamp and limit invariants |
| `canonical(value)` | RFC 8785 canonical JSON serialization |
| `decodeJsonText(text)` | Strict I-JSON decode (duplicates, noncharacters, lone surrogates, number round-tripping rejected) |
| `jsonProjection(value)` | The tagged projection used by reports |
| `CERTIFIED_INDEX_SHA256_BASE64URL`, `CERTIFIED_REGISTRY_DIGEST` | The certified identity pins this build carries |
| `verifyDescriptor(compact, predecessor?)` / `verifyDescriptorChain(compacts)` | Artifact-level verification: one party descriptor (with optional predecessor facts), or a full descriptor chain |
| `verifyAcceptance(compact, revisionText, descriptorCompacts)` / `verifyTermination(compact, revisionText, descriptorCompacts)` | Artifact-level verification of an acceptance / termination notice against the named revision and the signing party's descriptor chain |
| `verifyChain(chainInput)` / `verifyReceipt(compact, chainInput)` | Full chain-view verification (facts include the accepted/superseded topology and the verified acceptances); receipt verification against the verified chain |
| `checkSigningClaims(kind, claims)` | The producer build gate's claims half (the reference `decode_for_signing`): the claims-only schema checks per kind — `descriptor \| acceptance \| termination \| receipt` — shared with the verify paths; holder-side signers run it before any key is used |
| `decodeArtifact(compact)` / `verifySignature(message, signature, publicKey, alg)` | Framing-level decode (the holder-side provisional check) and the strict wrong-key guard primitive |
| `descriptorSigningInput(kid, claims, alg?)` / `receiptSigningInput(kid, claims, alg?)` | The build-only producers: the exact RFC 7515 signing input per kind (emission pair gated, claims schema gated, provisional decode) — no key, no signature |
| `acceptanceSigningInput(kid, claims, chainInput, alg?)` / `terminationSigningInput(kid, claims, chainInput, alg?)` | The set-aware producers: build first, then the R1–R3 refusal checks at the reference ordering |
| `assembleCompact(signingInput, signature)` | Assemble a validated signing input and its exact raw signature (registry-row length, framing re-decode, size gate) |
| `governingRevision(chainInput, at)` | The unique governing revision at one UTC instant — a digest, or `contested`/`none`, over the certified chain semantics |
| `decodeCharterRevision(text)` / `revisionDigest(text)` | Decode one canonical unsigned Charter Revision (claims + content digest over the exact text bytes) |
| `decodePartyDescriptor(compact)` / `descriptorDigest(compact)` | Decode one Party Descriptor's claims and digest without verifying its signature |
| `acceptanceRefusal(claims, chainInput)` / `terminationRefusal(claims, chainInput)` | The honest-signer refusal checks (R1–R3: claims-truth, no-equivocation, ancestry/governing coverage) over the caller's own view — `{ok: true}`, or `signing_refused` / `chain_invalid` / `signing_input_invalid`. Holder-side signers run these before any key is used; the rule that fired is deliberately not surfaced |

## Evidence

- **Dual-implementation agreement.** This verifier and the Elixir reference
  implementation are independent codebases with zero shared code. Their
  canonical reports must be byte-identical over the certified corpus — in
  this repository and over the unpacked published package — enforced by the
  reference repository's gates, together with a randomized differential
  harness and a 25-mutation red-required battery.
- **The certified corpus** ships in this package (`conformance/`), pinned by
  a raw index SHA-256 asserted at load.
- **This package never publishes verdict claims that were not recomputed
  from raw bytes.**

## Organization namespace

The `charter-agreement-protocol` npm organization hosts this protocol family's
TypeScript packages: `@charter-agreement-protocol/verifier` (this package) and
`@charter-agreement-protocol/signer` (reserved for the holder-side companion
signer's TypeScript package).

## SemVer

Package SemVer is decoupled from the protocol's `protocol_revision`: new
wire revisions land additively (minor releases; old revisions keep
verifying side by side); a package major is owed only when a shipped public
API is removed or verdicts change.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). © The Charter
Agreement Protocol authors.
