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
| `decodeJsonText(text, limits?)` | Strict I-JSON decode (duplicates, noncharacters, lone surrogates, number round-tripping rejected) |
| `jsonProjection(value)` | The tagged projection used by reports; object members retain text order |
| `Limits`, `DEFAULT_LIMITS`, `MAXIMUM_LIMITS` | Closed limits type, reference defaults and compiled maximum values; overrides must be nonnegative integers within the maximums |
| `ChainInput` | A chain view with `revisions`, `acceptances`, `descriptors`, and `terminations` string arrays |
| `VerificationOptions` | Optional `{ limits?: Partial<Limits>, profile?: { algorithms: string[]; revisions: { min: number; max: number } } }` for public verification |
| `SigningOptions` | Verification options plus an optional `algorithm` for `prepareSigning` |
| `capabilities()` / `algorithmRegistryDigest()` | Runtime known-answer results per signature registry row, and the signature registry digest |
| `CERTIFIED_INDEX_SHA256_BASE64URL`, `CERTIFIED_REGISTRY_DIGEST` | The certified identity pins this build carries |
| `verifyDescriptor(compact, predecessor?, options?)` / `verifyDescriptorChain(compacts, options?)` | Artifact-level verification: one party descriptor (with optional predecessor facts), or a full descriptor chain |
| `verifyAcceptance(compact, revisionText, descriptorCompacts, options?)` / `verifyTermination(compact, revisionText, descriptorCompacts, options?)` | Artifact-level verification of an acceptance / termination notice against the named revision and the signing party's descriptor chain |
| `verifyChain(chainInput, options?)` / `verifyReceipt(compact, chainInput, options?)` | Full chain-view verification (facts include topology, verified acceptances and termination notices); receipt verification against the verified chain |
| `checkSigningClaims(kind, claims)` | The producer build gate's claims half (the reference `decode_for_signing`): the claims-only schema checks per kind — `descriptor \| acceptance \| termination \| receipt` — shared with the verify paths; holder-side signers run it before any key is used |
| `decodeArtifact(compact)` / `verifySignature(message, signature, publicKey, alg, options?)` | Framing decode and the strict signature primitive; the latter retains its boolean result with optional limits and algorithm filtering |
| `descriptorSigningInput(kid, claims, alg?)` / `receiptSigningInput(kid, claims, alg?)` | The build-only producers: the exact RFC 7515 signing input per kind (emission pair gated, claims schema gated, provisional decode) — no key, no signature |
| `acceptanceSigningInput(kid, claims, chainInput, alg?)` / `terminationSigningInput(kid, claims, chainInput, alg?)` | The set-aware producers: build first, then the R1–R3 refusal checks at the reference ordering |
| `prepareSigning(kind, kid, claims, publicKey, context, options?)` | Check framing, claims, context, profile, limits, and the holder's own signing key before signing; return a `SigningPlan` |
| `finishSigning(plan, signature)` | Assemble under the plan's limits and run public verification with its retained context |
| `SigningPlan` / `SigningKind` | The plan class exposes `kind`, `input`, and `key` (`matched` or `unnamed`); kinds are `descriptor`, `acceptance`, `termination`, and `receipt` |
| `assembleCompact(signingInput, signature)` | Assemble a validated signing input and its exact raw signature (registry-row length, framing re-decode, size gate) |
| `governingRevision(chainInput, at, options?)` | The unique governing revision at one UTC instant — a digest, or `contested`/`none`, including verified termination closing |
| `decodeCharterRevision(text, options?)` / `revisionDigest(text, options?)` | Decode one canonical unsigned Charter Revision (claims + content digest over the exact text bytes) |
| `decodePartyDescriptor(compact)` / `descriptorDigest(compact)` | Decode one Party Descriptor's claims and digest without verifying its signature |
| `acceptanceRefusal(claims, chainInput)` / `terminationRefusal(claims, chainInput)` | The honest-signer refusal checks (R1–R3: claims-truth, no-equivocation, ancestry/governing coverage) over the caller's own view return `{ok: true}`, `signing_refused`, `signing_input_invalid`, or the set verification error. Holder-side signers run these before any key is used; the rule that fired is deliberately not surfaced |

`prepareSigning` accepts a predecessor or `null` for a descriptor, a chain view
(`revisions`, `acceptances`, `descriptors`, `terminations` arrays) for acceptance
and termination, and a chain view or bare revision text for a receipt. Pass a
canonical base64url public key. Its options are `algorithm`, `limits`, and
`profile`. Limits cover every artifact read, including the entire set. For
acceptance and termination, the profile covers the revision, the signing party's
descriptor history, and the new artifact; the full profile checks the rest of
the set. A receipt's profile covers the whole retained set and the new artifact.
A descriptor's profile includes its predecessor history.

Sign `plan.input.message`, then pass the raw `Uint8Array` signature to
`finishSigning`. Both signature functions accept plain and cross-realm
`Uint8Array` bytes, including Node Buffers. `verifySignature` returns `false` for
`ArrayBuffer` and `DataView` inputs; `finishSigning` returns `invalid_type` for
them. A bare-revision receipt has `key: "unnamed"`; public receipt
verification leaves its signature unchecked. `signing_key_invalid` means the
snapshot key fails the encoding or shape check; `signing_key_mismatch` means it
matches no active candidate in the holder's own view. The plan retains private
copies of its input, context arrays, limits, and profile. The existing producers
and `assembleCompact` continue to use default limits; use the plan API for caller
limits and the check before signing. A non-set passed to the existing set-aware
producers still returns `signing_input_invalid`.

Verification options default to the full algorithm registry, revisions 1..3,
and `DEFAULT_LIMITS`. Profiles apply to each signed artifact after its local
checks and before crypto; unsigned charter revisions use only the revision
axis. Public acceptance, termination, and receipt calls re-verify their
supplied context and check the artifact under the requested profile. `verifyChain` applies it throughout
the view. Malformed options return `invalid_limits` or `invalid_profile`;
excluded artifacts return `algorithm_outside_profile` or
`revision_outside_profile`.

Profiles may supply either `algorithms` or `revisions`; the omitted axis uses
the full supported range. A descriptor predecessor must retain its signed
`lineage`: pass the facts from a successful `verifyDescriptor` call to the
next call. The verifier rechecks those bytes and uses the resulting keys.

Chain views must supply all four artifact lists, using `[]` for empty lists.
The revision parties must be distinct descriptors and resolve to different
histories, and every supplied history must be named by some revision.

Each of the view's four artifact lists is bounded by
`max_artifact_set_items`; `max_artifact_set_bytes` bounds their combined
UTF-8 byte lengths before decoding. Corpus chain inputs can also supply
`limits`; receipt cases supply them inside the nested chain input.

Every facts record includes the reference's `not_verified` floor. Signed
records include `protocol_revision` and `alg`; unsigned revisions have
`alg: null`, and aggregate records have `protocol_revision: null`.
`decodeArtifact` also includes `signature` in `not_verified`. Artifact
verification can return `algorithm_unsupported_on_substrate` after its
deterministic checks. Corpus reporting stops with a diagnostic when the
substrate cannot verify, keeping that local result outside verdict reports.

## Evidence

- **Dual-implementation agreement.** This verifier and the Elixir reference
  implementation are independent codebases with zero shared code. Their
  canonical reports must be byte-identical over the certified corpus — in
  this repository and over the unpacked published package — enforced by the
  reference repository's gates, together with a randomized differential
  harness and a 25-mutation red-required battery.
- **The certified corpus** ships in this package (`conformance/`), pinned by
  a raw index SHA-256 asserted at load.
- **Ed25519 key and R admission.** After `npm run build`, run
  `npm run check:ed25519 -- /path/to/elixir/repository` to compare the source
  and built predicates with Elixir at `911d84b` on 10,000 seeded inputs and
  51 named edges for each role. The check compiles Elixir in a temporary copy
  of that commit, exposing its private R check by changing only its visibility.
  Run `npm run bench:ed25519` for admission and native signature costs, plus
  a valid chain with 80 descriptors, 200 revisions, and 400 acceptances.
- **This package never publishes verdict claims that were not recomputed
  from raw bytes.**

## The sibling signer

The `charter-agreement-protocol` npm organization hosts this protocol
family's two independent TypeScript packages — no Elixir code or dependency
at runtime; the Elixir reference is the certification oracle (this
package's vendored corpus is certified against it, and its CI
cross-verifies TypeScript-signed artifacts from raw bytes):

- **This package** — `@charter-agreement-protocol/verifier`: verification
  and the pure producer surface (signing inputs, refusal guards, assembly).
- [`@charter-agreement-protocol/signer`](https://www.npmjs.com/package/@charter-agreement-protocol/signer)
  — the holder-side companion: key custody, the wrong-key guard, and
  post-sign verification, delegating all protocol logic here.

The pair releases together: the signer depends on this package, so a
verifier release stages first and the signer locks and releases against
the published version immediately after.

## SemVer

Package SemVer is decoupled from the protocol's `protocol_revision`: new
wire revisions land additively (minor releases; old revisions keep
verifying side by side); a package major is owed only when a shipped public
API is removed or verdicts change.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). © The Charter
Agreement Protocol authors.
