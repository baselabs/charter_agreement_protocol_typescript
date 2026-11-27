# @charter-agreement-protocol/verifier

Independent TypeScript verifier for the
[Charter Agreement Protocol](https://hex.pm/packages/charter_agreement_protocol) (CAP).

**CAP verifies. It never authorizes.** This package re-verifies signed,
byte-exact evidence of what charter parties agreed — party descriptor key
histories (Ed25519 and, from `protocol_revision` 3, ML-DSA per RFC 9964),
charter revisions, acceptances, termination notices, and action
receipts — completely offline, with no network, no clock, and no central
authority. Every verification result carries a closed floor of what was
*not* verified: authority, execution, billing, legal validity, term
satisfaction, and more. Hosts read the evidence and decide.

## Descriptor rotation

Use `descriptorNextKeyCommitment` to commit to a successor’s active keys. Create
revision-8 descriptors with the existing signing-input API. Pass the signed
history to `encodeDescriptorPublication` and `verifyDescriptorPublication` to
check the current and next pair and its opening status.

## Signer scopes

A revision-8 descriptor may declare `signing_scopes`, an array of up to 64
role entries. Each entry has a `role` and up to 32 `signers`. A signer
entry has a `key_thumbprint` from an active verification key and an
`artifact_kinds` array drawn from `acceptance`, `descriptor`, `receipt`,
and `termination`. Roles, thumbprints within each role, and kinds within
each signer entry are sorted and unique. Omission leaves the descriptor
unrestricted. An empty scope array permits no match.

`signerThumbprint` identifies a descriptor key by its algorithm and public
key bytes. Renaming its key id preserves that identity. The predecessor must
match `descriptor` under some role for its signing key to sign a successor.

Acceptances and terminations use the descriptor digest in the signed claims.
Receipts look up the issuing role in the named accepted revision. Those
verifiers report `scope_status` (`not_required`, `matched`, `outside`,
or `not_verified`) and `signer_thumbprint`. Bare-revision receipts and
receipts whose named revision is unrecognized have `not_verified` scope
and a null thumbprint.

Chain verification keeps every verified acceptance. It records the first
applicable `credit_reason` in order: `arbiter_not_counted`,
`role_outside_quorum`, and `signer_outside_scope`. A replacement vote uses
the predecessor's acceptance rule. An ordinary vote can still count under
the predecessor's rule when a successor narrows its quorum. A vote with a
reason has `credit: "uncredited"` and contributes no quorum vote.
Every candidate party supplies ordinary assignment assent even if its role
is outside the quorum. An outside signer cannot supply that assent.
Eligible votes have `credit: "not_required"` and a null reason.
Single-artifact acceptance verification returns
`credit: "not_evaluated"` and a null reason.

Outside termination notices remain visible and contribute no termination
votes. Receipt scope is descriptive. Checked signing refuses outside scope
with `signing_refused`. An outside descriptor successor returns
`descriptor_chain_invalid` in verification and checked preparation.

## Install

```console
npm install @charter-agreement-protocol/verifier@^1.0.0
```


The maintainers' release process publishes inspected archives to npm with
provenance through GitHub Actions trusted publishing after owner approval.

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
process.exitCode = report.exitStatus; // 0 = all certified cases recomputed and agreed
```

Or from the shell:

```console
npx @charter-agreement-protocol/verifier@^1.0.0        # the vendored certified corpus
npx @charter-agreement-protocol/verifier@^1.0.0 --corpus DIR  # any corpus directory
```

Exit `0` means every case recomputed and agreed with the certified
expectations. The loader refuses a newly self-consistent corpus whose index
SHA-256 does not equal the certified release pin, so a tampered corpus
cannot verify green.

## API

| Export | What it does |
|---|---|
| `reportFor(root)` | Load + integrity-check + recompute a corpus directory; returns the canonical report bytes and exit status |
| `runConformanceCase(case)` | Run one decoded corpus case through the public verifier and project its verdict |
| `loadCorpus(root)` | Integrity-checked corpus load (canonical index, digests, file set, applicability floor, certified index pin) |
| `selfChecks()` | The self-check battery: SHA-256 known answers, canonical ordering, strict base64url, timestamp and limit invariants |
| `canonical(value)` | RFC 8785 canonical JSON serialization |
| `decodeJsonText(text, limits?)` | Strict I-JSON decode (duplicates, noncharacters, lone surrogates, number round-tripping rejected) |
| `jsonProjection(value)` | The tagged projection used by reports; object members retain text order |
| `Limits`, `DEFAULT_LIMITS`, `MAXIMUM_LIMITS` | Closed limits type, reference defaults and compiled maximum values; overrides must be nonnegative integers within the maximums |
| `ChainInput` | A chain view with `revisions`, `acceptances`, `descriptors`, and `terminations` string arrays |
| `VerificationOptions` | Optional `{ limits?: Partial<Limits>, profile?: { algorithms?: string[]; revisions?: { min: number; max: number } } }` for public verification |
| `SigningOptions` | Verification options plus an optional `algorithm` for `prepareSigning` |
| `algorithmRegistry()` / `emissions()` / `defaultEmissionName()` | Signature registry rows, producer algorithm/revision pairs and the default emission name |
| `Profile` / `DescriptorPredecessor` | Optional capability axes and retained descriptor identity/lineage types |
| `capabilities()` / `algorithmRegistryDigest()` | Runtime known-answer results per signature registry row, and the signature registry digest |
| `CERTIFIED_INDEX_SHA256_BASE64URL`, `CERTIFIED_REGISTRY_DIGEST` | The certified identity pins this build carries |
| `inspectReceipt(compact, chain, grantReference?, options?)` | Receipt bytes, verified provenance, grant digest equality, and governing agreement |
| `verifyDescriptor(compact, predecessor?, options?)` / `verifyDescriptorChain(compacts, options?)` | Artifact-level verification: one party descriptor (with optional predecessor facts), or a full descriptor chain |
| `signerThumbprint(key)` | Validate a descriptor verification-key declaration and return its tagged algorithm-and-public-key identity |
| `verifyAcceptance(compact, revisionText, descriptorCompacts, options?)` / `verifyTermination(compact, revisionText, descriptorCompacts, options?)` | Artifact-level verification of an acceptance / termination notice against the named revision and the signing party's descriptor chain |
| `verifyChain(chainInput, options?)` / `verifyReceipt(compact, chainInput, options?)` | Full chain-view verification (facts include topology, verified acceptances and termination notices); receipt verification against the verified chain, with `deployment_digest_matched` and `optional_extensions_retained` in its facts |
| `checkSigningClaims(kind, claims)` | The producer build gate's claims half (the reference `decode_for_signing`): the claims-only schema checks for the four wire artifact kinds — `descriptor \| acceptance \| termination \| receipt` — shared with the verify paths; holder-side signers run it before any key is used |
| `decodeArtifact(compact)` / `verifySignature(message, signature, publicKey, alg, options?)` | Framing decode and the strict signature primitive; the latter retains its boolean result with optional limits and algorithm filtering |
| `descriptorSigningInput(kid, claims, alg?)` / `receiptSigningInput(kid, claims, alg?)` | The build-only producers: the exact RFC 7515 signing input per kind (emission pair gated, claims schema gated, provisional decode) — no key, no signature |
| `acceptanceSigningInput(kid, claims, chainInput, alg?)` / `partyReplacementSigningInput(kid, claims, chainInput, alg?)` / `terminationSigningInput(kid, claims, chainInput, alg?)` | Set-aware producers. The replacement producer frames the departing party's marked acceptance. |
| `prepareSigning(kind, kid, claims, publicKey, context, options?)` | Check framing, claims, context, profile, limits, key membership, and signer scope before signing; return a `SigningPlan` |
| `retainSigningContext(kind, context, options?)` | Validate options and context shape, then capture a bounded context before awaiting custody. On success, `value(kid, claims, publicKey)` prepares with the same result and error order as `prepareSigning`. |
| `finishSigning(plan, signature)` | Assemble under the plan's limits and run public verification with its retained context |
| `SigningPlan` / `SigningKind` | The plan class exposes `kind`, `input`, and `key` (`matched` or `unnamed`); kinds are `descriptor`, `acceptance`, `party_replacement`, `termination`, and `receipt` |
| `assembleCompact(signingInput, signature)` | Assemble a validated signing input and its exact raw signature (registry-row length, framing re-decode, size gate) |
| `governingRevision(chainInput, at, options?)` | The unique governing revision at one UTC instant — a digest, or `contested`/`none`, including verified termination closing |
| `decodeCharterRevision(text, options?)` / `revisionDigest(text, options?)` | Decode one canonical unsigned Charter Revision (claims + content digest over the exact text bytes) |
| `decodePartyDescriptor(compact)` / `descriptorDigest(compact)` | Decode one Party Descriptor's claims and digest without verifying its signature |
| `acceptanceRefusal(claims, chainInput)` / `terminationRefusal(claims, chainInput)` | The honest-signer refusal checks (R1–R3: claims-truth, no-equivocation, ancestry/governing coverage) over the caller's own view return `{ok: true}`, `signing_refused`, `signing_input_invalid`, or the set verification error. Holder-side signers run these before any key is used; the rule that fired is deliberately not surfaced |

Additional exported structural types are `CanonicalValue`, `Projection`,
`DecodeResult`, `CaseResult`, `CorpusFile`, `CorpusIndex`, `ConformanceCase`,
`LoadedCorpus`, `CaseOutcome`, `ConformanceReport`, `ReportOutput`,
`SigningInput`, `ProducerResult`, `AlgRow`, `VerifyResult`, and `RefusalResult`.
The installed declarations contain their complete shapes.

Legacy artifacts, including receipts, use `Ed25519` at protocol revision 2
or `ML-DSA-65` at revision 3. Revision-8 party descriptors, acceptances
(including marked assignor acceptances), and termination notices can use
either algorithm.

`prepareSigning` accepts a predecessor or `null` for a descriptor, a chain view
(`revisions`, `acceptances`, `descriptors`, `terminations` arrays) for acceptance,
party replacement, and termination. It accepts a chain view for a receipt,
or bare revision text for a legacy charter. Pass a
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
them. A receipt prepared against a bare legacy revision has `key: "unnamed"`.
Preparing against a bare revision-8 charter returns `signing_refused`.
Public receipt verification against a bare revision lists `signature` in
`not_verified` and adds `ownership` for revision 8. `signing_key_invalid` means the
snapshot key fails the encoding or shape check; `signing_key_mismatch` means it
matches no active candidate in the holder's own view. The plan retains private
copies of its input, context arrays, limits, and profile. The existing producers
and `assembleCompact` continue to use default limits; use the plan API for caller
limits and the check before signing. A non-set passed to the existing set-aware
producers still returns `signing_input_invalid`.

The following public functions return typed results for malformed input and
unreadable getters or Proxies: `verifyDescriptor`, `verifyDescriptorChain`,
`verifyAcceptance`, `verifyTermination`, `verifyChain`, `verifyReceipt`,
`prepareSigning`, `retainSigningContext`, `finishSigning`, `governingRevision`, `decodeArtifact`,
`decodeCharterRevision`, `revisionDigest`, `decodePartyDescriptor`,
`descriptorDigest`, `checkSigningClaims`, `acceptanceRefusal`,
`terminationRefusal`, `descriptorSigningInput`, `receiptSigningInput`,
`acceptanceSigningInput`, `partyReplacementSigningInput`, `terminationSigningInput`, `assembleCompact`, and
`decodeJsonText`. `verifySignature` returns `false` for malformed input.
`canonical`, `jsonProjection`, `encodeBase64url`, `taggedDigest`, `loadCorpus`,
and `reportFor` retain their existing return shapes and can throw on invalid
caller input, corpus failures, or unavailable corpus verification.

Known option members are read once at entry with ordinary property reads;
inherited values and getters count. Claims use own enumerable JSON members.
Copies check array lengths and byte sizes before allocation and bound expanded
bytes and depth. Deep or excessively shared signing claims return
`signing_input_invalid`.

Verification options default to the full algorithm registry, revisions 1, 2, 3, and 8,
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
  harness and its red-required mutation battery.
- **The certified corpus** ships in this package (`conformance/`), pinned by
  an Elixir source commit and raw index SHA-256 checked at load.
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
  — the holder-side companion: key custody and the wrong-key guard. It
  calls `prepareSigning` before the key is used and `finishSigning` after,
  so every protocol check stays in this package.

The 1.0 signer supports both the certified verifier 0.7 line and 1.x.
Its registry lock pins published 0.7.0 for the baseline compatibility check.
Its other check binds verifier 1.0 to the commit and exact archive integrity
recorded from staging. For a paired release, the maintainers' release process
publishes and verifies the verifier before publishing the signer.

## SemVer

The 1.x public JavaScript exports, TypeScript contracts and documented option
and error shapes follow Semantic Versioning. Removing or renaming a public
surface, or making an incompatible change to valid-input behavior, requires a
major release. New exports and optional options or fields are minor additions. An incompatible
change to a closed TypeScript union requires a major release. Compatible bug and
security fixes can tighten malformed-input handling; they are recorded in the
changelog. Package versions do not change an artifact's `protocol_revision`.

## Conformance reference and development

`reference.json` pins the published Elixir CAP 1.0.0 archive and its checksum.
The current corpus contains 901 cases in 18 files copied from the
[canonical Elixir commit](https://github.com/baselabs/charter_agreement_protocol/tree/f1f2e2acd44e827d02cfeb81d26199758cc2f8dd/priv/conformance).
The verifier checks the SHA-256 of the index and every listed case file.
Legacy revisions require assent from both parties. One qualifying notice
can close a legacy charter. Every charter successor needs an accepted predecessor.
A signed legacy successor of an unsigned genesis can lose governing status
on replay. Revision 8 requires the revision's acceptance
quorum, the applicable predecessor quorum, and any required assignment
assent. Closure requires a termination quorum for the same governing
revision, reason, and effective instant. See the [core specification](https://github.com/baselabs/charter_agreement_protocol/blob/f1f2e2acd44e827d02cfeb81d26199758cc2f8dd/spec/core.md).
The browser bench can inspect a receipt with its retained artifact set and
optional grant digest. Its download contains the same JSON evidence that
`inspectReceipt` returns. The signed segments reconstruct the receipt
exactly when joined with periods.

Node and the browser bundle run all 901 cases. The browser uses the 50
explicit capability-limited outcomes for ML-DSA verification.
`npm run check:reference` fetches the exact Elixir source commit from
`reference.json`, compares all vendored files to its Git blobs, and checks
that the released cases are retained.
`npm run check:reference -- --report` compares their exact report rows;
it requires Elixir 1.19/1.20 on OTP 28/29 linked to OpenSSL 3.5 or newer.

Use Node >= 24.8.0 and npm; `.tool-versions` pins the development Node.
The lockfile records TypeScript 7 and the current Node declarations. Qualification
runs these commands on GitHub-hosted runners:

```console
npm ci
npm run check
```

`check` runs strict library and browser typechecks, the full native/browser and
resource-boundary suites, self-checks, both builds, corpus agreement, the
released-corpus check, and the packed-consumer documentation/declaration checks.
CI covers the exact Node in `.tool-versions` and the Node 24.8.0 compatibility
floor; both lanes require the exact Bun pin for its real substrate behavior.
The reference job also installs the exact Erlang/OTP and Elixir pins from that
file. Every runtime is checked after installation. `npm run check:package` proves package
contents and reproducible bytes, executes this quickstart and the installed CLI,
and writes the verified tarball to `artifacts/package.tgz`.

## Releases

The maintainers' release process runs covering checks on the build box where
configured, never on a workstation. This public repository has no build-box
checkout: its qualification runs on pinned GitHub-hosted runners at landing.
Prepare the version commit with matching `package.json` and `package-lock.json`
versions, stamp the changelog, and update the documented release and site badge.
Land the full commit through the maintainers' landing tool; it qualifies the commit
on `kci/**` before moving the default branch. Do not push the default branch or
version tags directly.

Send the release operator one message with the repository, full commit, version, what goes out,
and the green `qualified` run. The release operator obtains owner approval and dispatches
[publish.yml](https://github.com/baselabs/charter_agreement_protocol_typescript/blob/main/.github/workflows/publish.yml)
from the default branch with the full qualified SHA as `release_commit`.
The first job checks default-branch history, the successful `qualified` check and
the absence of a version tag before checkout. The build uses that commit and the
registry script comes from the workflow revision. The build refuses a package
name the registry lacks, a deprecated or unpublished version, and served bytes
that differ from the inspected archive. A first publication is the owner's
decision. The build produces the library and documentation site and inspects
the archive. The protected upload job verifies the archive checksum and stages
missing bytes with
`npm stage publish --provenance` through OIDC. No stored npm token is used.
The package becomes public only after the owner approves the staged release
on npmjs.com with 2FA.

A held release is finished by dispatching `publish.yml` again with the same
`release_commit` after approval. It stages only what is missing, skips an identical
served version, and refuses differing bytes or a retired version. npm's OIDC
credentials cannot read pending staged versions: a dispatch while approval
is still pending may attempt to stage again, which npm refuses without
replacing the staged version. Approve the pending stage before dispatching
again.

Read-back downloads the npm tarball and compares its bytes with the inspected
archive. After it verifies the signed release commit, the workflow exports
`charter-agreement-protocol-verifier-<version>.tgz`, the site docs archive and `SHA256SUMS`. The docs archive
contains root `index.html` and `release.json`. The release operator compares the
tarball with npm's bytes and tags the commit named by `release.json`.
For a paired release, publish and verify the verifier first.

### Release source attestation

npm provenance identifies the default-branch workflow revision. The release
workflow also signs a predicate containing the qualified `release_commit` over
the checked tarball's digest. Read-back checks that predicate against the
tarball downloaded from npm.

To verify a release, download the archives and `SHA256SUMS` from the matching
[`v<version>` GitHub release](https://github.com/baselabs/charter_agreement_protocol_typescript/releases) and run
`sha256sum --check SHA256SUMS` in their directory. Compare the tarball's SHA-512
with npm's `dist.integrity`, then verify its release source against the tag.

```sh
published_commit=$(gh api "repos/baselabs/charter_agreement_protocol_typescript/commits/v<version>" -q .sha)
gh attestation verify "charter-agreement-protocol-verifier-<version>.tgz" \
  --repo baselabs/charter_agreement_protocol_typescript \
  --signer-workflow baselabs/charter_agreement_protocol_typescript/.github/workflows/publish.yml \
  --source-ref refs/heads/main \
  --predicate-type 'https://github.com/baselabs/charter_agreement_protocol_typescript/blob/main/README.md#release-source-attestation' \
  --format json |
  jq -e --arg commit "$published_commit" \
    'any(.[]; .verificationResult.statement.predicate.release_commit == $commit)'
```

Site typechecking and building are required by `qualified`. The release operator dispatches
[pages.yml](https://github.com/baselabs/charter_agreement_protocol_typescript/blob/main/.github/workflows/pages.yml)
from the default branch to build and deploy the static site through GitHub's
`github-pages` environment. A default-branch push or version tag starts neither workflow.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). © The Charter
Agreement Protocol authors.
