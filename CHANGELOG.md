# Changelog

All notable public changes to `@charter-agreement-protocol/verifier` are
documented here.

## [Unreleased]

### Breaking

- `verifyDescriptor` requires a predecessor with retained signed `lineage`;
  the former `{ digest, claims }` shape returns `descriptor_chain_invalid`.
  `DescriptorPredecessor` is now exported. Pass verified facts to the next call:

  ```ts
  import { verifyDescriptor, type DescriptorPredecessor } from "@charter-agreement-protocol/verifier";
  const root = verifyDescriptor(genesisCompact);
  if (root.ok) {
    const previous: DescriptorPredecessor = root.facts;
    const next = verifyDescriptor(successorCompact, previous);
  }
  ```

  A genesis descriptor given a predecessor now returns
  `descriptor_chain_invalid` instead of verifying successfully. Both supplied
  digest aliases must match the reverified lineage. A lone successor with a
  noncanonical identity digest returns `descriptor_invalid` before the missing
  predecessor reports `descriptor_chain_invalid`.

### Changed

- Browser bundles using the shipped crypto shim now verify valid Ed25519
  signatures instead of returning `algorithm_unsupported_on_substrate`.
  ML-DSA still reports that code on this substrate.
- Standalone acceptance and termination profiles now admit the supplied
  revision first, then every descriptor in the supplied history, then the
  signed artifact. Receipt profiles reach the whole reverified chain view.
  Excluded context now returns `algorithm_outside_profile` or
  `revision_outside_profile` before artifact decoding, claims or signature
  errors that previously took precedence, or instead of a successful result.
- `verifyReceipt(compact, revisionText, options)` now accepts a canonical
  revision as context. Recognized claims return `governing_match: "undetermined"`
  and `chain_conflict: "none"`; `not_verified` includes `signature` because this
  context names no signing key. The receipt envelope is still admitted against
  the profile. Excluded revisions or envelopes return `revision_outside_profile`
  or `algorithm_outside_profile`; mismatched claims return
  `receipt_claims_mismatch`. Previously text context returned `chain_invalid`.
- Omitted artifact lists now return `invalid_type` through `governingRevision`,
  `acceptanceRefusal`, `terminationRefusal`, `acceptanceSigningInput` and
  `terminationSigningInput`, replacing `chain_invalid`. `verifyChain` and
  `verifyReceipt` also require all four lists, including explicit empty lists.
- All producer build failures now return `signing_input_invalid`, including
  malformed claims, extra members, invalid timestamps and unsupported emission
  algorithms. This replaces leaked schema and artifact codes, including
  `unknown_member`, `missing_required`, `nested_invalid`, `constraint_violation`,
  `cardinality_violation`, `descriptor_invalid`, `acceptance_invalid`,
  `termination_invalid`, `receipt_invalid`, `timestamp_invalid`, `invalid_type`
  and `algorithm_unsupported`. An explicit null algorithm now rejects with
  `signing_input_invalid` instead of selecting the default algorithm.
- `npm run build` removes `dist/` before compiling, so obsolete modules are
  removed from the compiled package.
- Year 0000, including February 29, now passes timestamp parsing on every
  artifact, indexed observation and governing query, matching RFC 3339 and
  the reference. The self-check now asserts acceptance of year zero.
- Revisions repeating a party descriptor now return `revision_invalid`.
  Views with both parties in one descriptor history, or a supplied history
  that no revision names, now return `chain_invalid`. Missing descriptors
  are skipped when comparing histories, as in the reference.
- Noncanonical signed digests now return `acceptance_invalid`,
  `termination_invalid` or `receipt_invalid`, including optional detail and
  nested receipt digests. A correctly signed receipt with a noncanonical
  revision digest no longer verifies successfully.
- Malformed termination and receipt timestamps now return
  `timestamp_invalid`; reversed valid times keep their artifact-specific
  errors. Acceptance timestamps precede predecessor-shape checks, and
  revision timestamps precede binding-digest checks.
- Descriptor key encodings that fit the schema but fail canonical encoding
  or the selected algorithm's byte length now return `descriptor_invalid`.
  Duplicate key IDs and the absence of an active key reject before extension
  and timestamp checks. Noncanonical descriptor identity digests also
  return `descriptor_invalid`.
- Chain routing checks the expected envelope type and both routing
  coordinates before artifact claims: wrong types now report
  `protected_header_invalid`, while missing signer coordinates or signer
  histories report `chain_invalid`. Missing artifact lists now report
  `invalid_type`; callers must supply empty lists explicitly.
- Successor descriptor links precede key selection. An incorrect link with
  an unknown key now reports `descriptor_chain_invalid`.
  `verifyDescriptor` re-verifies the predecessor's retained `lineage`,
  ignoring caller key claims. Predecessors without valid lineage reject
  with `descriptor_chain_invalid`; null claims no longer cause a crash.
  Successful descriptor facts include lineage for subsequent calls.
- Producers reject extra termination members, including `extensions`,
  with `signing_input_invalid`. Assembly re-decodes the complete artifact; framed
  inputs with invalid claims now return `signing_input_invalid`.
- Runtime file imports can no longer replace verification or substrate
  checks. The mutable test hook is removed from source and compiled output.
  Normal signature verification asks the runtime about key support without
  running signature vectors; only a crypto exception reruns the selected
  vector. A failing signature vector no longer overrides a successful
  normal crypto call.
- JSON limits count duplicate members after accepting the separator or closer
  following each value. Malformed containers now report `invalid_syntax` before
  `limit_exceeded`, `invalid_number` or `number_not_double_expressible` when
  that separator is missing or invalid. Numeric conversion errors are delayed
  until a container separator or the end of the root value is accepted.
  An excess duplicate member now reports `limit_exceeded`; an invalid value
  beyond an item or member bound reports its parse error first.
  Nontext revision inputs now report `invalid_type`.
- `verifySignature` returns false for messages over 1 MiB under default
  limits. Explicit null artifact lists report `invalid_type`.
  The exported `Profile` type accepts `algorithms` or `revisions` alone,
  with the omitted axis using the full supported range.

Several inputs that verified under 0.5.0 now reject: revision JSON with
whitespace or duplicate members; revisions with invalid member types,
constraints, timestamps or party counts; unknown signed claims or extra
members in closed nested objects; descriptor histories mixing parties or
successors with a missing or different party ID; chain views with fewer or
more than two party histories; malformed indexed pricing terms or receipt
observations; and artifact lists or byte totals exceeding caller limits.

- Public `verify*` functions gain optional trailing limits and profile
  arguments. Existing call signatures continue to work. `Limits`,
  `VerificationOptions`, `DEFAULT_LIMITS` and `MAXIMUM_LIMITS` are exported.
- Verified terminations close governing views at their effective instant
  when bound to the revision governing then; later receipts report a
  governing mismatch.
- Facts include `not_verified` and artifact metadata (`protocol_revision`
  and `alg` for signed artifacts). Framing decode adds `signature` to the
  unverified scope.
- Unavailable crypto substrates report `algorithm_unsupported_on_substrate`
  separately from invalid signatures, outside corpus verdict reports.
- JSON projections preserve input member order, including numeric-looking
  names. The float boxing seam used by the differential gate is unchanged.
- The vendored certified corpus contains 149 cases for verification semantics
  5 and uses the reference's expanded applicability floor. The registry digest
  and package version remain unchanged.

## [0.5.0] — 2026-09-24

The CAP 0.4.0 release-identity act, mirrored: the capability profile, the
honest capability probe, the signature registry's own identity, the
descriptor timestamp floor, and the 104-case certified corpus.

### Added

- The `chain.verify_profile` corpus surface: the capability-profile mirror
  of the reference `Chain.verify/6`. Admission walks the reference STAGE
  order (descriptors, then revisions, then acceptances and terminations);
  out-of-profile artifacts report `algorithm_outside_profile` /
  `revision_outside_profile` before any signature work; malformed profile
  specs report `invalid_type` / `invalid_profile` (strict, like the
  reference `Profile.new/1`).
- `capabilities()` — one verifiable verdict per registry row, derived from
  pinned known-answer verification vectors identical to the reference
  probe's bytes; linked-crypto identity informational only.
- `algorithmRegistryDigest()` — the signature algorithm registry's
  domain-separated identity, byte-equal to the reference
  `Algorithm.registry_digest/0`
  (`sha-256:bPZY8aw4NCp3kMt4bZAACFZIcBctGGuTSa6avESQlrM`); also exported
  from the package root alongside `capabilities()`.

### Changed

- `PartyDescriptor.effective_from` gains the 1..64 string-BYTE floor its
  seven sibling timestamp members carry (the reference schema-stage order:
  before key resolution and signature work; byte length, not UTF-16
  units) — the last live timestamp asymmetry.
- The vendored certified corpus is the 104-case snapshot (census digest
  `sha-256:bp_w7EUD…`; certified index identity
  `f--8DXp39J4wJkrpkD8ZTQpHkMlduX43Xvnz0HeObeA`): the three
  `chain.verify_profile` cases and the descriptor timestamp-floor witness
  join the population; agreement recomputed 104/104.

## [0.4.0] — 2026-09-17

### Added

- The producer surface (the Elixir reference `SigningInput`, now fully
  aligned): `descriptorSigningInput` / `receiptSigningInput` (build-only),
  `acceptanceSigningInput` / `terminationSigningInput` (set-aware: build
  first, then the R1–R3 refusal checks at the reference ordering), and
  `assembleCompact` (registry-row length, framing re-decode, size gate).
  Holder-side signers sign through these — exactly one producer
  implementation.
- `governingRevision(chainInput, at)` — the certified governing semantics
  as a public query (a digest, or `contested`/`none`).
- `decodeCharterRevision` / `revisionDigest` and
  `decodePartyDescriptor` / `descriptorDigest` — the decode/digest pairs
  over the certified internals.

### Fixed

- Never-throw hardening across the new surface: non-JSON claims values
  (the reference `tagged/1` walk) and non-object views return typed codes;
  `assembleCompact` validates the signing-input struct (message must be
  the exact protected/payload framing); `decodePartyDescriptor` binds the
  `cap+party` typ.

## [0.3.0] — 2026-09-17

### Added

- The honest-signer refusal checks as a public surface:
  `acceptanceRefusal` / `terminationRefusal` (R1 claims-truth, R2
  no-equivocation, R3 ancestry/governing coverage) over the caller's own
  verified view, and `checkSigningClaims` — the producer build gate's
  claims half (the reference `decode_for_signing`), shared with the verify
  paths. `verifyChain` facts grow the verified `acceptances`.

## [0.2.0] — 2026-09-16

### Added

- The artifact-level verification API: `verifyDescriptor`,
  `verifyDescriptorChain`, `verifyAcceptance`, `verifyTermination`,
  `verifyChain`, `verifyReceipt`, `decodeArtifact`, `verifySignature`,
  plus the registry/emission/digest primitives.

## [0.1.x] — 2026-09-15

- Initial public releases under the `charter-agreement-protocol` npm
  organization: corpus report machinery, canonical JSON, strict I-JSON
  decode, self-check battery, the `cap-verifier` CLI, and the
  `./package.json` export for consumer corpus-path resolution.
