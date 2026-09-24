# Changelog

All notable public changes to `@charter-agreement-protocol/verifier` are
documented here.

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
