# Changelog

All notable public changes to `@charter-agreement-protocol/verifier` are
documented here.

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
