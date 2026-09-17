// CAP never authorizes.
//
// The public surface of the independent TypeScript verifier: the corpus
// report machinery (canonical JSON, the strict I-JSON decoder, the
// self-check battery), artifact-level verification (descriptor, chain,
// acceptance, termination, receipt, full chain views), the governing/
// decode/ digest queries, the honest-signer refusal checks, and the pure
// producer surface (signing inputs per kind, assembly). Every verdict
// traces to corpus agreement with the Elixir reference implementation,
// recomputed from raw bytes.

export {
  canonical,
  loadCorpus,
  reportFor,
  selfChecks,
  decodeJsonText,
  jsonProjection,
  type CanonicalValue,
  type Projection,
  type DecodeResult,
  type CaseResult,
  type CorpusFile,
  type CorpusIndex,
  type ConformanceCase,
  type LoadedCorpus,
  type CaseOutcome,
  type ConformanceReport,
  type ReportOutput,
} from "./core.ts";

export {
  CERTIFIED_INDEX_SHA256_BASE64URL,
  CERTIFIED_REGISTRY_DIGEST,
  algorithmRegistry,
  emissions,
  defaultEmissionName,
  encodeBase64url,
  taggedDigest,
  decodeArtifact,
  verifySignature,
  verifyDescriptor,
  verifyDescriptorChain,
  verifyAcceptance,
  verifyTermination,
  verifyChain,
  verifyReceipt,
  acceptanceRefusal,
  checkSigningClaims,
  terminationRefusal,
  descriptorSigningInput,
  receiptSigningInput,
  acceptanceSigningInput,
  terminationSigningInput,
  assembleCompact,
  governingRevision,
  decodeCharterRevision,
  revisionDigest,
  decodePartyDescriptor,
  descriptorDigest,
  type SigningInput,
  type ProducerResult,
  type AlgRow,
  type VerifyResult,
  type RefusalResult,
} from "./core.ts";
