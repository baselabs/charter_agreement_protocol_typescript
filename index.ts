// CAP never authorizes.
//
// The public surface of the independent TypeScript verifier: report over a
// certified conformance corpus, canonical JSON, the strict I-JSON decoder,
// and the self-check battery. Every verdict traces to corpus agreement with
// the Elixir reference implementation, recomputed from raw bytes.

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
  terminationRefusal,
  type AlgRow,
  type VerifyResult,
  type RefusalResult,
} from "./core.ts";
