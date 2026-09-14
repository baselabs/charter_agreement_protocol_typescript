#!/usr/bin/env node
// CAP never authorizes.
//
// The corpus CLI. With --corpus DIRECTORY it verifies that directory; with
// no arguments it verifies the certified corpus vendored beside this module
// (the snapshot byte-synced with the Elixir package's priv/conformance and
// pinned by the index SHA-256 asserted at load).
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { reportFor } from "./core.ts";

const vendoredCorpus = join(dirname(fileURLToPath(import.meta.url)), "..", "conformance");
const argumentsList = process.argv.slice(2);

const corpus =
  argumentsList.length === 2 && argumentsList[0] === "--corpus"
    ? argumentsList[1]
    : argumentsList.length === 0
      ? vendoredCorpus
      : null;

if (corpus === null) {
  console.error("usage: charter-agreement-protocol [--corpus DIRECTORY]");
  process.exitCode = 2;
} else {
  try {
    const report = reportFor(corpus);
    process.stdout.write(report.bytes);
    process.exitCode = report.exitStatus;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
