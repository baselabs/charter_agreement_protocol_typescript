import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const reference = JSON.parse(readFileSync(join(root, "reference.json"), "utf8"));
assert.ok(["charter_agreement_protocol", "charter_agreement_signer"].includes(reference.package));
assert.match(reference.version, /^\d+\.\d+\.\d+$/);
assert.match(reference.archive_sha256, /^[a-f0-9]{64}$/);
assert.ok(process.argv.slice(2).every((value) => value === "--report"), "unknown reference-check argument");
assert.ok(!process.argv.includes("--report") || reference.package === "charter_agreement_protocol");
const scratch = mkdtempSync(join(tmpdir(), "charter-reference-"));
try {
  const url = `https://repo.hex.pm/tarballs/${reference.package}-${reference.version}.tar`;
  const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, `reference download: ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  assert.equal(createHash("sha256").update(archive).digest("hex"), reference.archive_sha256);
  const outer = join(scratch, "reference.tar");
  const contents = join(scratch, "contents.tar.gz");
  writeFileSync(outer, archive);
  writeFileSync(contents, execFileSync("tar", ["-xOf", outer, "contents.tar.gz"], { maxBuffer: 16 * 1024 * 1024 }));
  const read = (path) => execFileSync("tar", ["-xzOf", contents, `${reference.corpus_path}/${path}`], { maxBuffer: 16 * 1024 * 1024 });
  if (reference.package === "charter_agreement_protocol") {
    const index = JSON.parse(read("index.json"));
    assert.equal(index.total_cases, 541);
    // Keep the released corpus as a compatibility floor while the vendored
    // source commit and index pin identify the current corpus.
    const releasedIds = new Set();
    const caseDocument = (bytes) => JSON.parse(bytes, (_key, value, context) =>
      typeof value === "number" && context?.source ? { numberToken: context.source } : value);
    for (const { path } of index.files) {
      const current = caseDocument(readFileSync(join(root, "conformance", path)));
      const currentCases = new Map(current.cases.map(({ expect_limited, ...one }) => [one.id, one]));
      for (const one of caseDocument(read(path)).cases) {
        assert.deepEqual(currentCases.get(one.id), one, one.id);
        releasedIds.add(one.id);
      }
    }
    assert.equal(releasedIds.size, index.total_cases);
    if (process.argv.includes("--report")) {
      const sdk = join(scratch, "sdk");
      mkdirSync(sdk);
      execFileSync("tar", ["-xzf", contents, "-C", sdk]);
      const result = join(scratch, "report.json");
      const runner = join(scratch, "report.exs");
      writeFileSync(runner, `
        Mix.install([{:charter_agreement_protocol, path: ${JSON.stringify(sdk)}}])
        {:ok, io} = StringIO.open("")
        previous = Process.group_leader()
        Process.group_leader(self(), io)
        status = CharterAgreementProtocol.Conformance.Cli.run(["--corpus", Application.app_dir(:charter_agreement_protocol, "priv/conformance")])
        Process.group_leader(self(), previous)
        {_, bytes} = StringIO.contents(io)
        File.write!(${JSON.stringify(result)}, bytes)
        System.halt(status)
      `);
      execFileSync("elixir", [runner], { stdio: "inherit" });
      const { reportFor } = await import("../dist/index.js");
      const actual = reportFor(join(root, "conformance"));
      assert.equal(actual.exitStatus, 0);
      const current = JSON.parse(actual.bytes).results.filter((one) => releasedIds.has(one.id));
      assert.deepEqual(current, JSON.parse(readFileSync(result)).results);
      console.log(`Published Elixir/TypeScript verdicts match for ${releasedIds.size} cases`);
    }
    console.log(`Released Elixir corpus retained: ${releasedIds.size} cases`);
  } else {
    assert.deepEqual(readFileSync(join(root, "conformance/signer_cases.json")), read("signer_cases.json"));
    assert.equal(JSON.parse(read("signer_cases.json")).cases.length, 121);
    console.log("Published Elixir signer reference: all 121 rows byte-identical");
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
