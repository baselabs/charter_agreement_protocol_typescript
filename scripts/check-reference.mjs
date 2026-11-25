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
assert.ok(process.argv.slice(2).every((value) => ["--report", "--reverse-differential"].includes(value)), "unknown reference-check argument");
assert.ok(process.argv.length <= 3);
assert.ok(process.argv.length === 2 || reference.package === "charter_agreement_protocol");
assert.equal(reference.corpus_path, "priv/conformance");
assert.match(reference.corpus_source.commit, /^[a-f0-9]{40}$/);

function verifyCorpusSource(scratch) {
  const source = reference.corpus_source;
  const checkout = join(scratch, "source");
  execFileSync("git", ["init", "--quiet", checkout]);
  const git = (...args) => execFileSync("git", args, { cwd: checkout, maxBuffer: 32 * 1024 * 1024 });
  const remote = `https://github.com/baselabs/${reference.package}.git`;
  git("fetch", "--quiet", "--no-tags", "--depth=1", remote, source.commit);
  assert.equal(git("rev-parse", "FETCH_HEAD").toString().trim(), source.commit);

  const vendored = join(root, "conformance");
  let files;
  if (reference.package === "charter_agreement_protocol") {
    const index = readFileSync(join(vendored, "index.json"));
    assert.equal(createHash("sha256").update(index).digest("base64url"), source.index_sha256_base64url);
    files = ["index.json", ...JSON.parse(index).files.map((one) => one.path)];
    const sourceFiles = git("ls-tree", "-r", "-z", "--name-only", "FETCH_HEAD", "--", reference.corpus_path)
      .toString().split("\0").filter(Boolean);
    assert.deepEqual(sourceFiles.sort(), files.map((path) => `${reference.corpus_path}/${path}`).sort());
  } else {
    files = ["signer_cases.json"];
    const table = readFileSync(join(vendored, files[0]));
    assert.equal(createHash("sha256").update(table).digest("hex"), source.sha256);
  }
  for (const path of files) {
    const blob = git("cat-file", "blob", `FETCH_HEAD:${reference.corpus_path}/${path}`);
    assert.deepEqual(readFileSync(join(vendored, path)), blob, path);
  }
  console.log(`Canonical Elixir source ${source.commit}: ${files.length} exact Git blob(s)`);
  if (reference.package === "charter_agreement_protocol") {
    return JSON.parse(git("cat-file", "blob", `FETCH_HEAD:priv/release-metadata.json`));
  }
}

async function reverse(scratch, sourceMetadata) {
  const { checkReverseDifferential } = await import("./check-reverse-differential.mjs");
  await checkReverseDifferential(root, scratch, sourceMetadata);
}

async function verifyReference(scratch, sourceMetadata) {
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
    if (!process.argv.includes("--report")) {
      await reverse(scratch, sourceMetadata);
    }
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
      const { reportFor } = await import("../index.ts");
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
}

const scratch = mkdtempSync(join(tmpdir(), "charter-reference-"));
try {
  const sourceMetadata = verifyCorpusSource(scratch);
  if (process.argv.includes("--reverse-differential")) {
    await reverse(scratch, sourceMetadata);
  } else {
    await verifyReference(scratch, sourceMetadata);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
