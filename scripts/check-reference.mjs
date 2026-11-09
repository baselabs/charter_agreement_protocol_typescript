import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
    const files = ["index.json", ...index.files.map((entry) => entry.path)];
    for (const path of files) assert.deepEqual(readFileSync(join(root, "conformance", path)), read(path), path);
    assert.equal(readdirSync(join(root, "conformance/cases")).length, index.files.length);
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
      assert.deepEqual(Buffer.from(actual.bytes), readFileSync(result));
      console.log("Published Elixir/TypeScript reports: byte-identical, 541 cases");
    }
    console.log("Elixir reference archive and all 17 corpus files match");
  } else {
    assert.deepEqual(readFileSync(join(root, "conformance/signer_cases.json")), read("signer_cases.json"));
    assert.equal(JSON.parse(read("signer_cases.json")).cases.length, 121);
    console.log("Published Elixir signer reference: all 121 rows byte-identical");
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
