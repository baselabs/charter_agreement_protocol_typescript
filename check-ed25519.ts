import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ED25519_EDGES, generatedEd25519Inputs, loadEd25519Predicate } from "./ed25519-inputs.ts";

const reference = "774479d23b34eb853e6729ba53db77e8090e654e";
const repository = process.argv[2];
if (!repository || process.argv.length !== 3) throw new Error("usage: node check-ed25519.ts ELIXIR_REPOSITORY");
const resolved = execFileSync("git", ["-C", repository, "rev-parse", "774479d^{commit}"], { encoding: "utf8" }).trim();
assert.equal(resolved, reference);

const scratch = mkdtempSync(join(tmpdir(), "cap-ed25519-elixir-"));
try {
  const archive = execFileSync("git", ["-C", repository, "archive", reference], { maxBuffer: 32 * 1024 * 1024 });
  execFileSync("tar", ["-x", "-C", scratch], { input: archive });
  const generated = generatedEd25519Inputs();
  const inputs = [...generated, ...ED25519_EDGES.map((edge) => edge.bytes)];
  const inputPath = join(scratch, "keys.hex");
  const outputPath = join(scratch, "keys.results");
  const scriptPath = join(scratch, "check_keys.exs");
  writeFileSync(inputPath, inputs.map((bytes) => bytes.toString("hex")).join("\n") + "\n");
  writeFileSync(scriptPath, `
[input, output] = System.argv()
results =
  input
  |> File.stream!()
  |> Enum.map(fn line ->
    bytes = line |> String.trim() |> Base.decode16!(case: :lower)
    admitted = CharterAgreementProtocol.Signature.valid_key?(bytes, "Ed25519")
    if admitted != CharterAgreementProtocol.Signature.valid_key?(bytes, "EdDSA"),
      do: raise("Ed25519 aliases differ")
    if admitted, do: "true\\n", else: "false\\n"
  end)
File.write!(output, results)
`);
  execFileSync("mix", ["run", scriptPath, inputPath, outputPath], {
    cwd: scratch, env: { ...process.env, MIX_ENV: "prod" }, timeout: 120_000, encoding: "utf8",
  });
  const expected = readFileSync(outputPath, "utf8").trim().split("\n");
  assert.equal(expected.length, inputs.length);
  for (const [i, edge] of ED25519_EDGES.entries()) assert.equal(expected[generated.length + i], String(edge.admitted), edge.name);
  for (const built of [false, true]) {
    const predicate = await loadEd25519Predicate(built);
    let admitted = 0;
    for (const [i, bytes] of inputs.entries()) {
      const actual = predicate(bytes);
      assert.equal(String(actual), expected[i], `${built ? "built" : "source"} ${bytes.toString("hex")}`);
      if (actual) admitted++;
    }
    console.log(`Ed25519 ${built ? "built" : "source"} on Node ${process.version} against Elixir ${reference.slice(0, 7)}: ${inputs.length} agreed, 0 disagreed (${generated.length} generated, ${ED25519_EDGES.length} edges; ${admitted} admitted)`);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
