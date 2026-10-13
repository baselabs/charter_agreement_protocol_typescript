import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ED25519_EDGES, generatedEd25519Inputs, loadEd25519Checks } from "./ed25519-inputs.ts";

const reference = "911d84b2acd03a4c7c2941fbc07f830dd4016856";
const repository = process.argv[2];
if (!repository || process.argv.length !== 3) throw new Error("usage: node check-ed25519.ts ELIXIR_REPOSITORY");
const resolved = execFileSync("git", ["-C", repository, "rev-parse", `${reference}^{commit}`], { encoding: "utf8" }).trim();
assert.equal(resolved, reference);

const scratch = mkdtempSync(join(tmpdir(), "cap-ed25519-elixir-"));
try {
  const archive = execFileSync("git", ["-C", repository, "archive", reference], { maxBuffer: 32 * 1024 * 1024 });
  execFileSync("tar", ["-x", "-C", scratch], { input: archive });
  const signaturePath = join(scratch, "lib", "charter_agreement_protocol", "signature.ex");
  const source = readFileSync(signaturePath, "utf8");
  const anchor = "defp strict_ed25519_inputs?(";
  assert.equal(source.split(anchor).length - 1, 1);
  // Only visibility changes in the temporary copy; Elixir executes its real R check.
  writeFileSync(signaturePath, source.replace(anchor, "def strict_ed25519_inputs?("));
  const generated = generatedEd25519Inputs();
  const inputs = [...generated, ...ED25519_EDGES.map((edge) => edge.bytes)];
  const inputPath = join(scratch, "points.hex");
  const outputPath = join(scratch, "points.results");
  const scriptPath = join(scratch, "check_points.exs");
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
    r_admitted = CharterAgreementProtocol.Signature.strict_ed25519_inputs?(<<bytes::binary, 0::256>>, <<>>)
    "#{admitted},#{r_admitted}\\n"
  end)
File.write!(output, results)
`);
  execFileSync("mix", ["run", scriptPath, inputPath, outputPath], {
    cwd: scratch, env: { ...process.env, MIX_ENV: "prod", ERL_FLAGS: "+S 4:4" }, timeout: 120_000, encoding: "utf8",
  });
  const expected = readFileSync(outputPath, "utf8").trim().split("\n");
  assert.equal(expected.length, inputs.length);
  for (const [i, edge] of ED25519_EDGES.entries()) assert.equal(expected[generated.length + i], `${edge.admitted},${edge.admitted}`, edge.name);
  for (const built of [false, true]) {
    const checks = await loadEd25519Checks(built);
    let admitted = 0;
    for (const [i, bytes] of inputs.entries()) {
      const key = checks.validPublicKey(bytes.toString("base64url"), { keyAlgorithm: "Ed25519", publicKeyBytes: 32 });
      const r = checks.strictEd25519Signature(Buffer.concat([bytes, Buffer.alloc(32)]));
      assert.equal(`${key},${r}`, expected[i], `${built ? "built" : "source"} key/R ${bytes.toString("hex")}`);
      if (key) admitted++;
    }
    console.log(`Ed25519 keys and R ${built ? "built" : "source"} on Node ${process.version} against live Elixir ${reference.slice(0, 7)}: ${inputs.length} keys and ${inputs.length} R values agreed, 0 disagreed (${generated.length} generated, ${ED25519_EDGES.length} edges; ${admitted} admitted per role)`);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
