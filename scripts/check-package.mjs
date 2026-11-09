import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const verifier = pkg.name.endsWith("/verifier");
const scratch = mkdtempSync(join(tmpdir(), "charter-package-"));
const env = { ...process.env, PATH: dirname(process.execPath) + delimiter + process.env.PATH };
const run = (command, args, cwd = root) => execFileSync(command, args, { cwd, env, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
try {
  const pack = () => JSON.parse(run("npm", ["pack", "--json", "--pack-destination", scratch]))[0];
  const first = pack();
  const archive = join(scratch, first.filename);
  const bytes = readFileSync(archive);
  const second = pack();
  assert.deepEqual(readFileSync(archive), bytes, "npm archive reproducibility");
  assert.equal(first.integrity, second.integrity);
  assert.equal(first.integrity, `sha512-${createHash("sha512").update(bytes).digest("base64")}`);
  const paths = first.files.map((entry) => entry.path);
  const names = new Set(pkg.files.map((path) => path.split("/")[0]).concat("package.json"));
  for (const path of paths) {
    assert.ok(names.has(path.split("/")[0]), `unexpected package input: ${path}`);
    assert.ok(!/(^|\/)(\.env[^/]*|node_modules|scripts|test|web)(\/|$)/.test(path), path);
  }
  for (const path of ["dist/index.js", "dist/index.d.ts", "reference.json", "README.md", "SECURITY.md",
    verifier ? "conformance/index.json" : "conformance/signer_cases.json"]) assert.ok(paths.includes(path), path);
  for (const path of paths.filter((path) => path.startsWith("dist/"))) {
    assert.match(path, verifier ? /^dist\/(index|core|cli)\.(js|d\.ts)$/ : /^dist\/(index|signer)\.(js|d\.ts)$/);
  }
  const consumer = join(scratch, "consumer");
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  const dependencies = [archive];
  let verifierVersion;
  if (!verifier) {
    const baseline = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")).packages["node_modules/@charter-agreement-protocol/verifier"].version;
    verifierVersion = process.env.CAP_VERIFIER_ARCHIVE ? JSON.parse(readFileSync(join(root, "reference.json"), "utf8")).verifier.version : baseline;
    dependencies.push(process.env.CAP_VERIFIER_ARCHIVE ?? `@charter-agreement-protocol/verifier@${baseline}`);
  }
  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", ...dependencies], consumer);
  const installed = JSON.parse(readFileSync(join(consumer, "node_modules", pkg.name, "package.json"), "utf8"));
  assert.equal(installed.version, pkg.version);
  if (!verifier) assert.equal(JSON.parse(readFileSync(join(consumer, "node_modules/@charter-agreement-protocol/verifier/package.json"), "utf8")).version, verifierVersion);
  const source = readFileSync(join(root, "README.md"), "utf8");
  const example = /```js\n([\s\S]*?)\n```/.exec(source)?.[1];
  assert.ok(example, "README has an executable JavaScript quickstart");
  writeFileSync(join(consumer, "quickstart.mjs"), example);
  const output = run(process.execPath, ["quickstart.mjs"], consumer);
  if (verifier) {
    assert.ok(paths.includes("dist/cli.js"));
    assert.equal(JSON.parse(output).agreement, true);
    assert.equal(JSON.parse(run(process.execPath, ["node_modules/" + pkg.name + "/dist/cli.js"], consumer)).agreement, true);
  }
  else {
    const smoke = `import {verifyDescriptor} from '@charter-agreement-protocol/verifier';\n` +
      example + "\nif (!verifyDescriptor(result.result.descriptor).ok) throw new Error('installed verification failed');";
    writeFileSync(join(consumer, "verify.mjs"), smoke + `
      const other = generateKeyPairSync("ed25519");
      const claims = JSON.parse(Buffer.from(result.result.descriptor.split(".")[1], "base64url").toString());
      const wrong = await signDescriptor(claims, {...handle, sign: (message) => nodeSign(null, message, other.privateKey)});
      if (wrong.ok || wrong.error !== "signing_failed") throw new Error("installed wrong-key guard failed");
      console.log("INSTALLED_SIGNER_CHECKS_PASSED");
    `);
    assert.ok(run(process.execPath, ["verify.mjs"], consumer).trimEnd().endsWith("INSTALLED_SIGNER_CHECKS_PASSED"));
  }
  const imports = verifier ? "capabilities, verifyChain, type ChainInput" : "signDescriptor, type KeyHandle";
  writeFileSync(join(consumer, "types.ts"), `import {${imports}} from '${pkg.name}';\n`);
  writeFileSync(join(consumer, "tsconfig.json"), JSON.stringify({
    compilerOptions: { noEmit: true, strict: true, module: "nodenext", target: "es2023", types: ["node"], typeRoots: [join(root, "node_modules/@types")] },
    files: ["types.ts"],
  }));
  run(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--project", join(consumer, "tsconfig.json")], consumer);
  const artifacts = join(root, "artifacts");
  mkdirSync(artifacts, { recursive: true });
  cpSync(archive, join(artifacts, "package.tgz"));
  writeFileSync(join(artifacts, "SHA256SUMS"), `${createHash("sha256").update(bytes).digest("hex")}  package.tgz\n`);
  console.log(`${pkg.name}@${pkg.version}: exact package boundary, reproducible bytes, installed quickstart and declarations passed`);
  console.log(`Package integrity: ${first.integrity}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
