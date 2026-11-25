import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import test from "node:test";
import { compare } from "./scripts/check-reverse-differential.mjs";
import { registryTarballURL, releaseState } from "./scripts/npm-release-state.mjs";

// Selected fields recorded from the public registry; source URLs and dates are
// stored alongside the JSON. These are inputs to a pure function, no fake server.
const fixtures = JSON.parse(readFileSync(new URL("./test/fixtures/npm-release-state.json", import.meta.url), "utf8"));
const input = (fixture) => {
  const { packument, selectedVersion: version } = fixture;
  return { name: packument.name, version, integrity: packument.versions[version]?.dist.integrity };
};

test("reverse differential rejects swapped descriptor and signing witnesses", () => {
  const entries = [
    ["descriptor-publication-successor", "party_descriptor.verify"],
    ["descriptor-publication-sign-successor", "signing.prepare"],
  ];
  const pair = { baselines: ["npm:1.0.0"], entry_point: "corpus_runner", from: "protected_header_invalid", to: "valid" };
  const transitions = entries.map(([id, operation]) => ({
    operation, direction: "red_to_green", witnesses: [{ ...pair, cases: [id] }],
  }));
  const observations = (value) => new Map(entries.map(([id, operation]) =>
    [`corpus_runner/${id}`, { operation, value }]));
  const before = observations("protected_header_invalid");
  const after = observations({ status: "valid", output: {} });
  assert.equal(compare({ transitions }, before, after), 2);

  const [descriptor, signing] = transitions;
  const swapped = [
    { ...descriptor, witnesses: signing.witnesses },
    { ...signing, witnesses: descriptor.witnesses },
  ];
  assert.throws(() => compare({ transitions: swapped }, before, after),
    /does not name operation party_descriptor\.verify/);
});

test("reverse differential checks both successful projections", () => {
  const id = "legacy-unsigned-predecessor-leaves-no-governing-revision";
  const operation = "governing_revision";
  const outputs = { before: { governing_revisions: ["revision"] }, after: { governing_revisions: ["none"] } };
  const transitions = [{
    operation, direction: "green_to_green",
    witnesses: [{ entry_point: "corpus_runner", baselines: ["npm:1.0.0"], cases: [id], from: "valid", to: "valid", outputs }],
  }];
  const observed = (output) => new Map([[`corpus_runner/${id}`, { operation, value: { status: "valid", output } }]]);
  const before = observed(outputs.before);
  const after = observed(outputs.after);
  assert.equal(compare({ transitions }, before, after), 1);
  assert.throws(() => compare({ transitions: [] }, before, after), /legacy-unsigned-predecessor/);
  assert.throws(() => compare({ transitions }, before, observed({})), /legacy-unsigned-predecessor/);
});

test("a missing package name requires the owner's first-publication decision", () => {
  const name = decodeURIComponent(new URL(fixtures.missing.source).pathname.slice(1));
  assert.throws(() => releaseState({ ...input(fixtures.verifier), name }, fixtures.missing), /a first publication is the owner's decision/);
});

test("registry read failures and malformed packuments never allow an upload", () => {
  for (const status of [401, 403, 429, 500, 503]) {
    assert.throws(() => releaseState(input(fixtures.verifier), { status }), /registry read failed/);
  }
  for (const packument of [null, [], {}, { name: fixtures.verifier.packument.name, versions: {} }]) {
    assert.throws(() => releaseState(input(fixtures.verifier), { status: 200, packument }), /invalid full packument/);
  }
});

for (const key of ["verifier", "signer"]) {
  test(`${key}: a missing version of an existing name permits a non-replacing stage attempt`, () => {
    assert.equal(releaseState({ ...input(fixtures[key]), version: "99.0.0" }, fixtures[key]), "upload");
  });

  test(`${key}: an identical served version skips upload`, () => {
    assert.equal(releaseState(input(fixtures[key]), fixtures[key]), "served");
  });

  test(`${key}: differing or missing integrity refuses a served version`, () => {
    assert.throws(() => releaseState({ ...input(fixtures[key]), integrity: "sha512-different" }, fixtures[key]), /integrity differs/);
    const recorded = structuredClone(fixtures[key]);
    delete recorded.packument.versions[recorded.selectedVersion].dist.integrity;
    assert.throws(() => releaseState(input(fixtures[key]), recorded), /integrity differs/);
  });
}

test("deprecated versions are refused even when their archive is identical", () => {
  assert.throws(() => releaseState(input(fixtures.deprecated), fixtures.deprecated), /retired version is deprecated/);
});

test("publication history refuses an unpublished version", () => {
  assert.throws(() => releaseState(input(fixtures.unpublished), fixtures.unpublished), /retired version was published and unpublished/);
});

test("a registry response for another name or version is refused", () => {
  assert.throws(() => releaseState(input(fixtures.signer), fixtures.verifier), /invalid full packument/);
  const recorded = structuredClone(fixtures.verifier);
  recorded.packument.versions[recorded.selectedVersion].version = "99.0.0";
  assert.throws(() => releaseState(input(fixtures.verifier), recorded), /invalid version manifest/);
});

test("every workflow uses bash with pipefail and preserves failing command status", () => {
  const directory = new URL("./.github/workflows/", import.meta.url);
  const paths = readdirSync(directory).filter((path) => /\.ya?ml$/.test(path));
  assert.ok(paths.length > 0);
  const ci = readFileSync(new URL("ci.yml", directory), "utf8");
  assert.match(ci, /^        run: npm audit --audit-level=high$/m);
  for (const path of paths) {
    const source = readFileSync(new URL(path, directory), "utf8");
    assert.match(source, /^defaults:\n  run:\n    shell: bash\n/m, path);
    for (const [defaults] of source.matchAll(/^    defaults:\n(?:^      .*\n|^\n)*/gm)) {
      assert.match(defaults, /^        shell: bash$/m, path);
      assert.match(defaults, /^        working-directory:/m, path);
    }
    for (const [, image] of source.matchAll(/^    container: ([^\n]+)$/gm)) {
      assert.match(image, /:[^@\s]+@sha256:[0-9a-f]{64}$/, path);
    }
    assert.doesNotMatch(source, /\|\|\s*true\b/, path);
    assert.doesNotMatch(source, /^\s*(?:run: )?(?:echo|for)\b[^\n]*\$\(/m, path);
    assert.ok(!source.includes("<("), path);
  }
});

test("qualification requires workflow syntax and secret scanning", () => {
  const ci = readFileSync(new URL("./.github/workflows/ci.yml", import.meta.url), "utf8");
  const needs = ci.match(/^  qualified:\n(?:^    [^\n]*\n)*?^    needs: \[([^\n]+)\]$/m);
  assert.ok(needs, "qualified must declare its dependencies");
  const jobs = needs[1].split(", ");
  assert.ok(jobs.includes("workflow-syntax"));
  assert.ok(jobs.includes("secret-scan"));
});

test("CI reads exact runtime versions only through the pinned shared reader", () => {
  const reader = new URL("./scripts/toolchain.sh", import.meta.url);
  assert.equal(createHash("sha256").update(readFileSync(reader)).digest("hex"),
    "25bbfa023b7f031256428b498fe300fcc460988fea81277072355e4c0d933764");
  // The committed mode, not the checkout's: a checkout's permission bits follow its umask.
  assert.match(execFileSync("git", ["ls-files", "--stage", "--", "scripts/toolchain.sh"],
    { cwd: new URL("./", import.meta.url), encoding: "utf8" }), /^100755 /);
  const directory = new URL("./.github/workflows/", import.meta.url);
  const paths = readdirSync(directory).filter((path) => /\.ya?ml$/.test(path));
  assert.ok(paths.length > 0);
  for (const path of paths) {
    const source = readFileSync(new URL(path, directory), "utf8");
    assert.doesNotMatch(source, /\b(?:node-|bun-)?version-file:/, path);
    assert.doesNotMatch(source, /\bawk\b/, path);
    assert.doesNotMatch(source, /\b(?:bash|sh)\s+[^\n]*scripts\/toolchain\.sh/, path);
    assert.doesNotMatch(source, /\b(?:elixir|otp|node|bun|golang|elixir-version|otp-version|node-version|bun-version|go-version|EXPECTED_ELIXIR|EXPECTED_OTP|EXPECTED_NODE|EXPECTED_BUN|EXPECTED_GO):\s*["']?[0-9]/, path);
    for (const line of source.split("\n").filter((line) => !line.trimStart().startsWith("#") && line.includes(".tool-versions"))) {
      assert.ok(line.includes("scripts/toolchain.sh "), path);
    }
    for (const [job] of source.matchAll(/^  [\w-]+:\n.*?(?=^  [\w-]+:\n|(?![\s\S]))/gms)) {
      if (!/uses: (?:erlef\/setup-beam|actions\/setup-node|actions\/setup-go|oven-sh\/setup-bun)@/.test(job)) continue;
      if (path === "publish.yml" && /^  (?:upload|read-back):\n/.test(job)) {
        assert.ok(job.includes("node-version: ${{ needs.build.outputs.nodejs }}"), path);
      } else {
        assert.match(job, /run: scripts\/toolchain\.sh /, path);
        assert.match(job, /scripts\/toolchain\.sh --installed /, path);
        for (const [setup, tool] of [["erlef/setup-beam@", "elixir"], ["erlef/setup-beam@", "erlang"], ["actions/setup-node@", "nodejs"], ["actions/setup-go@", "golang"], ["oven-sh/setup-bun@", "bun"]]) {
          if (job.includes(setup)) assert.ok(job.includes(`"${tool}=$`), path);
        }
      }
      for (const [, value] of job.matchAll(/^          (?:elixir|otp|node|bun|go)-version: ([^\n]+)$/gm)) {
        assert.ok(value.startsWith("${{ "), path);
      }
    }
  }
});

const workflow = readFileSync(new URL("./.github/workflows/publish.yml", import.meta.url), "utf8");
const jobs = Object.fromEntries(workflow.split(/^(?= {2}\S)/m)
  .flatMap((block) => {
    const match = /^ {2}(release|build|upload|read-back):\n/.exec(block);
    return match ? [[match[1], block]] : [];
  }));
const jobSteps = (job) => job.match(/^      - [^\n]*\n(?: {8}[^\n]*\n|\n(?=\n* {8}))*/gm) ?? [];
const steps = [jobs.build, jobs.upload, jobs["read-back"]].flatMap(jobSteps);
const oneStep = (pattern) => {
  const found = steps.filter((step) => pattern.test(step));
  assert.equal(found.length, 1, `expected one step matching ${pattern}`);
  return found[0];
};

test("publication is dispatch-only and leaves releases to the maintainers", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:\s*\n/m);
  assert.doesNotMatch(workflow, /^  (push|tags):/m);
  assert.doesNotMatch(workflow, /gh\s+release\s+create|actions\/create-release|softprops\/action-gh-release|ncipollo\/release-action|createRelease|POST[^\n]*\/releases/);
  assert.match(workflow, /^    timeout-minutes: 90 # no green run yet$/m);
});

test("the release guard recognizes the real scoped package manifest", () => {
  const manifest = readFileSync(new URL("./package.json", import.meta.url), "utf8");
  const [validation] = jobs.release.match(/^ {10}name=\$\([^\n]+\) \|\|\n {12}\{ [^\n]+\}$/m);
  const validate = (input) => execFileSync("bash", [
    "-euo", "pipefail", "-c", `package=$(cat)\n${validation}\nprintf '%s' "$name"`,
  ], { input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });

  assert.equal(validate(manifest), JSON.parse(manifest).name);
  for (const name of ["@scope", "@scope/", "@Scope/pkg", "@scope/a/b", "@scope/.pkg", "@scope/pkg\n", "a".repeat(215)]) {
    assert.throws(() => validate(JSON.stringify({ name })),
      (error) => error.status === 1 && error.stdout.includes("does not declare a valid npm package name"));
  }
});

test("the release guard selects the npm dist-tag from the version", () => {
  const selection = jobs.release.match(/^ {10}case "\$version" in\n(?:^ {12}[^\n]+\n)+^ {10}esac$/m);
  assert.ok(selection, "the release guard must select a dist-tag");
  assert.ok(jobs.release.includes("printf 'dist_tag=%s\\n' \"$dist_tag\" >> \"$GITHUB_OUTPUT\""));
  assert.ok(jobs.release.includes("dist_tag: ${{ steps.validate.outputs.dist_tag }}"));

  for (const [version, expected] of [
    ["1.1.0", "latest"],
    ["1.1.0-rc.1", "next"],
    ["1.1.0-beta.2", "next"],
  ]) {
    const output = execFileSync("bash", [
      "-euo", "pipefail", "-c", `version=$1\n${selection[0]}\nprintf '%s' "$dist_tag"`,
      "release-dist-tag", version,
    ], { encoding: "utf8" });
    assert.equal(output, expected, version);
  }
});

test("served tarballs must come from the credential-free npm registry origin", () => {
  const url = "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz";
  assert.equal(registryTarballURL(url).href, url);
  for (const value of [
    null, "/pkg.tgz", "http://registry.npmjs.org/pkg.tgz", "https://npm.example/pkg.tgz",
    "https://user@registry.npmjs.org/pkg.tgz", "https://registry.npmjs.org:444/pkg.tgz",
    "blob:https://registry.npmjs.org/pkg.tgz",
  ]) {
    assert.throws(() => registryTarballURL(value), /credential-free registry\.npmjs\.org HTTPS/);
  }
});

test("read-back publishes one pinned consumer release-assets artifact", () => {
  const assets = oneStep(/^          name: release-assets$/m);
  assert.match(assets, /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\.6\.2/);
  assert.match(assets, /^          if-no-files-found: error$/m);
  assert.match(assets, /^          retention-days: 7$/m);
  assert.match(assets, /^            artifacts\/\$\{\{ needs\.release\.outputs\.archive \}\}$/m);
  assert.match(assets, /^            artifacts\/\$\{\{ needs\.release\.outputs\.docs \}\}$/m);
  assert.match(assets, /^            artifacts\/SHA256SUMS$/m);

  const assembled = oneStep(/name: Assemble the inspected release archives/);
  assert.ok(jobs.release.includes('archive_name="${name#@}"'));
  assert.ok(jobs.release.includes('archive_name="${archive_name/\\//-}-$version"'));
  assert.match(assembled, /test -f site-dist\/index\.html/);
  assert.match(assembled, /--arg commit "\$RELEASE_COMMIT"/);
  assert.match(assembled, /\{package: \$package, version: \$version, commit: \$commit\}' > site-dist\/release\.json/);
  assert.match(assembled, /-C site-dist -cf - \. \|/);
  assert.ok(assembled.includes('mv -- artifacts/package.tgz "artifacts/$ARCHIVE_NAME"'));
  assert.match(assembled, /sha256sum -- "\$ARCHIVE_NAME" "\$DOCS_ARCHIVE_NAME" > SHA256SUMS/);
  assert.ok(steps.indexOf(oneStep(/name: Refuse a package whose changelog/)) < steps.indexOf(assembled));
  assert.ok(steps.indexOf(assembled) < steps.indexOf(assets));
});

test("the exact archive is planned after inspection, staged only for upload, then read back", () => {
  const plan = oneStep(/node "\$RUNNER_TEMP\/release-workflow\/npm-release-state\.mjs" --plan /);
  const stage = oneStep(/run: npm stage publish /);
  const served = oneStep(/node "\$GITHUB_WORKSPACE\/release-workflow\/scripts\/npm-release-state\.mjs" --served /);
  assert.match(plan, /^        id: plan$/m);
  assert.match(stage, /^        if: needs\.build\.outputs\.state == 'upload'$/m);
  for (const step of [plan, served]) {
    assert.match(step, /RELEASE_NAME: \$\{\{ needs\.release\.outputs\.name \}\}/);
    assert.match(step, /RELEASE_VERSION: \$\{\{ needs\.release\.outputs\.version \}\}/);
    assert.match(step, /"\$RELEASE_NAME" "\$RELEASE_VERSION" "\.\/artifacts\/\$ARCHIVE_NAME"/);
  }
  assert.ok(stage.includes("DIST_TAG: ${{ needs.release.outputs.dist_tag }}"));
  assert.match(stage, /npm stage publish "\.\/artifacts\/\$ARCHIVE_NAME" --tag "\$DIST_TAG" --provenance --ignore-scripts --access public --registry=https:\/\/registry\.npmjs\.org\//);

  const attest = oneStep(/name: Attest the release source commit/);
  assert.match(attest, /subject-path: artifacts\/\$\{\{ needs\.release\.outputs\.archive \}\}/);
  assert.ok(attest.includes("predicate: '{\"release_commit\":\"${{ inputs.release_commit }}\"}'"));
  const [, predicate] = attest.match(/predicate-type: (\S+)/);
  assert.ok(served.includes(`--predicate-type ${predicate} --format json`));
  assert.match(served, /"\.\/artifacts\/\$ARCHIVE_NAME" "\$served"/);
  assert.match(served, /gh attestation verify "\$served"/);
  assert.match(served, /--signer-workflow "\$GITHUB_REPOSITORY\/\.github\/workflows\/publish\.yml"/);
  assert.ok(served.includes("RELEASE_COMMIT: ${{ inputs.release_commit }}"));
  assert.ok(served.includes('jq -e --arg commit "$RELEASE_COMMIT"'));
  assert.match(served, /\.verificationResult\.statement\.predicate\.release_commit == \$commit/);
  assert.ok(steps.indexOf(attest) < steps.indexOf(stage));
  assert.ok(steps.indexOf(served) < steps.indexOf(oneStep(/^          name: release-assets$/m)));
  const changelog = oneStep(/^      - name: Refuse a package whose changelog is not stamped for its version$/m);
  const archive = "./artifacts/package.tgz";
  const invocation = /python3[ \t]+-I[ \t]+-[ \t]+(["']?)(?:\.\/|\$GITHUB_WORKSPACE\/)?artifacts\/package\.tgz\1[ \t]+[^\n]*<</g;
  assert.equal([...workflow.matchAll(invocation)].length, 1);
  const canonical = changelog.replaceAll(/^ {6}/gm, "")
    .replace(archive, "path/to/package-archive");

  // The dedented YAML from infra 6f19bd49, baselabs/docs/ci.md:360–402.
  assert.equal(createHash("sha256").update(canonical).digest("hex"),
    "2a912ae3e07700555d8827da491b8875207341808b4a6c1137c07129f0cbfa30");
  const inspection = oneStep(/run: npm run check:package/);
  const checksum = oneStep(/run: sha256sum --check SHA256SUMS/);
  assert.ok(steps.indexOf(inspection) < steps.indexOf(checksum));
  assert.ok(steps.indexOf(checksum) < steps.indexOf(changelog));
  const releaseStep = /actions\/(?:attest[\w-]*|upload-artifact)@|gh attestation\b|scripts\/build_release_sbom\.sh|npm-release-state\.mjs --plan\b|npm (?:stage )?publish\b/;
  for (const step of steps.slice(0, steps.indexOf(changelog))) {
    assert.doesNotMatch(step, releaseStep);
  }
  assert.ok(steps.indexOf(plan) < steps.indexOf(stage));
  assert.ok(steps.indexOf(stage) < steps.indexOf(served));
});

test("qualification guards the release checkout and workflow-owned scripts", () => {
  assert.match(workflow, /workflow_dispatch:\n    inputs:\n      release_commit:\n        description: [^\n]+\n        required: true\n        type: string\n/);
  const guard = jobs.release;
  const actorFilter = `    if: contains(fromJSON('["corepay","palermo-git"]'), github.actor) && contains(fromJSON('["corepay","palermo-git"]'), github.triggering_actor)`;
  for (const job of Object.values(jobs)) assert.ok(job.includes(actorFilter));
  assert.equal([...workflow.matchAll(/^    environment:/gm)].length, 1);
  assert.match(guard, /checks: read/);
  assert.ok(guard.includes('.conclusion == "success"'));
  assert.ok(guard.includes("| .head_sha"));
  assert.ok(guard.includes("GH_TOKEN: ${{ github.token }}"));
  const checks = ["refs/heads/$DEFAULT_BRANCH", "^[0-9a-f]{40}$", "/compare/", "check-runs?check_name=qualified", "/contents/package.json?ref=$RELEASE_COMMIT", "matching-refs/tags/"];
  let previous = -1;
  for (const marker of checks) {
    const position = guard.indexOf(marker);
    assert.ok(position > previous, marker);
    previous = position;
  }
  assert.doesNotMatch(guard, /actions\/checkout|npm run build/);
  assert.match(jobs.build, /^    needs: release$/m);
  assert.match(jobs.upload, /^    needs: \[release, build\]$/m);
  assert.match(jobs["read-back"], /^    needs: \[release, build, upload\]$/m);
  assert.match(jobs.upload, /^    environment: publish$/m);
  assert.doesNotMatch(jobs.build + jobs["read-back"], /^    environment:/m);
  assert.doesNotMatch(jobs.build + jobs["read-back"], /id-token: write|secrets\./);
  assert.doesNotMatch(jobs.upload, /actions\/checkout@|npm ci|npm run |scripts\/toolchain\.sh/);
  assert.match(jobs.upload, /sha256sum --check --strict SHA256SUMS/);
  assert.match(jobs.upload, /npm stage publish .*--ignore-scripts/);
  assert.ok(jobs.build.includes("ref: ${{ inputs.release_commit }}"));
  assert.ok(jobs.build.includes("VERSION: ${{ needs.release.outputs.version }}"));
  assert.match(jobs.build, /git show "\$GITHUB_SHA:scripts\/npm-release-state\.mjs"/);
  assert.ok(jobs["read-back"].includes("ref: ${{ github.sha }}"));
  assert.ok(jobs.build.indexOf("actions/checkout@") < jobs.build.indexOf("npm run build:site"));
});
