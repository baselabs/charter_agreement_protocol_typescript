import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import { releaseState } from "./scripts/npm-release-state.mjs";

// Selected fields recorded from the public registry; source URLs and dates are
// stored alongside the JSON. These are inputs to a pure function, no fake server.
const fixtures = JSON.parse(readFileSync(new URL("./test/fixtures/npm-release-state.json", import.meta.url), "utf8"));
const input = (fixture) => {
  const { packument, selectedVersion: version } = fixture;
  return { name: packument.name, version, integrity: packument.versions[version]?.dist.integrity };
};

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

const workflow = readFileSync(new URL("./.github/workflows/publish.yml", import.meta.url), "utf8");
const steps = workflow.match(/^      - name: .*(?:\n(?!      - name:)[^\n]*)*/gm) ?? [];
const oneStep = (pattern) => {
  const found = steps.filter((step) => pattern.test(step));
  assert.equal(found.length, 1, `expected one step matching ${pattern}`);
  return found[0];
};

test("publication is dispatch-only and leaves releases to the maintainers", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:\s*\n/m);
  assert.doesNotMatch(workflow, /^\s*(push|tags|release):/m);
  assert.doesNotMatch(workflow, /gh\s+release\s+create|actions\/create-release|softprops\/action-gh-release|ncipollo\/release-action|createRelease|POST[^\n]*\/releases/);
  assert.match(workflow, /^    timeout-minutes: 90 # no green run yet$/m);
});

test("the consumer files leave as one pinned release-assets artifact before staging", () => {
  const assets = oneStep(/uses: actions\/upload-artifact@/);
  assert.match(assets, /uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\.6\.2/);
  assert.match(assets, /^          name: release-assets$/m);
  assert.match(assets, /^          if-no-files-found: error$/m);
  assert.match(assets, /^          retention-days: 7$/m);
  assert.match(assets, /^            artifacts\/package\.tgz$/m);
  assert.match(assets, /^            artifacts\/SHA256SUMS$/m);
  assert.ok(steps.indexOf(oneStep(/run: npm run check:package/)) < steps.indexOf(assets));
  assert.ok(steps.indexOf(oneStep(/run: sha256sum --check SHA256SUMS/)) < steps.indexOf(assets));
  assert.ok(steps.indexOf(assets) < steps.indexOf(oneStep(/run: npm stage publish /)));
});

test("the exact archive is planned after inspection, staged only for upload, then read back", () => {
  const plan = oneStep(/node scripts\/npm-release-state\.mjs --plan /);
  const stage = oneStep(/run: npm stage publish /);
  const served = oneStep(/node scripts\/npm-release-state\.mjs --served /);
  assert.match(plan, /^        id: plan$/m);
  assert.match(stage, /^        if: steps\.plan\.outputs\.state == 'upload'$/m);
  assert.match(served, /^        if: \$\{\{ !cancelled\(\) && steps\.plan\.outcome == 'success' \}\}$/m);
  for (const step of [plan, served]) {
    assert.match(step, /RELEASE_NAME: \$\{\{ steps\.package\.outputs\.name \}\}/);
    assert.match(step, /RELEASE_VERSION: \$\{\{ steps\.package\.outputs\.version \}\}/);
    assert.match(step, /"\$RELEASE_NAME" "\$RELEASE_VERSION" \.\/artifacts\/package\.tgz/);
  }
  assert.match(stage, /npm stage publish \.\/artifacts\/package\.tgz --provenance --ignore-scripts --access public --registry=https:\/\/registry\.npmjs\.org\//);
  assert.ok(steps.indexOf(oneStep(/run: sha256sum --check SHA256SUMS/)) < steps.indexOf(plan));
  assert.ok(steps.indexOf(plan) < steps.indexOf(stage));
  assert.ok(steps.indexOf(stage) < steps.indexOf(served));
  const tag = oneStep(/'ls-remote', '--tags', 'origin', `v\$\{version\}`/);
  assert.match(tag, /assert\.equal\(tags\.trim\(\), '', `v\$\{version\} is already tagged`\)/);
  assert.match(tag, /appendFileSync\(process\.env\.GITHUB_OUTPUT, `name=\$\{name\}\\nversion=\$\{version\}\\n`\)/);
});
