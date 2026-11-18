import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const heldMessage = "held for approval or not yet served: after the owner approves, dispatch publish.yml again on this same commit; it uploads only what is missing";

const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

// Pure decision over the full public packument, including its publication history.
export function releaseState({ name, version, integrity }, { status, packument }) {
  if (status === 404) throw new Error(`${name}: a first publication is the owner's decision`);
  if (status !== 200) throw new Error(`${name}: registry read failed (HTTP ${status})`);
  if (!object(packument) || packument.name !== name || !object(packument.versions) || !object(packument.time)) {
    throw new Error(`${name}: registry returned an invalid full packument`);
  }

  if (!Object.hasOwn(packument.versions, version)) {
    if (Object.hasOwn(packument.time, version)) {
      throw new Error(`${name}@${version}: retired version was published and unpublished`);
    }
    // npm 11.19.0's OIDC tokens cannot list/view staged versions. Its registry
    // shares the staged/published unique version index, refusing a duplicate
    // without replacement. Never reject a stage or use --force to work around it.
    // https://github.com/npm/cli/blob/v11.19.0/docs/lib/content/commands/npm-stage.md
    return "upload";
  }

  const manifest = packument.versions[version];
  if (!object(manifest) || manifest.name !== name || manifest.version !== version) {
    throw new Error(`${name}@${version}: registry returned an invalid version manifest`);
  }
  if (manifest.deprecated) throw new Error(`${name}@${version}: retired version is deprecated`);
  if (typeof manifest.dist?.integrity !== "string" || manifest.dist.integrity !== integrity) {
    throw new Error(`${name}@${version}: served archive integrity differs from the local tarball`);
  }
  return "served";
}

// Built-in fetch never reads npm credentials or exchanges the job's OIDC token.
export async function readPackument(name) {
  const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
    headers: { accept: "application/json", "cache-control": "no-cache" },
    credentials: "omit",
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  return { status: response.status, packument: response.status === 200 ? await response.json() : null };
}

export async function main(args) {
  const [mode, name, version, archive] = args;
  if (args.length !== 4 || !["--plan", "--served"].includes(mode) ||
      !/^(?:@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/.test(name ?? "") ||
      !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
    throw new Error("usage: node scripts/npm-release-state.mjs --plan|--served <name> <version> <tarball>");
  }
  let state;
  try {
    const integrity = `sha512-${createHash("sha512").update(readFileSync(archive)).digest("base64")}`;
    state = releaseState({ name, version, integrity }, await readPackument(name));
  } catch (error) {
    if (mode === "--served") throw new Error(`${error.message}; ${heldMessage}`);
    throw error;
  }
  if (mode === "--served") {
    if (state !== "served") throw new Error(`${name}@${version}: ${heldMessage}`);
    console.log(`${name}@${version}: served archive matches the local tarball`);
    return;
  }
  if (!process.env.GITHUB_OUTPUT) throw new Error("--plan requires GITHUB_OUTPUT");
  appendFileSync(process.env.GITHUB_OUTPUT, `state=${state}\n`);
  console.log(`state=${state}`);
  if (state === "upload") {
    console.log("Staged metadata is unavailable to OIDC; npm refuses duplicate staged versions without replacement.");
    console.log(heldMessage);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
