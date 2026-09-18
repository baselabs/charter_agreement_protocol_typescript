// Copies the static site pieces next to esbuild's bundle (managed-language,
// cross-platform — no shell in the build path) and cache-busts the asset URLs:
// every deploy gets styles.css/app.js suffixed with the commit SHA, so returning
// visitors can never be served a stale stylesheet from an unchanged URL.
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(fileURLToPath(import.meta.url));
const out = join(web, "..", "site-dist");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

let version = "dev";
try {
  version = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: join(web, "..") }).toString().trim();
} catch {
  // no git (e.g., an exported tree) — fall back to a content-free tag
}

let html = readFileSync(join(web, "index.html"), "utf8");
html = html.replace(/\.\/styles\.css"/g, `./styles.css?v=${version}"`).replace(/\.\/app\.js"/g, `./app.js?v=${version}"`);
writeFileSync(join(out, "index.html"), html);
cpSync(join(web, "styles.css"), join(out, "styles.css"));
console.log(`site: static assets staged in ${out} (asset version ?v=${version})`);
