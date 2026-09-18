// The browser stub for the verifier package's node:fs surface. The pure
// artifact paths (decode/verify/produce/assemble) never touch the filesystem;
// the corpus machinery does and cannot run in a page — every stub fails closed.
function refuse(name: string): never {
  throw new Error(`node:fs.${name} is not available in the browser (corpus machinery is server-side)`);
}
export const readFileSync = (..._a: unknown[]): never => refuse("readFileSync");
export const readdirSync = (..._a: unknown[]): never => refuse("readdirSync");
export const lstatSync = (..._a: unknown[]): never => refuse("lstatSync");
export const mkdtempSync = (..._a: unknown[]): never => refuse("mkdtempSync");
export const cpSync = (..._a: unknown[]): never => refuse("cpSync");
export const writeFileSync = (..._a: unknown[]): never => refuse("writeFileSync");
export const rmSync = (..._a: unknown[]): never => refuse("rmSync");
