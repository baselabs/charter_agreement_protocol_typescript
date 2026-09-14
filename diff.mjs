// Differential projection harness: reads one JSON text per line on stdin,
// emits the canonical JSON array of {decode, project} results — one object
// per line as produced by the reference implementation.
import { canonical, decodeJsonText, jsonProjection } from "./core.ts";
import { readFileSync } from "node:fs";

const lines = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
const results = lines.map((line) => {
  const decoded = decodeJsonText(line);
  return decoded.ok ? { status: "valid", output: jsonProjection(decoded.value) } :
    { status: "invalid", error_code: decoded.code };
});
process.stdout.write(`${canonical(results)}\n`);
