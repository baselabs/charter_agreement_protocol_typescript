import { reportFor } from "./core.ts";

const argumentsList = process.argv.slice(2);
if (argumentsList.length !== 2 || argumentsList[0] !== "--corpus") {
  console.error("usage: node verifier/cli.ts --corpus DIRECTORY");
  process.exitCode = 2;
} else {
  try {
    const report = reportFor(argumentsList[1]);
    process.stdout.write(report.bytes);
    process.exitCode = report.exitStatus;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
