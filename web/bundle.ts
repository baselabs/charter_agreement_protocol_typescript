import type { BuildOptions } from "esbuild";

export const browserBundleOptions: Pick<BuildOptions, "platform" | "target" | "alias" | "inject"> = {
  platform: "browser",
  target: "es2022",
  alias: {
    "node:crypto": "./web/shim/node-crypto.ts",
    "node:fs": "./web/shim/node-fs.ts",
    "node:path": "./web/shim/node-path.ts",
    "@charter-agreement-protocol/verifier": "./index.ts",
  },
  inject: ["./web/shim/buffer-global.ts"],
};
