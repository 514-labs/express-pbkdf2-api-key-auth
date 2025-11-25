import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/bin/generate-api-key.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
});
