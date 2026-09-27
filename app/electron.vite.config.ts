import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, externalizeDepsPlugin } from "electron-vite";

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
    resolve: {
      alias: { "@shared": resolve("src/shared") }
    },
    build: {
      rollupOptions: {
        // The MCP SDK ships ESM-only subpaths; keep it bundled rather than
        // externalized so the packaged main process resolves it at runtime.
        external: ["electron"]
      }
    }
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    resolve: {
      alias: { "@shared": resolve("src/shared") }
    },
    build: {
      rollupOptions: {
        // Electron cannot load an ESM preload into a sandboxed renderer, so this
        // is pinned to CJS with an explicit .cjs extension (the package is
        // "type": "module", which would otherwise make .js mean ESM).
        output: {
          format: "cjs",
          entryFileNames: "[name].cjs",
          inlineDynamicImports: true
        }
      }
    }
  },
  renderer: {
    resolve: {
      alias: {
        "@renderer": resolve("src/renderer/src"),
        "@shared": resolve("src/shared")
      }
    },
    plugins: [react(), tailwindcss()]
  }
});
