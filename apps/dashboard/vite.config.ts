import babel from "@rolldown/plugin-babel";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dashboard talks to the gateway's read API in dev. The proxy keeps the browser
// on a same-origin path (/api/...) so there is no CORS preflight; when the
// gateway is down the app falls back to a bundled fixture (see src/api.ts).
export default defineConfig({
  plugins: [react(), babel({ presets: [reactCompilerPreset()] })],
  server: {
    // Uncommon pinned port; strict so a taken port fails loudly instead of
    // silently shifting.
    port: 47306,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://localhost:8787",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
