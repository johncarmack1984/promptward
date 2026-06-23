import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dashboard talks to the gateway's read API in dev. The proxy keeps the browser
// on a same-origin path (/api/...) so there is no CORS preflight; when the
// gateway is down the app falls back to a bundled fixture (see src/api.ts).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8787",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
