import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  build: { sourcemap: false },
  server: { port: 5173, proxy: { "/api": { target: "http://localhost:8080", rewrite: (path) => path.replace(/^\/api/, "") } } }
});
