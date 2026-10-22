import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Library build for portfolio integration: an ES module exporting the root component and a
// mount() helper, with React kept external so a host page supplies its own copy.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist/lib",
    emptyOutDir: false,
    copyPublicDir: false,
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: () => "incident-loom.js",
      cssFileName: "incident-loom",
    },
    rollupOptions: {
      external: ["react", "react-dom", "react-dom/client", "react/jsx-runtime"],
    },
  },
});
