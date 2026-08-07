import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // recharts (d3 internals) and react-d3-tree dominate the bundle. Splitting
        // them keeps the app chunk small and lets the browser cache the heavy
        // visualisation libraries across deploys.
        manualChunks: {
          charts: ['recharts'],
          tree: ['react-d3-tree'],
          vendor: ['react', 'react-dom', '@tanstack/react-query'],
        },
      },
    },
  },
  server: {
    port: 5173,
    // The API's CORS allowlist includes this origin (see ADF_CORS_ORIGINS).
    proxy: {
      '/api': {
        target: process.env.VITE_ADF_API_URL ?? 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
