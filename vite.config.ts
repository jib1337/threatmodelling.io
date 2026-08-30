import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // Core React - rarely changes, cache separately
          'vendor-react': ['react', 'react-dom'],
          // React Flow - large library, cache separately
          'vendor-flow': ['@xyflow/react'],
          // Image export - only loaded when exporting
          'vendor-image': ['html-to-image'],
        },
      },
    },
    // Increase warning limit since we're intentionally chunking
    chunkSizeWarningLimit: 600,
  },
})
