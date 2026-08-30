import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { execFileSync } from 'node:child_process'

// Identifies the running build in the About modal, so a deployed site can be
// traced back to a commit. CI exports GITHUB_SHA; locally we ask git. A build
// from a tarball or a dirty tree has neither, hence the fallback.
function buildId() {
  const fromCI = process.env.GITHUB_SHA?.trim()
  if (fromCI) return fromCI.slice(0, 7)
  try {
    return execFileSync('git', ['rev-parse', '--short=7', 'HEAD'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim()
  } catch {
    return 'unknown'
  }
}

export default defineConfig({
  plugins: [react()],
  define: {
    __BUILD_ID__: JSON.stringify(buildId()),
  },
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
