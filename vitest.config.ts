import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Component and unit tests of the UI package (jsdom).
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    include: ['ui/src/**/*.test.{ts,tsx}'],
    setupFiles: ['./ui/src/test/setup.ts'],
    restoreMocks: true,
  },
})
