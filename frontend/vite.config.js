import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/health': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/nodes': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/catalog': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/repair': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/provider': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/metering': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
      '/accounting': {
        target: 'http://127.0.0.1:9000',
        changeOrigin: true,
      },
    },
  },
})
