import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Configure Vite server with local backend proxies (both REST and WebSockets)
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true
      },
      '/ws/live': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true
      }
    }
  }
})
