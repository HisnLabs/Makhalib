import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueJsx from '@vitejs/plugin-vue-jsx'

// Dev: `npm run dev` proxies /api to a running `makhalib ui`.
export default defineConfig({
  plugins: [vue(), vueJsx()],
  server: { proxy: { '/api': 'http://127.0.0.1:8088' } },
  build: { outDir: 'dist', emptyOutDir: true },
})
