import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [
    {name:'development-csp',transformIndexHtml(html,context){return context.server?html.replace(/<meta http-equiv="Content-Security-Policy"[^>]*\/>/,''):html;}},
    react(),
  ],
  worker:{format:'es'},
  build:{target:'es2022'},
  server:{port:5173},
  preview:{port:4173},
});
