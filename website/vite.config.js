import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = dirname(fileURLToPath(import.meta.url));
const configSchema = resolve(
  websiteDir,
  '../crates/rustbox-config-file/schema/rustbox-config-v1.schema.json',
);

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'publish-rustbox-config-schema',
      closeBundle() {
        const destination = resolve(
          websiteDir,
          'dist/schema/rustbox-config-v1.schema.json',
        );
        mkdirSync(dirname(destination), { recursive: true });
        copyFileSync(configSchema, destination);
      },
    },
  ],
  base: './',
  build: {
    rollupOptions: {
      input: {
        home: resolve(websiteDir, 'index.html'),
        config: resolve(websiteDir, 'config/index.html'),
        api: resolve(websiteDir, 'api/index.html'),
      },
    },
  },
});
