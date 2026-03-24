import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://a5ucanc.github.io',
  vite: {
    optimizeDeps: {
      include: ['fuse.js'],
    },
  },
});
