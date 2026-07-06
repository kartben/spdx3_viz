import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { defineConfig } from 'vite';

// Minimal HTML-partials plugin: expands `<include src="path/to/file.html">`
// (self-closing or with a matching `</include>`) by inlining the referenced
// file, recursively, at transform time. This lets index.html stay a thin shell
// while each view lives in its own src/views/*.html file — with zero runtime
// cost, since the composition happens at build/serve time and the browser only
// ever sees one assembled document (so Alpine's single x-data tree is intact).
const INCLUDE_RE = /<include\s+src="([^"]+)"\s*(?:\/>|>\s*<\/include>)/g;

function expandIncludes(html, baseDir, seen = new Set()) {
  return html.replace(INCLUDE_RE, (_, src) => {
    const file = resolve(baseDir, src);
    if (seen.has(file)) throw new Error(`Circular <include> at ${src}`);
    const body = readFileSync(file, 'utf8');
    return expandIncludes(body, dirname(file), new Set(seen).add(file));
  });
}

function htmlPartials() {
  const root = resolve(import.meta.dirname);
  return {
    name: 'html-partials',
    transformIndexHtml: {
      order: 'pre',
      handler: (html) => expandIncludes(html, root)
    },
    // Dev: a change to any partial should reload the page, since Vite only
    // watches index.html for the HTML entry by default.
    configureServer(server) {
      server.watcher.add(resolve(root, 'src/views'));
      server.watcher.on('change', (file) => {
        if (file.includes('/src/views/')) {
          server.ws.send({ type: 'full-reload' });
        }
      });
    }
  };
}

// Keep the Apache NOTICE with every production build, including the static
// dist/ bundle published to GitHub Pages or redistributed on its own.
function legalNotice() {
  return {
    name: 'legal-notice',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'NOTICE',
        source: readFileSync(resolve(import.meta.dirname, 'NOTICE'), 'utf8')
      });
    }
  };
}

// Static site: emitted with relative asset URLs (base './') so it works whether
// served from the GitHub Pages project subpath (/spdx3_viz/), a custom domain,
// or `python3 -m http.server` on the built `dist/` folder. Files under public/
// (the bundled samples/ and social images) are copied verbatim and keep their
// paths, so the runtime `fetch('samples/samples.json')` still resolves.
export default defineConfig({
  base: './',
  plugins: [htmlPartials(), legalNotice()],
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1500
  }
});
