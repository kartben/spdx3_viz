# SPDX 3 SBOM Visualizer

A browser-based tool for exploring [SPDX 3](https://spdx.dev/) SBOMs
(both SPDX 3.0 and 3.1). Drop one or more JSON-LD files and navigate the
relationships between packages, files, tools, builds, agents, etc. as an interactive graph.

## Features

- Easily load SPDX 3 (3.0 / 3.1) SBOMs by drag-and-drop, file picker, or the bundled samples.
- Automatically merges multiple files into one model and resolves cross-references between them.
- Interactive relationship graph, colored by element type and relationship.
- Dedicated views for packages, files, licenses, build configs, and builds.
- Runs entirely in the browser; no server or data upload.

See [CHANGELOG.md](CHANGELOG.md) for release history (also viewable in-app via
the "What's new" link).

## Usage

The app is built with [Vite](https://vite.dev/). For a production build:

```bash
npm install
npm run build                 # outputs a static site to dist/
python3 -m http.server -d dist 8000   # then open http://localhost:8000
```

The `dist/` folder is a self-contained static site (no server or data upload)
and is what gets published to GitHub Pages.

Sample SBOMs are available under `public/samples/` (served at `samples/`).

## Development

```bash
npm install
npm run dev       # Vite dev server with hot reload
npm test          # run unit tests
npm run lint      # ESLint
npm run format    # Prettier
```

### Layout

- `index.html` — thin shell that `<include>`s the view partials
- `src/views/` — one HTML partial per view (packages, files, graph, …),
  assembled at build time by the `html-partials` Vite plugin
- `src/main.js` — browser entry (imports styles, Alpine, and the app)
- `src/app.js` + `src/app/` — the Alpine component, split into focused mixins
- `src/parser/` — SBOM parsing (runs in a Web Worker)
- `src/graph/` — the d3 force-directed graph renderer
- `src/lib/` — utility modules (formatting, licenses, security, …)
