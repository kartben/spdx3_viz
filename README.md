# SPDX 3 SBOM Visualizer

A browser-based tool for exploring [SPDX 3](https://spdx.dev/) SBOMs (Software Bill of Materials).
Drop one or more JSON-LD files and navigate the relationships between packages, files, tools,
builds, agents, etc. as an interactive graph.

## Features

- Load SPDX 3 files from your computer, or start with one of the bundled samples.
- Combine several SBOM files into one model, with cross-document references resolved automatically.
- Search across the SBOM, browse dedicated views for each kind of element, inspect the raw JSON-LD,
  or explore relationships as an interactive graph.
- Follow dependencies, provenance, and blast radius in the Impact view. Use graph filters and
  heatmaps to focus on vulnerabilities or functional-safety gaps.
- Dig into software, files, licenses, builds, agents, hardware, AI datasets and models, security and
  VEX data, and functional-safety requirements when those profiles are present.
- Plot functional-safety coverage as requirements-by-verification (and implementation, evidence,
  specification) matrices, and export them to Excel.
- Trace requirements down to source snippets, inspect SBOM completeness statistics, and share links
  to exact views of the bundled samples.
- Keep the SBOM itself in your browser. Files loaded from your computer are parsed locally and are
  never uploaded.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Usage

Open the [hosted visualizer](https://kartben.github.io/spdx3_viz/), then drop one or more `.json` or
`.jsonld` files onto the page. You can also use the file picker or open a bundled sample. Adding
several files is useful when an SBOM is split across source, build, and output documents.

Everything needed to parse and explore your SBOM runs in the browser. The app only makes external
requests when you choose a bundled sample or when it looks up optional public metadata, such as SPDX
license text or a CVE record.

## Run locally

Development and CI use Node.js 22. The repository also uses Git LFS for one of the larger sample
files (why yes, the tool can ingest hundreds of megabytes worth of SBOMs just fine!), so pull the
LFS objects after cloning if you want all bundled samples.

```bash
git lfs pull
npm ci
npm run dev
```

Vite prints the local URL, normally `http://localhost:5173`. Changes to JavaScript, CSS, and view
partials are reflected automatically.

To check the production build locally:

```bash
npm run build
npm run preview
```

The build is written to `dist/`. It is a static site with relative asset paths, so it can be
published below a URL prefix or served directly with any static file server. Files under `public/`,
including the sample SBOMs, are copied into the build unchanged.

## Development

Run the same checks as CI with:

```bash
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

`npm run format` applies Prettier when you want it to fix formatting instead of only checking it.

### Layout

- `index.html`: thin shell that `<include>`s the view partials
- `src/views/`: one HTML partial per view (packages, files, graph, etc.), assembled at build time by
  the `html-partials` Vite plugin
- `src/main.js`: browser entry that imports styles, Alpine, and the app
- `src/app.js` + `src/app/`: the Alpine component, split into focused mixins
- `src/parser/`: SBOM parsing, run in a Web Worker
- `src/graph/`: the D3 force-directed graph renderer
- `src/lib/`: utility modules for formatting, licenses, security, and other shared logic
