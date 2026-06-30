# SPDX 3.0 SBOM Visualizer

A zero-build, browser-based tool for exploring [SPDX 3.0](https://spdx.dev/) SBOMs.
Drop one or more JSON-LD files and navigate the relationships between packages,
files, tools, builds, agents, and licenses as an interactive graph.

## Features

- Easily load SPDX3 SBOMs by drag-and-drop, file picker, or the bundled samples.
- Automatically merges multiple files into one model and resolves cross-references between them.
- Interactive relationship graph, colored by element type and relationship.
- Dedicated views for packages, files, licenses, build configs, and builds.
- Runs entirely in the browser; no server or data upload.

## Usage

Static site with no build step, just serve the folder and open it in a browser:

```bash
python3 -m http.server 8000   # then open http://localhost:8000
```

Sample SBOMs are available under `samples/`.

## Development

```bash
npm install
npm test          # run unit tests
npm run lint      # ESLint
npm run format    # Prettier
```
