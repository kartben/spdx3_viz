# SPDX 3.0 SBOM Visualizer

A zero-build, browser-based tool for exploring [SPDX 3.0](https://spdx.dev/) SBOMs.
Drop one or more JSON-LD files and navigate the relationships between packages,
files, tools, builds, agents, and licenses as an interactive graph.

## Features

- Drag-and-drop one or more SPDX 3.0 JSON-LD files.
- Multiple files are merged and cross-references resolved automatically.
- Interactive D3 force-directed graph with type-based coloring and filtering.

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
