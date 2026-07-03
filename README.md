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

### SPDX model

The SPDX type strings the app relies on (class names, property names, the
subclass hierarchy, and enumerated vocabularies like `RelationshipType`) are not
hand-maintained: they are generated from the official SPDX SHACL/OWL model. The
generator ([scripts/gen-model.mjs](scripts/gen-model.mjs)) parses the canonical
Turtle (`spdx-model.ttl`, the same artifact
[spdx-python-model](https://github.com/spdx/spdx-python-model) consumes) with
[N3](https://github.com/rdfjs/N3.js) (a dev-only dependency; nothing ships to the
browser).

```bash
npm run gen:model         # regenerate js/generated/ from the SPDX model
npm run gen:model:check   # fail if the committed output is stale (CI/pre-commit)
```

The generated files under `js/generated/` are committed and imported directly by
the browser, so this stays a zero-build site at runtime; `gen:model` is only run
when refreshing the model. Versions 3.0.1, 3.1 and 3.1-dev are generated; the app
targets 3.0.1 (selected in `js/spdx-model.js`). Set `SPDX_MODEL_DIR` to build
offline from a local model checkout instead of fetching.

The model is consumed two ways:

- **Drives behavior.** Element categorization uses the class hierarchy
  (`isSubclassOf`, so AI/dataset and any future `software_Package` subclass count
  as packages automatically), and every relationship type the model defines gets
  a graph filter, legend chip and a stable color, so uncommon or newly added
  types (e.g. `patchedBy`, `describes`) render instead of being silently dropped.
- **Validates the curated parts.** A unit test checks the hand-curated constants
  in `js/config.js` against the generated model, so a misspelling or spec drift
  fails the suite (this is how the `underInvestigation` -> `underInvestigationFor`
  fix was found).
