# AGENTS.md

## Cursor Cloud specific instructions

This is a client-side, browser-only SPDX 3 SBOM visualizer built with Vite (no
backend/server, no data upload). Dependencies are installed automatically by the
update script (`npm install`).

- Run the dev server with `npm run dev` (Vite, hot reload). It serves on
  `http://localhost:5173/`.
- Standard checks are documented in `CLAUDE.md` and mirror CI
  (`.github/workflows/deploy-pages.yml`): `npm run format:check`, `npm run lint`,
  `npm run typecheck`, `npm test`, `npm run build`. Run all of these before proposing a PR.
- Tests use the built-in Node test runner (`node --test`); no extra test framework.
- To manually verify the app, load a bundled sample SBOM from the landing page
  (see `public/samples/samples.json`). The "AI / ML model" sample is the smallest
  and fastest to load for a quick smoke test.
