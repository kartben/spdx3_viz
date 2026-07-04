# CLAUDE.md

## Before proposing/creating a PR

Always run these checks locally first (they mirror `.github/workflows/deploy-pages.yml` CI exactly) and fix any failures before proposing a PR:

```bash
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```
