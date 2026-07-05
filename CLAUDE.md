# CLAUDE.md

## Writing style

- Don't use em dashes (`—`) in prose, code comments, commit messages, changelog entries, or PR text. Use a colon, comma, parentheses, or two sentences instead.

## Changelog (`CHANGELOG.md`)

- Keep entries short: one concise line, like the existing bullets.
- Only add an entry for something genuinely notable: an important new capability, or a fix for a bug that shipped in a **previous** release. Do **not** add an entry for a bug introduced and fixed within the current unreleased cycle.
- Before adding a bullet, check whether it folds into an existing one for the same release rather than adding another line.

## Before proposing/creating a PR

Always run these checks locally first (they mirror `.github/workflows/deploy-pages.yml` CI exactly) and fix any failures before proposing a PR:

```bash
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```
