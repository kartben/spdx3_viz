# Changelog

All notable changes to this project are documented here. Also viewable in-app
via the "What's new" link.

## Unreleased

- **Changed:** migrated the build to Vite; reorganized source into modules and view partials.
- **Added:** dedicated Agents view.
- **Added:** createdBy/performedBy provenance edges in the graph, hidden by default.
- **Fixed:** UI cut off on mobile browsers.

## [0.0.4] - 2026-07-04

- **Added:** SPDX ExternalMap support, with placeholder nodes for external elements.
- **Added:** experimental Zephyr SPDX 3.1 sample.
- **Added:** SPDX 3.1 Hardware profile support.
- **Added:** SPDX 3.1 Functional Safety profile support, with a dedicated Requirements view.
- **Fixed:** build configs view showing up with nothing to show.

## [0.0.3] - 2026-07-03

- **Improved:** package and file lists now load incrementally on scroll.
- **Added:** AI model and dataset views, with a matching sample SBOM.
- **Added:** global search across all elements.
- **Added:** CycloneDX to SPDX 3 converter.
- **Added:** Raw JSON-LD view with syntax highlighting.
- **Added:** Trivy vulnerability scan sample; vulnerability/VEX filters now auto-enable when a scan has findings.

## [0.0.2] - 2026-07-03

- **Added:** sample SBOMs for Vue.js, Jenkins, Android, and Kubernetes.
- **Added:** CycloneDX property display, plus dynamic link, optional component, and hasVariant relationship types.
- **Improved:** graph rendering performance for large SBOMs, via node caching and a faster draw path.
- **Improved:** file list rendering, via memoization.

## [0.0.1] - 2026-07-02

- **Added:** initial release. Interactive relationship graph for SPDX 3 SBOMs, color-coded by element type.
- **Added:** sample SBOMs for Linux, Windows, Yocto, Zephyr, and a Docker container image.
