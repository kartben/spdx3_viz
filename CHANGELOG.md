# Changelog

All notable changes to this project are documented here. Also viewable in-app
via the "What's new" link.

## [0.0.6] - 2026-07-06

- **Added:** Snippet source viewer, with requirement-to-code traceability.
- **Added:** Ansible Automation Platform 2.6 sample (~40k packages) with VEX overlay.
- **Added:** Synthetic AEB safety case with full traceability.
- **Added:** Functional Safety verification rollup and requirement decomposition tree.
- **Added:** Graph traces requirements to their files through snippets.
- **Improved:** List filters and counts stay pinned while scrolling.
- **Improved:** Graph detail panel is drag-resizable, with width remembered.
- **Improved:** Much faster parsing of large, build-heavy SBOMs.
- **Fixed:** Licenses and Build views no longer freeze on huge lists.
- **Improved:** Impact view shows package versions to distinguish builds.
- **Improved:** Opening a deep list element jumps straight to it.
- **Fixed:** Browser Back from a document returns to the home screen.
- **Fixed:** Agent nodes are now indigo, distinct from vulnerability nodes.

## [0.0.5] - 2026-07-05

- **Added:** Shareable links tracking the current view and selected element.
- **Added:** PackageURL identifiers link out to deps.dev.
- **Added:** Impact view: trace provenance and blast radius, with risk rankings.
- **Added:** Security view surfacing CVSS, EPSS, and known-exploited signals.
- **Added:** Statistics view with completeness score and category breakdowns.
- **Added:** Dedicated Agents view.
- **Added:** CreatedBy/performedBy provenance edges, hidden by default.
- **Changed:** Simplified the dashboard and sidebar; empty views stay hidden.
- **Changed:** Migrated the build to Vite.
- **Fixed:** UI cut off on mobile browsers.

## [0.0.4] - 2026-07-04

- **Added:** SPDX ExternalMap support, with placeholder nodes for external elements.
- **Added:** Experimental Zephyr SPDX 3.1 sample.
- **Added:** SPDX 3.1 Hardware profile support.
- **Added:** SPDX 3.1 Functional Safety profile support, with a dedicated Requirements view.
- **Fixed:** Build configs view showing up with nothing to show.

## [0.0.3] - 2026-07-03

- **Improved:** Package and file lists now load incrementally on scroll.
- **Added:** AI model and dataset views, with a matching sample SBOM.
- **Added:** Global search across all elements.
- **Added:** CycloneDX to SPDX 3 converter.
- **Added:** Raw JSON-LD view with syntax highlighting.
- **Added:** Trivy vulnerability scan sample; vulnerability/VEX filters now auto-enable when a scan has findings.

## [0.0.2] - 2026-07-03

- **Added:** Sample SBOMs for Vue.js, Jenkins, Android, and Kubernetes.
- **Added:** CycloneDX property display, plus dynamic link, optional component, and hasVariant relationship types.
- **Improved:** Graph rendering performance for large SBOMs, via node caching and a faster draw path.
- **Improved:** File list rendering, via memoization.

## [0.0.1] - 2026-07-02

- **Added:** Initial release. Interactive relationship graph for SPDX 3 SBOMs, color-coded by element type.
- **Added:** Sample SBOMs for Linux, Windows, Yocto, Zephyr, and a Docker container image.
