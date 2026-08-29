# Changelog

All notable changes to this project are documented here. Also viewable in-app
via the "What's new" link.

## Unreleased

- **Added:** License compatibility analyzer.
- **Added:** Requirements roll up whether tests actually exercise the code.
- **Improved:** Functional Safety opens on the requirements, most urgent first.
- **Improved:** Requirement cards group snippets as file (N lines).
- **Fixed:** System requirements no longer count against the pass rate.
- **Improved:** Large downloads show bytes, an ETA, and never look stalled.
- **Improved:** Complete CPEs link to NVD by exact name.
- **Improved:** Graph opens faster and stays smoother on huge SBOMs.
- **Fixed:** Share links stay readable and restore the view.

## [0.5.0] - 2026-08-22

- **Fixed:** Wrong-format or broken files fail with a clear error.
- **Added:** Loads can be canceled from the progress overlay.
- **Improved:** Packages and Files filter by purpose, directory, missing fields.
- **Improved:** Package rows show version and license without expanding.
- **Improved:** List views search and filter faster on huge SBOMs.
- **Improved:** Faster Security and Safety views on huge SBOMs.
- **Improved:** Smaller initial download; highlighting, graph, charts load on demand.
- **Improved:** The start screen paints roughly twice as fast.
- **Improved:** Samples made of several files download in parallel.
- **Fixed:** Scrolling far into a huge list no longer bloats memory.
- **Fixed:** Searching Licenses, Builds, or Build configs returns to the top.
- **Improved:** Functional Safety decomposition, specification filter, pass-rate summary.
- **Added:** CISA 2026 Minimum Elements findings in Statistics.
- **Improved:** Sidebar groups SPDX profiles, with sticky Insights and Lucide icons.

## [0.4.0] - 2026-07-15

- **Fixed:** Large SBOMs (over ~512 MB) now load by streaming, without failing or freezing.
- **Improved:** Files view caps the extension filter to the most-used extensions.
- **Fixed:** Build cards no longer stall to open on large SBOMs.
- **Improved:** Graph legend filtering is faster on large SBOMs.
- **Improved:** Graph view repaints faster on large SBOMs.
- **Improved:** CVE cards clarify referenced files and flag VEX-cleared ones.
- **Fixed:** Online-only CVEs now resolve referenced files when expanded.
- **Fixed:** `hasPrerequisite` relationships now show on the graph (e.g. Zephyr build SBOMs).

## [0.3.0] - 2026-07-12

- **Added:** Graph layout picker: organic, hierarchy, radial, spotlight, and type lanes.
- **Added:** Files dialog to add or remove sample and local files.
- **Added:** Relationship Repartition chart in Statistics, with graph drill-down.
- **Added:** Remediation view listing actionable SBOM gaps, with filters.
- **Added:** Online vulnerability lookup via OSV.dev and NVD, merged with SBOM findings.
- **Added:** Scan findings flagged on the graph and in search.
- **Added:** Optional bundled indexes for offline CPE and CVE matching.
- **Added:** CVE details list affected files and functions, linked to SBOM.
- **Improved:** Impact adds a search-first element picker with provenance.
- **Fixed:** Overview cards no longer wrap awkwardly on narrow screens.

## [0.2.0] - 2026-07-07

- **Added:** Command palette (⌘K / Ctrl-K) to search and jump anywhere.
- **Added:** Per-element NTIA minimum-elements breakdown in Statistics.
- **Added:** Package cards show supplier and origin agents.
- **Added:** Supply Chain view with timeline, state-machine, processes, custody, and route-map angles.

## [0.1.0] - 2026-07-06

- **Improved:** Redesigned SBOM overview page.
- **Added:** Graph heatmap overlay for vulnerabilities, failing and unverified requirements.
- **Added:** "Hide orphans" graph toggle, to declutter disconnected nodes.
- **Improved:** Graph auto-fits to view on changes; reset zoom frames it all.
- **Improved:** Multiple snippet ranges of one file collapse into a single link.
- **Improved:** Snippet source viewer folds away code between covered ranges.
- **Fixed:** Graph now shows `tracedToDetail` requirement decomposition edges.

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
