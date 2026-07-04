/**
 * Release history shown in the in-app changelog modal.
 *
 * Mirrors CHANGELOG.md at the repo root; update both together.
 *
 * @module changelog
 */

export const CHANGELOG = [
  {
    version: 'Unreleased',
    date: null,
    items: [
      'Migrated the build to Vite and reorganized the source into focused modules and view partials.',
      'Added a dedicated Agents view with rich agent detail.',
      'Added createdBy and performedBy provenance edges to the graph, hidden by default.',
      'Fixed the bottom of the UI being cut off on mobile browsers.'
    ]
  },
  {
    version: '0.0.4',
    date: '2026-07-04',
    items: [
      'Added support for the SPDX 3.1 Hardware profile.',
      'Added support for the SPDX 3.1 Functional Safety profile, including a dedicated Requirements view.',
      'Added an experimental Zephyr RTOS sample showcasing hardware and requirement data.',
      'Fixed the build configs view appearing when there were no configs to show.',
      'Fixed requirement filters not resetting when navigating between requirements.'
    ]
  },
  {
    version: '0.0.3',
    date: '2026-07-03',
    items: [
      'Added a CycloneDX to SPDX 3 converter that preserves as much of the original data as possible.',
      'Added a Raw JSON-LD view with syntax highlighting for inspecting SBOM data directly.',
      'Vulnerability and VEX filters now auto-enable when a scan has relevant findings.',
      'Added support for SPDX ExternalMap, with placeholder nodes for elements defined outside the loaded files.',
      'Added a Trivy vulnerability scan sample.'
    ]
  },
  {
    version: '0.0.2',
    date: '2026-07-03',
    items: [
      'Faster graph rendering for large SBOMs, via node property caching and a lightweight draw path.',
      'Package and file lists now load incrementally on scroll instead of all at once.',
      'Added dedicated AI model and dataset views, with a matching sample SBOM.',
      'Added global search to jump straight to any package, file, or other element.',
      'General performance tuning for large datasets.'
    ]
  },
  {
    version: '0.0.1',
    date: '2026-07-02',
    items: [
      'Initial release.',
      'Drag-and-drop or browse to load SPDX 3 SBOMs directly in the browser, no server needed.',
      'Interactive relationship graph with color-coded element types.',
      'Bundled sample SBOMs: Vue.js, Jenkins, Android, and Kubernetes.',
      'Initial CycloneDX property display support, plus dynamic link, optional component, and hasVariant relationship types.'
    ]
  }
];
