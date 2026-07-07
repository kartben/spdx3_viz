// @ts-check
/**
 * Lazy wrapper around Mermaid, themed to match the app's dark slate palette.
 *
 * Mermaid is a heavy dependency (well over a megabyte), so it is pulled in via
 * dynamic `import()` and only when a diagram is first rendered. Vite splits it
 * into its own chunk, keeping it out of the initial bundle. The module keeps a
 * single memoised instance and initialises the theme once.
 *
 * @module lib/mermaid
 */

/** @type {Promise<any> | null} */
let mermaidPromise = null;

/**
 * Loads and initialises Mermaid on first use, then reuses the same instance.
 *
 * @returns {Promise<any>} the initialised mermaid module default export
 */
function getMermaid() {
  if (!mermaidPromise) {
    mermaidPromise = import('mermaid').then((mod) => {
      const mermaid = /** @type {any} */ (mod.default);
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: 'strict',
        theme: 'base',
        fontFamily: 'inherit',
        themeVariables: {
          darkMode: true,
          background: 'transparent',
          primaryColor: '#1e293b',
          primaryTextColor: '#e2e8f0',
          primaryBorderColor: '#475569',
          lineColor: '#64748b',
          fontSize: '13px',
          // stateDiagram-v2 specifics
          labelColor: '#e2e8f0',
          stateBkg: '#1e293b',
          stateBorder: '#475569',
          altBackground: '#0f172a',
          compositeBackground: '#0f172a',
          compositeBorder: '#475569',
          transitionColor: '#64748b',
          transitionLabelColor: '#a5b4fc',
          labelBackgroundColor: '#0b1220',
          edgeLabelBackground: '#0b1220',
          specialStateColor: '#e2e8f0',
          innerEndBackground: '#0b1220'
        }
      });
      return mermaid;
    });
  }
  return mermaidPromise;
}

/**
 * Renders Mermaid source to an SVG string. Each call uses a fresh element id so
 * repeated renders never collide with a lingering temporary node.
 *
 * @param {string} source - Mermaid diagram source
 * @returns {Promise<string>} the rendered SVG markup
 */
export async function renderMermaid(source) {
  const mermaid = await getMermaid();
  const id = `mmd-${Math.random().toString(36).slice(2)}`;
  const { svg } = await mermaid.render(id, source);
  return svg;
}
