// @ts-check
/**
 * A minimal highlight.js instance for the source viewer, loaded on demand.
 *
 * We import the core and register only the grammars the viewer needs, so Vite
 * bundles a handful of languages instead of the full ~1 MB set. Zephyr sources
 * are overwhelmingly C, with the rest covering the other extensions the source
 * viewer maps in `_buildSnippetWindows`.
 *
 * The imports are dynamic so those grammars land in their own chunk rather than
 * the main bundle (~41 kB, 15 kB gzipped): most sessions never open a file's
 * source, and the ones that do are already awaiting a fetch of it.
 *
 * @module lib/highlight
 */

/** Memoized loader promise, so the chunk is fetched at most once. */
let hljsPromise = null;

/**
 * Loads highlight.js with the source viewer's grammars registered. Repeat calls
 * share one load; a failed load isn't cached, so a later view can retry.
 *
 * @returns {Promise<any>}
 */
export function loadHighlighter() {
  if (!hljsPromise) {
    hljsPromise = Promise.all([
      import('highlight.js/lib/core'),
      import('highlight.js/lib/languages/c'),
      import('highlight.js/lib/languages/cpp'),
      import('highlight.js/lib/languages/python'),
      import('highlight.js/lib/languages/javascript')
    ]).then(([core, c, cpp, python, javascript]) => {
      const hljs = core.default;
      hljs.registerLanguage('c', c.default);
      hljs.registerLanguage('cpp', cpp.default);
      hljs.registerLanguage('python', python.default);
      hljs.registerLanguage('javascript', javascript.default);
      return hljs;
    });
    hljsPromise.catch(() => {
      hljsPromise = null;
    });
  }
  return hljsPromise;
}
