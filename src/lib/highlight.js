// @ts-check
/**
 * A minimal highlight.js instance for the source viewer.
 *
 * We import the core and register only the grammars the viewer needs, so Vite
 * bundles a handful of languages instead of the full ~1 MB set. Zephyr sources
 * are overwhelmingly C, with the rest covering the other extensions the source
 * viewer maps in `_buildSnippetWindows`.
 *
 * @module lib/highlight
 */
import hljs from 'highlight.js/lib/core';
import c from 'highlight.js/lib/languages/c';
import cpp from 'highlight.js/lib/languages/cpp';
import python from 'highlight.js/lib/languages/python';
import javascript from 'highlight.js/lib/languages/javascript';

hljs.registerLanguage('c', c);
hljs.registerLanguage('cpp', cpp);
hljs.registerLanguage('python', python);
hljs.registerLanguage('javascript', javascript);

export default hljs;
