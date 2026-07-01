"""Tiny static server for local preview that disables caching.

`python -m http.server` sends no Cache-Control, so browsers heuristically cache
ES modules and keep serving stale copies after edits. This sends no-store on
every response so the preview always reflects the latest source.

Usage: python3 .claude/serve.py [port]
"""

import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PORT", 8753))
    ThreadingHTTPServer(("", port), NoCacheHandler).serve_forever()
