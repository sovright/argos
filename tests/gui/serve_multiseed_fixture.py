"""Serve the real GUI with synthetic Tauri responses for manual browser checks.
No real keys, network scans, wallet files, or transactions are used.
Run: python3 tests/gui/serve_multiseed_fixture.py
"""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2] / 'gui' / 'src'
FIXTURE = Path(__file__).with_name('multiseed_fixture.js')

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path == '/':
            body = (ROOT / 'index.html').read_text().replace('./styles.css', './styles.css?v=' + str((ROOT / 'styles.css').stat().st_mtime_ns)).replace(
                '<script src="./main.js"></script>',
                f'<script src="/fixture.js?v={FIXTURE.stat().st_mtime_ns}"></script><script src="./main.js?v={(ROOT / "main.js").stat().st_mtime_ns}"></script>')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path.split('?', 1)[0] == '/fixture.js':
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript')
            self.end_headers()
            self.wfile.write(FIXTURE.read_bytes())
        else:
            super().do_GET()

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1]) if len(sys.argv) > 1 else 8765), Handler).serve_forever()
