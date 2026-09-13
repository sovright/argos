"""Serve the real GUI with synthetic address responses; never use real seeds."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2] / 'gui' / 'src'
FIXTURE = Path(__file__).with_name('addresses_fixture.js')
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)
    def do_GET(self):
        if self.path == '/':
            body = (ROOT / 'index.html').read_text().replace('<script src="./main.js"></script>', '<script src="/fixture.js"></script><script src="./main.js"></script>')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(body.encode())
        elif self.path == '/fixture.js':
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript')
            self.end_headers()
            self.wfile.write(FIXTURE.read_bytes())
        else:
            super().do_GET()
ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1]) if len(sys.argv) > 1 else 8776), Handler).serve_forever()
