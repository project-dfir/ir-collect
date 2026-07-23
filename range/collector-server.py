#!/usr/bin/env python3
"""
Minimal POST/PUT-capable upload collector for IR-Collect lab/training runs.

The collectors ship their sealed bundle with a raw HTTP body:
    IR-Collect.ps1 -Dest http://<collector>:8000/        (Invoke-RestMethod -Method Put -InFile)
    ir-collect.sh  -d    http://<collector>:8000/         (curl -T)
This server accepts that, plus multipart (curl -F 'file=@x' .../upload) and raw --data-binary.
It streams the body straight to ./loot/ so large triage bundles don't buffer in RAM.

NO AUTHENTICATION - run it only inside an isolated range/lab network.

Usage:  python3 collector-server.py [PORT] [LOOT_DIR]
        python3 collector-server.py 8000 ./loot
"""
import http.server, socketserver, os, sys, cgi, datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
ROOT = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(os.getcwd(), 'loot')
os.makedirs(ROOT, exist_ok=True)


def safe_name(name):
    name = os.path.basename((name or '').strip())
    if not name:
        name = 'upload_' + datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%SZ') + '.bin'
    # keep it inside ROOT
    return name.replace('..', '_')


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'IRCollect-Collector/1.0'

    def _stream_to(self, fname):
        n = int(self.headers.get('Content-Length', 0) or 0)
        path = os.path.join(ROOT, safe_name(fname))
        left = n
        with open(path, 'wb') as f:
            while left > 0:
                chunk = self.rfile.read(min(1 << 20, left))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        return path, n

    def _ok(self, path, n):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        msg = "OK stored %s (%d bytes)\n" % (path, n)
        self.wfile.write(msg.encode())
        sys.stdout.write(msg)
        sys.stdout.flush()

    def do_PUT(self):
        path, n = self._stream_to(self.path.lstrip('/'))
        self._ok(path, n)

    def do_POST(self):
        ctype = self.headers.get('Content-Type', '')
        if ctype.startswith('multipart/form-data'):
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': ctype})
            saved = []
            for k in form.keys():
                item = form[k]
                if getattr(item, 'filename', None):
                    p = os.path.join(ROOT, safe_name(item.filename))
                    with open(p, 'wb') as f:
                        f.write(item.file.read())
                    saved.append(p)
            self._ok('; '.join(saved) or '(none)', 0)
        else:
            path, n = self._stream_to(self.path.lstrip('/') or 'upload.bin')
            self._ok(path, n)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'IR-Collect collector is up. PUT or POST your sealed bundle.\n')

    def log_message(self, *a):
        pass


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == '__main__':
    with ThreadingServer(('0.0.0.0', PORT), Handler) as srv:
        print("IR-Collect collector listening on :%d  ->  %s" % (PORT, ROOT))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nbye")
