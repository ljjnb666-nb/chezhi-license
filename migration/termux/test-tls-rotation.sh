#!/usr/bin/env bash
set -euo pipefail
umask 077
src="$(cd -- "$(dirname -- "$0")" && pwd -P)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
bash "$src/stage-loopback-tls.sh" "$tmp/old"
before="$(sha256sum "$tmp/old/tls-cert" "$tmp/old/tls-key")"
bash "$src/stage-loopback-tls.sh" "$tmp/new"
if bash "$src/stage-loopback-tls.sh" "$tmp/old"; then echo 'overwrote candidate'; exit 1; fi
[ "$(sha256sum "$tmp/old/tls-cert" "$tmp/old/tls-key")" = "$before" ]
for dir in old new; do
    [ "$(stat -c %a "$tmp/$dir")" = 700 ]
    [ "$(stat -c %a "$tmp/$dir/tls-cert")" = 600 ]
    [ "$(stat -c %a "$tmp/$dir/tls-key")" = 600 ]
done
python3 - "$tmp" <<'PY'
import http.client
import pathlib
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
root = pathlib.Path(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fixture")
    def log_message(self, *args):
        pass
def exercise(served, trusted):
    path = root / served
    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(path / "tls-cert", path / "tls-key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        for name, allowed in trusted:
            client_ctx = ssl.create_default_context(cafile=str(root / name / "tls-cert"))
            client = http.client.HTTPSConnection("127.0.0.1", server.server_port,
                                                 timeout=3, context=client_ctx)
            try:
                client.request("GET", "/")
                response = client.getresponse()
                assert allowed and response.status == 200 and response.read() == b"fixture"
            except ssl.SSLCertVerificationError:
                assert not allowed, "valid trust failed"
            finally:
                client.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()
exercise("old", [("old", True), ("new", False)])
exercise("new", [("old", False), ("new", True)])
exercise("old", [("new", False), ("old", True)])
print("PASS TLS_ROTATION_FIXTURE old/new trust refusal, staged activation, rollback and IP verification")
PY
[ "$(sha256sum "$tmp/old/tls-cert" "$tmp/old/tls-key")" = "$before" ]
