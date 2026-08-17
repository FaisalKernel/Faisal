#!/usr/bin/env python3
import argparse
import base64
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "faisal-journal-trust"))
import faisal_remote_kms_client as client


class Handler(BaseHTTPRequestHandler):
    token = ""
    seen = None

    def do_POST(self):
        if self.path != "/v1/transit/sign/faisal-journal":
            self.send_error(404)
            return
        if self.headers.get("X-Vault-Token") != self.token:
            self.send_error(403)
            return
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size))
        Handler.seen = body
        if not body.get("input"):
            self.send_error(400)
            return
        signature = base64.b64encode(b"mock-vault-signature").decode("ascii")
        payload = {"data": {"signature": "vault:v3:" + signature}}
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    Handler.token = "local-vault-test-token"
    server = HTTPServer(("localhost", args.port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.environ["SSL_CERT_FILE"] = args.cert
    signer = client.VaultTransitSigner(
        f"https://localhost:{args.port}", Handler.token, "faisal-journal"
    )
    result = signer.sign(b"journal-attestation")
    expected = base64.b64encode(b"journal-attestation").decode("ascii")
    if Handler.seen != {"input": expected}:
        raise RuntimeError("Vault request payload mismatch")
    if result.signature != b"mock-vault-signature" or result.key_generation != 3:
        raise RuntimeError("Vault response parsing mismatch")
    print("FJT_VAULT_HTTPS_INTEGRATION_OK")
    server.shutdown()
    thread.join(timeout=3)
    print("FJT_VAULT_MOCK_INTEGRATION_SELFTEST_OK")


if __name__ == "__main__":
    main()
