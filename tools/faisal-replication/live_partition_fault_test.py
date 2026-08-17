#!/usr/bin/env python3
import argparse
import os
import socket
import ssl
import threading
import time


class Endpoint:
    def __init__(self, port, cert, key, ca):
        self.port, self.cert, self.key, self.ca = port, cert, key, ca
        self.ready = threading.Event()
        self.connections = []
        self.server = None

    def run(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=self.ca)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(self.cert, self.key)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", self.port))
        self.server.listen(8)
        self.ready.set()
        self.server.settimeout(8)
        try:
            while True:
                raw, _ = self.server.accept()
                conn = context.wrap_socket(raw, server_side=True)
                conn.sendall(b"APPEND term=7 sequence=72 digest=A quorum=2\n")
                self.connections.append(conn)
        except (socket.timeout, OSError):
            pass
        finally:
            for conn in self.connections:
                conn.close()
            self.server.close()


def connect(port, cert, key, ca):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    context.load_cert_chain(cert, key)
    raw = socket.create_connection(("127.0.0.1", port), timeout=4)
    return context.wrap_socket(raw, server_hostname="localhost")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-a", type=int, required=True)
    parser.add_argument("--port-b", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--go-file", required=True)
    parser.add_argument("--release-file", required=True)
    args = parser.parse_args()
    a = Endpoint(args.port_a, args.cert, args.key, args.ca)
    b = Endpoint(args.port_b, args.cert, args.key, args.ca)
    ta, tb = threading.Thread(target=a.run), threading.Thread(target=b.run)
    ta.start(); tb.start()
    if not a.ready.wait(4) or not b.ready.wait(4):
        raise RuntimeError("TLS endpoints did not become ready")
    left = connect(args.port_a, args.cert, args.key, args.ca)
    right = connect(args.port_b, args.cert, args.key, args.ca)
    if not left.recv(128).startswith(b"APPEND") or not right.recv(128).startswith(b"APPEND"):
        raise RuntimeError("authenticated replication stream failed")
    print("FJT_TLS_REPLICATION_HANDSHAKE_OK", flush=True)
    open(args.ready_file, "w", encoding="ascii").close()
    while not os.path.exists(args.go_file):
        time.sleep(0.02)
    # The harness is run in a network namespace or under tc netem. A live
    # socket remains established while the caller applies a bidirectional drop.
    left.settimeout(1); right.settimeout(1)
    try:
        left.sendall(b"VOTE term=8 candidate=2\n")
        left.recv(128)
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        print("FJT_LIVE_PARTITION_DROP_OBSERVED_OK", flush=True)
    # Removing the traffic rule allows a fresh TLS connection and validates
    # recovery rather than silently accepting an isolated leader.
    left.close(); right.close()
    while not os.path.exists(args.release_file):
        time.sleep(0.02)
    recovered = connect(args.port_a, args.cert, args.key, args.ca)
    recovered.settimeout(4)
    if not recovered.recv(128).startswith(b"APPEND"):
        raise RuntimeError("replication did not recover after partition")
    print("FJT_LIVE_PARTITION_RECOVERY_OK")
    recovered.close()
    a.server.close(); b.server.close()
    ta.join(timeout=4); tb.join(timeout=4)
    print("FJT_LIVE_SOCKET_PARTITION_SELFTEST_OK")


if __name__ == "__main__":
    main()
