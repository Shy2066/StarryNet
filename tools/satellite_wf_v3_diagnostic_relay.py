#!/usr/bin/env python3
"""Header-free logging TCP relay for the bounded V3 proxy-path diagnosis."""

import argparse
import datetime
import json
import select
import socket
import socketserver
import sys
from pathlib import Path


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="microseconds")


def parse_endpoint(value):
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError("endpoint must be host:port")
    return host, int(port)


class DiagnosticRelayHandler(socketserver.BaseRequestHandler):
    def event(self, name, **fields):
        self.server.log({
            "event": name,
            "utc": utc_now(),
            "peer": "{}:{}".format(*self.client_address[:2]),
            **fields
        })

    def handle(self):
        upstream = None
        self.event("client_accepted")
        try:
            self.event("upstream_connect_started",
                       upstream="{}:{}".format(*self.server.upstream))
            upstream = socket.create_connection(self.server.upstream, timeout=20)
            self.event("upstream_connected")
            self.request.settimeout(None)
            upstream.settimeout(None)
            active = [self.request, upstream]
            peer_by_socket = {self.request: upstream, upstream: self.request}
            while active:
                readable, _writable, _errors = select.select(active, [], [], 1.0)
                for source in readable:
                    data = source.recv(65536)
                    target = peer_by_socket[source]
                    if not data:
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        active.remove(source)
                    else:
                        target.sendall(data)
            self.event("connection_closed", upstream_connected=True)
        except (OSError, ValueError) as exc:
            self.event("connection_error", error_type=type(exc).__name__,
                       upstream_connected=upstream is not None)
        finally:
            for connection in (self.request, upstream):
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass


class DiagnosticThreadedRelay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, upstream, ready_file):
        self.upstream = upstream
        self.ready_file = Path(ready_file)
        socketserver.ThreadingTCPServer.__init__(
            self, address, DiagnosticRelayHandler)

    def log(self, fields):
        sys.stdout.write(json.dumps(fields, sort_keys=True) + "\n")
        sys.stdout.flush()


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    relay = sub.add_parser("relay")
    relay.add_argument("--listen", required=True)
    relay.add_argument("--upstream", required=True)
    relay.add_argument("--ready-file", required=True)
    args = parser.parse_args(argv)
    if args.command != "relay":
        parser.error("relay command required")
    listen = parse_endpoint(args.listen)
    upstream = parse_endpoint(args.upstream)
    server = DiagnosticThreadedRelay(listen, upstream, args.ready_file)
    server.ready_file.write_text(json.dumps({
        "pid": __import__("os").getpid(),
        "listen": "{}:{}".format(*server.server_address[:2]),
        "upstream": "{}:{}".format(*upstream),
        "diagnostic_only": True,
    }) + "\n", encoding="utf-8")
    server.log({"event": "listener_ready", "utc": utc_now(),
                "listen": "{}:{}".format(*server.server_address[:2]),
                "upstream": "{}:{}".format(*upstream)})
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
