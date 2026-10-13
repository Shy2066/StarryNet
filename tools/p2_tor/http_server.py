#!/usr/bin/env python3
"""Small threaded fixture server for the isolated P2/P3 test network."""
import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from functools import partial


class FixtureHandler(SimpleHTTPRequestHandler):
    server_version = "StarryNetFixture/1.0"

    def log_message(self, format_string, *args):
        super().log_message(format_string, *args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    handler = partial(FixtureHandler, directory=str(directory))
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
