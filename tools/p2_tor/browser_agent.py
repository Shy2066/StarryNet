#!/usr/bin/env python3
"""Run one isolated Firefox page visit through the local Tor SOCKS proxy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import uuid


class Marionette:
    def __init__(self, sock):
        self.sock = sock
        self.next_id = 0
        # Firefox 153 advertises Marionette protocol 3.  Older Firefox
        # releases used the compact [id, command, params] packet; keep the
        # fallback so the collector remains usable with the project's older
        # pinned browser images.
        self.protocol_version = 2

    def set_protocol_from_greeting(self, greeting):
        self.protocol_version = int(greeting.get("marionetteProtocol", 2))

    def _read_exact(self, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise RuntimeError("Firefox Marionette closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read_message(self):
        digits = bytearray()
        while True:
            char = self._read_exact(1)
            if char == b":":
                break
            if char < b"0" or char > b"9" or len(digits) > 8:
                raise RuntimeError("Invalid Firefox Marionette frame header")
            digits.extend(char)
        if not digits:
            raise RuntimeError("Empty Firefox Marionette frame length")
        length = int(digits.decode("ascii"))
        if length <= 0 or length > 16 * 1024 * 1024:
            raise RuntimeError("Unexpected Firefox Marionette frame size")
        return json.loads(self._read_exact(length).decode("utf-8"))

    def send(self, value):
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.sock.sendall(str(len(payload)).encode("ascii") + b":" + payload)

    def command(self, name, params=None, timeout=70):
        self.next_id += 1
        request_id = self.next_id
        if self.protocol_version >= 3:
            self.send([0, request_id, name, params or {}])
        else:
            self.send([request_id, name, params or {}])
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.monotonic()))
            message = self.read_message()
            if not isinstance(message, list):
                continue
            if self.protocol_version >= 3:
                if len(message) < 2 or message[0] != 1 or message[1] != request_id:
                    continue
                if len(message) < 4:
                    raise RuntimeError("Malformed Firefox Marionette response")
                error = message[2]
                if error is not None:
                    raise RuntimeError("Firefox Marionette {0}: {1}".format(
                        error.get("error", "error"),
                        error.get("message", "unknown error")))
                return message[3]
            if message and message[0] == request_id:
                if len(message) < 3:
                    raise RuntimeError("Malformed Firefox Marionette response")
                if message[1] is not None:
                    raise RuntimeError("Firefox Marionette {0}: {1}".format(
                        message[1].get("error", "error"),
                        message[1].get("message", "unknown error")))
                return message[2]
        raise TimeoutError("Firefox Marionette command timed out: " + name)


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def request_agent(socket_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(socket_path)
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        response = bytearray()
        while not response.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        if not response:
            raise RuntimeError("Tor client agent returned an empty response")
        return json.loads(response.decode("utf-8"))


def browser_binary():
    for name in ("firefox-esr", "firefox"):
        found = shutil.which(name)
        if found:
            return found
    raise RuntimeError("Firefox ESR is not installed in the P2 image")


def run_visit(args):
    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    label = args.sample_id
    token = request_agent(args.agent_socket, {
        "command": "begin_visit", "label": label})
    if not token.get("started"):
        raise RuntimeError("Could not start Tor STREAM evidence collection")

    profile = root / ("profile-" + uuid.uuid4().hex)
    profile.mkdir()
    # The client container has a read-only root filesystem.  Firefox reads
    # HOME/XDG locations during startup (before it opens the profile), and a
    # read-only /root can leave it alive without ever opening Marionette.  Keep
    # all such runtime state inside this sample's writable output directory so
    # every attempt remains isolated and auditable.
    home_dir = root / "home"
    cache_dir = root / "cache"
    config_dir = root / "config"
    runtime_dir = root / "runtime"
    for directory in (home_dir, cache_dir, config_dir, runtime_dir):
        directory.mkdir(mode=0o700, exist_ok=True)
    prefs = [
        'user_pref("network.proxy.type", 1);',
        'user_pref("network.proxy.socks", "127.0.0.1");',
        'user_pref("network.proxy.socks_port", 9050);',
        'user_pref("network.proxy.socks_version", 5);',
        'user_pref("network.proxy.socks_remote_dns", true);',
        'user_pref("network.proxy.no_proxies_on", "");',
        'user_pref("network.proxy.failover_direct", false);',
        'user_pref("network.dns.disablePrefetch", true);',
        'user_pref("network.prefetch-next", false);',
        'user_pref("network.http.speculative-parallel-limit", 0);',
        'user_pref("browser.cache.disk.enable", false);',
        'user_pref("browser.cache.memory.enable", false);',
        'user_pref("marionette.port", 2828);',
    ]
    (profile / "user.js").write_text("\n".join(prefs) + "\n")
    firefox = browser_binary()
    version = subprocess.check_output([firefox, "--version"], text=True).strip()
    log_path = root / "firefox.log"
    process = None
    driver = None
    sock = None
    start = time.monotonic()
    failure = None
    page_result = None
    stream_evidence = None
    try:
        with log_path.open("wb") as log:
            firefox_env = {
                **os.environ,
                "MOZ_HEADLESS": "1",
                "HOME": str(home_dir),
                "XDG_CACHE_HOME": str(cache_dir),
                "XDG_CONFIG_HOME": str(config_dir),
                "XDG_RUNTIME_DIR": str(runtime_dir),
            }
            process = subprocess.Popen([firefox, "--headless", "--marionette",
                "--no-remote", "--profile", str(profile)], stdout=log,
                stderr=subprocess.STDOUT, env=firefox_env)
        deadline = time.monotonic() + 30
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Firefox exited before Marionette was ready")
            try:
                sock.connect(("127.0.0.1", 2828))
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("Firefox Marionette did not become ready")
        sock.settimeout(10)
        driver = Marionette(sock)
        greeting = driver.read_message()
        if not isinstance(greeting, dict) or greeting.get("applicationType") != "gecko":
            raise RuntimeError("Unexpected Firefox Marionette greeting")
        driver.set_protocol_from_greeting(greeting)
        session = driver.command("WebDriver:NewSession", {
            "capabilities": {"alwaysMatch": {
                "browserName": "firefox", "acceptInsecureCerts": True}}})
        page_result = driver.command("WebDriver:Navigate", {"url": args.url},
                                     timeout=args.timeout + 10)
        script = ("return {ready: document.readyState, title: document.title, "
            "marker: document.documentElement.dataset.pilotComplete || "
            "document.body.dataset.pilotComplete || '', "
            "images: Array.from(document.images).map(x => ({complete:x.complete, "
            "width:x.naturalWidth})), stylesheets: document.styleSheets.length, "
            "url: location.href};")
        page = None
        wait_deadline = time.monotonic() + args.timeout
        while time.monotonic() < wait_deadline:
            response = driver.command("WebDriver:ExecuteScript", {
                "script": script, "args": []}, timeout=15)
            page = response.get("value", response)
            images = page.get("images", []) if isinstance(page, dict) else []
            images_ready = len(images) >= args.expected_images and all(
                item.get("complete") and item.get("width", 0) > 0
                for item in images)
            marker_ready = page.get("marker") == args.expected_marker
            if (page.get("ready") == "complete" and marker_ready
                    and images_ready
                    and page.get("stylesheets", 0) >= args.minimum_stylesheets):
                break
            time.sleep(0.25)
        else:
            raise TimeoutError("Page load marker or required assets did not complete")
        if args.post_load_seconds:
            time.sleep(args.post_load_seconds)
        page_result = page
    except Exception as exc:
        failure = str(exc)
    finally:
        if driver is not None:
            try:
                driver.command("WebDriver:DeleteSession", {}, timeout=10)
            except Exception:
                pass
            try:
                driver.sock.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        try:
            stream_evidence = request_agent(args.agent_socket, {
                "command": "end_visit", "token": token["token"]})
        except Exception as exc:
            failure = failure or ("Could not close Tor STREAM evidence: " + str(exc))
        user_js = profile / "user.js"
        if user_js.is_file():
            shutil.copy2(user_js, root / "user.js")
        shutil.rmtree(profile, ignore_errors=True)

    stream_rows = (stream_evidence or {}).get("stream_events", [])
    successful_streams = [row for row in stream_rows
        if row.get("status") == "SUCCEEDED"
        and row.get("target_address") == args.server_ip
        and int(row.get("target_port", -1)) == args.server_port
        and str(row.get("circ_id")) == str(token.get("circuit_id"))]
    result = {
        "sample_id": label, "url": args.url, "browser": version,
        "firefox_profile_prefs_sha256": hashlib.sha256(
            (root / "user.js").read_bytes()).hexdigest(),
        "page": page_result, "expected_marker": args.expected_marker,
        "expected_images": args.expected_images,
        "tor_circuit_id": token.get("circuit_id"),
        "tor_stream_evidence": stream_evidence,
        "visit_started_epoch": (stream_evidence or {}).get("started_epoch"),
        "visit_ended_epoch": (stream_evidence or {}).get("ended_epoch"),
        "target_stream_succeeded_on_circuit": bool(successful_streams),
        "elapsed_seconds": round(time.monotonic() - start, 6),
        "ok": bool(not failure and page_result and successful_streams),
    }
    if failure:
        result["error"] = failure
    write_json(root / "result.json", result)
    print(json.dumps(result, sort_keys=True))
    if not result["ok"]:
        raise RuntimeError(failure or "Browser visit did not pass its evidence gates")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-socket", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--server-port", type=int, default=18080)
    parser.add_argument("--expected-marker", required=True)
    parser.add_argument("--expected-images", type=int, default=0)
    parser.add_argument("--minimum-stylesheets", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--post-load-seconds", type=int, default=5)
    parser.add_argument("--output-dir", required=True)
    run_visit(parser.parse_args())


if __name__ == "__main__":
    main()
