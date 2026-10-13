#!/usr/bin/env python3
"""Control one pinned Tor circuit and serve local visit requests over a Unix socket."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

CircStatus = Controller = EventType = None


def write_json(path, value):
    target = Path(path)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(target)


def route_to(host):
    try:
        return subprocess.check_output(["ip", "route", "get", host],
                                       text=True, timeout=5).strip()
    except Exception as exc:
        return "route lookup failed: " + str(exc)


def run_agent(args):
    global CircStatus, Controller, EventType
    try:
        from stem import CircStatus as stem_circ_status
        from stem.control import Controller as stem_controller
        from stem.control import EventType as stem_event_type
    except ImportError as exc:
        raise RuntimeError("python3-stem is required: " + str(exc))
    CircStatus = stem_circ_status
    Controller = stem_controller
    EventType = stem_event_type
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    socket_path = root / "agent.sock"
    if socket_path.exists():
        socket_path.unlink()
    event_log = (root / "controller_events.jsonl").open("a", buffering=1)
    controller = Controller.from_port(port=args.control_port)
    controller.authenticate()

    bootstrap_deadline = time.monotonic() + args.bootstrap_timeout
    bootstrap_text = ""
    while time.monotonic() < bootstrap_deadline:
        bootstrap_text = controller.get_info("status/bootstrap-phase", "")
        if "PROGRESS=100" in bootstrap_text:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError("Tor client bootstrap timed out: " + bootstrap_text)

    def record_event(event):
        row = {"event": str(event), "wall_utc": time.time()}
        event_log.write(json.dumps(row, sort_keys=True) + "\n")

    def attach_page_stream(event):
        record_event(event)
        if (event.status == "NEW"
                and event.target_address == args.server_ip
                and str(event.target_port) == str(args.server_port)):
            try:
                controller.attach_stream(event.id, circuit_id)
            except Exception as exc:
                row = {"event": "ATTACH_FAILED", "stream_id": event.id,
                       "circuit_id": circuit_id, "error": str(exc),
                       "wall_utc": time.time()}
                event_log.write(json.dumps(row, sort_keys=True) + "\n")

    controller.add_event_listener(record_event, EventType.CIRC)
    controller.add_event_listener(attach_page_stream, EventType.STREAM)
    controller.set_conf("__LeaveStreamsUnattached", "1")
    path = [item.upper() for item in args.path.split(",") if item]
    if len(path) != 3:
        raise RuntimeError("The controlled Tor path must contain Guard, Middle, Exit")
    circuit_id = controller.new_circuit(path, await_build=True,
                                        timeout=args.circuit_timeout)
    circuit = controller.get_circuit(circuit_id)
    write_json(root / "circuit_initial.json", {
        "bootstrap": bootstrap_text,
        "circuit_id": circuit_id,
        "status": str(circuit.status),
        "requested_fingerprints": path,
        "actual_path": circuit.path,
        "created_at": str(circuit.created),
    })
    write_json(args.ready_file, {"ready": True, "circuit_id": circuit_id,
                                 "status": str(circuit.status),
                                 "path": circuit.path,
                                 "requested_fingerprints": path})

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    server.listen(8)
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                request = b""
                while not request.endswith(b"\n"):
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                message = {}
                try:
                    message = json.loads(request.decode("utf-8"))
                    if message.get("command") == "stop":
                        connection.sendall(b'{"stopped":true}\n')
                        break
                    if message.get("command") != "visit":
                        raise ValueError("Unknown agent command")
                    circuit_id, result = visit(controller, circuit_id, path,
                                               args, message)
                except Exception as exc:
                    result = {"ok": False, "error": str(exc)}
                    if message.get("command") == "visit" and message.get("label"):
                        result["label"] = str(message["label"])
                        result["wall_utc"] = time.time()
                        write_json(root / (result["label"] + ".json"), result)
                connection.sendall((json.dumps(result, sort_keys=True) + "\n").encode())
    finally:
        try:
            controller.reset_conf("__LeaveStreamsUnattached")
        except Exception:
            pass
        controller.close()
        event_log.close()
        server.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def visit(controller, circuit_id, path, args, message):
    label = str(message["label"])
    root = Path(args.root)
    output = root / (label + ".html")
    curl_log = root / (label + ".curl.txt")
    result_path = root / (label + ".json")
    rebuilt = False
    circuit = None
    try:
        circuit = controller.get_circuit(circuit_id)
    except Exception:
        circuit = None
    if circuit is None or circuit.status != CircStatus.BUILT:
        circuit_id = controller.new_circuit(path, await_build=True,
                                            timeout=args.circuit_timeout)
        rebuilt = True
        circuit = controller.get_circuit(circuit_id)

    url = "http://{0}:{1}/{2}".format(args.server_ip, args.server_port,
                                        args.object_name)
    write_out = "http_code=%{http_code}\\nsize_download=%{size_download}\\ntime_total=%{time_total}\\nremote_ip=%{remote_ip}"
    command = ["curl", "--noproxy", "", "--socks5-hostname",
               "127.0.0.1:{0}".format(args.socks_port), "--http1.1",
               "--connect-timeout", "10", "--max-time", "60", "-sS",
               "-o", str(output), "-w", write_out, url]
    start = time.monotonic()
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=70)
    elapsed = time.monotonic() - start
    curl_log.write_text(completed.stdout)
    metrics = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            metrics[key] = value
    current = controller.get_circuit(circuit_id)
    result = {
        "label": label,
        "ok": completed.returncode == 0 and metrics.get("http_code") == "200",
        "curl_exit_code": completed.returncode,
        "curl_metrics": metrics,
        "wall_seconds": round(elapsed, 6),
        "route_to_guard": route_to(args.guard_ip),
        "circuit_id": circuit_id,
        "circuit_rebuilt_before_visit": rebuilt,
        "circuit_status_after_visit": str(current.status),
        "requested_fingerprints": path,
        "actual_path": current.path,
        "object_bytes": output.stat().st_size if output.exists() else None,
    }
    if output.exists():
        import hashlib
        result["object_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    if completed.returncode:
        result["curl_error"] = completed.stdout
    write_json(result_path, result)
    return circuit_id, result


def request_visit(args):
    request = {"command": "visit", "label": args.label}
    return request_agent(args.socket, request)


def request_agent(socket_path, request):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(75)
    client.connect(socket_path)
    client.sendall((json.dumps(request) + "\n").encode())
    response = b""
    while not response.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        response += chunk
    client.close()
    return json.loads(response.decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--root", required=True)
    serve.add_argument("--control-port", type=int, default=9051)
    serve.add_argument("--socks-port", type=int, default=9050)
    serve.add_argument("--bootstrap-timeout", type=int, default=180)
    serve.add_argument("--circuit-timeout", type=int, default=120)
    serve.add_argument("--guard-ip", required=True)
    serve.add_argument("--server-ip", required=True)
    serve.add_argument("--server-port", type=int, required=True)
    serve.add_argument("--object-name", required=True)
    serve.add_argument("--path", required=True)
    serve.add_argument("--ready-file", required=True)
    visit_parser = subparsers.add_parser("visit")
    visit_parser.add_argument("--socket", required=True)
    visit_parser.add_argument("--label", required=True)
    stop = subparsers.add_parser("stop")
    stop.add_argument("--socket", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        run_agent(args)
        return
    if args.command == "visit":
        print(json.dumps(request_visit(args), sort_keys=True))
        return
    print(json.dumps(request_agent(args.socket, {"command": "stop"})))


if __name__ == "__main__":
    main()
