#!/usr/bin/env python3
"""Long-lived TCP/UDP endpoint used by the E_v4 StarryNet replay coordinator.

The coordinator sends a small line protocol over stdin.  Keeping the endpoint
alive for a whole StarryNet session avoids starting a container process for
every trace.  All timestamps are CLOCK_MONOTONIC timestamps so that the two
containers can use the same kernel clock domain.
"""

import argparse
import fcntl
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import termios
import time


MAGIC = b"EV4\0"
VERSION = 1
HEADER = struct.Struct("!4sBbHQQQ")
HEADER_BYTES = HEADER.size
DEFAULT_PAYLOAD_BYTES = 512
TCP_HELLO = struct.Struct("!4sQ")
_EMIT_LOCK = threading.Lock()


def decode_tcp_info(data):
    """Read the Linux UAPI prefix; absent kernel extensions stay unknown."""
    if len(data) < 8:
        raise ValueError("short Linux TCP_INFO header")
    result = {"available_bytes": len(data), "state": data[0],
              "ca_state": data[1], "retransmits": data[2],
              "probes": data[3], "backoff": data[4]}
    fields = (("rto_us", 8, "I"), ("rtt_us", 68, "I"),
              ("snd_mss_bytes", 16, "I"), ("unacked_segments", 24, "I"),
              ("lost_segments", 32, "I"), ("retrans_segments", 36, "I"),
              ("snd_cwnd_segments", 80, "I"), ("total_retrans", 100, "I"),
              ("bytes_acked", 120, "Q"), ("notsent_bytes", 144, "I"),
              ("rwnd_limited_us", 176, "Q"), ("sndbuf_limited_us", 184, "Q"),
              ("peer_snd_wnd_bytes", 228, "I"))
    for name, offset, kind in fields:
        result[name] = (struct.unpack_from("=" + kind, data, offset)[0]
                        if len(data) >= offset + struct.calcsize("=" + kind) else None)
    return result


class TCPStateSampler:
    """Read-only socket snapshots in a separate thread and JSONL file."""

    def __init__(self, connection, path, context, activity, interval=0.5):
        self.connection, self.path = connection, Path(path)
        self.context, self.activity = dict(context), activity
        if interval <= 0:
            raise ValueError("TCP state interval must be positive")
        self.interval = float(interval)
        self.stop_event = threading.Event()
        self.thread = None
        self.handle = None
        self.rows = self.tcp_info_rows = 0
        self.errors = []

    def snapshot(self, reason):
        row = dict(self.context, type="tcp_state", schema_version=1,
                   clock_domain="CLOCK_MONOTONIC", observed_ns=monotonic_ns(),
                   reason=reason, active_write=self.activity(), errors=[])
        row["tcp_info"] = None
        row["outq_bytes"] = None
        row["sndbuf_bytes"] = row["rcvbuf_bytes"] = None
        try:
            row["tcp_info"] = decode_tcp_info(self.connection.getsockopt(
                socket.IPPROTO_TCP, socket.TCP_INFO, 256))
            self.tcp_info_rows += 1
        except (OSError, ValueError, AttributeError) as exc:
            row["errors"].append("TCP_INFO: " + str(exc))
        try:
            # Linux SIOCOUTQ/TIOCOUTQ includes not-sent and not-ACKed bytes;
            # TCP_INFO.notsent_bytes, when available, separates the former.
            value = fcntl.ioctl(self.connection.fileno(), termios.TIOCOUTQ,
                                struct.pack("=I", 0))
            row["outq_bytes"] = struct.unpack("=I", value)[0]
        except OSError as exc:
            row["errors"].append("SIOCOUTQ: " + str(exc))
        try:
            row["sndbuf_bytes"] = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            row["rcvbuf_bytes"] = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except OSError as exc:
            row["errors"].append("socket buffers: " + str(exc))
        row["sampling_finished_ns"] = monotonic_ns()
        self.handle.write(json.dumps(row, sort_keys=True) + "\n")
        self.rows += 1
        for error in row["errors"]:
            if error not in self.errors:
                self.errors.append(error)

    def start(self):
        try:
            self.handle = self.path.open("a", encoding="utf-8", buffering=1)
            self.snapshot("start")
        except (OSError, ValueError) as exc:
            self.errors.append(str(exc))
            if self.handle:
                self.handle.close()
                self.handle = None
            return

        def sample():
            try:
                while not self.stop_event.wait(self.interval):
                    self.snapshot("periodic")
            except (OSError, ValueError) as exc:
                self.errors.append(str(exc))
        self.thread = threading.Thread(target=sample, name="tcp-state", daemon=True)
        self.thread.start()

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.thread and self.thread.is_alive():
            self.errors.append("TCP state sampler did not stop")
        elif self.handle:
            try:
                self.snapshot("final")
            except (OSError, ValueError) as exc:
                self.errors.append(str(exc))
            self.handle.close()
            self.handle = None
        return {"rows": self.rows, "tcp_info_rows": self.tcp_info_rows,
                "errors": list(self.errors)}


def monotonic_ns():
    """Return a monotonic clock in nanoseconds on old container Pythons too."""
    native = getattr(time, "monotonic_ns", None)
    if native is not None:
        return native()
    return int(time.monotonic() * 1000000000)


def emit(value):
    with _EMIT_LOCK:
        sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()


class RouteMonitor:
    """Observe kernel changes without waiting for or modifying routing."""

    def __init__(self, role, peer):
        self.role = role
        self.peer = peer
        self.process = None
        self.thread = None
        self.stop_requested = threading.Event()

    def record(self, kind, **fields):
        fields.update(type=kind, role=self.role, peer=self.peer,
                      observed_ns=monotonic_ns(), clock_domain="CLOCK_MONOTONIC")
        emit(fields)

    def start(self):
        try:
            self.process = subprocess.Popen(
                ["ip", "monitor", "route", "link"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, bufsize=1)
        except OSError as exc:
            self.record("route_monitor_error", phase="start", error=str(exc))
            return
        self.record("route_monitor_started")
        self.thread = threading.Thread(target=self.read_changes, daemon=True)
        self.thread.start()
        for command in (["ip", "-4", "route", "show"], ["ip", "-o", "link", "show"]):
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, universal_newlines=True,
                                        timeout=3)
                self.record("route_snapshot", command=command, output=result.stdout,
                            returncode=result.returncode)
                if result.returncode:
                    self.record("route_monitor_error", phase="snapshot",
                                error=result.stderr, command=command)
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.record("route_monitor_error", phase="snapshot", error=str(exc),
                            command=command)

    def read_changes(self):
        for line in self.process.stdout:
            self.record("route_change", event=line.rstrip("\n"))
        returncode = self.process.wait()
        stderr = self.process.stderr.read()
        if stderr.strip() or not self.stop_requested.is_set():
            self.record("route_monitor_error", phase="stream", returncode=returncode,
                        error=stderr)

    def close(self):
        if self.process is None:
            return
        self.stop_requested.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.thread:
            self.thread.join(timeout=2)
        self.record("route_monitor_stopped", returncode=self.process.poll())
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()


def packet(sample_token, sequence, direction, offset_ns, payload_bytes):
    if payload_bytes < HEADER_BYTES:
        raise ValueError("payload_bytes is smaller than the E_v4 header")
    data = HEADER.pack(MAGIC, VERSION, int(direction), 0,
                       int(sample_token), int(sequence), int(offset_ns))
    return data + (b"\0" * (payload_bytes - len(data)))


def unpack(data):
    if len(data) < HEADER_BYTES:
        return None
    magic, version, direction, _reserved, token, sequence, offset_ns = HEADER.unpack(
        data[:HEADER_BYTES])
    if magic != MAGIC or version != VERSION or direction not in (-1, 1):
        return None
    return {"sample_token": token, "sequence": sequence,
            "direction": direction, "scheduled_offset_ns": offset_ns}


class Endpoint:
    def __init__(self, role, peer, listen_port, peer_port, payload_bytes, tail_seconds):
        if role not in ("client", "remote"):
            raise ValueError("role must be client or remote")
        self.role = role
        self.peer = peer
        self.listen_port = int(listen_port)
        self.peer_port = int(peer_port)
        self.payload_bytes = int(payload_bytes)
        self.tail_seconds = float(tail_seconds)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4194304)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
        self.sock.bind(("0.0.0.0", self.listen_port))

    def receive_until(self, sample_token, stop_ns, records, errors):
        self.sock.settimeout(0.2)
        while monotonic_ns() < stop_ns:
            try:
                data, address = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                errors.append(str(exc))
                break
            observed_ns = monotonic_ns()
            value = unpack(data)
            if value is None or value["sample_token"] != sample_token:
                continue
            records.append({
                "action": "recv",
                "observed_ns": observed_ns,
                "sequence": value["sequence"],
                "direction": value["direction"],
                "scheduled_offset_ns": value["scheduled_offset_ns"],
                "bytes": len(data),
                "peer": address[0],
            })

    def run_sample(self, sample_id, sample_token, start_ns, events):
        records = []
        errors = []
        receiver_stop_ns = start_ns
        if events:
            receiver_stop_ns = start_ns + max(int(e["offset_ns"]) for e in events)
        receiver_stop_ns += int(self.tail_seconds * 1e9)
        receiver = threading.Thread(
            target=self.receive_until,
            args=(sample_token, receiver_stop_ns, records, errors),
            daemon=True,
        )
        receiver.start()
        send_errors = []
        try:
            for event in events:
                offset_ns = int(event["offset_ns"])
                target_ns = int(start_ns) + offset_ns
                while True:
                    remaining = target_ns - monotonic_ns()
                    if remaining <= 0:
                        break
                    time.sleep(min(remaining / 1e9, 0.01))
                direction = int(event["direction"])
                should_send = ((self.role == "client" and direction == 1) or
                               (self.role == "remote" and direction == -1))
                if not should_send:
                    continue
                try:
                    data = packet(sample_token, int(event["sequence"]),
                                  direction, offset_ns, self.payload_bytes)
                    observed_ns = monotonic_ns()
                    self.sock.sendto(data, (self.peer, self.peer_port))
                    records.append({
                        "action": "send",
                        "observed_ns": observed_ns,
                        "sequence": int(event["sequence"]),
                        "direction": direction,
                        "scheduled_offset_ns": offset_ns,
                        "bytes": len(data),
                        "peer": self.peer,
                    })
                except OSError as exc:
                    send_errors.append({"sequence": int(event["sequence"]),
                                        "observed_ns": monotonic_ns(),
                                        "scheduled_offset_ns": offset_ns,
                                        "clock_domain": "CLOCK_MONOTONIC",
                                        "error": str(exc)})
            while monotonic_ns() < receiver_stop_ns:
                time.sleep(0.01)
        finally:
            receiver.join(timeout=max(1.0, self.tail_seconds + 1.0))
        for value in records:
            value["sample_id"] = sample_id
            value["sample_token"] = sample_token
        emit({"type": "sample_done", "sample_id": sample_id,
              "role": self.role, "records": records,
              "receive_errors": errors, "send_errors": send_errors,
              "finished_ns": monotonic_ns()})

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TCPEndpoint:
    """One full-duplex connection per sample, with fixed-size application frames.

    Bind the client to its stable ground-station address, not an address on a
    satellite interface that disappears during handover. An ephemeral client
    port avoids reusing a recently closed TCP four-tuple between samples.
    """

    def __init__(self, role, peer, listen_port, peer_port, payload_bytes,
                 bind_address="0.0.0.0", completion_timeout=30.0, connect_timeout=30.0,
                 state_log_path=None, state_interval=0.5):
        if role not in ("client", "remote") or payload_bytes < HEADER_BYTES:
            raise ValueError("invalid TCP endpoint role or frame size")
        if completion_timeout <= 0 or connect_timeout <= 0:
            raise ValueError("TCP timeouts must be positive")
        self.role, self.peer = role, peer
        self.listen_port, self.peer_port = int(listen_port), int(peer_port)
        self.payload_bytes = int(payload_bytes)
        self.bind_address = bind_address
        self.completion_timeout = float(completion_timeout)
        self.connect_timeout = float(connect_timeout)
        self.listener = self.connection = None
        self.prepared_token = None
        self.state_log_path, self.state_interval = state_log_path, float(state_interval)
        self.active_write = None
        if self.state_interval <= 0:
            raise ValueError("TCP state interval must be positive")
        if state_log_path:
            Path(state_log_path).parent.mkdir(parents=True, exist_ok=True)
            Path(state_log_path).touch(exist_ok=False)
        if role == "remote":
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((bind_address, self.listen_port))
            self.listener.listen(1)

    @staticmethod
    def read_exact(connection, size, deadline_ns):
        data = bytearray()
        while len(data) < size:
            remaining = (deadline_ns - monotonic_ns()) / 1e9
            if remaining <= 0:
                raise TimeoutError("TCP handshake deadline exceeded")
            connection.settimeout(remaining)
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise ConnectionError("TCP peer closed during handshake")
            data.extend(chunk)
        return bytes(data)

    def prepare_sample(self, token):
        self.close_connection()
        deadline_ns = monotonic_ns() + int(self.connect_timeout * 1e9)
        stage = "accept" if self.role == "remote" else "connect"
        started_ns = monotonic_ns()
        emit({"type": "tcp_prepare_started", "role": self.role,
              "sample_token": token, "stage": stage,
              "peer": self.peer, "bind_address": self.bind_address,
              "observed_ns": started_ns})
        try:
            if self.role == "remote":
                self.listener.settimeout(self.connect_timeout)
                self.connection, address = self.listener.accept()
                if address[0] != self.peer:
                    raise ConnectionError("unexpected TCP peer: " + address[0])
            else:
                self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connection.bind((self.bind_address, 0))
                self.connection.settimeout(self.connect_timeout)
                self.connection.connect((self.peer, self.peer_port))
            connection = self.connection
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4194304)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4194304)
            hello = TCP_HELLO.pack(b"EV4T", token)
            stage = "token_handshake"
            connection.settimeout(max(0.001, (deadline_ns - monotonic_ns()) / 1e9))
            if self.role == "client":
                connection.sendall(hello)
            received = self.read_exact(connection, TCP_HELLO.size, deadline_ns)
            if received != hello:
                raise ConnectionError("TCP sample token mismatch")
            if self.role == "remote":
                connection.sendall(hello)
            connection.setblocking(False)
            self.prepared_token = token
        except BaseException as exc:
            exc.tcp_stage = stage
            try:
                local_address = self.connection.getsockname() if self.connection else None
            except OSError:
                local_address = None
            emit({"type": "tcp_prepare_failed", "role": self.role,
                  "sample_token": token, "stage": stage,
                  "peer": self.peer, "local_address": local_address,
                  "observed_ns": monotonic_ns(), "started_ns": started_ns,
                  "error_type": type(exc).__name__, "error": str(exc)})
            self.close_connection()
            raise

    def receive_frames(self, token, expected, deadline_ns, records, errors, aborted):
        connection = self.connection
        buffer = bytearray()
        received = set()
        try:
            while monotonic_ns() < deadline_ns:
                readable, _, _ = select.select([connection], [], [], min(
                    0.2, max(0.0, (deadline_ns - monotonic_ns()) / 1e9)))
                if not readable:
                    continue
                try:
                    chunk = connection.recv(65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    if buffer or received != set(expected):
                        raise ConnectionError("TCP EOF with partial frame or missing events")
                    return
                buffer.extend(chunk)
                while len(buffer) >= self.payload_bytes:
                    frame = bytes(buffer[:self.payload_bytes])
                    del buffer[:self.payload_bytes]
                    value = unpack(frame)
                    if (value is None or value["sample_token"] != token or
                            value["sequence"] not in expected or
                            value["sequence"] in received or
                            (value["direction"], value["scheduled_offset_ns"]) !=
                            expected[value["sequence"]]):
                        raise ConnectionError("invalid or duplicate TCP application frame")
                    received.add(value["sequence"])
                    records.append(dict(value, action="recv", observed_ns=monotonic_ns(),
                                        bytes=self.payload_bytes, peer=self.peer))
            raise TimeoutError("TCP receive deadline exceeded before complete EOF")
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
            aborted.set()

    def send_frame(self, data, deadline_ns, aborted):
        submitted = 0
        try:
            while submitted < len(data):
                remaining = (deadline_ns - monotonic_ns()) / 1e9
                if remaining <= 0:
                    raise TimeoutError("TCP send deadline exceeded")
                if aborted.is_set():
                    raise ConnectionError("TCP receive stream failed")
                _, writable, _ = select.select([], [self.connection], [], min(0.2, remaining))
                if not writable:
                    continue
                try:
                    count = self.connection.send(data[submitted:])
                except BlockingIOError:
                    continue
                if count == 0:
                    raise ConnectionError("TCP send returned zero")
                submitted += count
                if getattr(self, "active_write", None) is not None:
                    self.active_write = dict(self.active_write, bytes_submitted=submitted)
        except OSError as exc:
            exc.bytes_submitted = submitted
            raise

    def run_sample(self, sample_id, sample_token, start_ns, events):
        if self.connection is None or self.prepared_token != sample_token:
            raise RuntimeError("TCP sample was not prepared")
        outgoing_direction = 1 if self.role == "client" else -1
        outgoing = [x for x in events if int(x["direction"]) == outgoing_direction]
        expected = {int(x["sequence"]): (int(x["direction"]), int(x["offset_ns"]))
                    for x in events if int(x["direction"]) != outgoing_direction}
        deadline_ns = start_ns + max((int(x["offset_ns"]) for x in events), default=0)
        deadline_ns += int(self.completion_timeout * 1e9)
        records, errors, send_errors = [], [], []
        aborted = threading.Event()
        receiver = threading.Thread(target=self.receive_frames, args=(
            sample_token, expected, deadline_ns, records, errors, aborted), daemon=True)
        sampler = None
        state_summary = None
        if self.state_log_path:
            sampler = TCPStateSampler(self.connection, self.state_log_path,
                {"sample_id": sample_id, "sample_token": sample_token, "role": self.role,
                 "sample_start_ns": start_ns, "completion_deadline_ns": deadline_ns,
                 "local_address": self.connection.getsockname(),
                 "peer_address": self.connection.getpeername()},
                lambda: self.active_write, self.state_interval)
            sampler.start()
        receiver.start()
        try:
            for index, event in enumerate(outgoing):
                submitted = 0
                try:
                    target_ns = start_ns + int(event["offset_ns"])
                    while monotonic_ns() < target_ns:
                        if aborted.is_set():
                            raise ConnectionError("TCP receive stream failed")
                        time.sleep(max(0.0, min((target_ns - monotonic_ns()) / 1e9, 0.01)))
                    data = packet(sample_token, int(event["sequence"]), outgoing_direction,
                                  int(event["offset_ns"]), self.payload_bytes)
                    observed_ns = monotonic_ns()
                    self.active_write = {"sequence": int(event["sequence"]),
                                         "scheduled_offset_ns": int(event["offset_ns"]),
                                         "write_started_ns": observed_ns, "bytes_submitted": 0}
                    self.send_frame(data, deadline_ns, aborted)
                    records.append({"action": "send", "direction": outgoing_direction,
                                    "sequence": int(event["sequence"]), "observed_ns": observed_ns,
                                    "send_completed_ns": monotonic_ns(),
                                    "scheduled_offset_ns": int(event["offset_ns"]),
                                    "bytes": self.payload_bytes, "peer": self.peer})
                    self.active_write = None
                except OSError as exc:
                    submitted = getattr(exc, "bytes_submitted", 0)
                    for remaining in outgoing[index:]:
                        send_errors.append({"sequence": int(remaining["sequence"]),
                                            "observed_ns": monotonic_ns(),
                                            "scheduled_offset_ns": int(remaining["offset_ns"]),
                                            "clock_domain": "CLOCK_MONOTONIC", "error": str(exc),
                                            "bytes_submitted": submitted})
                        submitted = 0
                    break
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except OSError as exc:
                errors.append(str(exc))
            receiver.join(timeout=max(0.0, (deadline_ns - monotonic_ns()) / 1e9) + 0.5)
        finally:
            if sampler:
                state_summary = sampler.close()
            self.active_write = None
            self.close_connection()
            receiver.join(timeout=1.0)
        if receiver.is_alive():
            raise RuntimeError("TCP receiver failed to stop")
        for value in records:
            value.update(sample_id=sample_id, sample_token=sample_token)
        emit({"type": "sample_done", "sample_id": sample_id, "role": self.role,
              "transport": "tcp", "records": records, "receive_errors": errors,
              "send_errors": send_errors, "finished_ns": monotonic_ns(),
              "tcp_state_summary": state_summary,
              "completion_deadline_ns": deadline_ns})

    def close_connection(self):
        if self.connection is not None:
            try:
                self.connection.close()
            finally:
                self.connection = None
                self.prepared_token = None

    def close(self):
        self.close_connection()
        if self.listener is not None:
            self.listener.close()
            self.listener = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("client", "remote"), required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--listen-port", type=int, default=19999)
    parser.add_argument("--peer-port", type=int)
    parser.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    parser.add_argument("--tail-seconds", type=float, default=5.0)
    parser.add_argument("--transport", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--bind-address", default="0.0.0.0")
    parser.add_argument("--tcp-completion-timeout", type=float, default=30.0)
    parser.add_argument("--tcp-connect-timeout", type=float, default=30.0)
    parser.add_argument("--tcp-state-log")
    parser.add_argument("--tcp-state-interval", type=float, default=0.5)
    args = parser.parse_args()
    if args.peer_port is None:
        args.peer_port = args.listen_port
    endpoint = (TCPEndpoint(args.role, args.peer, args.listen_port, args.peer_port,
                           args.payload_bytes, args.bind_address,
                           args.tcp_completion_timeout, args.tcp_connect_timeout,
                           args.tcp_state_log, args.tcp_state_interval)
                if args.transport == "tcp" else
                Endpoint(args.role, args.peer, args.listen_port,
                         args.peer_port, args.payload_bytes, args.tail_seconds))
    route_monitor = RouteMonitor(args.role, args.peer)
    try:
        route_monitor.start()
        emit({"type": "ready", "role": args.role,
              "monotonic_ns": monotonic_ns(),
              "listen_port": ((endpoint.listener.getsockname()[1] if args.role == "remote"
                               else None) if args.transport == "tcp" else args.listen_port),
              "bind_address": args.bind_address,
              "payload_bytes": args.payload_bytes, "transport": args.transport})
        begin = None
        events = []
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            command = json.loads(line)
            operation = command.get("op")
            if operation == "begin":
                if begin is not None:
                    raise RuntimeError("received begin before completing sample")
                begin = command
                events = []
            elif operation == "event":
                if begin is None:
                    raise RuntimeError("event received outside a sample")
                events.append({"sequence": int(command["sequence"]),
                               "direction": int(command["direction"]),
                               "offset_ns": int(command["offset_ns"])})
            elif operation == "end":
                if begin is None or begin.get("sample_id") != command.get("sample_id"):
                    raise RuntimeError("end does not match current sample")
                if args.transport == "tcp":
                    endpoint.prepare_sample(int(begin["sample_token"]))
                # Event transfer is complete, but the coordinator has not
                # necessarily prepared the peer endpoint yet.  Retain the
                # event list and acknowledge preparation; the separate
                # ``start`` operation supplies the common monotonic origin.
                prepared = {"type": "prepared", "role": args.role,
                            "sample_id": begin["sample_id"],
                            "event_count": len(events), "transport": args.transport}
                if args.transport == "tcp":
                    prepared["local_address"] = endpoint.connection.getsockname()
                    prepared["peer_address"] = endpoint.connection.getpeername()
                emit(prepared)
            elif operation == "start":
                if begin is None or begin.get("sample_id") != command.get("sample_id"):
                    raise RuntimeError("start does not match prepared sample")
                start_ns = int(command["start_ns"])
                if monotonic_ns() >= start_ns:
                    raise RuntimeError("sample start deadline passed before start command")
                endpoint.run_sample(begin["sample_id"], int(begin["sample_token"]),
                                    start_ns, events)
                begin = None
                events = []
            elif operation == "stop":
                break
            else:
                raise RuntimeError("unknown operation: " + str(operation))
    except BaseException as exc:
        emit({"type": "agent_error", "role": args.role,
              "error": ("TCP " + args.role + "/" + exc.tcp_stage + ": " + str(exc)
                        if hasattr(exc, "tcp_stage") else str(exc))})
        return 1
    finally:
        try:
            route_monitor.close()
        finally:
            endpoint.close()
    emit({"type": "stopped", "role": args.role})
    return 0


if __name__ == "__main__":
    sys.exit(main())
