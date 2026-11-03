#!/usr/bin/env python3
"""Long-lived UDP endpoint used by the E_v4 StarryNet replay coordinator.

The coordinator sends a small line protocol over stdin.  Keeping the endpoint
alive for a whole StarryNet session avoids starting a container process for
every trace.  All timestamps are CLOCK_MONOTONIC timestamps so that the two
containers can use the same kernel clock domain.
"""

import argparse
import json
import socket
import struct
import sys
import threading
import time


MAGIC = b"EV4\0"
VERSION = 1
HEADER = struct.Struct("!4sBbHQQQ")
HEADER_BYTES = HEADER.size
DEFAULT_PAYLOAD_BYTES = 512


def monotonic_ns():
    """Return a monotonic clock in nanoseconds on old container Pythons too."""
    native = getattr(time, "monotonic_ns", None)
    if native is not None:
        return native()
    return int(time.monotonic() * 1000000000)


def emit(value):
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("client", "remote"), required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--listen-port", type=int, default=19999)
    parser.add_argument("--peer-port", type=int)
    parser.add_argument("--payload-bytes", type=int, default=DEFAULT_PAYLOAD_BYTES)
    parser.add_argument("--tail-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if args.peer_port is None:
        args.peer_port = args.listen_port
    endpoint = Endpoint(args.role, args.peer, args.listen_port,
                        args.peer_port, args.payload_bytes, args.tail_seconds)
    emit({"type": "ready", "role": args.role,
          "monotonic_ns": monotonic_ns(),
          "listen_port": args.listen_port,
          "payload_bytes": args.payload_bytes})
    try:
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
                # Event transfer is complete, but the coordinator has not
                # necessarily prepared the peer endpoint yet.  Retain the
                # event list and acknowledge preparation; the separate
                # ``start`` operation supplies the common monotonic origin.
                emit({"type": "prepared", "role": args.role,
                      "sample_id": begin["sample_id"],
                      "event_count": len(events)})
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
              "error": str(exc)})
        return 1
    finally:
        endpoint.close()
    emit({"type": "stopped", "role": args.role})
    return 0


if __name__ == "__main__":
    sys.exit(main())
