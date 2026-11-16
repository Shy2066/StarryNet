#!/usr/bin/env python3
"""Annotate existing E_v4 attempts offline; never rewrite run artifacts."""

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re


LINK = re.compile(r"^(Deleted )?(\d+): ([^:@ ]+)(?:@[^: ]+)?: <([^>]*)>")
SATELLITE_LINK = re.compile(r"^B(?:26|27)-eth\d+$")


def load_session(directory):
    summary = json.loads((directory / "summary.json").read_text())
    result = {"anchor_ns": summary["session_anchor_monotonic_ns"], "roles": {},
              "summary_sha256": hashlib.sha256((directory / "summary.json").read_bytes()).hexdigest()}
    for role in ("client", "remote"):
        path = directory / (role + "_agent.jsonl")
        try:
            rows = [(number, json.loads(line)) for number, line in
                    enumerate(path.read_text().splitlines(), 1) if line.strip()]
            rows = [(n, x) for n, x in rows if x.get("type", "").startswith("route_")]
            counts = Counter(x["type"] for _, x in rows)
            snapshots = [x for _, x in rows if x["type"] == "route_snapshot"]
            if (counts["route_monitor_started"] != 1 or
                    counts["route_monitor_stopped"] != 1 or
                    counts["route_monitor_error"] or len(snapshots) != 2 or
                    any(x.get("returncode") != 0 for x in snapshots) or
                    any(x.get("clock_domain") != "CLOCK_MONOTONIC" or
                        type(x.get("observed_ns")) is not int for _, x in rows)):
                raise ValueError("monitor lifecycle, snapshots or clock evidence incomplete")
            route_snapshot = next(x for x in snapshots if
                                  x["command"] == ["ip", "-4", "route", "show"])
            link_snapshot = next(x for x in snapshots if
                                 x["command"] == ["ip", "-o", "link", "show"])
            monitor_start = next(x["observed_ns"] for _, x in rows
                                 if x["type"] == "route_monitor_started")
            monitor_end = next(x["observed_ns"] for _, x in rows
                               if x["type"] == "route_monitor_stopped")
            if monitor_end < monitor_start:
                raise ValueError("monitor stop precedes start")
            prefix = str(ipaddress.ip_network(route_snapshot["peer"] + "/24", strict=False))
            active = {}
            for line in link_snapshot["output"].splitlines():
                match = LINK.match(line)
                if match and SATELLITE_LINK.match(match[3]):
                    active[match[2]] = {"UP", "LOWER_UP"}.issubset(match[4].split(","))
            if not active:
                raise ValueError("initial satellite interface state unavailable")
            events, intervals, unparsed = [], [], 0
            route_gap = access_gap = None
            for number, row in sorted(rows, key=lambda item: item[1]["observed_ns"]):
                if row["type"] != "route_change":
                    continue
                raw = row["event"].strip()
                event = {"role": role, "observed_ns": row["observed_ns"],
                         "log_path": str(path), "line": number, "raw": raw}
                tokens = raw.split()
                deleted = tokens[:1] == ["Deleted"]
                route = tokens[1:] if deleted else tokens
                if route[:1] == ["default"]:
                    event["kind"] = "default_route_deleted" if deleted else "default_route_added"
                    events.append(event)
                if route[:1] == [prefix]:
                    event["kind"] = "peer_route_deleted" if deleted else "peer_route_added"
                    events.append(event)
                    if deleted and route_gap is None:
                        route_gap = {"kind": "peer_route_gap", "start": event, "end": None}
                        intervals.append(route_gap)
                    elif not deleted and route_gap is not None:
                        route_gap["end"] = event
                        route_gap = None
                match = LINK.match(raw)
                if match and (match[2] in active or SATELLITE_LINK.match(match[3])):
                    was_up = any(active.values())
                    up = not match[1] and {"UP", "LOWER_UP"}.issubset(match[4].split(","))
                    active[match[2]] = up
                    event["kind"] = "satellite_link_up" if up else "satellite_link_down"
                    events.append(event)
                    if was_up and not any(active.values()):
                        access_gap = {"kind": "access_link_gap", "start": event, "end": None}
                        intervals.append(access_gap)
                    elif any(active.values()) and access_gap is not None:
                        access_gap["end"] = event
                        access_gap = None
                if raw.startswith("Unknown message:"):
                    unparsed += 1
            result["roles"][role] = {
                "available": True, "events": events, "intervals": intervals,
                "monitor_start_ns": monitor_start, "monitor_end_ns": monitor_end,
                "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "unparsed_change_count": unparsed,
            }
        except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
            result["roles"][role] = {"available": False, "reason": str(exc)}
    return result


def annotate(evidence, session):
    result = {"sample_id": evidence["sample_id"],
              "session_id": evidence["session_id"], "attempt_id": evidence["attempt_id"],
              "original_status": evidence["status"],
              "planned_handover_count": evidence.get("handover_count"),
              "actual_event_count": None, "related_events": [],
              "related_intervals": [], "anomaly_labels": ["unknown"]}
    if session is None:
        result["diagnostic_status"] = "unavailable"
        return result
    result["monitor_health"] = {role: {k: v for k, v in data.items()
                                      if k not in ("events", "intervals")}
                                for role, data in session["roles"].items()}
    result["session_summary_sha256"] = session["summary_sha256"]
    start = evidence.get("simulation_start_second")
    end = evidence.get("simulation_end_second")
    if start is None or end is None:
        result["diagnostic_status"] = "unavailable"
        return result
    anchor = session["anchor_ns"]
    first, last = anchor + int(start * 1e9), anchor + int(end * 1e9)
    # Include recorded packet/error observations when execution ran late.
    for role in ("client", "remote"):
        observations = evidence.get(role + "_records", []) + [
            x for x in evidence.get(role + "_send_errors", [])
            if x.get("clock_domain") == "CLOCK_MONOTONIC"]
        for row in observations:
            if type(row.get("observed_ns")) is int:
                first, last = min(first, row["observed_ns"]), max(last, row["observed_ns"])
    result["observation_window_ns"] = [first, last]
    healthy = all(x["available"] and x["monitor_start_ns"] <= first and
                  last <= x["monitor_end_ns"] for x in session["roles"].values())
    result["diagnostic_status"] = "available" if healthy else "unavailable"
    if not healthy:
        return result
    labels = set()
    for role, data in session["roles"].items():
        result["related_events"].extend(x for x in data["events"]
                                        if first <= x["observed_ns"] <= last)
        errors = [x for x in evidence.get(role + "_send_errors", [])
                  if type(x.get("observed_ns")) is int and
                  x.get("clock_domain") == "CLOCK_MONOTONIC" and
                  ("[Errno 101]" in x.get("error", "") or
                   "Network is unreachable" in x.get("error", ""))]
        for interval in data["intervals"]:
            begin = interval["start"]["observed_ns"]
            finish = (interval["end"]["observed_ns"] if interval["end"] else
                      data["monitor_end_ns"])
            if begin > last or finish < first:
                continue
            matched = [x["observed_ns"] for x in errors if begin <= x["observed_ns"] <= finish]
            related = dict(interval, role=role, unreachable_error_count=len(matched))
            related["first_unreachable_error_ns"] = min(matched) if matched else None
            related["last_unreachable_error_ns"] = max(matched) if matched else None
            result["related_intervals"].append(related)
            if matched:
                if interval["kind"] == "access_link_gap":
                    labels.add("access_link_interruption")
                elif interval["end"] is not None:
                    labels.add("route_convergence_gap")
                else:
                    labels.add("peer_route_unavailable")
    result["related_events"].sort(key=lambda x: x["observed_ns"])
    result["actual_event_count"] = len(result["related_events"])
    result["anomaly_labels"] = sorted(labels) if labels else (
        ["unknown"] if evidence["status"] != "success" else [])
    return result


def diagnose(run_root):
    sessions, attempts = {}, []
    for path in sorted(run_root.glob("samples/*/attempts/*/evidence.json")):
        evidence = json.loads(path.read_text())
        sid = evidence["session_id"]
        if sid == "preflight":
            continue
        if sid not in sessions:
            try:
                sessions[sid] = load_session(run_root / "sessions" / sid)
            except (OSError, ValueError, KeyError):
                sessions[sid] = None
        row = annotate(evidence, sessions[sid])
        row["evidence_path"] = str(path)
        row["evidence_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        attempts.append(row)
    if not attempts:
        raise ValueError("no replay attempt evidence found")
    return {"schema_version": 1, "run_root": str(run_root),
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "interpretation": "Labels are temporal evidence associations, not per-packet causal proof. "
            "actual_event_count counts decoded peer/default route and satellite link notifications, not handovers. "
            "Times are user-space CLOCK_MONOTONIC observations. Unknown diagnostics do not mean no outage.",
            "attempts": attempts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_root, output = args.run_root.resolve(), args.output.resolve()
    if output == run_root or run_root in output.parents:
        parser.error("output must be outside the original run directory")
    report = diagnose(run_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"output": str(output), "attempts": len(report["attempts"]),
                      "labels": dict(Counter(label for x in report["attempts"]
                                             for label in x["anomaly_labels"]))}))


if __name__ == "__main__":
    main()
