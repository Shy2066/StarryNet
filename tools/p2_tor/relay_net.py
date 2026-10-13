#!/usr/bin/env python3
"""Configure, start, inventory, and archive the private Chutney relay network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


def run_logged(command, env, log_path, timeout):
    result = subprocess.run(command, env=env, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout,
                            cwd="/opt/chutney")
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with Path(log_path).open("a") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.write(result.stdout)
        if not result.stdout.endswith("\n"):
            log.write("\n")
    if result.returncode:
        raise RuntimeError("Command failed ({0}): {1}".format(
            result.returncode, " ".join(command)) + "\n" + result.stdout[-4000:])
    return result.stdout


def environment(args):
    env = os.environ.copy()
    env.update({
        "CHUTNEY_DATA_DIR": args.data_dir,
        "CHUTNEY_LISTEN_ADDRESS": args.listen_ip,
        "CHUTNEY_DNS_CONF": "/dev/null",
        "CHUTNEY_TOR_SANDBOX": "0",
        "CHUTNEY_CONTROLLING_PID": "1",
        "CHUTNEY_START_TIME": "180",
    })
    return env


def node_files(data_dir):
    for torrc in sorted(Path(data_dir, "nodes").glob("*/torrc")):
        text = torrc.read_text(errors="replace")
        nickname = re.search(r"^Nickname\s+(\S+)", text, re.MULTILINE)
        datadir = re.search(r"^DataDirectory\s+(\S+)", text, re.MULTILINE)
        if nickname and datadir:
            yield torrc, nickname.group(1), Path(datadir.group(1)), text


def patch_exit(args):
    candidates = [(p, n, d, text) for p, n, d, text in node_files(args.data_dir)
                  if n.endswith("e")]
    if len(candidates) != 1:
        raise RuntimeError("Expected exactly one Chutney exit relay; found "
                           + str([n for _, n, _, _ in candidates]))
    torrc, nickname, datadir, text = candidates[0]
    lines = [line for line in text.splitlines()
             if not line.strip().startswith("ExitPolicy ")
             and not line.strip().startswith("ExitPolicyRejectPrivate ")]
    lines.extend(["ExitPolicyRejectPrivate 0",
                  "ExitPolicy accept {0}:{1}".format(args.server_ip,
                                                      args.server_port),
                  # These ports give the relay an Exit flag in the testing
                  # network's microdescriptor consensus. Runtime egress is
                  # separately restricted to the fixed page server.
                  "ExitPolicy accept *:80",
                  "ExitPolicy accept *:443",
                  "ExitPolicy reject *:*"])
    torrc.write_text("\n".join(lines) + "\n")
    return nickname


def parse_fingerprint(path):
    if not path.is_file():
        return None
    fields = path.read_text(errors="replace").split()
    return fields[-1].upper() if fields else None


def authority_v3_identity(datadir):
    cert = datadir / "keys" / "authority_certificate"
    if not cert.is_file():
        return None
    match = re.search(r"^fingerprint\s+(\S+)",
                      cert.read_text(errors="replace"), re.MULTILINE)
    return match.group(1).upper() if match else None


def inventory(args):
    nodes = []
    for torrc, nickname, datadir, text in node_files(args.data_dir):
        def integer(option):
            match = re.search(r"^" + option + r"\s+(\d+)", text,
                              re.MULTILINE | re.IGNORECASE)
            return int(match.group(1)) if match else None

        role = "authority" if re.search(
            r"^AuthoritativeDirectory\s+1\b", text, re.MULTILINE) else (
            "guard" if nickname.endswith("g") else (
                "middle" if nickname.endswith("m") else (
                    "exit" if nickname.endswith("e") else "client")))
        advertised = re.search(r"^Address\s+(\S+)", text, re.MULTILINE)
        nodes.append({
            "nickname": nickname,
            "role": role,
            "advertised_address": advertised.group(1) if advertised else None,
            "fingerprint": parse_fingerprint(datadir / "fingerprint"),
            "authority_v3_identity": authority_v3_identity(datadir),
            "or_port": integer("ORPort"),
            "dir_port": integer("DirPort"),
            "control_port": integer("ControlPort"),
            "torrc": str(torrc),
            "data_directory": str(datadir),
        })
    return sorted(nodes, key=lambda item: (item["role"], item["nickname"]))


def archive(args):
    root = Path(args.data_dir)
    target = Path(args.archive)
    target.parent.mkdir(parents=True, exist_ok=True)
    safe_names = {"torrc", "fingerprint", "fingerprint-ed25519",
                  "authority_certificate", "notice.log", "info.log"}
    with tarfile.open(target, "w:gz") as bundle:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.name not in safe_names:
                continue
            if "keys" in path.parts and path.name != "authority_certificate":
                continue
            bundle.add(path, arcname=str(path.relative_to(root)))
        network_file = Path(args.network_file)
        if network_file.is_file():
            bundle.add(network_file, arcname="network/p2-smoke")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(json.dumps({"archive": str(target), "sha256": digest}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chutney", default="/opt/chutney/chutney")
    parser.add_argument("--network", default="networks/p2-smoke")
    parser.add_argument("--network-file", default="/p2/source/networks/p2-smoke")
    parser.add_argument("--data-dir", default="/p2/chutney-data")
    parser.add_argument("--listen-ip", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--log", default="/p2/chutney-setup.log")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("configure")
    subparsers.add_parser("start")
    subparsers.add_parser("wait")
    subparsers.add_parser("stop")
    subparsers.add_parser("metadata")
    archive_parser = subparsers.add_parser("archive")
    archive_parser.add_argument("--archive", required=True)
    args = parser.parse_args()
    env = environment(args)
    if args.command == "configure":
        run_logged([args.chutney, "configure", args.network], env,
                   args.log, 120)
        exit_name = patch_exit(args)
        print(json.dumps({"configured": True, "exit_nickname": exit_name},
                         sort_keys=True))
    elif args.command == "start":
        run_logged([args.chutney, "start", args.network], env, args.log, 120)
        print(json.dumps({"started": True}, sort_keys=True))
    elif args.command == "wait":
        output = run_logged([args.chutney, "wait_for_bootstrap", args.network],
                            env, args.log, 250)
        print(json.dumps({"bootstrapped": True, "output": output[-4000:]},
                         sort_keys=True))
    elif args.command == "stop":
        result = subprocess.run([args.chutney, "stop", args.network], env=env,
                                text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=45,
                                cwd="/opt/chutney")
        with Path(args.log).open("a") as log:
            log.write("$ " + args.chutney + " stop " + args.network + "\n")
            log.write(result.stdout)
        if result.returncode:
            raise RuntimeError("Chutney shutdown failed: " + result.stdout)
        print(json.dumps({"stopped": True}, sort_keys=True))
    elif args.command == "metadata":
        print(json.dumps(inventory(args), indent=2, sort_keys=True))
    elif args.command == "archive":
        archive(args)


if __name__ == "__main__":
    main()
