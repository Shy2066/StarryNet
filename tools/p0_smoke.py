#!/usr/bin/env python3
"""Prepare or run the native 25-satellite, two-ground-station smoke experiment."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
GS = [[50.110924, 8.682127], [46.635700, 14.311817]]


def command(*args):
    return subprocess.check_output(args, universal_newlines=True, timeout=30).strip()


def inventory():
    return {
        'containers': command('docker', 'ps', '-aq').split(),
        'networks': command('docker', 'network', 'ls', '-q').split(),
        'services': command('docker', 'service', 'ls', '--format', '{{.Name}}').split(),
    }


def preflight():
    missing = [m for m in ('numpy', 'skyfield', 'sgp4', 'paramiko', 'requests')
               if importlib.util.find_spec(m) is None]
    if missing:
        raise RuntimeError(f'Missing Python dependencies: {missing}')
    if command('docker', 'info', '--format', '{{.Swarm.ControlAvailable}}') != 'true':
        raise RuntimeError('A Docker Swarm manager is required; this script does not initialize Swarm')
    if command('docker', 'info', '--format', '{{.Swarm.Nodes}}') != '1':
        raise RuntimeError('P0 requires a single-node Swarm')
    command('docker', 'image', 'inspect', 'lwsen/starlab_node:1.0', '--format', '{{.Id}}')
    names = command('docker', 'ps', '-a', '--format', '{{.Names}}').split()
    networks = command('docker', 'network', 'ls', '--format', '{{.Name}}').split()
    before = inventory()
    if 'constellation-test' in before['services'] or any(n.startswith('ovs_container_') for n in names):
        raise RuntimeError('Existing StarryNet resources found; inspect them before starting another run')
    if any(re.fullmatch(r'(?:Le|La|GS|GSL)_.*', n) for n in networks):
        raise RuntimeError('Existing StarryNet network names found; legacy resources are retained')
    details = json.loads(command('docker', 'network', 'inspect', *networks))
    planned = [ipaddress.ip_network(f'10.0.{i}.0/24') for i in range(1, 51)]
    planned += [ipaddress.ip_network(f'9.{g}.{s}.0/24') for g in (1, 2) for s in range(1, 26)]
    planned += [ipaddress.ip_network(f'9.{g}.{g}.0/24') for g in (26, 27)]
    for detail in details:
        for item in detail.get('IPAM', {}).get('Config') or []:
            subnet = item.get('Subnet')
            if subnet and any(ipaddress.ip_network(subnet).overlaps(p) for p in planned):
                raise RuntimeError(f'Existing Docker subnet overlaps P0: {detail["Name"]} {subnet}')
    return before


def prepare():
    run = ROOT / 'artifacts' / 'p0' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    run.mkdir(parents=True)
    config = json.loads((ROOT / 'config.json').read_text())
    config.update({'Name': 'p0', '# of orbit': 5, '# of satellites': 5,
                   'GS number': 2, 'Duration (s)': 100, 'update_time (s)': 10,
                   'remote_machine_IP': '', 'remote_machine_username': '',
                   'remote_machine_password': ''})
    (run / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
    manifest = {'experiment': 'P0_StarryNet_Official_Network_Smoke',
                'source_commit': command('git', '-C', str(ROOT), 'rev-parse', 'HEAD'),
                'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [*sorted((ROOT / 'starrynet').glob('*.py')), Path(__file__).resolve()]},
                'python': sys.version, 'ground_stations': GS,
                'simulation_seconds': 100, 'delay_update_seconds': 10,
                'ping_times': list(range(15, 100, 10)), 'iperf_times': [35, 75],
                'routing_times': [15, 55, 95]}
    (run / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    # Freeze the sources used by repeated uploads during this run.
    shutil.copytree(ROOT / 'starrynet', run / 'source' / 'starrynet',
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(__file__, run / 'source' / 'p0_smoke.py')
    return run


def topology_report(run, path):
    import numpy as np
    matrices = [np.loadtxt(p, delimiter=',') for p in sorted(path.glob('delay/*.txt'), key=lambda p: int(p.stem))]
    assert len(matrices) == 100
    assert all(a.shape == (27, 27) and np.isfinite(a).all() and (a >= 0).all()
               and np.allclose(a, a.T) for a in matrices)
    attachment = [[np.flatnonzero(a[g, :25]).tolist() for g in (25, 26)] for a in matrices]
    report = {'matrix_count': len(matrices), 'matrix_shape': [27, 27],
              'ground_station_missing_link_seconds': [sum(not a[g] for a in attachment) for g in (0, 1)],
              'ground_station_handover_count': [sum(a[g] != b[g] for a, b in zip(attachment, attachment[1:])) for g in (0, 1)],
              'initial_satellite_nodes_one_based': [[n + 1 for n in a] for a in attachment[0]],
              'handover_seconds': [i + 2 for i, (a, b) in enumerate(zip(attachment, attachment[1:])) if a != b],
              'delay_matrix_changes': sum(not np.array_equal(a, b) for a, b in zip(matrices, matrices[1:]))}
    (run / 'topology.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def ping_result(path, handover_seconds):
    second = int(path.stem.rsplit('_', 1)[1])
    text = path.read_text()
    stats = re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received, ([\d.]+)% packet loss', text)
    rtt = re.search(r'rtt min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms', text)
    received = int(stats[2]) if stats else 0
    transition = any(t <= second <= t + 10 for t in handover_seconds)
    if received == 0 and not (transition and (stats or 'Network is unreachable' in text)):
        raise RuntimeError(f'Ping failed outside a recognized handover measurement: {path.name}')
    return {'scheduled_second': second, 'transmitted': int(stats[1]) if stats else None,
            'received': received, 'loss_percent': float(stats[3]) if stats else None,
            'rtt_avg_ms': float(rtt[2]) if rtt else None,
            'handover_window': transition, 'route_unreachable': 'Network is unreachable' in text}


def snapshot(sn, run, label):
    data = {}
    for node in (7, 13, 14, 26, 27):
        cid = sn.container_id_list[node - 1]
        data[str(node)] = {
            'interfaces': command('docker', 'exec', cid, 'ip', '-o', 'address'),
            'routes': command('docker', 'exec', cid, 'ip', 'route'),
            'qdisc': command('docker', 'exec', cid, 'tc', '-s', 'qdisc', 'show'),
            'bird': command('docker', 'exec', cid, 'birdc', 'show', 'protocols'),
        }
    route = command('docker', 'exec', sn.container_id_list[25], 'ip', 'route', 'get', '9.27.27.10')
    if not re.search(r'\bdev B26-eth\d+\b', route):
        raise RuntimeError(f'GS26 traffic does not use a satellite interface: {route}')
    data['gs26_to_gs27_route'] = route
    (run / f'snapshot_{label}.json').write_text(json.dumps(data, indent=2) + '\n')


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['plan', 'preflight', 'topology', 'run'], nargs='?', default='plan')
    args = parser.parse_args()
    # The upstream resource names are fixed: serialize local P0 invocations.
    import fcntl
    lock = (ROOT / '.p0.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another P0 process is running')
    if args.mode == 'plan':
        print('P0: local execution; 25 satellites + 2 GS; 100s; ping GS26->GS27; '
              'iperf3 at 35/75s; OSPF; labelled cleanup; no damage or static route overrides.')
        return
    if args.mode == 'preflight':
        print(json.dumps({'preflight_passed': True, 'inventory': preflight()}, indent=2))
        return
    before = preflight() if args.mode == 'run' else None
    run = prepare()
    sys.path.insert(0, str(run / 'source'))
    print(f'Output: {run}', flush=True)
    from starrynet.sn_thread import WORKER_ERRORS
    errors = WORKER_ERRORS
    errors.clear()
    sn = None
    summary = {'basic_smoke_passed': False, 'scientific_fidelity_verified': False,
               'bandwidth_limit_verified': False, 'loss_rate_verified': False,
               'handover_verified': False, 'mode': args.mode}
    try:
        from starrynet.sn_synchronizer import StarryNet
        sn = StarryNet(str(run / 'config.json'), GS, 1, [[1, 27]], local=True, argv=[])
        path = run / sn.file_path
        summary['topology'] = topology_report(run, path)
        if errors:
            raise RuntimeError(f'Initialization worker failed: {errors}')
        if args.mode == 'topology':
            summary['topology_preparation_passed'] = True
            return
        for action in (sn.create_nodes, sn.create_links):
            action()
            if errors:
                raise RuntimeError(f'Worker failed: {errors}')
        if len(sn.container_id_list) != 27:
            raise RuntimeError('Expected 27 StarryNet containers')
        # Keep only StarryNet interfaces up, preventing a Docker management path.
        for cid in sn.container_id_list:
            interfaces = command('docker', 'exec', cid, 'ip', '-o', 'link')
            for name in re.findall(r'^\d+:\s+([^:@\s]+)', interfaces, re.MULTILINE):
                if name != 'lo' and not name.startswith('B'):
                    command('docker', 'exec', cid, 'ip', 'link', 'set', 'dev', name, 'down')
        sn.run_routing_deamon()
        if errors:
            raise RuntimeError(f'Routing worker failed: {errors}')
        snapshot(sn, run, 'before')
        for t in range(15, 100, 10):
            sn.set_ping(26, 27, t)
        for t in (35, 75):
            sn.set_perf(26, 27, t)
        for t in (15, 55, 95):
            sn.check_routing_table(26, t)
            sn.check_routing_table(27, t)
        sn.start_emulation()
        if errors:
            raise RuntimeError(f'Emulation worker failed: {errors}')
        snapshot(sn, run, 'after')
        pings = list(path.glob('ping-26-27_*.txt'))
        perfs = list(path.glob('perf-26-27_*.txt'))
        routes = list(path.glob('route-*.txt'))
        if len(pings) != 9 or len(perfs) != 2 or len(routes) != 6:
            raise RuntimeError('Missing scheduled measurement files')
        if any(not re.search(r'[1-9]\d*(?:\.\d+)?\s+[KMG]?bits/sec\s+receiver', p.read_text()) for p in perfs):
            raise RuntimeError('iperf receiver throughput missing or zero')
        summary['ping_results'] = [ping_result(p, summary['topology']['handover_seconds'])
            for p in sorted(pings, key=lambda p: int(p.stem.rsplit('_', 1)[1]))]
        summary['iperf_results'] = []
        for p in sorted(perfs, key=lambda p: int(p.stem.rsplit('_', 1)[1])):
            result = re.search(r'([\d.]+)\s+([KMG]?)bits/sec\s+receiver', p.read_text())
            summary['iperf_results'].append({'scheduled_second': int(p.stem.rsplit('_', 1)[1]),
                'receiver_bits_per_second': float(result[1]) * {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9}[result[2]]})
        summary['basic_smoke_passed'] = True
    except BaseException as exc:
        summary['error'] = str(exc)
        raise
    finally:
        if args.mode == 'run':
            try:
                from starrynet.sn_orchestrater import sn_stop_emulation
                sn_stop_emulation()
                after = inventory()
                summary['cleanup_verified'] = before == after
                if before != after:
                    summary['basic_smoke_passed'] = False
                    summary['cleanup_error'] = {'before': before, 'after': after}
            except Exception as exc:
                summary['basic_smoke_passed'] = False
                summary['cleanup_error'] = str(exc)
        summary['wall_seconds'] = round(time.monotonic() - started, 3)
        (run / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2), flush=True)
    if not summary['basic_smoke_passed']:
        raise RuntimeError('Smoke validation failed; inspect summary.json')


if __name__ == '__main__':
    main()
