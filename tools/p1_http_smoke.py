#!/usr/bin/env python3
"""Fetch one fixed HTTP object before and after a StarryNet ground handover."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from p0_smoke import GS, command, inventory, ping_result, preflight, topology_report

CLIENT_NODE = 26
SERVER_NODE = 27
SERVER_IP = '9.27.27.10'
HTTP_PORT = 18080
REMOTE_DIR = '/tmp/starrynet-p1'
OBJECT_NAME = 'fixed-object.bin'
OBJECT_SIZE = 1024 * 1024


def docker_exec(cid, *args, timeout=60):
    output = subprocess.check_output(['docker', 'exec', str(cid)] +
        [str(arg) for arg in args], universal_newlines=True, timeout=timeout)
    return output.strip()


def docker_cp(source, destination):
    result = subprocess.run(['docker', 'cp', str(source), str(destination)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=60)
    if result.returncode:
        raise RuntimeError('docker cp failed: ' + result.stderr.strip())


def tshark_output(*args):
    result = subprocess.run(['tshark'] + [str(arg) for arg in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
        timeout=60)
    if result.returncode:
        raise RuntimeError('tshark failed: ' + result.stderr.strip())
    return result.stdout.strip()


def make_object():
    seed = b'StarryNet-P1-fixed-HTTP-object-v1:'
    blocks = []
    index = 0
    size = 0
    while size < OBJECT_SIZE:
        block = hashlib.sha256(seed + str(index).encode('ascii')).digest()
        blocks.append(block)
        size += len(block)
        index += 1
    return b''.join(blocks)[:OBJECT_SIZE]


def prepare():
    run = ROOT / 'artifacts' / 'p1_http' / datetime.now(timezone.utc).strftime(
        '%Y%m%dT%H%M%S_%fZ')
    run.mkdir(parents=True)
    config = json.loads((ROOT / 'config.json').read_text())
    config.update({'Name': 'p1-http', '# of orbit': 5,
                   '# of satellites': 5, 'GS number': 2,
                   'Duration (s)': 100, 'update_time (s)': 10,
                   'remote_machine_IP': '', 'remote_machine_username': '',
                   'remote_machine_password': ''})
    (run / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
    fixture = run / 'fixture' / OBJECT_NAME
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(make_object())
    sources = [*sorted((ROOT / 'starrynet').glob('*.py')),
               ROOT / 'tools' / 'p0_smoke.py', Path(__file__).resolve()]
    manifest = {
        'experiment': 'P1_StarryNet_Fixed_HTTP_Object_Capture',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source_commit': command('git', '-C', str(ROOT), 'rev-parse', 'HEAD'),
        'source_sha256': {str(path.relative_to(ROOT)):
                          hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sources},
        'python': sys.version,
        'ground_stations': GS,
        'simulation_seconds': 100,
        'object': {'name': OBJECT_NAME, 'bytes': OBJECT_SIZE,
                   'sha256': hashlib.sha256(fixture.read_bytes()).hexdigest()},
        'http': {'host': SERVER_IP, 'port': HTTP_PORT,
                 'visits': 'one before and one after the first scheduled GS handover'},
        'capture': {'endpoints': ['GS26', 'GS27'], 'interface': 'any',
                    'filter': 'tcp port 18080'},
        'tshark_version': tshark_output('--version').splitlines()[0],
    }
    (run / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    shutil.copytree(ROOT / 'starrynet', run / 'source' / 'starrynet',
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(ROOT / 'tools' / 'p0_smoke.py', run / 'source' / 'p0_smoke.py')
    shutil.copy2(Path(__file__).resolve(), run / 'source' / 'p1_http_smoke.py')
    return run, fixture, manifest


def disable_management_interfaces(sn):
    for cid in sn.container_id_list:
        interfaces = command('docker', 'exec', cid, 'ip', '-o', 'link')
        for name in re.findall(r'^\d+:\s+([^:@\s]+)', interfaces, re.MULTILINE):
            if name != 'lo' and not name.startswith('B'):
                command('docker', 'exec', cid, 'ip', 'link', 'set',
                        'dev', name, 'down')


def setup_http_server(server_cid, fixture):
    docker_exec(server_cid, 'mkdir', '-p', REMOTE_DIR)
    docker_cp(fixture, str(server_cid) + ':' + REMOTE_DIR + '/' + OBJECT_NAME)
    server_log = REMOTE_DIR + '/http-server.log'
    server_pid = REMOTE_DIR + '/http-server.pid'
    script = ('cd {directory}; python3 -m http.server --bind {address} '
              '{port} > {log} 2>&1 & echo $! > {pid}; wait $!').format(
                  directory=shlex.quote(REMOTE_DIR), address=SERVER_IP,
                  port=HTTP_PORT, log=shlex.quote(server_log),
                  pid=shlex.quote(server_pid))
    subprocess.run(['docker', 'exec', '-d', str(server_cid), 'sh', '-c', script],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=15)
    # A loopback HEAD request checks listener readiness without adding a GET to
    # either packet capture (captures start only after this check).
    url = 'http://{0}:{1}/{2}'.format(SERVER_IP, HTTP_PORT, OBJECT_NAME)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            status = docker_exec(server_cid, 'curl', '--noproxy', '*', '-sS',
                                 '-I', '--connect-timeout', '1', '--max-time',
                                 '2', '-o', '/dev/null', '-w', '%{http_code}',
                                 url, timeout=5)
            if status == '200':
                return
        except (RuntimeError, subprocess.CalledProcessError):
            pass
        time.sleep(0.25)
    log = ''
    try:
        log = docker_exec(server_cid, 'cat', server_log)
    except Exception:
        pass
    raise RuntimeError('HTTP server did not become ready: ' + log)


def start_capture(cid, label):
    docker_exec(cid, 'mkdir', '-p', REMOTE_DIR)
    pcap = REMOTE_DIR + '/' + label + '.pcap'
    pid = REMOTE_DIR + '/' + label + '.pid'
    log = REMOTE_DIR + '/' + label + '-tcpdump.log'
    script = ('tcpdump -i any -n -s 0 -U -w {pcap} '
              "'tcp port {port}' > {log} 2>&1 & echo $! > {pid}; wait $!").format(
                  pcap=shlex.quote(pcap), port=HTTP_PORT,
                  log=shlex.quote(log), pid=shlex.quote(pid))
    subprocess.run(['docker', 'exec', '-d', str(cid), 'sh', '-c', script],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   timeout=15)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(cid, 'sh', '-c',
                                   'wc -c < ' + shlex.quote(pcap), timeout=5))
            if size >= 24:
                return {'cid': str(cid), 'label': label, 'pcap': pcap,
                        'pid': pid, 'log': log}
        except (RuntimeError, ValueError, subprocess.CalledProcessError):
            pass
        time.sleep(0.2)
    try:
        detail = docker_exec(cid, 'cat', log)
    except Exception as exc:
        detail = str(exc)
    raise RuntimeError('tcpdump did not initialize for {0}: {1}'.format(label, detail))


def stop_capture(capture):
    if capture is None:
        return
    docker_exec(capture['cid'], 'sh', '-c',
                'kill -INT "$(cat {0})"'.format(shlex.quote(capture['pid'])))
    # SIGINT makes tcpdump flush and close its pcap file.
    deadline = time.monotonic() + 10
    last_size = -1
    stable = 0
    while time.monotonic() < deadline:
        try:
            size = int(docker_exec(capture['cid'], 'sh', '-c',
                                   'wc -c < ' + shlex.quote(capture['pcap']),
                                   timeout=5))
        except (RuntimeError, ValueError, subprocess.CalledProcessError):
            break
        if size == last_size and size >= 24:
            stable += 1
            if stable >= 2:
                return
        else:
            last_size = size
            stable = 0
        time.sleep(0.2)


class VisitScheduler:
    def __init__(self, client_cid, anchor):
        self.client_cid = str(client_cid)
        self.anchor = anchor
        self.events = []
        self.lock = threading.Lock()

    def launch(self, scheduled_second):
        stamp = datetime.now(timezone.utc).isoformat()
        elapsed = round(time.monotonic() - self.anchor, 3)
        directory = REMOTE_DIR + '/visit_' + str(scheduled_second)
        download = directory + '/download.bin'
        curl_log = directory + '/curl.log'
        exit_file = directory + '/exit_code'
        url = 'http://{0}:{1}/{2}'.format(SERVER_IP, HTTP_PORT, OBJECT_NAME)
        write_out = ('http_code=%{http_code}\nsize_download=%{size_download}'
                     '\ntime_total=%{time_total}\nremote_ip=%{remote_ip}')
        script = (
            'mkdir -p {directory}; '
            'curl --noproxy "*" --http1.1 --connect-timeout 5 --max-time 30 '
            '-sS -o {download} -w {write_out} {url} > {curl_log} 2>&1; '
            'rc=$?; echo "$rc" > {exit_file}; exit "$rc"').format(
                directory=shlex.quote(directory),
                download=shlex.quote(download),
                write_out=shlex.quote(write_out), url=shlex.quote(url),
                curl_log=shlex.quote(curl_log),
                exit_file=shlex.quote(exit_file))
        result = subprocess.run(['docker', 'exec', '-d', self.client_cid,
                                 'sh', '-c', script],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=15)
        event = {'scheduled_second': int(scheduled_second),
                 'wall_utc': stamp, 'wall_seconds_from_emulation_start': elapsed,
                 'launch_returncode': result.returncode,
                 'launch_stdout': result.stdout.strip(),
                 'launch_stderr': result.stderr.strip()}
        with self.lock:
            self.events.append(event)
        if result.returncode:
            raise RuntimeError('Could not launch HTTP visit: ' + result.stderr.strip())


def wait_for_visits(client_cid, visit_times, run, expected_hash):
    visits = []
    for scheduled_second in visit_times:
        directory = REMOTE_DIR + '/visit_' + str(scheduled_second)
        exit_file = directory + '/exit_code'
        visit = {'scheduled_second': scheduled_second,
                 'curl_completed': False, 'object_matches_expected': False}
        try:
            deadline = time.monotonic() + 45
            exit_code = ''
            while time.monotonic() < deadline:
                try:
                    exit_code = docker_exec(client_cid, 'sh', '-c',
                        'cat {0} 2>/dev/null || true'.format(shlex.quote(exit_file)),
                        timeout=5)
                    if exit_code:
                        break
                except RuntimeError:
                    pass
                time.sleep(0.5)
            if not exit_code:
                raise RuntimeError('HTTP visit did not finish within 45 seconds')
            visit['curl_completed'] = True
            visit['curl_exit_code'] = int(exit_code)
            curl_log = docker_exec(client_cid, 'cat', directory + '/curl.log')
            log_path = run / 'downloads' / ('visit_{0}_curl.log'.format(scheduled_second))
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(curl_log)
            file_info = docker_exec(client_cid, 'sh', '-c',
                'sha256sum {0} && wc -c < {0}'.format(
                    shlex.quote(directory + '/download.bin')))
            fields = file_info.splitlines()
            if len(fields) < 2:
                raise RuntimeError('Could not inspect downloaded object')
            actual_hash = fields[0].split()[0]
            actual_size = int(fields[1].strip())
            local_copy = run / 'downloads' / ('visit_{0}.bin'.format(scheduled_second))
            docker_cp(str(client_cid) + ':' + directory + '/download.bin', local_copy)
            local_hash = hashlib.sha256(local_copy.read_bytes()).hexdigest()
            metrics = {}
            for key, value in re.findall(
                    r'^(http_code|size_download|time_total|remote_ip)=(.*)$',
                    curl_log, re.MULTILINE):
                metrics[key] = value
            visit.update({'curl_metrics': metrics, 'bytes': actual_size,
                'sha256': actual_hash, 'copied_sha256': local_hash,
                'object_matches_expected': actual_hash == expected_hash
                    and local_hash == expected_hash and actual_size == OBJECT_SIZE
                    and metrics.get('http_code') == '200'
                    and int(exit_code) == 0})
        except Exception as exc:
            visit['error'] = str(exc)
        visits.append(visit)
    return visits


def analyze_capture(pcap, label):
    packet_numbers = tshark_output('-r', pcap, '-T', 'fields',
                                   '-e', 'frame.number').splitlines()
    output = tshark_output('-r', pcap, '-d',
                     'tcp.port=={0},http'.format(HTTP_PORT), '-Y',
                     'http.request or http.response', '-T', 'fields',
                     '-E', 'separator=|', '-e', 'frame.number', '-e', 'ip.src',
                     '-e', 'tcp.srcport', '-e', 'ip.dst', '-e', 'tcp.dstport',
                     '-e', 'http.request.method', '-e', 'http.request.uri',
                     '-e', 'http.response.code')
    raw_responses = tshark_output('-r', pcap, '-Y',
        'tcp.srcport=={0} && tcp.payload contains "HTTP/1.0 200 OK"'.format(
            HTTP_PORT), '-T', 'fields', '-e', 'frame.number').splitlines()
    rows = []
    requests = 0
    responses = 0
    for line in output.splitlines():
        fields = line.split('|')
        fields += [''] * (8 - len(fields))
        row = {'frame': fields[0], 'source': fields[1],
               'source_port': fields[2], 'destination': fields[3],
               'destination_port': fields[4], 'method': fields[5],
               'uri': fields[6], 'response_code': fields[7]}
        rows.append(row)
        if row['method'] == 'GET' and row['uri'] == '/' + OBJECT_NAME:
            requests += 1
        if row['response_code'] == '200':
            responses += 1
    (pcap.parent / (label + '_http_packets.json')).write_text(
        json.dumps(rows, indent=2) + '\n')
    return {'label': label, 'pcap': str(pcap), 'pcap_bytes': pcap.stat().st_size,
            'packet_count': len(packet_numbers), 'http_request_count': requests,
            'http_200_response_count': max(responses, len(raw_responses)),
            'dissected_http_200_response_count': responses,
            'raw_http_200_header_count': len(raw_responses),
            'http_packets_file': label + '_http_packets.json'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['plan', 'preflight', 'run'], nargs='?',
                        default='plan')
    args = parser.parse_args()
    lock = (ROOT / '.p0.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another local StarryNet experiment is running')
    if args.mode == 'plan':
        print('P1: 25 satellites + 2 GS; one 1 MiB HTTP object fetched before '
              'and after the first GS handover; client/server PCAP; SHA-256 gate.')
        return
    if not shutil.which('tshark'):
        raise RuntimeError('Host tshark is required to validate captured HTTP transactions')
    if args.mode == 'preflight':
        print(json.dumps({'preflight_passed': True, 'inventory': preflight()}, indent=2))
        return

    before = preflight()
    run, fixture, manifest = prepare()
    started = time.monotonic()
    sys.path.insert(0, str(run / 'source'))
    print('Output: {0}'.format(run), flush=True)
    from starrynet.sn_thread import WORKER_ERRORS
    WORKER_ERRORS.clear()
    sn = None
    captures = []
    server_cid = None
    summary = {'engineering_http_capture_passed': False,
               'scientific_fidelity_verified': False,
               'cleanup_verified': False, 'mode': args.mode,
               'object': manifest['object'], 'visits': [], 'captures': []}
    failure = None
    try:
        from starrynet.sn_synchronizer import StarryNet
        sn = StarryNet(str(run / 'config.json'), GS, 1, [[1, 27]],
                       local=True, argv=[])
        path = run / sn.file_path
        summary['topology'] = topology_report(run, path)
        handovers = [second for second in summary['topology']['handover_seconds']
                     if 15 < second < 85]
        if not handovers:
            raise RuntimeError('No GS handover is available for a before/after HTTP pair')
        handover = handovers[0]
        visit_times = [handover - 18, handover + 22]
        if visit_times[0] < 15 or visit_times[1] > 95:
            raise RuntimeError('The handover time leaves no safe before/after HTTP window')
        summary['handover_second'] = handover
        summary['http_visit_seconds'] = visit_times
        if WORKER_ERRORS:
            raise RuntimeError('Initialization worker failed: {0}'.format(WORKER_ERRORS))

        for action in (sn.create_nodes, sn.create_links):
            action()
            if WORKER_ERRORS:
                raise RuntimeError('StarryNet worker failed: {0}'.format(WORKER_ERRORS))
        if len(sn.container_id_list) != 27:
            raise RuntimeError('Expected 27 StarryNet containers')
        disable_management_interfaces(sn)
        server_cid = sn.container_id_list[SERVER_NODE - 1]
        client_cid = sn.container_id_list[CLIENT_NODE - 1]
        setup_http_server(server_cid, fixture)
        sn.run_routing_deamon()
        if WORKER_ERRORS:
            raise RuntimeError('Routing worker failed: {0}'.format(WORKER_ERRORS))
        from p0_smoke import snapshot
        snapshot(sn, run, 'before')

        captures.append(start_capture(client_cid, 'client'))
        captures.append(start_capture(server_cid, 'server'))
        visitor = VisitScheduler(client_cid, time.monotonic())
        for visit_time in visit_times:
            sn.schedule_callback(visit_time, visitor.launch)
        for second in sorted(set([15, *visit_times, handover + 2, 95])):
            sn.set_ping(CLIENT_NODE, SERVER_NODE, second)
        for second in sorted(set([15, *visit_times, 95])):
            sn.check_routing_table(CLIENT_NODE, second)
            sn.check_routing_table(SERVER_NODE, second)
        emulation_anchor = time.monotonic()
        visitor.anchor = emulation_anchor
        sn.start_emulation()
        if WORKER_ERRORS:
            raise RuntimeError('Emulation worker failed: {0}'.format(WORKER_ERRORS))
        summary['scheduled_http_events'] = sorted(visitor.events,
            key=lambda item: item['scheduled_second'])
        if len(visitor.events) != len(visit_times):
            raise RuntimeError('Not all scheduled HTTP visits were launched')
        summary['visits'] = wait_for_visits(client_cid, visit_times, run,
                                            manifest['object']['sha256'])
        if not all(item.get('object_matches_expected') for item in summary['visits']):
            raise RuntimeError('One or more HTTP objects failed verification; see visits and curl logs')
        snapshot(sn, run, 'after')
        summary['ping_results'] = [ping_result(path / ('ping-26-27_{0}.txt'.format(second)),
                                               summary['topology']['handover_seconds'])
            for second in sorted(set([15, *visit_times, handover + 2, 95]))]
        summary['route_files'] = sorted(p.name for p in path.glob('route-*.txt'))
    except BaseException as exc:
        failure = exc
        summary['error'] = str(exc)
    finally:
        capture_results = []
        for capture in captures:
            try:
                stop_capture(capture)
                local_pcap = run / 'captures' / (capture['label'] + '.pcap')
                local_pcap.parent.mkdir(parents=True, exist_ok=True)
                docker_cp(capture['cid'] + ':' + capture['pcap'], local_pcap)
                capture_results.append(analyze_capture(local_pcap, capture['label']))
            except Exception as exc:
                capture_results.append({'label': capture['label'], 'error': str(exc)})
                if failure is None:
                    failure = exc
                    summary['error'] = str(exc)
        summary['captures'] = capture_results
        try:
            server_log = docker_exec(server_cid, 'cat', REMOTE_DIR + '/http-server.log')
            (run / 'http_server.log').write_text(server_log)
        except Exception:
            pass
        try:
            sn_stop = __import__('starrynet.sn_orchestrater',
                                 fromlist=['sn_stop_emulation']).sn_stop_emulation
            sn_stop()
            summary['cleanup_verified'] = before == inventory()
            if not summary['cleanup_verified'] and failure is None:
                failure = RuntimeError('Docker inventory changed after scoped cleanup')
                summary['error'] = str(failure)
        except Exception as exc:
            summary['cleanup_error'] = str(exc)
            if failure is None:
                failure = exc
                summary['error'] = str(exc)
        client_capture = next((item for item in capture_results
                               if item.get('label') == 'client'), {})
        server_capture = next((item for item in capture_results
                               if item.get('label') == 'server'), {})
        visit_gate = (len(summary['visits']) == 2 and
                      all(item.get('object_matches_expected') for item in summary['visits']))
        capture_gate = all(item.get('packet_count', 0) > 0 and
                           item.get('http_request_count', 0) >= 2 and
                           item.get('http_200_response_count', 0) >= 2 and
                           item.get('pcap_bytes', 0) > 24
                           for item in (client_capture, server_capture))
        summary['payload_integrity_passed'] = visit_gate
        summary['dual_endpoint_http_pcap_passed'] = capture_gate
        summary['engineering_http_capture_passed'] = bool(
            visit_gate and capture_gate and summary['cleanup_verified'] and failure is None)
        summary['wall_seconds'] = round(time.monotonic() - started, 3)
        (run / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary, indent=2), flush=True)
    if failure is not None:
        raise failure
    if not summary['engineering_http_capture_passed']:
        raise RuntimeError('P1 HTTP/capture validation failed; inspect summary.json')


if __name__ == '__main__':
    main()
