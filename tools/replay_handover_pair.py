#!/usr/bin/env python3
"""One-source TCP diagnostic at the same observed GSL handover, loss 1% vs 0%."""
import argparse
import fcntl
import json
from pathlib import Path
import re
import shutil
import sys
import time

import replay_trace_over_starrynet as replay

PROFILE = {
    'sample_id': '18-8', 'ground_station': 27, 'old_satellite': 13,
    'new_satellite': 7, 'simulation_second': 53,
    'anchor': 'successful_old_interface_down_command_end',
    'start_offset_seconds': 1.0, 'phase_tolerance_seconds': 0.1,
    'anchor_wait_timeout_seconds': 180.0,
}
DEFAULT_BASELINE = Path('/mnt/HDD4T/shy/StarryNet_E_v4/pilot_tcp_zero_loss_20261111/runs/20261111T101451_555989Z/manifest.json')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_rows(path):
    with Path(path).open(encoding='utf-8') as f:
        return [json.loads(line) for line in f]


def require_event(topology, profile):
    node = profile['ground_station']
    seconds = [s for s in topology['handover_seconds'] if node in
               topology['handover_ground_stations_by_second'].get(str(s), [])]
    if not seconds:
        raise replay.ReplayError('diagnostic target ground station has no handover')
    second = min(seconds)
    before = replay.attachment_for_second(topology, second - .001, node)
    after = replay.attachment_for_second(topology, second, node)
    if (second != profile['simulation_second'] or
            before != [profile['old_satellite'] - 1] or
            after != [profile['new_satellite'] - 1]):
        raise replay.ReplayError('diagnostic target handover differs from frozen event')


def wait_for_anchor(context, profile):
    """Observe the append-only command log without delaying the switch thread."""
    require_event(context['topology'], profile)
    expected = 'docker exec -i {} ip link set dev B{}-eth{} down'.format(
        context['remote_cid'], profile['ground_station'], profile['old_satellite'])
    deadline = time.monotonic() + profile['anchor_wait_timeout_seconds']
    with (Path(context['session_dir']) / 'commands.jsonl').open(encoding='utf-8') as f:
        while time.monotonic() < deadline:
            if context['emulation_errors']:
                raise replay.ReplayError('emulation failed while waiting for handover')
            position = f.tell()
            line = f.readline()
            if not line.endswith('\n'):
                f.seek(position)
                time.sleep(.02)
                continue
            row = json.loads(line)
            if row['command'] != expected or row['end_monotonic_ns'] < context['session_anchor_ns']:
                continue
            if row['returncode'] != 0:
                raise replay.ReplayError('target old-interface down command failed')
            if row.get('clock_domain') != 'CLOCK_MONOTONIC' or row['end_monotonic_ns'] < row['start_monotonic_ns']:
                raise replay.ReplayError('target command clock is not valid')
            start_ns = row['end_monotonic_ns'] + int(profile['start_offset_seconds'] * 1e9)
            if start_ns < replay.monotonic_ns() + int(replay.DISPATCH_LEAD_SECONDS * 1e9):
                raise replay.ReplayError('missed diagnostic anchor; refusing to move sample to a later phase')
            return start_ns, {'profile': dict(profile), 'anchor_command': row,
                              'sample_start_monotonic_ns': start_ns,
                              'clock_domain': 'CLOCK_MONOTONIC'}
    raise replay.ReplayError('timed out waiting for the frozen old-interface down event')


def create_plan(root, baseline_path=DEFAULT_BASELINE):
    root = Path(root).resolve()
    baseline = replay.load_manifest(baseline_path)
    frozen_base = read_json(Path(baseline['run_dir']) / 'frozen_config.json')
    if replay.sha256_file(Path(baseline['run_dir']) / 'frozen_config.json') != baseline['frozen_config_sha256']:
        raise replay.ReplayError('baseline frozen configuration hash mismatch')
    if frozen_base['config'] != baseline['topology']['config']:
        raise replay.ReplayError('baseline topology configuration mismatch')
    if baseline['transport'] != 'tcp' or baseline['agent_sha256'] != replay.sha256_file(replay.AGENT_SOURCE):
        raise replay.ReplayError('requires the existing TCP endpoint baseline')
    if baseline['runtime_source_sha256'] != replay.runtime_source_hashes():
        raise replay.ReplayError('StarryNet runtime differs from baseline')
    selected = [r for r in baseline['source_rows'] if r['sample_id'] == PROFILE['sample_id']]
    if len(selected) != 1:
        raise replay.ReplayError('baseline must contain exactly one 18-8 source identity')
    entry = selected[0]
    source = Path(entry['source_path'])
    if replay.sha256_file(source) != entry['source_sha256']:
        raise replay.ReplayError('source file changed')
    # This new root must never replace a previous paired diagnostic.
    root.mkdir(parents=True, exist_ok=False)
    runner_sha = replay.sha256_file(Path(__file__))
    arms = []
    for loss in (1, 0):
        args = argparse.Namespace(input=Path(baseline['input_root']),
            dataset_output=root / ('loss_' + str(loss)) / 'unused_dataset',
            seed=baseline['seed'], speed=baseline['speed'], session_seconds=180,
            guard_seconds=baseline['guard_seconds'], transport='tcp', link_loss_percent=loss)
        sessions = replay.build_sessions([source], args.seed, 180, args.speed, args.guard_seconds)
        run_dir = replay.next_run_dir(root / ('loss_' + str(loss)) / 'runs')
        manifest = replay.build_manifest(args, [source], sessions, run_dir, 'diagnostic')
        # Retain every frozen topology choice; only duration and random loss differ.
        config = dict(baseline['topology']['config'])
        config['Duration (s)'] = 180
        for key in ('satellite link loss ("X"% )', 'sat-ground loss ("X"% )'):
            config[key] = loss
        manifest['topology']['config'] = config
        manifest['handover_control_profile'] = dict(PROFILE)
        manifest['diagnostic_runner_sha256'] = runner_sha
        manifest['baseline_manifest'] = str(Path(baseline_path).resolve())
        source_dir = run_dir / 'source'
        source_dir.mkdir()
        replay.atomic_write_json(source_dir / 'manifest.json', {
            'schema_version': 1, 'input_root': manifest['input_root'],
            'source_count': 1, 'source_total_bytes': manifest['source_total_bytes'],
            'source_digest_sha256': manifest['source_digest_sha256'], 'rows': manifest['source_rows']})
        for path in (Path(__file__), Path(replay.__file__)):
            shutil.copy2(str(path), str(source_dir / path.name))
        manifest['source_manifest_sha256'] = replay.sha256_file(source_dir / 'manifest.json')
        frozen = dict(frozen_base, config=config, handover_control_profile=dict(PROFILE),
                      diagnostic_runner_sha256=runner_sha)
        replay.atomic_write_json(run_dir / 'frozen_config.json', frozen)
        manifest['frozen_config_sha256'] = replay.sha256_file(run_dir / 'frozen_config.json')
        replay.atomic_write_json(run_dir / 'manifest.json', manifest)
        (run_dir / 'attempts.jsonl').touch()
        replay.check_frozen_config(replay.load_manifest(run_dir / 'manifest.json'))
        arms.append({'loss_percent': loss, 'manifest': str(run_dir / 'manifest.json'),
                     'manifest_sha256': replay.sha256_file(run_dir / 'manifest.json')})
    pair = {'schema_version': 1, 'tool': 'replay_handover_pair', 'profile': dict(PROFILE),
            'runner_sha256': runner_sha, 'baseline_manifest': str(Path(baseline_path).resolve()),
            'source_id': entry['sample_id'], 'source_sha256': entry['source_sha256'],
            'arms': arms, 'created_utc': replay.utc_now(), 'purpose': 'diagnostic_only'}
    replay.atomic_write_json(root / 'pair.json', pair)
    return root / 'pair.json'


def load_pair(path):
    path = Path(path).resolve()
    pair = read_json(path)
    if (pair.get('tool') != 'replay_handover_pair' or pair.get('schema_version') != 1
            or pair.get('profile') != PROFILE or len(pair.get('arms', [])) != 2
            or [a['loss_percent'] for a in pair['arms']] != [1, 0]
            or pair.get('runner_sha256') != replay.sha256_file(Path(__file__))):
        raise replay.ReplayError('paired diagnostic contract or runner changed')
    manifests = []
    for arm in pair['arms']:
        if replay.sha256_file(arm['manifest']) != arm['manifest_sha256']:
            raise replay.ReplayError('diagnostic manifest changed')
        manifest = replay.load_manifest(arm['manifest'])
        replay.check_frozen_config(manifest)
        frozen = read_json(Path(manifest['run_dir']) / 'frozen_config.json')
        if any(obj.get('handover_control_profile') != PROFILE or
               obj.get('diagnostic_runner_sha256') != pair['runner_sha256']
               for obj in (manifest, frozen)):
            raise replay.ReplayError('diagnostic phase configuration is not frozen')
        if manifest['mode'] != 'diagnostic' or manifest['source_count'] != 1:
            raise replay.ReplayError('requires a separate one-source diagnostic plan')
        source = manifest['source_rows'][0]
        if source['sample_id'] != pair['source_id'] or source['source_sha256'] != pair['source_sha256']:
            raise replay.ReplayError('paired source identity mismatch')
        if replay.sha256_file(source['source_path']) != pair['source_sha256']:
            raise replay.ReplayError('paired source file changed')
        if any(manifest['topology']['config'][k] != arm['loss_percent'] for k in
               ('satellite link loss ("X"% )', 'sat-ground loss ("X"% )')):
            raise replay.ReplayError('paired loss configuration mismatch')
        manifests.append(manifest)
    if manifests[0]['source_rows'] != manifests[1]['source_rows'] or manifests[0]['sessions'] != manifests[1]['sessions']:
        raise replay.ReplayError('paired source or initial schedule differs')
    for key in ('speed', 'seed', 'session_seconds', 'transport', 'docker_bridge_masquerade',
                'agent_sha256', 'runtime_source_sha256', 'tcp_state_interval_seconds',
                'tcp_completion_timeout_seconds', 'tcp_connect_timeout_seconds'):
        if manifests[0][key] != manifests[1][key]:
            raise replay.ReplayError('paired runtime parameter differs: ' + key)
    if any(m['session_seconds'] != 180 or m['transport'] != 'tcp' or
           m['docker_bridge_masquerade'] is not False for m in manifests):
        raise replay.ReplayError('paired diagnostic requires the frozen short TCP no-NAT setup')
    a, b = [m['topology']['config'] for m in manifests]
    allowed = {'satellite link loss ("X"% )', 'sat-ground loss ("X"% )'}
    if {k for k in a if a[k] != b[k]} != allowed:
        raise replay.ReplayError('paired topology differs beyond random loss')
    return pair, manifests


def verify_arm(manifest, profile):
    run = Path(manifest['run_dir'])
    directory = run / 'sessions/session-0001'
    s = read_json(directory / 'summary.json')
    if (s['status'] != 'completed' or not s['cleanup_verified'] or s.get('cleanup_errors')
            or s.get('worker_errors') or s.get('tcp_state_errors')):
        raise replay.ReplayError('diagnostic session or cleanup did not complete')
    require_event(s['topology'], profile)
    if read_json(directory / 'config.json') != manifest['topology']['config']:
        raise replay.ReplayError('runtime configuration differs from frozen plan')
    logs = {role: replay.validate_tcp_state_log(directory / (role + '_tcp_state.jsonl'), role)
            for role in ('client', 'remote')}
    replay.require_tcp_state_diagnostics(dict(s, tcp_state_logs=logs))
    if any(logs[role]['sha256'] != s['tcp_state_logs'][role]['sha256'] for role in logs):
        raise replay.ReplayError('TCP state log hash mismatch')
    pcap = replay.validate_pcap(directory / 'client.pcap')
    if pcap['sha256'] != s['pcap']['sha256'] or replay.replay_capture_count(pcap, 'tcp') < 1:
        raise replay.ReplayError('diagnostic capture is incomplete')
    bridges = read_json(s['bridge_networks_after'])
    if (replay.sha256_file(s['bridge_networks_after']) != s['bridge_networks_after_sha256']
            or not s.get('new_bridge_names') or any(b['options'].get(
                'com.docker.network.bridge.enable_ip_masquerade') != 'false' for b in bridges)):
        raise replay.ReplayError('dynamic no-NAT bridge evidence incomplete')
    sample_dir = run / 'samples' / profile['sample_id']
    e = read_json(sample_dir / 'evidence.json')
    if e['status'] != 'success' or e['trace_sha256'] != replay.sha256_file(sample_dir / 'trace'):
        raise replay.ReplayError('sample delivery or trace integrity failed')
    source = manifest['source_rows'][0]
    if e['source_sha256'] != source['source_sha256'] or e['sample_id'] != source['sample_id']:
        raise replay.ReplayError('sample source identity mismatch')
    events, info = replay.load_sample_events(source)
    count = len(events)
    pairs = {(r['sequence'], r['direction']) for r in events}
    for role in ('client', 'remote'):
        rows = e[role + '_records']
        state_summary = e.get(role + '_tcp_state_summary') or {}
        if not state_summary.get('tcp_info_rows') or state_summary.get('errors'):
            raise replay.ReplayError('sample TCP state summary incomplete')
        if len(rows) != count or {(r['sequence'], r['direction']) for r in rows} != pairs:
            raise replay.ReplayError('missing or duplicate source event identity')
        for row in rows:
            send = (row['direction'] == 1) == (role == 'client')
            if row['action'] != ('send' if send else 'recv'):
                raise replay.ReplayError('event endpoint role mismatch')
        if e[role + '_send_errors'] or e[role + '_receive_errors']:
            raise replay.ReplayError('endpoint errors present')
    if any(r['scheduled_offset_ns'] != int(round(events[r['sequence']]['offset_ns'] / manifest['speed']))
           for r in e['remote_records']):
        raise replay.ReplayError('source schedule differs from endpoint evidence')
    if any(e[d + '_lost'] or e[d + '_send_failed'] or
           e[d + '_sent'] != e['expected_' + d] or e[d + '_received'] != e['expected_' + d]
           for d in ('inbound', 'outbound')):
        raise replay.ReplayError('application event accounting incomplete')
    control = e['handover_control']
    if control['profile'] != profile or control.get('clock_domain') != 'CLOCK_MONOTONIC':
        raise replay.ReplayError('evidence phase profile mismatch')
    command = control['anchor_command']
    commands = read_rows(directory / 'commands.jsonl')
    loss = manifest['topology']['config']['sat-ground loss ("X"% )']
    shaping = [r for r in commands if 'tc qdisc replace' in r['command'] and
               ('B7-eth27 ' in r['command'] or 'B27-eth7 ' in r['command'])]
    if len(shaping) != 2 or any(r['returncode'] != 0 or not re.search(
            r'\bloss\s+([0-9.]+)%', r['command']) or
            float(re.search(r'\bloss\s+([0-9.]+)%', r['command']).group(1)) != loss for r in shaping):
        raise replay.ReplayError('dynamic GSL loss configuration is not proven')
    if (command not in commands or command['returncode'] != 0 or
            command.get('clock_domain') != 'CLOCK_MONOTONIC' or not re.fullmatch(
            r'docker exec -i \S+ ip link set dev B27-eth13 down', command['command'])):
        raise replay.ReplayError('actual target switch command is not proven')
    start = command['end_monotonic_ns'] + int(profile['start_offset_seconds'] * 1e9)
    if control['sample_start_monotonic_ns'] != start:
        raise replay.ReplayError('sample start moved from frozen anchor')
    phase_errors = {}
    sampled_retrans = {}
    for role in ('client', 'remote'):
        states = read_rows(directory / (role + '_tcp_state.jsonl'))
        if not states or any(r['sample_id'] != profile['sample_id'] or r['sample_start_ns'] != start
                             or r.get('clock_domain') != 'CLOCK_MONOTONIC' for r in states):
            raise replay.ReplayError('TCP sample start differs from anchor')
        first = min((r for r in e[role + '_records'] if r['action'] == 'send'), key=lambda r: r['sequence'])
        scheduled = int(round(events[first['sequence']]['offset_ns'] / manifest['speed']))
        phase_errors[role] = (first['observed_ns'] - start - scheduled) / 1e9
        sampled_retrans[role] = max(r['tcp_info']['total_retrans'] for r in states)
    trace = replay.validate_trace(sample_dir / 'trace')
    if trace['rows'] != count:
        raise replay.ReplayError('export trace event count differs')
    cr = e['client_records']
    lines = [line.split() for line in (sample_dir / 'trace').read_text().splitlines()]
    if any(int(row[1]) != event['direction'] or abs(float(row[0]) -
            (event['observed_ns'] - cr[0]['observed_ns']) / 1e9) > .51e-9
            for row, event in zip(lines, cr)):
        raise replay.ReplayError('trace values differ from client event evidence')
    duration = (max(r['observed_ns'] for r in cr) - min(r['observed_ns'] for r in cr)) / 1e9
    writes = [r for r in e['remote_records'] if r['action'] == 'send']
    routes = [dict(r, sample_relative_seconds=(r['observed_ns'] - start) / 1e9)
              for r in read_rows(directory / 'client_agent.jsonl')
              if r.get('type') == 'route_change' and '9.27.27.0/24' in r['event']]
    paths = [run / 'manifest.json', run / 'frozen_config.json', directory / 'summary.json',
             directory / 'commands.jsonl', directory / 'config.json', sample_dir / 'evidence.json',
             sample_dir / 'trace', directory / 'client.pcap', Path(s['bridge_networks_after'])]
    paths += [directory / (role + suffix) for role in ('client', 'remote')
              for suffix in ('_agent.jsonl', '_tcp_state.jsonl')]
    return {'sample_id': source['sample_id'], 'delivery_complete': True,
            'phase_errors_seconds': phase_errors,
            'alignment_verified': all(0 <= v <= profile['phase_tolerance_seconds'] for v in phase_errors.values()),
            'observed_start_offset_seconds': profile['start_offset_seconds'] + phase_errors['client'],
            'anchor_command': command, 'source_duration_seconds': info['duration_seconds'] / manifest['speed'],
            'client_trace_duration_seconds': duration,
            'max_inbound_write_seconds': max((r['send_completed_ns'] - r['observed_ns']) / 1e9 for r in writes),
            'sampled_total_retrans_max': sampled_retrans, 'client_peer_route_events': routes,
            'cleanup_verified': True, 'input_hashes': {str(p): replay.sha256_file(p) for p in paths}}


def verify_pair(path):
    pair, manifests = load_pair(path)
    results = [dict(verify_arm(m, pair['profile']), loss_percent=a['loss_percent'])
               for a, m in zip(pair['arms'], manifests)]
    phase_difference = abs(results[0]['observed_start_offset_seconds'] - results[1]['observed_start_offset_seconds'])
    aligned = all(r['alignment_verified'] for r in results) and phase_difference <= PROFILE['phase_tolerance_seconds']
    return {'diagnostic_pair_completed': True, 'alignment_verified': aligned,
            'passed': aligned, 'pair': str(Path(path).resolve()),
            'phase_difference_seconds': phase_difference, 'conditions': results,
            'scientific_fidelity_verified': False}


def run_pair(path):
    path = Path(path).resolve()
    pair, manifests = load_pair(path)
    with (path.parent / '.run.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise replay.ReplayError('another paired diagnostic is active') from exc
        if any((Path(m['run_dir']) / 'sessions').exists() for m in manifests):
            raise replay.ReplayError('existing diagnostic evidence retained; use verify, or create a fresh pair')
        replay.check_docker_capabilities()
        for arm, manifest in zip(pair['arms'], manifests):
            replay.storage_guard(manifest)
            session = manifest['sessions'][0]
            replay.run_session(manifest, session, session['samples'],
                Path(manifest['run_dir']) / 'sessions' / session['session_id'], 180,
                session_tail_seconds=0.0,
                sample_start_resolver=lambda context: wait_for_anchor(context, pair['profile']))
            result = verify_arm(manifest, pair['profile'])
            replay.atomic_write_json(Path(manifest['run_dir']) / 'diagnostic_result.json', result)
            print(json.dumps({'condition_completed': True, 'loss_percent': arm['loss_percent'],
                              'alignment_verified': result['alignment_verified']}, sort_keys=True))
        result = verify_pair(path)
        replay.atomic_write_json(path.parent / 'pair_result.json', result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    plan = sub.add_parser('plan')
    plan.add_argument('--root', type=Path, required=True)
    plan.add_argument('--baseline-manifest', type=Path, default=DEFAULT_BASELINE)
    for name in ('run', 'verify'):
        sub.add_parser(name).add_argument('--pair', type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.command:
        parser.error('a command is required')
    try:
        if args.command == 'plan':
            print(json.dumps({'planned': True, 'pair': str(create_plan(args.root, args.baseline_manifest)),
                              'conditions': 2, 'samples_per_condition': 1}, indent=2))
            return 0
        result = run_pair(args.pair) if args.command == 'run' else verify_pair(args.pair)
        shown = {k: v for k, v in result.items() if k != 'conditions'}
        shown['conditions'] = [{k: r[k] for k in (
            'loss_percent', 'sample_id', 'delivery_complete', 'alignment_verified',
            'phase_errors_seconds', 'client_trace_duration_seconds', 'max_inbound_write_seconds')}
            for r in result['conditions']]
        if args.command == 'run':
            shown['summary'] = str(Path(args.pair).resolve().parent / 'pair_result.json')
        print(json.dumps(shown, ensure_ascii=False, indent=2))
        return 0 if result['passed'] else 1
    except (OSError, ValueError, KeyError, replay.ReplayError) as exc:
        print('HANDOVER DIAGNOSTIC ERROR: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
