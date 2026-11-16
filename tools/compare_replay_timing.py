#!/usr/bin/env python3
"""Offline paired application-event timing audit; never starts emulation."""
import argparse
from collections import Counter, defaultdict
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import numpy as np

import replay_trace_over_starrynet as replay


def quantile(values, q):
    return float(np.percentile(values, q)) if len(values) else None


def ks_distance(a, b):
    """Descriptive two-ECDF distance, including ties; no hypothesis test."""
    a, b = np.sort(a), np.sort(b)
    if not len(a) or not len(b):
        return None
    support = np.unique(np.concatenate((a, b)))
    return float(np.max(np.abs(np.searchsorted(a, support, side='right') / float(len(a))
                               - np.searchsorted(b, support, side='right') / float(len(b)))))


def burst_sizes(times, directions, idle_seconds=None):
    """Consecutive same-direction events; optionally split on gap > idle."""
    sizes = []
    for i, direction in enumerate(directions):
        if i == 0 or direction != directions[i - 1] or (
                idle_seconds is not None and times[i] - times[i - 1] > idle_seconds):
            sizes.append(1)
        else:
            sizes[-1] += 1
    return np.asarray(sizes, dtype=int)


def inversion_count(sequence):
    """Count source-order inversions in an observed permutation in O(n log n)."""
    if sorted(sequence) != list(range(len(sequence))):
        raise ValueError('sequence must be a complete source-ID permutation')
    tree = [0] * (len(sequence) + 1)
    count = 0
    for seen, value in enumerate(sequence):
        index, prefix = value + 1, 0
        while index:
            prefix += tree[index]
            index -= index & -index
        count += seen - prefix
        index = value + 1
        while index < len(tree):
            tree[index] += 1
            index += index & -index
    return count


def event_timings(events, client_records, remote_records, start_ns):
    """Join by sequence, never by observed row position. All clocks monotonic."""
    count = len(events)
    client = {r['sequence']: r for r in client_records}
    remote = {r['sequence']: r for r in remote_records}
    if len(client_records) != count or len(remote_records) != count or set(client) != set(range(count)) or set(remote) != set(range(count)):
        raise ValueError('missing or duplicate event identity')
    result = []
    first_ns = min(r['observed_ns'] for r in client_records)
    for event in events:
        seq, direction = event['sequence'], event['direction']
        c, r = client[seq], remote[seq]
        expected_action = 'send' if direction == 1 else 'recv'
        remote_action = 'recv' if expected_action == 'send' else 'send'
        if c['direction'] != direction or r['direction'] != direction or c['action'] != expected_action or r['action'] != remote_action:
            raise ValueError('event direction/action mismatch')
        sender, receiver = (c, r) if direction == 1 else (r, c)
        scheduled_ns = event['offset_ns']
        # Remote records retain the unnormalised protocol offset.
        if r['scheduled_offset_ns'] != scheduled_ns:
            raise ValueError('source/scheduled offset mismatch')
        send_ns, recv_ns = sender['observed_ns'], receiver['observed_ns']
        complete_ns = sender['send_completed_ns']
        if recv_ns < send_ns or complete_ns < send_ns:
            raise ValueError('inconsistent monotonic clock order')
        result.append({'sequence': seq, 'direction': direction,
                       'source_offset_seconds': scheduled_ns / 1e9,
                       'replay_offset_seconds': (c['observed_ns'] - first_ns) / 1e9,
                       'aligned_shift_ms': ((c['observed_ns'] - first_ns) - scheduled_ns) / 1e6,
                       'sender_start_lag_ms': (send_ns - start_ns - scheduled_ns) / 1e6,
                       'sender_write_duration_ms': (complete_ns - send_ns) / 1e6,
                       'application_transfer_ms': (recv_ns - send_ns) / 1e6})
    return result


def load_export(path):
    rows = [line.split() for line in path.read_text().splitlines()]
    if not rows or any(len(row) != 2 for row in rows):
        raise ValueError('invalid export trace: ' + str(path))
    times = np.asarray([float(row[0]) for row in rows])
    directions = np.asarray([int(row[1]) for row in rows])
    if not np.all(np.isfinite(times)) or np.any(np.diff(times) < 0) or not set(directions).issubset({-1, 1}):
        raise ValueError('invalid export values: ' + str(path))
    return times, directions


def compare_shape(source_times, source_directions, replay_times, replay_directions):
    if len(source_times) != len(replay_times) or Counter(source_directions) != Counter(replay_directions):
        raise ValueError('unpaired event counts')
    source_iat, replay_iat = np.diff(source_times), np.diff(replay_times)
    if np.any(source_iat < 0) or np.any(replay_iat < 0):
        raise ValueError('negative IAT')
    row = {'source_duration_s': float(source_times[-1] - source_times[0]),
           'replay_duration_s': float(replay_times[-1] - replay_times[0]),
           'direction_position_mismatch_fraction': float(np.mean(source_directions != replay_directions)),
           'iat_ecdf_ks': ks_distance(source_iat, replay_iat),
           'iat_wasserstein_ms': float(np.mean(np.abs(np.sort(source_iat) - np.sort(replay_iat)))) * 1000 if len(source_iat) else None}
    row['duration_ratio'] = row['replay_duration_s'] / row['source_duration_s'] if row['source_duration_s'] else None
    # Resolution sensitivity only: put both IAT distributions into the same
    # 1 ms bins. This is not a quality threshold or a change to exported data.
    row['iat_ecdf_ks_1ms_bins'] = ks_distance(
        np.rint(source_iat * 1e9).astype(np.int64) // 1000000,
        np.rint(replay_iat * 1e9).astype(np.int64) // 1000000)
    for name, times, directions, iat in [('source', source_times, source_directions, source_iat), ('replay', replay_times, replay_directions, replay_iat)]:
        bursts = burst_sizes(times, directions)
        row[name + '_burst_count'] = len(bursts)
        row[name + '_burst_size_p50'] = quantile(bursts, 50)
        row[name + '_burst_size_p95'] = quantile(bursts, 95)
        for q in (50, 95, 99):
            row[name + '_iat_p' + str(q) + '_ms'] = quantile(iat * 1000, q)
        row[name + '_zero_iat_fraction'] = float(np.mean(iat == 0)) if len(iat) else None
        for threshold in (0.1, 1, 10):
            row[name + '_iat_le_' + str(threshold) + 'ms_fraction'] = float(np.mean(iat * 1000 <= threshold)) if len(iat) else None
        for direction, label in [(1, 'outbound'), (-1, 'inbound')]:
            gaps = np.diff(times[directions == direction]) * 1000
            row[name + '_' + label + '_iat_p95_ms'] = quantile(gaps, 95)
    row['burst_count_ratio'] = row['replay_burst_count'] / float(row['source_burst_count'])
    row['burst_size_ecdf_ks'] = ks_distance(burst_sizes(source_times, source_directions), burst_sizes(replay_times, replay_directions))
    return row


def write_csv(path, rows):
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def cdf_plot(ax, values, label, **kwargs):
    ordered = np.sort(values)
    indices = np.unique(np.linspace(0, len(ordered) - 1, min(1500, len(ordered))).astype(int))
    ax.plot(ordered[indices], (indices + 1) / float(len(ordered)), label=label, **kwargs)


def plots(output, rows, shapes, pooled, top):
    os.environ.setdefault('MPLCONFIGDIR', '/tmp/starrynet-timing-matplotlib')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False})
    fig, axes = plt.subplots(2, 2, figsize=(11, 8))
    ax = axes[0, 0]
    for cls in sorted(set(r['class_id'] for r in rows)):
        group = [r for r in rows if r['class_id'] == cls]
        ax.scatter([r['source_duration_s'] for r in group], [r['replay_duration_s'] for r in group], label='Class ' + str(cls), alpha=.75)
    lim = max(max(r['source_duration_s'], r['replay_duration_s']) for r in rows) * 1.05
    ax.plot([0, lim], [0, lim], '--', color='gray', linewidth=1)
    ax.set(xlabel='Source duration (s)', ylabel='TCP replay duration (s)', title='Paired trace duration (50 samples)')
    ax.legend(fontsize=8)
    ax = axes[0, 1]
    for key, label in [('source_iat', 'Source'), ('replay_iat', 'TCP replay')]:
        cdf_plot(ax, np.concatenate(pooled[key]) * 1000, label)
    ax.set_xscale('symlog', linthresh=.001)
    ax.set(xlabel='Adjacent application-event interval (ms)', ylabel='ECDF', title='Event-weighted interval distribution')
    ax.legend()
    ax = axes[1, 0]
    ax.scatter([r['source_burst_count'] for r in rows], [r['replay_burst_count'] for r in rows], alpha=.75)
    lim = max(max(r['source_burst_count'], r['replay_burst_count']) for r in rows) * 1.05
    ax.plot([0, lim], [0, lim], '--', color='gray', linewidth=1)
    ax.set(xlabel='Source directional bursts', ylabel='Replay directional bursts', title='Same-direction runs; no idle cutoff')
    ax = axes[1, 1]
    for key, label in [('sender_start_lag_ms', 'Sender start lag'), ('application_transfer_ms', 'Send-start to receive')]:
        cdf_plot(ax, np.asarray(pooled[key]), label)
    ax.set_xscale('symlog', linthresh=.001)
    ax.set(xlabel='Application timing (ms)', ylabel='ECDF', title='Observed timing components; both directions')
    ax.legend()
    fig.tight_layout()
    for ext in ('png', 'pdf'):
        fig.savefig(str(output / ('timing_overview.' + ext)), dpi=180)
    plt.close(fig)
    fig, axes = plt.subplots(len(top), 2, figsize=(11, 3 * len(top)), squeeze=False)
    for index, row in enumerate(top):
        sid = row['sample_id'];source, replayed, records = shapes[sid]
        ax = axes[index, 0]
        ax.plot(source, np.arange(1, len(source) + 1), label='Source')
        ax.plot(replayed, np.arange(1, len(replayed) + 1), label='Replay')
        ax.set(title=sid + ': duration ratio %.2f' % row['duration_ratio'], xlabel='Time since first event (s)', ylabel='Cumulative events')
        ax.legend()
        ax = axes[index, 1]
        for direction, label in [(1, 'Outbound'), (-1, 'Inbound')]:
            group = [r for r in records if r['direction'] == direction]
            ax.scatter([r['source_offset_seconds'] for r in group], [r['aligned_shift_ms'] / 1000 for r in group], s=4, alpha=.5, label=label)
        ax.axhline(0, color='gray', linewidth=1)
        ax.set(title='Paired event shift after first-event alignment', xlabel='Source scheduled offset (s)', ylabel='Replay minus source (s)')
        ax.legend()
    fig.tight_layout()
    for ext in ('png', 'pdf'):
        fig.savefig(str(output / ('largest_duration_changes.' + ext)), dpi=180)
    plt.close(fig)


def run(args):
    output = args.output.resolve()
    if output.exists():
        raise ValueError('use a new report directory: ' + str(output))
    manifest = replay.load_manifest(args.manifest)
    replay.check_frozen_config(manifest)
    if manifest.get('transport') != 'tcp' or manifest.get('trace_semantics') != 'client_application_events':
        raise ValueError('requires TCP application-event evidence')
    run_dir, dataset = Path(manifest['run_dir']), Path(manifest['dataset_output'])
    hashes = {}
    def track(path):
        path = Path(path).resolve()
        hashes[str(path)] = replay.sha256_file(path)
        return path
    track(args.manifest);track(run_dir / 'frozen_config.json');track(run_dir / 'source/manifest.json')
    metadata = {}
    session_ids = {json.loads((run_dir / 'samples' / r['sample_id'] / 'evidence.json').read_text())['session_id'] for r in manifest['source_rows']}
    for session_id in sorted(session_ids):
        directory = run_dir / 'sessions' / session_id
        track(directory / 'summary.json')
        for role in ('client', 'remote'):
            with track(directory / (role + '_agent.jsonl')).open() as f:
                for line in f:
                    row = json.loads(line)
                    if row.get('type') == 'sample_done':
                        key = (session_id, row['sample_id'], role, row['finished_ns'])
                        if key in metadata:
                            raise ValueError('duplicate completion identity')
                        metadata[key] = row['completion_deadline_ns']
    output.mkdir(parents=True)
    rows, sensitivity, pooled, shapes = [], [], defaultdict(list), {}
    event_file = gzip.open(str(output / 'paired_event_timing.csv.gz'), 'wt', encoding='utf-8', newline='')
    writer = None
    for entry in sorted(manifest['source_rows'], key=lambda x: tuple(map(int, x['sample_id'].split('-')))):
        sid = entry['sample_id']
        source_path = track(entry['source_path'])
        info = replay.read_trace(source_path)
        evidence_path = track(run_dir / 'samples' / sid / 'evidence.json')
        evidence = json.loads(evidence_path.read_text())
        export_path = track(dataset / sid)
        if info['sha256'] != entry['source_sha256'] or info['sha256'] != evidence['source_sha256'] or hashes[str(export_path)] != evidence['trace_sha256']:
            raise ValueError('artifact hash mismatch: ' + sid)
        if evidence['status'] != 'success' or any(evidence[k] for k in ('client_send_errors', 'client_receive_errors', 'remote_send_errors', 'remote_receive_errors')):
            raise ValueError('sample not complete: ' + sid)
        events = [dict(e, offset_ns=int(round(e['offset_ns'] / manifest['speed']))) for e in info['events']]
        source_times = np.asarray([e['offset_ns'] / 1e9 for e in events])
        source_directions = np.asarray([e['direction'] for e in events])
        rt, rd = load_export(export_path)
        c = evidence['client_records'];r = evidence['remote_records']
        if [(x['observed_ns'], x['sequence']) for x in c] != sorted((x['observed_ns'], x['sequence']) for x in c):
            raise ValueError('client evidence is not in observed order')
        normalized = np.asarray([(x['observed_ns'] - c[0]['observed_ns']) / 1e9 for x in c])
        if len(rt) != len(c) or not np.allclose(rt, normalized, rtol=0, atol=.51e-9) or list(rd) != [x['direction'] for x in c]:
            raise ValueError('export/evidence mismatch: ' + sid)
        deadlines = [metadata[(evidence['session_id'], sid, role, evidence[role + '_finished_ns'])] for role in ('client', 'remote')]
        if deadlines[0] != deadlines[1]:
            raise ValueError('endpoint deadline mismatch')
        start_ns = deadlines[0] - max(e['offset_ns'] for e in events) - int(manifest['tcp_completion_timeout_seconds'] * 1e9)
        details = event_timings(events, c, r, start_ns)
        row = {'sample_id': sid, 'class_id': info['class_id'], 'session_id': evidence['session_id'],
               'event_count': len(events), 'source_small_reversal_count': info['small_reversal_count'],
               'source_max_backward_ms': max((x['backward_seconds'] for x in info['small_reversals']), default=0) * 1000,
               'planned_handover_overlap_count': evidence.get('handover_count'),
               'start_reconstruction': 'exact_common_deadline_minus_last_offset_minus_grace'}
        row.update(compare_shape(source_times, source_directions, rt, rd))
        permutation = [x['sequence'] for x in c]
        inversions = inversion_count(permutation)
        row['source_order_inversions'] = inversions
        row['inverted_event_pair_fraction'] = 2.0 * inversions / (len(c) * (len(c) - 1)) if len(c) > 1 else 0
        for direction, label in [(1, 'outbound'), (-1, 'inbound')]:
            group = [x for x in details if x['direction'] == direction]
            for metric in ('sender_start_lag_ms', 'sender_write_duration_ms', 'application_transfer_ms'):
                values = [x[metric] for x in group]
                row[label + '_' + metric + '_p95'] = quantile(values, 95)
                row[label + '_' + metric + '_max'] = max(values) if values else None
        rows.append(row)
        for cutoff in (None, .01, .1, 1.0):
            f = len(burst_sizes(source_times, source_directions, cutoff));e = len(burst_sizes(rt, rd, cutoff))
            sensitivity.append({'sample_id': sid, 'idle_cutoff_seconds': cutoff,
                                'source_bursts': f, 'replay_bursts': e, 'ratio': e / float(f)})
        pooled['source_iat'].append(np.diff(source_times));pooled['replay_iat'].append(np.diff(rt))
        for detail in details:
            record = dict(sample_id=sid, **detail)
            if writer is None:
                writer = csv.DictWriter(event_file, fieldnames=list(record));writer.writeheader()
            writer.writerow(record)
            for metric in ('sender_start_lag_ms', 'sender_write_duration_ms', 'application_transfer_ms'):
                pooled[metric].append(detail[metric])
        shapes[sid] = (source_times, rt, details)
    event_file.close()
    write_csv(output / 'sample_comparison.csv', rows)
    write_csv(output / 'burst_sensitivity.csv', sensitivity)
    classes = []
    for cls in sorted(set(r['class_id'] for r in rows)):
        group = [r for r in rows if r['class_id'] == cls]
        classes.append({'class_id': cls, 'sample_count': len(group),
                        'duration_ratio_median': quantile([r['duration_ratio'] for r in group], 50),
                        'duration_ratio_max': max(r['duration_ratio'] for r in group),
                        'iat_ecdf_ks_median': quantile([r['iat_ecdf_ks'] for r in group], 50),
                        'burst_count_ratio_median': quantile([r['burst_count_ratio'] for r in group], 50)})
    write_csv(output / 'class_summary.csv', classes)
    top = sorted(rows, key=lambda r: r['duration_ratio'], reverse=True)[:3]
    summary = {'manifest': str(args.manifest.resolve()), 'dataset': str(dataset), 'sample_count': len(rows),
               'source_event_count': sum(r['event_count'] for r in rows), 'input_file_count': len(hashes),
               'source_small_reversal_samples': sum(r['source_small_reversal_count'] > 0 for r in rows),
               'reference': 'source line-order IDs, cumulative maximum of relative timestamps, rounded dispatch offsets, manifest speed',
               'interval_weighting': 'per-sample medians in sample summaries; pooled IAT ECDF is weighted by event count',
               'burst_definition': 'maximal consecutive same-direction runs in each observable sequence; no idle cutoff',
               'duration_ratio': {str(q): quantile([r['duration_ratio'] for r in rows], q) for q in (0, 50, 95, 100)},
               'duration_ratio_gt_2_count': sum(r['duration_ratio'] > 2 for r in rows),
               'duration_ratio_gt_1_1_count': sum(r['duration_ratio'] > 1.1 for r in rows),
               'burst_count_ratio': {str(q): quantile([r['burst_count_ratio'] for r in rows], q) for q in (0, 50, 95, 100)},
               'samples_with_changed_burst_count': sum(r['source_burst_count'] != r['replay_burst_count'] for r in rows),
               'direction_position_mismatch_fraction_median': quantile([r['direction_position_mismatch_fraction'] for r in rows], 50),
               'iat_ecdf_ks_median': quantile([r['iat_ecdf_ks'] for r in rows], 50),
               'iat_ecdf_ks_1ms_bins_median': quantile([r['iat_ecdf_ks_1ms_bins'] for r in rows], 50),
               'samples_with_sender_lag_gt_1s': sum(max(r[d + '_sender_start_lag_ms_max'] for d in ('outbound', 'inbound')) > 1000 for r in rows),
               'samples_with_write_block_gt_1s': sum(max(r[d + '_sender_write_duration_ms_max'] for d in ('outbound', 'inbound')) > 1000 for r in rows),
               'largest_duration_changes': [{k:r[k] for k in ('sample_id','source_duration_s','replay_duration_s','duration_ratio','source_burst_count','replay_burst_count','outbound_sender_start_lag_ms_max','inbound_sender_start_lag_ms_max','inbound_application_transfer_ms_max')} for r in top],
               'application_timing_ms': {key: {str(q): quantile(pooled[key], q) for q in (0, 50, 95, 99, 100)} for key in ('sender_start_lag_ms','sender_write_duration_ms','application_transfer_ms')},
               'source_iat_ms': {str(q): quantile(np.concatenate(pooled['source_iat']) * 1000, q) for q in (50,95,99)},
               'replay_iat_ms': {str(q): quantile(np.concatenate(pooled['replay_iat']) * 1000, q) for q in (50,95,99)},
               'pooled_iat_fractions': {name: {'zero': float(np.mean(np.concatenate(pooled[name + '_iat']) == 0)),
                                              'le_1ms': float(np.mean(np.concatenate(pooled[name + '_iat']) <= .001))}
                                        for name in ('source', 'replay')},
               'thresholds_are_descriptive_not_acceptance_gates': True,
               'network_packet_retransmissions_attributed': False, 'website_fingerprinting_evaluated': False}
    plots(output, rows, shapes, pooled, top)
    for path, digest in hashes.items():
        if replay.sha256_file(path) != digest:
            raise ValueError('input changed during analysis: ' + path)
    summary['all_input_hashes_unchanged'] = True
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    (output / 'input_hashes.json').write_text(json.dumps(hashes, indent=2) + '\n')
    shutil.copy2(str(Path(__file__).resolve()), str(output / 'analysis_script.py'))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    run(parser.parse_args())
