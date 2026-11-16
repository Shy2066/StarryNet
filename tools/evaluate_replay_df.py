#!/usr/bin/env python3
"""Audit paired pilot data, then manually evaluate a frozen 75-class DF.

Audit loads weights strictly but never runs inference. Evaluation uses an audited
NPZ and checks all recorded artifact hashes before running the model.
"""
import argparse
import csv
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
WFLIB = Path('/home/shy/Project/Website-Fingerprinting-Library')
RUN = Path('/mnt/HDD4T/shy/StarryNet_E_v4/pilot_tcp_no_nat_20261111/runs/20261111T032636_222983Z')
DEFAULT_OUTPUT = ROOT / 'artifacts/reports/wf_model_data_audit_20261111'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def encoded_trace(path, length=10000):
    values = np.loadtxt(path, ndmin=2)
    if values.shape[1] != 2 or not len(values) or not np.isfinite(values).all():
        raise ValueError('Invalid trace: ' + str(path))
    if (values[:, 0] < 0).any() or not np.isin(values[:, 1], [-1, 1]).all():
        raise ValueError('Invalid timestamp/direction: ' + str(path))
    values = values[np.argsort(values[:, 0], kind='stable')]
    t = values[:, 0].astype(np.float32)
    t[t == 0] = np.nextafter(np.float32(0), np.float32(1))
    out = np.zeros(length, dtype=np.float32)
    n = min(length, len(values))
    out[:n] = t[:n] * values[:n, 1]
    return out


def row_key(x, y):
    return int(y), hashlib.sha256(np.asarray(x, dtype=np.float32).tobytes()).hexdigest()


def load_model(checkpoint, model_file):
    import torch
    spec = importlib.util.spec_from_file_location('audited_df', model_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    model = module.DF(75)
    weights = torch.load(checkpoint, map_location='cpu', weights_only=True)
    model.load_state_dict(weights, strict=True)
    model.eval()
    return model


def audit(args):
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / 'audit.json'
    if report_path.exists():
        raise FileExistsError('Audit already exists; choose a new --output directory')
    bindings = {}
    def bind(path):
        bindings[str(path.resolve())] = sha(path)
    manifest_path = args.run / 'manifest.json'
    dataset_manifest_path = args.run / 'dataset_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    exported = json.loads(dataset_manifest_path.read_text())
    training_manifest = WFLIB / 'logs/domain_runs/tor_clean_3seed/manifest.json'
    checkpoint = WFLIB / 'checkpoints/domain_runs/tor_clean_3seed/tor_fiber/DF/seed_42.pth'
    model_file = WFLIB / 'WFlib/models/DF.py'
    for path in [Path(__file__), manifest_path, dataset_manifest_path, training_manifest, checkpoint, model_file]:
        bind(path)
    config = json.loads(training_manifest.read_text())
    assert config['status'] == 'complete'
    assert config['config']['resolved_model_configs']['DF']['feature'] == 'DIR'
    assert config['config']['resolved_model_configs']['DF']['seq_len'] == 5000
    load_model(checkpoint, model_file)  # Strict compatibility check only; no forward pass.
    membership = {}
    split_counts = {}
    for split in ['train', 'valid', 'test']:
        path = WFLIB / 'datasets/tor_fiber' / (split + '.npz')
        bind(path)
        with np.load(path) as d:
            x, y = d['X'], d['y']
        split_counts[split] = len(y)
        for index, (row, label) in enumerate(zip(x, y)):
            membership.setdefault(row_key(row, label), []).append((split, index))
    source_rows = {s['sample_id']: s for session in manifest['sessions'] for s in session['samples']}
    rows, originals, replays, labels = [], [], [], []
    ids = set()
    for item in exported['samples']:
        sid = item['sample_id']
        if sid in ids:
            raise ValueError('Duplicate sample ID: ' + sid)
        ids.add(sid)
        label = int(sid.split('-')[0])
        assert label == item['class_id'] and 0 <= label < 75
        source = Path(manifest['input_root']) / sid
        replay = Path(manifest['dataset_output']) / sid
        assert sha(source) == item['source_sha256'] == source_rows[sid]['source_sha256']
        assert sha(replay) == item['trace_sha256']
        bind(source)
        bind(replay)
        raw = encoded_trace(source)
        matches = membership.get(row_key(raw, label), [])
        if len(matches) != 1:
            raise ValueError('Missing/ambiguous source split: {} {}'.format(sid, matches))
        split, index = matches[0]
        rows.append({'sample_id': sid, 'label': label, 'split': split, 'split_row': index})
        originals.append(np.sign(raw[:5000]))
        replays.append(np.sign(encoded_trace(replay)[:5000]))
        labels.append(label)
    assert len(rows) == exported['sample_count'] == 50
    packed = out / 'paired_inputs.npz'
    np.savez_compressed(packed, original=np.asarray(originals, dtype=np.float32)[:, None, :],
                        replay=np.asarray(replays, dtype=np.float32)[:, None, :],
                        labels=np.asarray(labels, dtype=np.int64),
                        sample_ids=np.asarray([r['sample_id'] for r in rows]),
                        splits=np.asarray([r['split'] for r in rows]))
    bind(packed)
    with (out / 'sample_membership.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=['sample_id', 'label', 'split', 'split_row'])
        writer.writeheader()
        writer.writerows(rows)
    report = {'audit_passed': True, 'inference_run': False, 'model': 'DF', 'seed': 42,
              'checkpoint': str(checkpoint), 'model_file': str(model_file), 'classes': 75,
              'feature': 'DIR', 'sequence_length': 5000, 'split_counts': split_counts,
              'pilot_membership': dict(Counter(r['split'] for r in rows)),
              'test_ids': [r['sample_id'] for r in rows if r['split'] == 'test'],
              'paired_inputs': str(packed), 'bindings': bindings,
              'training_provenance': 'Completed clean-run manifest; source-valid Macro-F1 selection. Historical training-time dataset hashes unavailable; current split content verified.',
              'scope': 'All50 is a paired diagnostic with train/valid overlap. Test-only is a small previously existing holdout subset, not a new independent test or full 75-class benchmark.'}
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'bindings'}, indent=2, ensure_ascii=False))


def evaluate(args):
    import torch
    from sklearn.metrics import accuracy_score, f1_score
    report = json.loads((args.output / 'audit.json').read_text())
    for path, expected in report['bindings'].items():
        if sha(path) != expected:
            raise ValueError('Artifact changed since audit: ' + path)
    result_dir = args.output / ('evaluation_' + args.subset)
    if result_dir.exists():
        raise FileExistsError('Evaluation output already exists: ' + str(result_dir))
    with np.load(report['paired_inputs']) as data:
        keep = data['splits'] == 'test' if args.subset == 'test' else np.ones(len(data['labels']), dtype=bool)
        y = data['labels'][keep]
        ids = data['sample_ids'][keep]
        inputs = {domain: data[domain][keep] for domain in ['original', 'replay']}
    if not len(y):
        raise ValueError('No eligible test samples')
    torch.set_num_threads(2)
    model = load_model(report['checkpoint'], report['model_file']).to(args.device)
    results, predictions = {}, {}
    with torch.inference_mode():
        for domain, x in inputs.items():
            pred = []
            for i in range(0, len(x), 16):
                pred.extend(model(torch.from_numpy(x[i:i+16]).to(args.device)).argmax(1).cpu().tolist())
            predictions[domain] = np.asarray(pred)
            results[domain] = {'accuracy': float(accuracy_score(y, pred)),
                               'macro_f1_present_classes': float(f1_score(y, pred, labels=np.unique(y), average='macro', zero_division=0))}
    results.update({'subset': args.subset, 'sample_count': len(y), 'present_labels': np.unique(y).tolist(),
                    'output_classes': 75, 'diagnostic_only': True,
                    'paired_prediction_agreement': float(np.mean(predictions['original'] == predictions['replay'])),
                    'accuracy_delta_replay_minus_original': results['replay']['accuracy'] - results['original']['accuracy'],
                    'audit_sha256': sha(args.output / 'audit.json'), 'scope': report['scope']})
    result_dir.mkdir()
    (result_dir / 'metrics.json').write_text(json.dumps(results, indent=2) + '\n')
    with (result_dir / 'predictions.csv').open('w') as f:
        writer = csv.writer(f)
        writer.writerow(['sample_id', 'label', 'original_prediction', 'replay_prediction'])
        writer.writerows(zip(ids, y, predictions['original'], predictions['replay']))
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['audit', 'evaluate'])
    parser.add_argument('--run', type=Path, default=RUN)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--subset', choices=['test', 'all'], default='test')
    parser.add_argument('--device', default='cpu')
    args = parser.parse_args()
    (audit if args.action == 'audit' else evaluate)(args)


if __name__ == '__main__':
    main()
