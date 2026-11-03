#!/usr/bin/env python3
"""Bounded V5 TLS stability gate. Never starts Browser/Tor or writes sample ledgers."""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import satellite_wf_v3_dataset_candidate_20261029_v5 as v5
import satellite_wf_v3_proxy_path_diagnosis as old

OUT = ROOT / 'artifacts/reports/gre_nat_tls_recovery_20261030'
RELAY = ROOT / 'tools/satellite_wf_v3_tls_relay_20261030.py'
PLAN = ROOT / 'protocols/gre_nat_tls_recovery_20261030/frozen_plan.json'


def inputs():
    paths = [Path(__file__).resolve(), RELAY, v5.CONFIG_PATH, v5.COHORT_PLAN,
             Path(v5.collector.__file__), Path(v5.collector.dynamic.__file__),
             ROOT / 'tools/satellite_wf_v3_route_nat.py',
             ROOT / 'tools/tor_browser_starrynet_smoke_v2.py']
    return {str(p.relative_to(ROOT)): v5.sha256(p) for p in paths}


def audit():
    from audit_tls_recovery_plan_20261030 import audit as check
    value = check(PLAN)
    OUT.mkdir(parents=True, exist_ok=True)
    v5.write_json(OUT / 'plan_audit.json', value)
    return value


def run():
    if not audit()['passed']: raise RuntimeError('freeze audit failed')
    if not os.environ.get('TMUX') or os.environ.get('CONDA_DEFAULT_ENV') != 'starrynet':
        raise RuntimeError('requires tmux and conda starrynet')
    if (OUT / 'result.json').exists() or (OUT / 'topology').exists():
        raise RuntimeError('diagnosis already attempted; do not repeat automatically')
    locks = old._acquire_locks()
    protected = list(v5.OUT_DIR.glob('*ledger*.jsonl')) + list((ROOT/'protocols/satellite_wf_v3_candidate_20261029_v5').rglob('*'))
    protected = [p for p in protected if p.is_file()]
    before = {str(p): v5.sha256(p) for p in protected}
    c = v5.collector
    d = c.dynamic
    probes = []
    real_command = d.fixed.run_command
    real_relay = c.v2_runner.start_host_relay
    def command(args, timeout=60, check=True):
        args = [str(x) for x in args]
        if 'curl' not in args or '--proxy' not in args or 'https://example.com/' not in args:
            return real_command(args, timeout=timeout, check=check)
        endpoint = args[args.index('--proxy')+1]
        common = ['--noproxy', '', '--silent', '--show-error', '--verbose',
                  '--connect-timeout', '5', '--max-time', '15', '--output', '/dev/null',
                  '--write-out', '%{http_code}', 'https://example.com/']
        clean = ['env']
        for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy'):
            clean += ['-u',key]
        cases = [
            ('host_modern_direct', clean+['/home/shy/anaconda3/bin/curl','--proxy','http://127.0.0.1:17897']+common),
            ('same_image_host_direct', ['docker','run','--rm','--network','host','--entrypoint','curl','lwsen/starlab_node:1.0','--proxy','http://127.0.0.1:17897']+common),
            ('host_modern_relay', clean+['/home/shy/anaconda3/bin/curl','--proxy',endpoint]+common),
            ('gs27_old_relay', ['docker','exec',s.egress_id]+clean+['curl','--proxy',endpoint]+common),
            ('gs26_old_gre', ['docker','exec',s.client_id]+clean+['curl','--proxy',endpoint]+common),
            ('gs26_old_gre_repeat2', ['docker','exec',s.client_id]+clean+['curl','--proxy',endpoint]+common),
            ('gs26_old_gre_repeat3', ['docker','exec',s.client_id]+clean+['curl','--proxy',endpoint]+common)]
        first = None
        for label, cmd in cases:
            print('TLS_PROBE '+label, flush=True)
            r = real_command(cmd, timeout=25, check=False)
            record = dict(label=label, command=cmd, utc=v5.utc_now(), returncode=r.returncode,
                          http_status=r.stdout.strip(), stderr=r.stderr,
                          passed=r.returncode == 0 and r.stdout.strip() == '200')
            probes.append(record)
            v5.write_json(OUT / 'probes.json', probes)
            if label == 'gs26_old_gre': first = r
            if not record['passed']:
                raise old.DiagnosticBoundary('first failed probe; stop and preserve closure evidence')
        # No helper can be started even if the original route probe succeeds.
        raise old.DiagnosticBoundary('expected TLS diagnostic stop before Browser/Tor helper')
    try:
        if c.active_v3_collectors(): raise RuntimeError('active V3 collector')
        v5.configure_collector()
        d.DYNAMIC_ARTIFACTS = OUT / 'topology'
        preflight = d.fixed.preflight()
        config = v5.read_json(v5.BROWSER_CONFIG)
        pilot = v5.read_json(v5.COHORT_PLAN)
        s = c.BrowserTorSession(pilot, {'sample_id':'tls-diagnostic-20261030'}, config, v5.BROWSER_CONFIG)
        s.source_paths += [Path(__file__).resolve(), RELAY]
        def no_helper(): raise RuntimeError('Browser helper forbidden')
        s._start_browser_helper = no_helper
        def report(run_dir, summary):
            Path(run_dir, 'REPORT.md').write_text('Diagnostic only; controlled stop before Browser/Tor. See result.json.\n')
        s.write_report = report
        c.v2_runner.start_host_relay = lambda script,run_dir,listen,upstream: real_relay(RELAY,run_dir,listen,upstream)
        d.fixed.run_command = command
        result = d.run_scenario('dynamic_no_handover', browser_session=s, preflight_result=preflight,
                                topology_duration_seconds=d.BROWSER_TOPOLOGY_SECONDS,
                                simulation_start_utc=d.BROWSER_SIMULATION_START_UTC)
        raw = v5.read_json(result['summary'])
        after = {str(p):v5.sha256(p) for p in protected}
        value = dict(result=result, probes=probes,
                     protected_inputs_unchanged=before == after,
                     protected_input_hashes_before=before, protected_input_hashes_after=after,
                     cleanup={k:raw.get(k) for k in ('cleanup_verified','route_nat_restored','docker_inventory_restored')},
                     relay_cleanup_verified=raw.get('browser_tor',{}).get('host_relay_cleanup_verified'),
                     browser_tor_started=False, collection_started=False, training_started=False,
                     diagnostic_completed=len(probes)==7,
                     consecutive_gre_successes=sum(p['passed'] for p in probes if p['label'].startswith('gs26_old_gre')))
        v5.write_json(OUT / 'result.json', value)
    finally:
        d.fixed.run_command = real_command
        c.v2_runner.start_host_relay = real_relay
        old._release_locks(locks)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['audit','run'])
    a=parser.parse_args()
    if a.command == 'audit':
        r=audit(); print(json.dumps(r)); sys.exit(0 if r['passed'] else 2)
    else: run()
