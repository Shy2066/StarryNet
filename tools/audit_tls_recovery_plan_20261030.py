#!/usr/bin/env python3
"""Read-only structural and hash audit of the post-diagnosis stability plan."""
import hashlib
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/'protocols/gre_nat_tls_recovery_20261030/frozen_plan.json'


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def audit(path=DEFAULT):
    path=Path(path)
    p=json.loads(path.read_text())
    errors=[]
    def require(test,msg):
        if not test: errors.append(msg)
    require(p.get('plan_id')=='gre-nat-tls-recovery-20261030-r1','unexpected plan id')
    require(p.get('status')=='frozen_diagnostic_only','unsafe plan status')
    require(p.get('root_cause_resolved') is False,'historical root cause remains unresolved')
    require(p.get('collection_allowed') is False and p.get('training_allowed') is False,'scope changed')
    require(p.get('max_parallel_runs')==1 and p.get('topology_runs_max')==1,'topology budget changed')
    require(p.get('probes_max')==7 and p.get('consecutive_gre_successes_required')==3,'probe budget changed')
    require(p.get('on_gate_failure')=='stop_and_replan_no_automatic_retry','stop policy changed')
    require(p.get('probe_target')=='https://example.com/','target changed')
    for rel,digest in p['frozen_inputs'].items():
        f=ROOT/rel
        require(f.is_file() and sha(f)==digest,'input changed: '+rel)
    require(p.get('probe_order')==['host_modern_direct','same_image_host_direct','host_modern_relay','gs27_old_relay','gs26_old_gre','gs26_old_gre_repeat2','gs26_old_gre_repeat3'],'probe order changed')
    require(p.get('closure_logging')==['direction','byte_count','forwarded_count','eof','socket_error'],'closure observations changed')
    require(p.get('tls_version_override') is False and p.get('certificate_verification_required') is True,'TLS policy changed')
    freeze=json.loads(path.with_name('freeze_hashes.json').read_text())
    require(freeze.get('plan_sha256')==sha(path),'plan freeze hash mismatch')
    require(freeze.get('auditor_sha256')==sha(__file__),'auditor hash mismatch')
    result=json.loads((ROOT/p['diagnostic_result']).read_text())
    require(result.get('diagnostic_completed') is True and result.get('protected_inputs_unchanged') is True,'initial diagnosis incomplete or changed inputs')
    require(all(v is True for v in result.get('cleanup',{}).values()) and result.get('relay_cleanup_verified') is True,'initial cleanup not verified')
    return dict(plan_id=p['plan_id'],passed=not errors,errors=errors,plan_sha256=sha(path),
                diagnostic_execution_ready=not errors,collection_execution_ready=False,
                stability_gate_passed=False,root_cause_resolved=False,
                collection_started=False,training_started=False)

if __name__=='__main__':
    r=audit(Path(sys.argv[1]) if len(sys.argv)>1 else DEFAULT)
    print(json.dumps(r,indent=2)); sys.exit(0 if r['passed'] else 2)
