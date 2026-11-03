import copy
import json
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import audit_tls_recovery_plan_20261030 as audit

class RecoveryAuditTest(unittest.TestCase):
    def test_frozen_plan_passes(self):
        result=audit.audit()
        self.assertTrue(result['passed'],result['errors'])
        self.assertFalse(result['collection_execution_ready'])
        self.assertFalse(result['root_cause_resolved'])

    def changed_plan(self, mutate):
        original=json.loads(audit.DEFAULT.read_text())
        p=copy.deepcopy(original)
        mutate(p)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'frozen_plan.json'
            path.write_text(json.dumps(p))
            path.with_name('freeze_hashes.json').write_text(json.dumps(dict(
                plan_sha256=audit.sha(path),auditor_sha256=audit.sha(audit.__file__))))
            return audit.audit(path)

    def test_collection_permission_cannot_be_added(self):
        result=self.changed_plan(lambda p:p.update(collection_allowed=True))
        self.assertFalse(result['passed'])
        self.assertIn('scope changed',result['errors'])

    def test_modified_runtime_hash_rejected(self):
        def change(p):
            p['frozen_inputs']['tools/diagnose_gre_nat_tls_recovery_20261030.py']='0'*64
        result=self.changed_plan(change)
        self.assertFalse(result['passed'])
        self.assertTrue(any('input changed:' in e for e in result['errors']))

if __name__=='__main__': unittest.main()
