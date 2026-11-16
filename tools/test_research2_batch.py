#!/usr/bin/env python3
"""Offline tests for frozen Research 2 batch planning and gates."""

from __future__ import print_function

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parent))
import research2_batch as batch


class Research2BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_root = Path(tempfile.mkdtemp(prefix="research2-batch-tests-"))
        cls.input_root = cls.temp_root / "input"
        cls.input_root.mkdir()
        for class_id in range(75):
            for repeat_id in range(80):
                duration = repeat_id // 2 + 1
                path = cls.input_root / ("{0}-{1}".format(class_id, repeat_id))
                path.write_text("0 1\n{0} -1\n".format(duration), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(str(cls.temp_root), ignore_errors=True)

    def _fake_core_planner(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(list(command))
            self.assertEqual(command[2], "plan")
            option = lambda name: command[command.index(name) + 1]
            ids_path = Path(option("--sample-ids"))
            ids_doc = json.loads(ids_path.read_text(encoding="utf-8"))
            ids = ids_doc["sample_ids"]
            cohort_key = option("--cohort-key")
            topology_mode = option("--topology-mode")
            diagnostic_mode = (option("--diagnostic-mode")
                               if "--diagnostic-mode" in command else None)
            scenario = option("--scenario") if "--scenario" in command else None
            batch_path = Path(option("--batch-manifest"))
            state = json.loads(batch_path.read_text(encoding="utf-8"))
            source_map = {row["sample_id"]: row for row in state["source_rows"]}
            run_root = Path(option("--run-root"))
            run_dir = run_root / ("mock-{0:02d}".format(len(calls)))
            run_dir.mkdir(parents=True)
            manifest_path = run_dir / "manifest.json"
            manifest = {
                "cohort_key": cohort_key,
                "source_ids_sha256": hashlib.sha256(ids_path.read_bytes()).hexdigest(),
                "source_count": len(ids),
                "source_rows": [source_map[sample_id] for sample_id in ids],
                "status": "planned",
                "mode": ("diagnostic" if diagnostic_mode else
                         "pilot" if "--pilot" in command else "formal"),
                "diagnostic_mode": diagnostic_mode,
                "scenario": scenario,
                "topology": {"mode": topology_mode},
                "tcp_completion_timeout_seconds": int(
                    option("--tcp-completion-seconds")
                    if "--tcp-completion-seconds" in command else "120"),
                "run_dir": str(run_dir),
                "dataset_output": option("--dataset-output"),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps({"planned": True,
                                                      "manifest": str(manifest_path)}),
                                   stderr="")
        return runner, calls

    def _plan(self, name="batch-test"):
        runner, calls = self._fake_core_planner()
        result = batch.plan_batch(
            input_root=self.input_root,
            artifacts_root=self.temp_root / "artifacts" / name,
            batch_id="batch-" + name,
            owner_id="codex-test", service_name="starrynet-test",
            runner=runner)
        return result, calls

    def test_discovery_and_plan_freeze_all_four_cohorts(self):
        result, calls = self._plan("plan")
        manifest_path = Path(result["batch_manifest"])
        state = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(state["input_file_count"], 6000)
        self.assertEqual(len(state["source_hashes"]), 6000)
        self.assertEqual(len(state["source_ids"]["sample_ids"]), 6000)
        self.assertEqual(len(state["pilot_ids"]), 150)
        self.assertEqual(len(state["dynamic_ids"]), 5)
        self.assertEqual(len(state["deadline_ids"]), 3)
        self.assertEqual(len(calls), 12)  # 4 pilot + 4 full + 2 dynamic + 2 deadline
        self.assertEqual(state["status"], "planned")
        self.assertEqual(state["stage"], "planned")

        for class_id in range(75):
            selected = [value for value in state["pilot_ids"]
                        if value.startswith(str(class_id) + "-")]
            self.assertEqual(selected, ["{0}-0".format(class_id),
                                        "{0}-78".format(class_id)])
        deadline_commands = [command for command in calls
                             if "--diagnostic-mode" in command]
        self.assertEqual(len(deadline_commands), 4)  # stable/crossing + deadline arms
        for seconds in ("30", "120"):
            matching = [command for command in deadline_commands
                        if "--tcp-completion-seconds" in command and
                        command[command.index("--tcp-completion-seconds") + 1] == seconds]
            self.assertEqual(len(matching), 1)
            self.assertIn("fixed", matching[0])
            self.assertIn("base", matching[0])
        dynamic_commands = [command for command in calls
                            if "--diagnostic-mode" in command and
                            command[command.index("--diagnostic-mode") + 1]
                            in ("stable", "crossing")]
        self.assertEqual(len(dynamic_commands), 2)
        for command in dynamic_commands:
            self.assertEqual(command[command.index("--link-loss-percent") + 1], "0")
        for key, cohort in state["cohorts"].items():
            ids_path = Path(cohort["ids_file"])
            self.assertEqual(hashlib.sha256(ids_path.read_bytes()).hexdigest(),
                             cohort["sha256"], key)
        self.assertEqual(state["source_ids_sha256"],
                         hashlib.sha256(Path(state["source_ids_file"]).read_bytes()).hexdigest())

        capacity_calls = []

        def fake_capacity(command, **kwargs):
            capacity_calls.append(list(command))
            gate_path = Path(command[command.index("--output") + 1])
            gate_path.write_text(json.dumps({"passed": True,
                                             "required_free_bytes": 20}),
                                 encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")

        capacity = batch._capacity_gate(manifest_path, fake_capacity)
        capacity_command = capacity_calls[0]
        self.assertEqual(capacity_command[2], "capacity")
        pilot_start = capacity_command.index("--pilot-manifests") + 1
        full_start = capacity_command.index("--full-manifests") + 1
        self.assertEqual(capacity_command[pilot_start:pilot_start + 4],
                         [state["manifests"]["pilot"][name]["manifest"]
                          for name in batch.SCENARIOS])
        self.assertEqual(capacity_command[full_start:full_start + 4],
                         [state["manifests"]["full"][name]["manifest"]
                          for name in batch.SCENARIOS])
        self.assertEqual(Path(capacity["path"]),
                         manifest_path.parent / "capacity_gate.json")

    def test_selection_is_deterministic_on_duration_ties(self):
        rows = batch.discover_sources(self.input_root)
        cohorts = batch.select_cohorts(rows)
        expected = []
        for class_id in range(75):
            expected.extend(("{0}-0".format(class_id),
                             "{0}-78".format(class_id)))
        self.assertEqual(cohorts["pilot"], expected)
        self.assertEqual(cohorts["dynamic"], ["0-0", "18-0", "37-0", "56-0", "74-0"])

    def test_plan_updates_preserve_core_frozen_topology(self):
        result, _ = self._plan("preserve")
        path = Path(result["batch_manifest"])
        state = json.loads(path.read_text(encoding="utf-8"))
        state["frozen_topology"] = {"sha256": "frozen-topology-hash",
                                    "time_index": 23}
        path.write_text(json.dumps(state), encoding="utf-8")
        batch.update_batch(path, {"stage": "test-progress"})
        updated = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(updated["frozen_topology"], state["frozen_topology"])

    def test_run_never_replans_and_resume_uses_existing_manifest(self):
        result, _ = self._plan("resume")
        path = Path(result["batch_manifest"])
        state = json.loads(path.read_text(encoding="utf-8"))
        entry = state["manifests"]["pilot"]["base"]
        child_path = Path(entry["manifest"])
        child = json.loads(child_path.read_text(encoding="utf-8"))
        child["status"] = "preflight_passed"
        child["preflight"] = {"status": "passed"}
        child_path.write_text(json.dumps(child), encoding="utf-8")
        calls = []

        def fail_on_run(command, **kwargs):
            calls.append(list(command))
            return SimpleNamespace(returncode=9, stdout="", stderr="injected stop")

        with self.assertRaises(batch.BatchError):
            batch.run_batch(path, resume=True, runner=fail_on_run)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], "run")
        self.assertIn("--resume", calls[0])
        self.assertNotIn("plan", [command[2] for command in calls])
        latest = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(latest["status"], "failed")

    def test_capacity_gate_and_pilot_gate_fail_closed(self):
        passed = batch.capacity_gate(100, 40, safety_bytes=20)
        failed = batch.capacity_gate(79, 40, safety_bytes=20)
        self.assertTrue(passed["passed"])
        self.assertEqual(passed["required_free_bytes"], 80)
        self.assertFalse(failed["passed"])
        with self.assertRaises(batch.BatchError):
            batch._pilot_gate({"complete": False})
        self.assertTrue(batch._pilot_gate({"complete": True}))

    def test_missing_full_outputs_cannot_be_reported_complete(self):
        result, _ = self._plan("incomplete")
        path = Path(result["batch_manifest"])
        state = json.loads(path.read_text(encoding="utf-8"))
        state["status"] = "complete"  # corrupt claim must be downgraded by actual audit
        path.write_text(json.dumps(state), encoding="utf-8")
        audit = batch.audit_full_coverage(path)
        self.assertFalse(audit["complete"])
        status = batch.status_batch(path)
        self.assertEqual(status["status"], "integrity_error")
        self.assertFalse(status["complete"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(batch.main(["status", "--batch", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
