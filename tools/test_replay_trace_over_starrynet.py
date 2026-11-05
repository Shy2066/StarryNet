#!/usr/bin/env python3
import contextlib
import io
import inspect
import json
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from replay_trace_over_starrynet import (
    ReplayError,
    GS,
    P2_CONFIG,
    build_sessions,
    check_frozen_config,
    cmd_plan,
    final_route_snapshot,
    allocate_recovery_session,
    rebase_runtime_schedule,
    session_setup_retry_allowed,
    SatelliteRouteUnavailable,
    max_infrastructure_attempts,
    next_attempt_number,
    parse_args,
    runtime_source_hashes,
    load_sample_events,
    verification_traffic_summary,
    read_trace,
    retry_allowed,
    sample_is_valid,
    session_evidence_is_valid,
    starrynet_resources_cleared,
    stop_capture,
    validate_pcap,
    write_sample_result,
    validate_trace,
    wait_for_satellite_route,
)
from e_replay_agent import Endpoint, monotonic_ns, packet, unpack


class ReplayTraceCoreTests(unittest.TestCase):
    def test_config_uses_the_requested_file_and_isolated_argv(self):
        from starrynet.sn_utils import sn_load_file

        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first.write_text(json.dumps(P2_CONFIG), encoding="utf-8")
            alternate = dict(P2_CONFIG, Name="alternate-config")
            second.write_text(json.dumps(alternate), encoding="utf-8")
            with mock.patch.object(sys, "argv", ["test", "--sat_number", "99"]):
                args = sn_load_file(str(second), GS, argv=[])
            self.assertEqual(args.cons_name, "alternate-config")
            self.assertEqual(args.sat_number, 5)

    def test_original_starrynet_constructor_arguments_remain_compatible(self):
        from starrynet.sn_synchronizer import StarryNet

        parameters = inspect.signature(StarryNet.__init__).parameters
        self.assertEqual(list(parameters)[:5], [
            "self", "configuration_file_path", "GS_lat_long",
            "hello_interval", "AS"])
        self.assertEqual(parameters["local"].default, False)
        self.assertIsNone(parameters["argv"].default)

    def test_container_discovery_sorts_swarm_nodes_numerically(self):
        from starrynet import sn_utils

        rows = ["id-10 constellation-test.10.task",
                "id-2 constellation-test.2.task",
                "id-1 constellation-test.1.task"]
        with mock.patch.object(sn_utils, "sn_remote_cmd", return_value=rows):
            result = sn_utils.sn_get_container_info(object())
        self.assertEqual(result, ["id-1", "id-2", "id-10"])

    def test_reset_waits_until_every_swarm_container_is_ready(self):
        from starrynet import sn_utils

        ready_counts = []
        def remote_command(_remote, command):
            if command.startswith("docker ps --filter"):
                count = min(len(ready_counts) + 1, 2)
                ready_counts.append(count)
                return ["id-{0} constellation-test.{0}.task".format(index)
                        for index in range(1, count + 1)]
            return []

        with mock.patch.object(sn_utils, "sn_remote_cmd",
                               side_effect=remote_command), \
                mock.patch.object(sn_utils, "sn_remote_checked_cmd") as create, \
                mock.patch.object(sn_utils, "sleep"):
            sn_utils.sn_reset_docker_env(object(), "constellation-test", 2)
        create.assert_called_once()
        self.assertEqual(ready_counts, [1, 2])

    def test_worker_exception_is_raised_by_join(self):
        from starrynet.sn_thread import CheckedThread, WORKER_ERRORS

        WORKER_ERRORS[:] = []
        def fail():
            raise ValueError("worker failed")
        thread = CheckedThread(target=fail)
        thread.start()
        with self.assertRaisesRegex(ValueError, "worker failed"):
            thread.join()
        self.assertEqual(WORKER_ERRORS, ["worker failed"])

    def test_stop_emulation_cleans_resources_then_propagates_scheduler_error(self):
        from starrynet import sn_synchronizer

        events = []
        class Scheduler:
            alive = True
            def is_alive(self):
                return self.alive
            def request_stop(self):
                events.append("request_stop")
            def join(self, timeout=None):
                events.append("scheduler_join")
                self.alive = False
                raise RuntimeError("scheduler failed")

        class StopThread:
            def __init__(self, *_args):
                pass
            def start(self):
                events.append("cleanup_start")
            def join(self):
                events.append("cleanup_join")

        instance = sn_synchronizer.StarryNet.__new__(sn_synchronizer.StarryNet)
        instance.emulation_thread = Scheduler()
        instance.remote_ssh = object()
        instance.remote_ftp = object()
        instance.file_path = "test"
        with mock.patch.object(sn_synchronizer, "sn_Emulation_Stop_Thread",
                               StopThread):
            with self.assertRaisesRegex(RuntimeError, "scheduler failed"):
                instance.stop_emulation()
        self.assertEqual(events, ["request_stop", "scheduler_join",
                                  "cleanup_start", "cleanup_join"])

    def test_stop_emulation_quiesces_scheduler_before_resource_removal(self):
        from starrynet import sn_synchronizer

        events = []

        class Scheduler:
            alive = True
            def is_alive(self):
                return self.alive
            def request_stop(self):
                events.append("request_stop")
            def join(self, timeout=None):
                events.append(("scheduler_join", timeout))
                self.alive = False
            worker_error = None

        class StopThread:
            def __init__(self, *_args):
                events.append("cleanup_construct")
            def start(self):
                events.append("cleanup_start")
            def join(self):
                events.append("cleanup_join")

        instance = sn_synchronizer.StarryNet.__new__(sn_synchronizer.StarryNet)
        instance.emulation_thread = Scheduler()
        instance.remote_ssh = object()
        instance.remote_ftp = object()
        instance.file_path = "test"
        with mock.patch.object(sn_synchronizer, "sn_Emulation_Stop_Thread",
                               StopThread):
            instance.stop_emulation()
        self.assertEqual(events, ["request_stop", ("scheduler_join", 30),
                                  "cleanup_construct", "cleanup_start",
                                  "cleanup_join"])

    def test_cleanup_scope_ignores_unrelated_docker_changes(self):
        baseline = {"containers": ["unrelated-a"],
                    "networks": ["bridge", "unrelated-net"],
                    "services": [],
                    "starrynet_service_containers": [],
                    "starrynet_owner_networks": []}
        changed = dict(baseline, containers=["unrelated-b"],
                       networks=["bridge", "another-net"])
        self.assertTrue(starrynet_resources_cleared(baseline))
        self.assertTrue(starrynet_resources_cleared(changed))
        self.assertFalse(starrynet_resources_cleared(
            dict(changed, starrynet_service_containers=["task-a"])))
        self.assertFalse(starrynet_resources_cleared(
            dict(changed, starrynet_owner_networks=["network-a"])))
        self.assertFalse(starrynet_resources_cleared(
            dict(changed, services=["constellation-test"])))

    def test_session_evidence_requires_the_recorded_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"run_dir": str(root)}
            session = {"session_id": "session-0001"}
            session_dir = root / "sessions" / "session-0001"
            (session_dir / "route_snapshots").mkdir(parents=True)
            (session_dir / "logs").mkdir()
            for name in ("before.json", "after.json"):
                (session_dir / "route_snapshots" / name).write_text("{}")
            (session_dir / "logs" / "tcpdump.log").write_text("ok\n")
            (session_dir / "summary.json").write_text(json.dumps({
                "status": "completed", "cleanup_verified": True,
                "pcap": {"bytes": 24, "ev4_packet_count": 1},
            }))
            self.assertFalse(session_evidence_is_valid(manifest, session))
            (session_dir / "client.pcap").write_bytes(b"x" * 24)
            self.assertTrue(session_evidence_is_valid(manifest, session))

    def test_cleanup_tolerates_resources_disappearing_during_swarm_removal(self):
        from starrynet import sn_orchestrater

        outputs = ["constellation-test\n", "container-a\n", "network-a\n"]
        with mock.patch.object(sn_orchestrater.subprocess, "check_output",
                               side_effect=outputs), \
                mock.patch.object(sn_orchestrater.subprocess, "run") as run, \
                mock.patch.object(sn_orchestrater, "sleep"):
            sn_orchestrater.sn_stop_emulation()

        self.assertEqual(run.call_count, 3)
        self.assertTrue(all(call[1].get("check") is False
                            for call in run.call_args_list))

    def test_dynamic_gsl_replaces_existing_root_qdisc(self):
        from starrynet import sn_utils

        commands = []

        def record_command(_executor, command):
            commands.append(command)
            if "ip addr |" in command:
                return ["eth-test@if123\n"]
            return []

        @contextlib.contextmanager
        def no_pause(*_args, **_kwargs):
            yield

        containers = ["sat"] * 25 + ["gs26", "gs27"]
        matrix = [[0.0 for _ in range(27)] for _ in range(27)]
        matrix[12][26] = 10.85
        with mock.patch.object(sn_utils, "sn_remote_cmd", side_effect=record_command), \
                mock.patch.object(sn_utils, "sn_remote_checked_cmd",
                                  side_effect=record_command), \
                mock.patch.object(sn_utils, "sn_pause_kernel_exports", no_pause):
            sn_utils.sn_establish_new_GSL(
                containers, matrix, 25, 5, 1, 13, 27, object())

        qdisc = [command for command in commands if " tc qdisc " in command]
        self.assertEqual(len(qdisc), 2)
        self.assertTrue(all(" tc qdisc replace dev " in command
                            for command in qdisc))
        self.assertTrue(all("delay 10.85ms loss 1% rate 5Gbit" in command
                            for command in qdisc))

    def test_dynamic_delay_update_replaces_root_qdisc(self):
        from starrynet import sn_orchestrater

        with mock.patch.object(sn_orchestrater.subprocess, "check_output",
                               return_value=("qdisc netem 1: root delay 7.5ms "
                                             "1.3ms distribution normal loss 1% "
                                             "rate 5Gbit limit 1000\n")), \
                mock.patch.object(sn_orchestrater.subprocess, "run") as run:
            sn_orchestrater.sn_delay_change(0, 1, 10.85, ["a", "b"], 2)

        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call[0][0][5] == "replace"
                            for call in run.call_args_list))
        self.assertTrue(all(call[1].get("check") is True
                            for call in run.call_args_list))
        for call in run.call_args_list:
            command = call[0][0]
            self.assertIn("10.85ms", command)
            self.assertIn("1.3ms", command)
            self.assertIn("distribution", command)
            self.assertIn("normal", command)
            self.assertIn("loss", command)
            self.assertIn("1%", command)
            self.assertIn("rate", command)
            self.assertIn("5Gbit", command)
            self.assertIn("limit", command)
            self.assertIn("1000", command)

    def test_stop_capture_waits_until_tcpdump_is_not_alive_before_copy(self):
        capture = {"cid": "container-a", "remote_dir": "/tmp/e-replay-v4",
                   "remote_pcap": "/tmp/e-replay-v4/client.pcap",
                   "remote_log": "/tmp/e-replay-v4/tcpdump.log"}
        exec_outputs = ["", "alive", "alive", "", "tcpdump clean exit"]
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch("replay_trace_over_starrynet.docker_exec",
                           side_effect=exec_outputs) as docker_exec_mock, \
                mock.patch("replay_trace_over_starrynet.docker_cp") as docker_cp_mock, \
                mock.patch("replay_trace_over_starrynet.time.sleep"):
            result = stop_capture(capture, directory)

        self.assertEqual(result, Path(directory) / "client.pcap")
        self.assertEqual(docker_exec_mock.call_count, 5)
        docker_cp_mock.assert_called_once_with(
            "container-a:/tmp/e-replay-v4/client.pcap",
            Path(directory) / "client.pcap")

    def test_route_check_waits_through_handover_gap(self):
        missing = {"route": "unreachable", "interfaces": "", "qdisc": "",
                   "satellite_route": False}
        ready = {"route": "via 9.1.2.50 dev B26-eth2", "interfaces": "",
                 "qdisc": "", "satellite_route": True}
        with mock.patch("replay_trace_over_starrynet.route_snapshot",
                        side_effect=[missing, ready]) as snapshot, \
                mock.patch("replay_trace_over_starrynet.time.sleep"):
            self.assertEqual(wait_for_satellite_route("cid", "9.27.27.10", 5),
                             ready)
        self.assertEqual(snapshot.call_count, 2)

    def test_final_route_gap_is_recorded_without_raising(self):
        with mock.patch("replay_trace_over_starrynet.wait_for_satellite_route",
                        side_effect=ReplayError("temporarily unreachable")):
            result = final_route_snapshot("cid", "9.27.27.10", 5)
        self.assertFalse(result["satellite_route"])
        self.assertTrue(result["unavailable"])
        self.assertIn("temporarily unreachable", result["error"])

    def test_route_timeout_has_a_distinct_rollover_exception(self):
        missing = {"route": "unreachable", "interfaces": "", "qdisc": "",
                   "satellite_route": False}
        with mock.patch("replay_trace_over_starrynet.route_snapshot",
                        return_value=missing), \
                mock.patch("replay_trace_over_starrynet.time.monotonic",
                           side_effect=[0.0, 1.0]):
            with self.assertRaises(SatelliteRouteUnavailable):
                wait_for_satellite_route("cid", "9.27.27.10", 0.0)

    def test_recovery_session_supersedes_previous_and_copies_samples(self):
        session = {"session_id": "session-0001",
                   "samples": [{"sample_id": "0-0"}]}
        manifest = {"sessions": [session]}
        recovery = allocate_recovery_session(manifest, session)
        self.assertTrue(recovery["session_id"].startswith("recovery-"))
        self.assertLess(len(recovery["session_id"]), 64)
        self.assertEqual(session["superseded_by"], recovery["session_id"])
        self.assertEqual(recovery["recovery_of"], "session-0001")
        self.assertEqual(recovery["samples"], session["samples"])
        self.assertIsNot(recovery["samples"], session["samples"])

    def test_setup_retry_requires_clean_sample_free_startup_failure(self):
        summary = {"status": "aborted", "cleanup_verified": True,
                   "sample_results": [], "phase": "create_nodes"}
        self.assertTrue(session_setup_retry_allowed(summary, 1))
        self.assertTrue(session_setup_retry_allowed(summary, 2))
        self.assertFalse(session_setup_retry_allowed(summary, 3))
        summary["sample_results"] = [{"sample_id": "0-0", "status": "success"}]
        self.assertFalse(session_setup_retry_allowed(summary, 1))

    def test_resume_schedule_rebases_pending_suffix_at_warmup(self):
        samples = [
            {"sample_id": "0-1", "start_second": 422.0,
             "duration_seconds": 10.0, "dispatch_lead_seconds": 0.5},
            {"sample_id": "1-1", "start_second": 434.0,
             "duration_seconds": 20.0, "dispatch_lead_seconds": 1.0},
        ]
        rebased = rebase_runtime_schedule(samples, 0.5)
        self.assertEqual(rebased[0]["start_second"], 15.0)
        self.assertEqual(rebased[1]["start_second"], 26.5)
        self.assertEqual(samples[0]["start_second"], 422.0)

    def test_manifest_controls_infrastructure_attempt_limit(self):
        self.assertEqual(max_infrastructure_attempts({
            "attempt_policy": {"max_infrastructure_retries": 2}}), 3)
        self.assertEqual(max_infrastructure_attempts({}), 2)

    def write_trace(self, root, name, rows):
        path = Path(root) / name
        path.write_text("".join("{0}\t{1}\n".format(t, d) for t, d in rows),
                        encoding="utf-8")
        return path

    def test_small_reversal_is_clamped_without_reordering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_trace(directory, "0-0", [(0.0, 1), (1.0, -1),
                                                       (0.999, 1), (2.0, -1)])
            info = read_trace(path)
            self.assertEqual(info["small_reversal_count"], 1)
            self.assertEqual([event["sequence"] for event in info["events"]], [0, 1, 2, 3])
            self.assertEqual([event["offset_seconds"] for event in info["events"]],
                             [0.0, 1.0, 1.0, 2.0])

    def test_large_reversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_trace(directory, "0-0", [(0.0, 1), (0.1, -1),
                                                       (-1.0, 1)])
            with self.assertRaises(ReplayError):
                read_trace(path)

    def test_session_planner_balances_classes_and_respects_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            files = []
            for class_id in range(3):
                for repeat_id in range(4):
                    files.append(self.write_trace(
                        directory, "{0}-{1}".format(class_id, repeat_id),
                        [(0.0, 1), (0.2, -1)]))
            sessions = build_sessions(files, 2024, 100, 1.0, 0.5)
            self.assertEqual(sum(len(item["samples"]) for item in sessions), 12)
            self.assertTrue(all(item["used_seconds"] <= 100 for item in sessions))

    def test_output_validator_rejects_reversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace"
            path.write_text("0.0\t1\n0.2\t-1\n0.1\t1\n", encoding="utf-8")
            with self.assertRaises(ReplayError):
                validate_trace(path)

    def test_output_validator_accepts_both_directions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace"
            path.write_text("0.0\t1\n0.0\t-1\n0.2\t1\n", encoding="utf-8")
            result = validate_trace(path)
            self.assertEqual(result["rows"], 3)
            self.assertEqual(result["direction_counts"], {1: 2, -1: 1})

    def test_plan_command_creates_versioned_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            input_root = Path(directory) / "input"
            run_root = Path(directory) / "runs"
            output_root = Path(directory) / "output"
            input_root.mkdir()
            for class_id in range(5):
                for repeat_id in range(10):
                    self.write_trace(input_root, "{0}-{1}".format(class_id * 18, repeat_id),
                                     [(0.0, 1), (0.1, -1)])
            args = type("Args", (), {
                "input": input_root, "run_root": run_root,
                "dataset_output": output_root, "seed": 2024, "speed": 1.0,
                "session_seconds": 900, "guard_seconds": 0.5,
                "max_samples": None, "pilot": False,
            })()
            self.assertEqual(cmd_plan(args), 0)
            manifests = list(run_root.glob("*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text())
            self.assertEqual(manifest["source_count"], 50)
            self.assertTrue(manifest["topology"]["dynamic_required"])
            self.assertEqual(manifest["session_seconds"], 900)
            self.assertEqual(Path(manifest["dataset_output"]), output_root.resolve())
            self.assertTrue(manifest["source_digest_sha256"])
            self.assertTrue(all(
                session["used_seconds"] <= session["session_seconds"]
                for session in manifest["sessions"]))
            self.assertEqual(set(manifest["runtime_source_sha256"]), {
                "starrynet/sn_orchestrater.py",
                "starrynet/sn_synchronizer.py",
                "starrynet/sn_observer.py",
                "starrynet/sn_thread.py",
                "starrynet/sn_utils.py",
                "starrynet/local.py",
            })
            self.assertEqual(manifest["runtime_source_sha256"], runtime_source_hashes())

    def test_seeded_schedule_is_deterministic_and_fits_session_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = []
            for class_id in range(5):
                for repeat_id in range(10):
                    files.append(self.write_trace(
                        root, "{0}-{1}".format(class_id * 18, repeat_id),
                        [(0.0, 1), (0.1, -1)]))
            first = build_sessions(files, 2024, 900, 1.0, 0.5)
            second = build_sessions(files, 2024, 900, 1.0, 0.5)
        self.assertEqual(first, second)
        self.assertEqual(sum(len(item["samples"]) for item in first), 50)
        self.assertTrue(all(item["used_seconds"] <= item["session_seconds"] - 60
                            for item in first))

    def test_pilot_plan_defaults_to_900_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_root = root / "input"
            input_root.mkdir()
            for class_id in (0, 18, 37, 56, 74):
                for repeat_id in range(10):
                    self.write_trace(input_root,
                                     "{0}-{1}".format(class_id, repeat_id),
                                     [(0.0, 1), (0.1, -1)])
            args = type("Args", (), {
                "input": input_root, "run_root": root / "runs",
                "dataset_output": root / "pilot_dataset", "seed": 2024,
                "speed": 1.0, "session_seconds": None, "guard_seconds": 0.5,
                "max_samples": None, "pilot": True,
            })()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_plan(args), 0)
            manifest_path = next((root / "runs").glob("*/manifest.json"))
            manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["mode"], "pilot")
        self.assertEqual(manifest["source_count"], 50)
        self.assertEqual(manifest["session_seconds"], 900)

    def test_formal_plan_checks_6000_sample_coverage_capacity_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_root = root / "input"
            input_root.mkdir()
            files = []
            for class_id in range(75):
                for repeat_id in range(80):
                    files.append(self.write_trace(
                        input_root, "{0}-{1}".format(class_id, repeat_id),
                        [(0.0, 1), (0.01, -1)]))
            files.sort(key=lambda path: tuple(
                int(part) for part in path.name.split("-")))
            args = type("Args", (), {
                "input": input_root, "run_root": root / "runs",
                "dataset_output": root / "formal_dataset", "seed": 2024,
                "speed": 1.0, "session_seconds": None, "guard_seconds": 0.5,
                "max_samples": None, "pilot": False,
            })()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_plan(args), 0)
            manifest_path = next((root / "runs").glob("*/manifest.json"))
            manifest = json.loads(manifest_path.read_text())
            scheduled_again = build_sessions(files, 2024, 9000, 1.0, 0.5)
            def schedule_signature(sessions):
                return [(session["session_id"], [
                    (sample["sample_id"], sample["start_second"])
                    for sample in session["samples"]]) for session in sessions]
            self.assertEqual(schedule_signature(manifest["sessions"]),
                             schedule_signature(scheduled_again))
            digest = __import__("hashlib").sha256(files[0].read_bytes()).hexdigest()
        self.assertEqual(manifest["mode"], "formal")
        self.assertEqual(manifest["session_seconds"], 9000)
        self.assertEqual(manifest["source_count"], 6000)
        self.assertEqual(len(manifest["coverage"]), 75)
        self.assertTrue(all(len(value["deciles_present"]) >= 8
                            for value in manifest["coverage"].values()))
        self.assertTrue(all(session["used_seconds"] <= 8940
                            for session in manifest["sessions"]))
        self.assertEqual(manifest["source_rows"][0]["source_sha256"], digest)
        self.assertEqual(Path(manifest["dataset_output"]),
                         (root / "formal_dataset").resolve())
        self.assertFalse((root / "formal_dataset").exists())

    def test_changed_runtime_hash_rejects_existing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            frozen = run_dir / "frozen_config.json"
            frozen.write_text(json.dumps({"config": P2_CONFIG}), encoding="utf-8")
            manifest = {
                "generator_sha256": __import__("hashlib").sha256(
                    Path(__file__).with_name("replay_trace_over_starrynet.py")
                    .read_bytes()).hexdigest(),
                "agent_sha256": __import__("hashlib").sha256(
                    Path(__file__).with_name("e_replay_agent.py").read_bytes()).hexdigest(),
                "runtime_source_sha256": {},
                "run_dir": str(run_dir),
                "frozen_config_sha256": __import__("hashlib").sha256(
                    frozen.read_bytes()).hexdigest(),
                "topology": {"config": P2_CONFIG},
            }
            with self.assertRaisesRegex(ReplayError, "runtime source changed"):
                check_frozen_config(manifest)

    def test_changed_input_hash_rejects_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.write_trace(directory, "0-0", [(0.0, 1), (0.1, -1)])
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            source.write_text("0.0\t1\n0.2\t-1\n", encoding="utf-8")
            with self.assertRaisesRegex(ReplayError, "source hash changed"):
                load_sample_events({"sample_id": "0-0", "source_path": str(source),
                                    "source_sha256": digest})

    def test_verification_reports_both_directions_loss_and_one_way_outputs(self):
        evidence = [
            {"sample_id": "0-0", "status": "success",
             "outbound_sent": 10, "outbound_received": 9,
             "outbound_lost": 1, "outbound_send_failed": 0,
             "expected_outbound": 10,
             "inbound_sent": 8, "inbound_received": 8,
             "inbound_lost": 0, "inbound_send_failed": 0,
             "expected_inbound": 8},
            {"sample_id": "0-1", "status": "success",
             "outbound_sent": 3, "outbound_received": 2,
             "outbound_lost": 1, "outbound_send_failed": 0,
             "expected_outbound": 3,
             "inbound_sent": 0, "inbound_received": 0,
             "inbound_lost": 0, "inbound_send_failed": 0,
             "expected_inbound": 0},
        ]
        result = verification_traffic_summary(evidence, {
            "0-0": {"1": 9, "-1": 8}, "0-1": {"1": 2}})
        self.assertEqual(result["observed_output_event_counts"],
                         {"1": 11, "-1": 8})
        self.assertEqual(result["bidirectional_output_sample_count"], 1)
        self.assertEqual(result["single_direction_output_sample_ids"], ["0-1"])
        self.assertEqual(result["outbound"]["loss_rate_among_sent"], 2 / 13.0)
        self.assertEqual(result["inbound"]["loss_rate_among_sent"], 0.0)

    def test_run_resume_flag_is_accepted(self):
        args = parse_args(["run", "--manifest", "/tmp/manifest.json", "--resume"])
        self.assertEqual(args.command, "run")
        self.assertTrue(args.resume)

    def test_agent_header_round_trip_preserves_event_identity(self):
        value = unpack(packet(1234, 7, -1, 9000000, 512))
        self.assertEqual(value, {"sample_token": 1234, "sequence": 7,
                                 "direction": -1, "scheduled_offset_ns": 9000000})

    def test_agent_monotonic_clock_returns_nanoseconds(self):
        self.assertIsInstance(monotonic_ns(), int)
        self.assertGreater(monotonic_ns(), 0)

    def test_agent_runs_nonempty_event_batch(self):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except PermissionError:
            self.skipTest("sandbox does not permit UDP sockets")
        try:
            probe.bind(("127.0.0.1", 0))
        except PermissionError:
            probe.close()
            self.skipTest("sandbox does not permit UDP sockets")
        listen_port = probe.getsockname()[1]
        probe.close()
        endpoint = Endpoint("client", "127.0.0.1", listen_port, 9, 512, 0.0)
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                endpoint.run_sample(
                    "test-0", 1234, monotonic_ns() + 100000000,
                    [{"sequence": 0, "direction": 1, "offset_ns": 0}])
            self.assertIn('"type":"sample_done"', output.getvalue())
        finally:
            endpoint.close()

    def test_pcap_validator_accepts_a_classic_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            path.write_bytes(
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
                + struct.pack("<IIII", 0, 0, 14, 14) + b"\0" * 14)
            result = validate_pcap(path)
            self.assertEqual(result["magic"], "d4c3b2a1")
            self.assertGreaterEqual(result["bytes"], 24)

    def test_pcap_validator_identifies_ev4_udp_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            payload = packet(1234, 7, 1, 9000000, 512)
            udp = struct.pack("!HHHH", 19999, 20000, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0,
                             64, 17, 0, b"\x01\x02\x03\x04", b"\x05\x06\x07\x08")
            frame = b"\0" * 12 + struct.pack("!H", 0x0800) + ip + udp
            global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                        65535, 1)
            packet_header = struct.pack("<IIII", 0, 0, len(frame), len(frame))
            path.write_bytes(global_header + packet_header + frame)
            result = validate_pcap(path)
            self.assertEqual(result["ev4_packet_count"], 1)
            self.assertEqual(result["udp_packet_count"], 1)

    def test_pcap_validator_identifies_ev4_in_linux_cooked_v2(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            payload = packet(1234, 7, 1, 9000000, 512)
            udp = struct.pack("!HHHH", 19999, 20000, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0,
                             64, 17, 0, b"\x01\x02\x03\x04", b"\x05\x06\x07\x08")
            # Linux cooked capture v2: protocol, reserved, ifindex, hatype,
            # packet type, address length, address.
            sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6,
                               b"\0" * 8)
            frame = sll2 + ip + udp
            global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                        65535, 276)
            packet_header = struct.pack("<IIII", 0, 0, len(frame), len(frame))
            path.write_bytes(global_header + packet_header + frame)
            result = validate_pcap(path)
            self.assertEqual(result["ev4_packet_count"], 1)
            self.assertEqual(result["udp_packet_count"], 1)

    def test_attempt_artifacts_are_append_only_and_success_root_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.write_trace(root, "0-0", [(0.0, 1), (0.1, -1)])
            manifest = {
                "run_id": "run-test", "run_dir": str(root),
                "source_rows": [{"sample_id": "0-0",
                                 "source_sha256": __import__("hashlib").sha256(
                                     source.read_bytes()).hexdigest()}],
            }
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source),
                      "source_sha256": manifest["source_rows"][0]["source_sha256"],
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            client = {"records": [
                {"action": "send", "direction": 1, "sequence": 0,
                 "observed_ns": 1000, "scheduled_offset_ns": 0},
                {"action": "recv", "direction": -1, "sequence": 1,
                 "observed_ns": 2000, "scheduled_offset_ns": 100000000},
            ]}
            remote = {"records": [
                {"action": "recv", "direction": 1, "sequence": 0,
                 "observed_ns": 1100, "scheduled_offset_ns": 0},
                {"action": "send", "direction": -1, "sequence": 1,
                 "observed_ns": 1900, "scheduled_offset_ns": 100000000},
            ]}
            first = write_sample_result(manifest, sample, "session-0001",
                                        "attempt-1", client, remote, 0, {})
            self.assertEqual(first["status"], "success")
            self.assertTrue(sample_is_valid(manifest, "0-0"))
            root_trace_hash = __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "trace").read_bytes()).hexdigest()
            self.assertEqual(next_attempt_number(manifest, "0-0"), 2)
            second = write_sample_result(manifest, sample, "session-0001",
                                         "attempt-2", None, None, 0, {},
                                         status_override="infrastructure_failure",
                                         error_type="test", error_message="expected")
            self.assertEqual(second["status"], "infrastructure_failure")
            self.assertEqual(next_attempt_number(manifest, "0-0"), 3)
            self.assertEqual(root_trace_hash, __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "trace").read_bytes()).hexdigest())

    def test_resume_does_not_retry_nonretryable_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = {"run_dir": directory}
            (Path(directory) / "attempts.jsonl").write_text(
                json.dumps({"sample_id": "0-0", "attempt_id": "attempt-1",
                            "status": "failure", "retryable": False}) + "\n",
                encoding="utf-8")
            self.assertFalse(retry_allowed(manifest, "0-0"))
            (Path(directory) / "attempts.jsonl").write_text(
                json.dumps({"sample_id": "0-0", "attempt_id": "attempt-1",
                            "status": "infrastructure_failure", "retryable": True}) + "\n",
                encoding="utf-8")
            self.assertTrue(retry_allowed(manifest, "0-0"))

    def test_resume_reclassifies_legacy_endpoint_transport_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"run_dir": directory}
            (root / "attempts.jsonl").write_text(
                json.dumps({"sample_id": "0-0", "attempt_id": "attempt-1",
                            "status": "failure", "retryable": False}) + "\n",
                encoding="utf-8")
            attempt = root / "samples" / "0-0" / "attempts" / "attempt-1"
            attempt.mkdir(parents=True)
            (attempt / "evidence.json").write_text(json.dumps({
                "client_observed_event_count": 0,
                "client_send_errors": [
                    {"sequence": 0, "error": "[Errno 101] Network is unreachable"}],
                "remote_send_errors": [], "client_receive_errors": [],
                "remote_receive_errors": [],
            }), encoding="utf-8")
            self.assertTrue(retry_allowed(manifest, "0-0"))

    def test_zero_observation_with_send_error_is_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.write_trace(root, "0-0", [(0.0, 1), (0.1, -1)])
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            manifest = {"run_id": "run-test", "run_dir": str(root)}
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source), "source_sha256": digest,
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            client = {"records": [], "send_errors": [
                {"sequence": 0, "error": "[Errno 101] Network is unreachable"}]}
            remote = {"records": [], "send_errors": []}
            evidence = write_sample_result(
                manifest, sample, "session-0001", "attempt-1",
                client, remote, 0, {})
            self.assertEqual(evidence["status"], "infrastructure_failure")
            self.assertEqual(evidence["error_type"], "endpoint_transport_error")


if __name__ == "__main__":
    unittest.main()
