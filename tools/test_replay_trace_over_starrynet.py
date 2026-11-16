#!/usr/bin/env python3
import contextlib
import io
import inspect
import json
import socket
import struct
import sys
import threading
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from collections import deque

sys.path.insert(0, str(Path(__file__).resolve().parent))

from replay_trace_over_starrynet import (
    AgentProcess,
    PAYLOAD_BYTES,
    ReplayError,
    GS,
    P2_CONFIG,
    build_sessions,
    check_frozen_config,
    cmd_plan,
    cmd_run,
    append_attempt,
    final_route_snapshot,
    gzip_artifact,
    allocate_recovery_session,
    rebase_runtime_schedule,
    session_setup_retry_allowed,
    SatelliteRouteUnavailable,
    max_infrastructure_attempts,
    next_attempt_number,
    parse_args,
    runtime_source_hashes,
    run_sample_counts,
    load_sample_events,
    verification_traffic_summary,
    read_agent_sample,
    read_trace,
    retry_allowed,
    sample_token,
    sample_is_valid,
    sha256_file,
    session_evidence_is_valid,
    starrynet_resources_cleared,
    stop_capture,
    validate_pcap,
    verify_session_endpoint_logs,
    write_sample_result,
    validate_trace,
    wait_for_satellite_route,
)
from e_replay_agent import Endpoint, RouteMonitor, monotonic_ns, packet, unpack


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
        def remote_command(_remote, command, check=True):
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
        with self.assertRaisesRegex(RuntimeError, "Background StarryNet worker failed") as caught:
            thread.join()
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertEqual(str(caught.exception.__cause__), "worker failed")
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
            summary = {
                "status": "completed", "cleanup_verified": True,
            }
            (session_dir / "summary.json").write_text(json.dumps(summary))
            self.assertFalse(session_evidence_is_valid(manifest, session))
            payload = packet(1234, 0, 1, 0, PAYLOAD_BYTES)
            udp = struct.pack("!HHHH", 19999, 20000, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0,
                             64, 17, 0, b"\x01\x02\x03\x04", b"\x05\x06\x07\x08")
            frame = b"\0" * 12 + struct.pack("!H", 0x0800) + ip + udp
            global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                        65535, 1)
            packet_header = struct.pack("<IIII", 0, 0, len(frame), len(frame))
            pcap_path = session_dir / "client.pcap"
            pcap_path.write_bytes(global_header + packet_header + frame)
            summary["pcap"] = validate_pcap(pcap_path)
            summary["pcap_compression"] = gzip_artifact(pcap_path)
            (session_dir / "summary.json").write_text(
                json.dumps(summary, sort_keys=True), encoding="utf-8")
            self.assertTrue(session_evidence_is_valid(manifest, session))
            compressed = Path(summary["pcap_compression"]["path"])
            self.assertTrue(compressed.is_file())
            self.assertEqual(sha256_file(compressed),
                             summary["pcap_compression"]["compressed_sha256"])
            self.assertEqual(summary["pcap_compression"]["original_sha256"],
                             summary["pcap"]["sha256"])

    def test_cleanup_tolerates_resources_disappearing_during_swarm_removal(self):
        from starrynet import sn_orchestrater

        calls = []
        def command(arguments, **kwargs):
            arguments = list(arguments)
            docker_arguments = arguments[1:]
            calls.append(docker_arguments)
            if docker_arguments[:2] == ["service", "inspect"]:
                return "constellation-test\n" if sum(
                    1 for item in calls if item[:2] == ["service", "inspect"]) == 1 else ""
            if docker_arguments[:2] == ["ps", "-aq"]:
                return "container-a\n" if sum(
                    1 for item in calls if item[:2] == ["ps", "-aq"]) == 1 else ""
            if docker_arguments[:3] == ["network", "ls", "--filter"]:
                return "network-a\n" if sum(
                    1 for item in calls if item[:2] == ["network", "ls"]) == 1 else ""
            if docker_arguments in (["service", "rm", "constellation-test"],
                                    ["rm", "-f", "container-a"],
                                    ["network", "rm", "network-a"]):
                raise sn_orchestrater.subprocess.CalledProcessError(1, arguments)
            raise AssertionError("unexpected Docker cleanup command: {}".format(
                docker_arguments))

        with mock.patch.object(sn_orchestrater.subprocess, "check_output",
                               side_effect=command), \
                mock.patch.object(sn_orchestrater, "sleep"):
            sn_orchestrater.sn_stop_emulation()

        self.assertIn(["service", "rm", "constellation-test"], calls)
        self.assertIn(["rm", "-f", "container-a"], calls)
        self.assertIn(["network", "rm", "network-a"], calls)
        self.assertEqual(len(calls), 9)

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

    def test_generated_kernel_configs_preserve_routes_during_gsl_setup(self):
        from starrynet import sn_observer

        for autonomous_systems in ([[1, 3]], [[2]]):
            with self.subTest(autonomous_systems=autonomous_systems), \
                    tempfile.TemporaryDirectory() as directory:
                observer = sn_observer.Observer.__new__(sn_observer.Observer)
                observer.configuration_file_path = directory
                observer.file_path = "topology"
                observer.intra_routing = "OSPF"
                observer.orbit_number = 1
                observer.sat_number = 1
                observer.GS_lat_long = [[0, 0], [1, 1]]
                observer.AS = autonomous_systems
                observer.hello_interval = 1
                matrix = [[0, 1, 1], [1, 0, 0], [1, 0, 0]]
                with mock.patch.object(sn_observer, "sn_remote_cmd"), \
                        mock.patch.object(sn_observer, "sn_get_param", return_value=matrix):
                    observer.generate_conf(object(), mock.Mock())
                files = list((Path(directory) / "topology" / "conf"
                              / "bird-1-2").glob("B*.conf"))
                self.assertEqual(len(files), 3 if len(autonomous_systems[0]) == 2 else 1)
                for path in files:
                    config = path.read_text()
                    self.assertRegex(config, r"protocol kernel \{\s+persist;\s+ipv4")
                    self.assertIn("export all;", config)

    def test_local_commands_record_monotonic_execution_intervals(self):
        from starrynet.local import LocalExecutor

        for returncode in (0, 7):
            with self.subTest(returncode=returncode), \
                    tempfile.TemporaryDirectory() as directory, \
                    mock.patch("starrynet.local.subprocess.run", return_value=mock.Mock(
                        returncode=returncode, stdout="output", stderr="error")), \
                    mock.patch("starrynet.local.time.monotonic", side_effect=[1.0, 2.0]):
                executor = LocalExecutor(directory)
                if returncode:
                    with self.assertRaises(RuntimeError):
                        executor.run("true")
                else:
                    executor.run("true")
                record = json.loads((Path(directory) / "commands.jsonl").read_text())
                self.assertEqual(record["command"], "true")
                self.assertEqual(record["start_monotonic_ns"], 1000000000)
                self.assertEqual(record["end_monotonic_ns"], 2000000000)
                self.assertEqual(record["returncode"], returncode)
                self.assertEqual(record["clock_domain"], "CLOCK_MONOTONIC")
                self.assertIn("$ true", (Path(directory) / "commands.log").read_text())

    def test_route_monitor_records_kernel_events_and_unexpected_exit(self):
        monitor = RouteMonitor("remote", "9.26.26.10")
        monitor.process = mock.Mock(
            stdout=io.StringIO("Deleted 9.26.26.0/24 via 9.2.13.50\nB27-eth13 DOWN\n"),
            stderr=io.StringIO("monitor ended"))
        monitor.process.wait.return_value = 1
        with mock.patch("e_replay_agent.emit") as emit, \
                mock.patch("e_replay_agent.monotonic_ns", return_value=123):
            monitor.read_changes()
        records = [call[0][0] for call in emit.call_args_list]
        self.assertEqual([r["type"] for r in records], [
            "route_change", "route_change", "route_monitor_error"])
        self.assertEqual(records[0]["event"], "Deleted 9.26.26.0/24 via 9.2.13.50")
        self.assertTrue(all(r["role"] == "remote" and r["observed_ns"] == 123
                            and r["clock_domain"] == "CLOCK_MONOTONIC" for r in records))
        self.assertEqual(records[-1]["returncode"], 1)

    def test_route_monitor_missing_ip_is_a_diagnostic_error(self):
        monitor = RouteMonitor("client", "9.27.27.10")
        with mock.patch("e_replay_agent.subprocess.Popen", side_effect=OSError("ip missing")), \
                mock.patch("e_replay_agent.emit") as emit:
            monitor.start()
            monitor.close()
        record = emit.call_args[0][0]
        self.assertEqual(record["type"], "route_monitor_error")
        self.assertEqual(record["phase"], "start")
        self.assertIsNone(monitor.process)

    def test_route_monitor_reports_stderr_even_when_stopped_deliberately(self):
        monitor = RouteMonitor("client", "9.27.27.10")
        monitor.stop_requested.set()
        monitor.process = mock.Mock(stdout=io.StringIO(""),
                                    stderr=io.StringIO("netlink receive error No buffer space available"))
        monitor.process.wait.return_value = -15
        with mock.patch("e_replay_agent.emit") as emit:
            monitor.read_changes()
        record = emit.call_args[0][0]
        self.assertEqual(record["type"], "route_monitor_error")
        self.assertIn("No buffer space available", record["error"])

    def test_route_monitor_start_snapshot_and_cleanup_are_read_only(self):
        for snapshot_returncode in (0, 1):
            with self.subTest(snapshot_returncode=snapshot_returncode):
                monitor = RouteMonitor("client", "9.27.27.10")
                process = mock.Mock(stdout=io.StringIO(""), stderr=io.StringIO(""))
                process.poll.side_effect = [None, -15]
                process.wait.return_value = -15
                with mock.patch("e_replay_agent.subprocess.Popen", return_value=process) as popen, \
                        mock.patch("e_replay_agent.threading.Thread") as thread, \
                        mock.patch("e_replay_agent.subprocess.run", return_value=mock.Mock(
                            stdout="snapshot", stderr="snapshot failed", returncode=snapshot_returncode)) as run, \
                        mock.patch("e_replay_agent.emit") as emit:
                    monitor.start()
                    monitor.close()
                self.assertEqual(popen.call_args[0][0], ["ip", "monitor", "route", "link"])
                self.assertEqual([call[0][0] for call in run.call_args_list], [
                    ["ip", "-4", "route", "show"], ["ip", "-o", "link", "show"]])
                process.terminate.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=2)
                thread.return_value.join.assert_called_once_with(timeout=2)
                records = [call[0][0] for call in emit.call_args_list]
                self.assertEqual(records[0]["type"], "route_monitor_started")
                self.assertEqual(records[-1]["type"], "route_monitor_stopped")
                snapshots = [row for row in records if row["type"] == "route_snapshot"]
                self.assertEqual(len(snapshots), 2)
                self.assertTrue(all(row["returncode"] == snapshot_returncode for row in snapshots))
                errors = [row for row in records if row["type"] == "route_monitor_error"]
                self.assertEqual(len(errors), 2 if snapshot_returncode else 0)

    def test_route_diagnostics_do_not_interfere_with_agent_sample_messages(self):
        agent = AgentProcess.__new__(AgentProcess)
        diagnostic = {"type": "route_change", "role": "remote", "event": "route updated"}
        prepared = {"type": "prepared", "sample_id": "0-0"}
        completed = {"type": "sample_done", "sample_id": "0-0", "records": []}
        agent.output = deque([diagnostic, prepared, completed])
        agent.output_lock = threading.Lock()
        agent.process = mock.Mock()
        self.assertEqual(agent.wait_prepared("0-0", 1), prepared)
        self.assertEqual(agent.wait_sample("0-0", 1), completed)
        self.assertIn(diagnostic, agent.output)

    def test_agent_send_errors_record_actual_and_scheduled_times(self):
        with mock.patch("e_replay_agent.socket.socket") as socket_factory, \
                mock.patch("e_replay_agent.monotonic_ns", return_value=123456789), \
                mock.patch("e_replay_agent.emit") as emit:
            socket_factory.return_value.sendto.side_effect = OSError(101, "Network is unreachable")
            endpoint = Endpoint("client", "127.0.0.1", 19999, 20000, 512, 0.0)
            try:
                with mock.patch.object(endpoint, "receive_until"):
                    endpoint.run_sample("0-0", 123, 0, [
                        {"sequence": 0, "direction": 1, "offset_ns": 0}])
            finally:
                endpoint.close()
            errors = emit.call_args[0][0]["send_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["sequence"], 0)
            self.assertEqual(errors[0]["observed_ns"], 123456789)
            self.assertEqual(errors[0]["scheduled_offset_ns"], 0)
            self.assertEqual(errors[0]["clock_domain"], "CLOCK_MONOTONIC")

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

    def make_tcp_endpoint_rows(self, sample, client_sequences=None,
                               remote_sequences=None):
        events, _info = load_sample_events(sample)
        token = sample_token(sample["sample_id"])
        selections = {"client": client_sequences, "remote": remote_sequences}
        result = {}
        for role in ("client", "remote"):
            selected = selections[role]
            selected = None if selected is None else set(selected)
            row = {"sample_id": sample["sample_id"], "sample_token": token,
                   "role": role, "transport": "tcp", "records": [],
                   "send_errors": [], "receive_errors": [],
                   "finished_ns": 10000000}
            for event in events:
                sequence = event["sequence"]
                if selected is not None and sequence not in selected:
                    continue
                direction = event["direction"]
                is_sender = ((role == "client" and direction == 1) or
                             (role == "remote" and direction == -1))
                action = "send" if is_sender else "recv"
                observed_ns = (1000000 + sequence * 1000
                               + (0 if role == "client" else 100))
                record = {"action": action, "direction": direction,
                          "sequence": sequence, "observed_ns": observed_ns,
                          "scheduled_offset_ns": event["offset_ns"],
                          "bytes": PAYLOAD_BYTES,
                          "sample_id": sample["sample_id"],
                          "sample_token": token}
                if is_sender:
                    record["send_completed_ns"] = observed_ns + 50
                row["records"].append(record)
            result[role] = row
        return result["client"], result["remote"]

    def write_compressed_agent_logs(self, root, session_id, client_row,
                                    remote_row):
        session_dir = Path(root) / "sessions" / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        artifacts = {}
        for role, endpoint_row in (("client", client_row),
                                   ("remote", remote_row)):
            raw_path = session_dir / (role + "_agent.jsonl")
            log_row = dict(endpoint_row, type="sample_done", role=role)
            raw_path.write_text(json.dumps(log_row, sort_keys=True) + "\n",
                                encoding="utf-8")
            original_hash = sha256_file(raw_path)
            artifact = gzip_artifact(raw_path)
            self.assertEqual(artifact["original_sha256"], original_hash)
            self.assertEqual(artifact["compressed_sha256"],
                             sha256_file(artifact["path"]))
            artifacts[role] = artifact
        (session_dir / "summary.json").write_text(json.dumps({
            "client_agent_log": artifacts["client"],
            "remote_agent_log": artifacts["remote"],
        }, sort_keys=True), encoding="utf-8")
        return session_dir, artifacts

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
                "starrynet/resource_scope.py",
                "tools/research2_evidence.py",
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
                "transport": "tcp", "speed": 1.0,
                "source_rows": [{"sample_id": "0-0",
                                 "source_sha256": __import__("hashlib").sha256(
                                     source.read_bytes()).hexdigest()}],
            }
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source),
                      "source_sha256": manifest["source_rows"][0]["source_sha256"],
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            client, remote = self.make_tcp_endpoint_rows(sample)
            first_route_meta = {
                "route_before_sample": "9.27.27.60 dev B26-eth13 src 9.26.26.50\n",
                "route_wait_seconds": 1.25,
                "route_wait_timeout_seconds": 30.0,
            }
            first = write_sample_result(manifest, sample, "session-0001",
                                        "attempt-1", client, remote, 0,
                                        first_route_meta)
            self.assertEqual(first["status"], "success")
            self.assertTrue(sample_is_valid(manifest, "0-0"))
            session_dir, log_artifacts = self.write_compressed_agent_logs(
                root, "session-0001", client, remote)
            verified_summary = verify_session_endpoint_logs(
                manifest, "session-0001", [first])
            self.assertEqual(verified_summary["client_agent_log"],
                             log_artifacts["client"])
            for role, endpoint in (("client", client), ("remote", remote)):
                log_path = Path(log_artifacts[role]["path"])
                self.assertEqual(sha256_file(log_path),
                                 log_artifacts[role]["compressed_sha256"])
                persisted = read_agent_sample(log_path, "0-0", sample_token("0-0"))
                self.assertEqual(persisted["records"], endpoint["records"])
                self.assertEqual([row["sequence"] for row in persisted["records"]],
                                 [row["sequence"] for row in endpoint["records"]])
            remote_log = Path(log_artifacts["remote"]["path"])
            remote_log.write_bytes(remote_log.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ReplayError, "compressed remote agent log"):
                verify_session_endpoint_logs(manifest, "session-0001", [first])
            first_attempt = (root / "samples" / "0-0" / "attempts"
                             / "attempt-1" / "evidence.json")
            for path in (first_attempt, root / "samples" / "0-0" / "evidence.json"):
                saved = json.loads(path.read_text(encoding="utf-8"))
                for key, value in first_route_meta.items():
                    self.assertEqual(saved[key], value)
            root_trace_hash = __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "trace").read_bytes()).hexdigest()
            root_evidence_hash = __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "evidence.json").read_bytes()).hexdigest()
            self.assertEqual(next_attempt_number(manifest, "0-0"), 2)
            zero_reception_client, zero_reception_remote = self.make_tcp_endpoint_rows(
                sample, client_sequences=[0], remote_sequences=[1])
            second_route_meta = {
                "route_before_sample": "9.27.27.60 dev B26-eth7 src 9.26.26.50\n",
                "route_wait_seconds": 0.0,
                "route_wait_timeout_seconds": 30.0,
            }
            second = write_sample_result(manifest, sample, "session-0001",
                                         "attempt-2", zero_reception_client,
                                         zero_reception_remote, 0,
                                         second_route_meta)
            self.assertEqual(second["status"], "failure")
            self.assertEqual(second["error_type"], "tcp_incomplete_reception")
            self.assertEqual(next_attempt_number(manifest, "0-0"), 3)
            self.assertEqual(root_trace_hash, __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "trace").read_bytes()).hexdigest())
            self.assertEqual(root_evidence_hash, __import__("hashlib").sha256(
                (root / "samples" / "0-0" / "evidence.json").read_bytes()).hexdigest())
            self.assertTrue(sample_is_valid(manifest, "0-0"))
            attempt_root = root / "samples" / "0-0" / "attempts" / "attempt-2"
            self.assertTrue((attempt_root / "trace").is_file())
            self.assertTrue((attempt_root / "evidence.json").is_file())
            saved = json.loads((attempt_root / "evidence.json").read_text(encoding="utf-8"))
            for key, value in second_route_meta.items():
                self.assertEqual(saved[key], value)

    def test_no_endpoint_reception_failure_is_preserved_and_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.write_trace(root, "0-0", [(0.0, 1), (0.1, -1)])
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            manifest = {"run_id": "run-test", "run_dir": str(root),
                        "transport": "tcp", "speed": 1.0}
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source), "source_sha256": digest,
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            cases = [("attempt-1", [], []),
                     ("attempt-2", [], [{"sequence": 1,
                                         "scheduled_offset_ns": 100000000,
                                         "observed_ns": 2000000,
                                         "clock_domain": "CLOCK_MONOTONIC",
                                         "bytes_submitted": 0,
                                         "error": "send failed"}])]
            for attempt_id, remote_sequences, remote_send_errors in cases:
                client, remote = self.make_tcp_endpoint_rows(
                    sample, client_sequences=[0],
                    remote_sequences=remote_sequences)
                remote["send_errors"] = remote_send_errors
                session_id = "session-" + attempt_id
                evidence = write_sample_result(
                    manifest, sample, session_id, attempt_id,
                    client, remote, 0, {})
                self.assertEqual(evidence["status"], "failure")
                self.assertEqual(evidence["error_type"], "no_endpoint_reception")
                _session_dir, artifacts = self.write_compressed_agent_logs(
                    root, session_id, client, remote)
                attempt_root = (root / "samples" / "0-0" / "attempts"
                                / attempt_id)
                saved = json.loads(
                    (attempt_root / "evidence.json").read_text(encoding="utf-8"))
                for key in ("route_before_sample", "route_wait_seconds",
                            "route_wait_timeout_seconds"):
                    self.assertIsNone(saved[key])
                self.assertEqual(saved["client_record_count"], len(client["records"]))
                self.assertEqual(saved["remote_record_count"], len(remote["records"]))
                self.assertEqual(saved["remote_send_errors"],
                                 remote.get("send_errors", []))
                for role, endpoint in (("client", client), ("remote", remote)):
                    log_path = Path(artifacts[role]["path"])
                    self.assertEqual(sha256_file(log_path),
                                     artifacts[role]["compressed_sha256"])
                    persisted = read_agent_sample(
                        log_path, "0-0", sample_token("0-0"))
                    self.assertEqual(persisted["records"], endpoint["records"])
                    self.assertEqual(persisted.get("send_errors", []),
                                     endpoint.get("send_errors", []))
                    self.assertEqual([row["sequence"] for row in persisted["records"]],
                                     [row["sequence"] for row in endpoint["records"]])
                self.assertTrue((attempt_root / "trace").is_file())
                append_attempt(manifest, {
                    "sample_id": "0-0", "attempt_id": attempt_id,
                    "status": evidence["status"],
                    "retryable": evidence["status"] == "infrastructure_failure",
                })
                self.assertFalse(retry_allowed(manifest, "0-0"))
            self.assertFalse(sample_is_valid(manifest, "0-0"))

    def test_status_override_precedes_no_endpoint_reception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.write_trace(root, "0-0", [(0.0, 1), (0.1, -1)])
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            manifest = {"run_id": "run-test", "run_dir": str(root),
                        "transport": "tcp", "speed": 1.0}
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source), "source_sha256": digest,
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            client, remote = self.make_tcp_endpoint_rows(sample)
            evidence = write_sample_result(
                manifest, sample, "session-0001", "attempt-1", client,
                remote, 0, {}, status_override="infrastructure_failure",
                error_type="explicit_override", error_message="kept override")
            self.assertEqual(evidence["status"], "infrastructure_failure")
            self.assertEqual(evidence["error_type"], "explicit_override")
            self.assertEqual(evidence["error_message"], "kept override")

    def test_partial_reception_with_send_error_is_a_nonretryable_failure(self):
        for endpoint_role, failed_sequence in (("client", 2), ("remote", 3)):
            with self.subTest(endpoint_role=endpoint_role), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = self.write_trace(root, "0-0", [
                    (0.0, 1), (0.1, -1), (0.2, 1), (0.3, -1)])
                digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
                manifest = {"run_id": "run-test", "run_dir": str(root),
                            "transport": "tcp", "speed": 1.0}
                sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                          "source_path": str(source), "source_sha256": digest,
                          "start_second": 15.0, "duration_seconds": 0.3,
                          "event_count": 4}
                client, remote = self.make_tcp_endpoint_rows(
                    sample, client_sequences=[0, 1], remote_sequences=[0, 1])
                row = client if endpoint_role == "client" else remote
                row["send_errors"] = [{"sequence": failed_sequence,
                                       "observed_ns": 3000,
                                       "scheduled_offset_ns": (
                                           200000000 if failed_sequence == 2
                                           else 300000000),
                                       "clock_domain": "CLOCK_MONOTONIC",
                                       "bytes_submitted": 0,
                                       "error": "[Errno 101] Network is unreachable"}]
                evidence = write_sample_result(
                    manifest, sample, "session-0001", "attempt-1", client, remote, 0, {})
                self.assertEqual(evidence["status"], "failure")
                self.assertEqual(evidence["error_type"], "tcp_incomplete_reception")
                attempt = root / "samples" / "0-0" / "attempts" / "attempt-1"
                saved = json.loads((attempt / "evidence.json").read_text())
                self.assertEqual(saved[endpoint_role + "_send_errors"], row["send_errors"])
                self.assertTrue((attempt / "trace").is_file())
                self.assertFalse(sample_is_valid(manifest, "0-0"))
                append_attempt(manifest, {"sample_id": "0-0", "attempt_id": "attempt-1",
                                          "status": evidence["status"], "retryable": False})
                self.assertFalse(retry_allowed(manifest, "0-0"))

    def test_partial_tcp_endpoint_reception_is_failure_with_loss_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.write_trace(root, "0-0", [(0.0, 1), (0.1, -1)])
            digest = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
            manifest = {"run_id": "run-test", "run_dir": str(root),
                        "transport": "tcp", "speed": 1.0}
            sample = {"sample_id": "0-0", "class_id": 0, "repeat_id": 0,
                      "source_path": str(source), "source_sha256": digest,
                      "start_second": 15.0, "duration_seconds": 0.1,
                      "event_count": 2}
            cases = [("attempt-1", [0], [0], 1, 0),
                     ("attempt-2", [1], [1], 0, 1)]
            for attempt_id, client_sequences, remote_sequences, outbound_received, inbound_received in cases:
                client, remote = self.make_tcp_endpoint_rows(
                    sample, client_sequences=client_sequences,
                    remote_sequences=remote_sequences)
                evidence = write_sample_result(
                    manifest, sample, "session-0001", attempt_id,
                    client, remote, 0, {})
                self.assertEqual(evidence["status"], "failure")
                self.assertEqual(evidence["error_type"], "tcp_incomplete_reception")
                self.assertEqual(evidence["outbound_received"],
                                 outbound_received)
                self.assertEqual(evidence["inbound_received"],
                                 inbound_received)
                self.assertFalse(sample_is_valid(manifest, "0-0"))

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
            manifest = {"run_id": "run-test", "run_dir": str(root),
                        "transport": "udp"}
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


class RunSummaryTests(unittest.TestCase):
    def test_counts_are_unique_and_do_not_treat_unknown_or_infrastructure_as_interruptions(self):
        manifest = {"sessions": [
            {"superseded_by": "new", "samples": [{"sample_id": "99-0"}]},
            {"samples": [{"sample_id": "0-{}".format(i)} for i in range(5)]},
            {"samples": [{"sample_id": "0-1"}]},
        ]}
        rows = [
            {"sample_id": "0-0", "attempt_id": "attempt-1", "status": "success"},
            {"sample_id": "0-0", "attempt_id": "attempt-2", "status": "failure",
             "retryable": False, "network_loss_is_measurement": True},
            {"sample_id": "0-1", "attempt_id": "attempt-1", "status": "failure",
             "retryable": False, "network_loss_is_measurement": True},
            {"sample_id": "0-2", "attempt_id": "attempt-1", "status": "infrastructure_failure",
             "retryable": True, "network_loss_is_measurement": False},
            {"sample_id": "0-3", "attempt_id": "attempt-1", "status": "failure",
             "retryable": False},
            {"sample_id": "preflight-0-0", "status": "success"},
            {"sample_id": "99-0", "status": "success"},
        ]
        with mock.patch("replay_trace_over_starrynet.read_attempts", return_value=rows):
            counts = run_sample_counts(manifest, {"0-0"}, {"0-0", "0-1", "0-3"})
        self.assertEqual(counts, {"planned_samples": 5, "attempted_samples": 4,
                                  "successful_samples": 1, "interrupted_samples": 1,
                                  "other_attempted_samples": 2, "unattempted_samples": 1})

    def test_latest_numeric_attempt_and_existing_valid_success_take_precedence(self):
        manifest = {"sessions": [{"samples": [{"sample_id": "0-0"},
                                                 {"sample_id": "0-1"}]}]}
        rows = [{"sample_id": "0-0", "attempt_id": "attempt-10",
                 "status": "infrastructure_failure", "retryable": True},
                {"sample_id": "0-0", "attempt_id": "attempt-2", "status": "failure",
                 "retryable": False, "network_loss_is_measurement": True}]
        with mock.patch("replay_trace_over_starrynet.read_attempts", return_value=rows):
            counts = run_sample_counts(manifest, {"0-1"}, {"0-0"})
        self.assertEqual(counts["attempted_samples"], 2)
        self.assertEqual(counts["successful_samples"], 1)
        self.assertEqual(counts["interrupted_samples"], 0)
        self.assertEqual(counts["other_attempted_samples"], 1)

    def check_command_summary(self, failed_ids):
        import replay_trace_over_starrynet as replay
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ids = {"0-{}".format(i) for i in range(50)}
            manifest = {"run_dir": str(root), "manifest_path": str(root / "manifest.json"),
                        "preflight": {"status": "passed"}, "session_seconds": 900,
                        "sessions": [{"session_id": "session-0001", "samples": [
                            {"sample_id": sid} for sid in sorted(ids)]}]}
            for sid in ids:
                append_attempt(manifest, {"sample_id": sid, "attempt_id": "attempt-1",
                                          "status": "failure" if sid in failed_ids else "success",
                                          "retryable": False, "network_loss_is_measurement": True})
            before = (root / "attempts.jsonl").read_bytes()
            stream = io.StringIO()
            with mock.patch.object(replay, "load_manifest", return_value=manifest), \
                    mock.patch.object(replay, "check_frozen_config"), \
                    mock.patch.object(replay, "storage_guard", return_value={}), \
                    mock.patch.object(replay, "sample_is_valid",
                                      side_effect=lambda _m, sid: sid not in failed_ids), \
                    mock.patch.object(replay, "retry_allowed", return_value=False), \
                    mock.patch.object(replay, "session_evidence_is_valid", return_value=True), \
                    mock.patch.object(replay, "run_session") as run, \
                    contextlib.redirect_stdout(stream):
                exit_code = cmd_run(type("Args", (), {"manifest": root / "manifest.json"})())
            run.assert_not_called()
            output = json.loads(stream.getvalue())
            self.assertEqual(output["planned_samples"], 50)
            self.assertEqual(output["attempted_samples"], 50)
            self.assertEqual(output["successful_samples"], 50 - len(failed_ids))
            self.assertEqual(output["interrupted_samples"], len(failed_ids))
            self.assertEqual(output["other_attempted_samples"], 0)
            self.assertEqual(output["unattempted_samples"], 0)
            self.assertEqual(output["run_completed"], not bool(failed_ids))
            self.assertEqual(exit_code, 1 if failed_ids else 0)
            saved = json.loads((root / "manifest.json").read_text())
            self.assertEqual(saved["status"], "incomplete_nonretryable" if failed_ids
                             else "run_completed")
            self.assertNotIn("attempted_samples", saved)
            self.assertEqual((root / "attempts.jsonl").read_bytes(), before)
            if failed_ids:
                self.assertEqual(output["nonretryable_samples"], sorted(failed_ids))
                self.assertEqual(output["retryable_samples"], [])
                self.assertEqual(output["retry_exhausted_samples"], [])
            else:
                self.assertEqual(output["sessions"], 0)

    def test_command_keeps_failure_status_exit_code_and_retry_lists(self):
        self.check_command_summary({"0-1", "0-7", "0-46"})

    def test_command_keeps_success_status_and_exit_code(self):
        self.check_command_summary(set())


if __name__ == "__main__":
    unittest.main()
