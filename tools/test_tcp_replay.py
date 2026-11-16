#!/usr/bin/env python3
"""TCP framing, bounded failures, metadata and local loopback checks only."""
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import e_replay_agent as agent
import replay_trace_over_starrynet as replay


class TCPReplayTests(unittest.TestCase):
    def bare_endpoint(self):
        endpoint = agent.TCPEndpoint.__new__(agent.TCPEndpoint)
        endpoint.connection = mock.Mock()
        endpoint.payload_bytes = 512
        endpoint.peer = "127.0.0.1"
        return endpoint

    def receive(self, chunks, expected):
        endpoint = self.bare_endpoint()
        endpoint.connection.recv.side_effect = chunks
        records, errors, aborted = [], [], threading.Event()
        with mock.patch.object(agent.select, "select", return_value=([endpoint.connection], [], [])):
            endpoint.receive_frames(123, expected, agent.monotonic_ns() + int(1e9),
                                    records, errors, aborted)
        return records, errors, aborted

    def test_tcp_reassembles_split_and_coalesced_frames(self):
        a = agent.packet(123, 0, -1, 0, 512)
        b = agent.packet(123, 1, -1, 100, 512)
        records, errors, aborted = self.receive(
            [BlockingIOError(), a[:13], a[13:] + b[:121], b[121:], b""],
            {0: (-1, 0), 1: (-1, 100)})
        self.assertEqual([x["sequence"] for x in records], [0, 1])
        self.assertEqual(errors, [])
        self.assertFalse(aborted.is_set())

    def test_tcp_rejects_truncated_duplicate_and_wrong_token_frames(self):
        frame = agent.packet(123, 0, -1, 0, 512)
        for chunks in ([frame[:-1], b""], [frame + frame, b""],
                       [agent.packet(124, 0, -1, 0, 512), b""]):
            with self.subTest(chunks=chunks[0][:10]):
                _, errors, aborted = self.receive(chunks, {0: (-1, 0)})
                self.assertTrue(errors)
                self.assertTrue(aborted.is_set())

    def test_partial_writes_are_completed_and_failed_bytes_recorded(self):
        endpoint = self.bare_endpoint()
        endpoint.connection.send.side_effect = [2, BlockingIOError(), 3, 3]
        with mock.patch.object(agent.select, "select", return_value=([], [endpoint.connection], [])):
            endpoint.send_frame(b"abcdefgh", agent.monotonic_ns() + int(1e9), threading.Event())
        self.assertEqual([c[0][0] for c in endpoint.connection.send.call_args_list],
                         [b"abcdefgh", b"cdefgh", b"cdefgh", b"fgh"])
        endpoint.connection.send.side_effect = [2, OSError(32, "Broken pipe")]
        with mock.patch.object(agent.select, "select", return_value=([], [endpoint.connection], [])):
            with self.assertRaises(OSError) as caught:
                endpoint.send_frame(b"abcdefgh", agent.monotonic_ns() + int(1e9), threading.Event())
        self.assertEqual(caught.exception.bytes_submitted, 2)

    def test_send_and_receive_deadlines_are_bounded(self):
        endpoint = self.bare_endpoint()
        with self.assertRaises(TimeoutError):
            endpoint.send_frame(b"abc", 0, threading.Event())
        records, errors, aborted = [], [], threading.Event()
        endpoint.receive_frames(123, {}, 0, records, errors, aborted)
        self.assertTrue(errors)
        self.assertTrue(aborted.is_set())

    def test_tcp_client_binds_stable_address_with_ephemeral_port(self):
        with mock.patch.object(agent.socket, "socket") as factory:
            connection = factory.return_value
            connection.recv.return_value = agent.TCP_HELLO.pack(b"EV4T", 123)
            endpoint = agent.TCPEndpoint("client", "9.27.27.10", 19999, 20000,
                                         512, "9.26.26.10")
            endpoint.prepare_sample(123)
            connection.bind.assert_called_once_with(("9.26.26.10", 0))
            connection.connect.assert_called_once_with(("9.27.27.10", 20000))
            self.assertEqual(endpoint.prepared_token, 123)
            endpoint.close()
            connection.close.assert_called_once_with()

    def test_handshake_token_mismatch_closes_connection(self):
        with mock.patch.object(agent.socket, "socket") as factory:
            factory.return_value.recv.return_value = agent.TCP_HELLO.pack(b"EV4T", 124)
            factory.return_value.getsockname.return_value = ("127.0.0.1", 45000)
            endpoint = agent.TCPEndpoint("client", "127.0.0.1", 19999, 20000, 512)
            with self.assertRaisesRegex(ConnectionError, "token mismatch"):
                endpoint.prepare_sample(123)
            self.assertIsNone(endpoint.connection)
            self.assertIsNone(endpoint.prepared_token)

    def test_tcp_capture_counts_payload_segments_separately_from_events(self):
        def frame(payload):
            ip = bytearray(20)
            ip[0], ip[9] = 0x45, 6
            ip[2:4] = struct.pack("!H", 40 + len(payload))
            tcp = bytearray(20)
            tcp[:4] = struct.pack("!HH", 45000, 20000)
            tcp[12] = 0x50
            return bytes(ip + tcp) + payload
        packets = [frame(b""), frame(b"EV"), frame(b"4\0" + b"x" * 1022)]
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "tcp.pcap"
            data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
            for value in packets:
                data += struct.pack("<IIII", 1, 0, len(value), len(value)) + value
            p.write_bytes(data)
            counts = replay.validate_pcap(p)
        self.assertEqual(counts["tcp_packet_count"], 3)
        self.assertEqual(counts["tcp_payload_packet_count"], 2)
        self.assertEqual(counts["udp_packet_count"], 0)
        self.assertEqual(replay.replay_capture_count(counts, "tcp"), 2)
        self.assertEqual(replay.replay_capture_count(counts, "udp"), 0)

    def test_capture_filter_uses_selected_transport(self):
        for transport in ("tcp", "udp"):
            with mock.patch.object(replay, "docker_exec", side_effect=["", "", "24"]) as execute:
                replay.start_capture("test", Path("/tmp"), "any", transport)
            command = execute.call_args_list[1][0][-1]
            self.assertIn(transport + " port 19999 or " + transport + " port 20000", command)

    def test_new_plan_defaults_to_tcp_and_freezes_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "input"
            sources.mkdir()
            for index in range(3):
                (sources / ("0-" + str(index))).write_text("0.0\t1\n0.1\t-1\n")
            args = replay.parse_args(["plan", "--input", str(sources),
                                      "--run-root", str(root / "runs"),
                                      "--dataset-output", str(root / "dataset"),
                                      "--session-seconds", "900"])
            with contextlib.redirect_stdout(io.StringIO()):
                replay.cmd_plan(args)
            path = next((root / "runs").glob("*/manifest.json"))
            manifest = replay.load_manifest(path)
            self.assertEqual(manifest["transport"], "tcp")
            self.assertEqual(manifest["dataset_id"], "E_v4_dynamic_replay_tcp")
            self.assertIs(manifest["docker_bridge_masquerade"], False)
            self.assertEqual(manifest['tcp_state_interval_seconds'], .5)
            replay.check_frozen_config(manifest)
            manifest['tcp_state_interval_seconds'] = .2
            with self.assertRaisesRegex(replay.ReplayError, 'frozen transport'):
                replay.check_frozen_config(manifest)
            manifest['tcp_state_interval_seconds'] = .5
            manifest["docker_bridge_masquerade"] = True
            with self.assertRaisesRegex(replay.ReplayError, "frozen transport"):
                replay.check_frozen_config(manifest)
            manifest["docker_bridge_masquerade"] = False
            manifest["transport"] = "udp"
            with self.assertRaisesRegex(replay.ReplayError, "frozen transport"):
                replay.check_frozen_config(manifest)
            self.assertEqual(replay.parse_args(["plan", "--transport", "udp"]).transport, "udp")

    def test_zero_loss_plan_reaches_preflight_and_full_runtime_configs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "input"
            sources.mkdir()
            (sources / "0-0").write_text("0.0\t1\n0.1\t-1\n")
            args = replay.parse_args([
                "plan", "--input", str(sources), "--run-root", str(root / "runs"),
                "--dataset-output", str(root / "dataset"), "--pilot",
                "--session-seconds", "900", "--link-loss-percent", "0"])
            with contextlib.redirect_stdout(io.StringIO()):
                replay.cmd_plan(args)
            manifest = replay.load_manifest(next((root / "runs").glob("*/manifest.json")))
            frozen = replay.check_frozen_config(manifest)["config"]
            loss_keys = {'satellite link loss ("X"% )', 'sat-ground loss ("X"% )'}
            default = replay.make_config(900)
            self.assertEqual({k for k in default if default[k] != frozen[k]}, loss_keys)
            self.assertTrue(all(frozen[k] == 0 and default[k] == 1 for k in loss_keys))
            for duration in (90, 900):
                path = replay.make_runtime_config(root, duration, frozen)
                actual = json.loads(path.read_text())
                self.assertEqual(actual, dict(frozen, **{"Duration (s)": duration}))
                from starrynet.sn_utils import sn_load_file
                parsed = sn_load_file(str(path), replay.GS, argv=[])
                self.assertEqual((parsed.sat_loss, parsed.sat_ground_loss), (0, 0))
            self.assertEqual(frozen["Duration (s)"], 900)
            self.assertEqual(replay.P2_CONFIG['satellite link loss ("X"% )'], 1)

    def test_session_entry_passes_frozen_config_before_starting_topology(self):
        class StopBeforeTopology(Exception):
            pass
        with tempfile.TemporaryDirectory() as directory:
            frozen = replay.make_config(900, 0)
            for duration in (90, 900):
                with mock.patch.object(replay, "make_runtime_config", side_effect=StopBeforeTopology) as create:
                    with self.assertRaises(StopBeforeTopology):
                        replay.run_session({"topology": {"config": frozen}},
                                           {}, [], Path(directory), duration)
                create.assert_called_once_with(Path(directory), duration, frozen)

    def test_link_loss_cli_rejects_nonfinite_and_out_of_range_values(self):
        for value in ("-1", "101", "nan", "inf", "-inf"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                replay.parse_args(["plan", "--link-loss-percent=" + value])
        self.assertEqual(replay.parse_args(["plan", "--link-loss-percent", "1"]).link_loss_percent, 1)
        self.assertEqual(replay.parse_args(["plan", "--link-loss-percent", "100"]).link_loss_percent, 100)

    def test_bridge_masquerade_flag_is_scoped_to_owned_network_creation(self):
        from starrynet import sn_orchestrater as orchestrater
        owned = 'docker network create --label starrynet.owner=constellation-test '
        commands = [owned + 'Le_0-0_1-0 --subnet 10.0.1.0/24',
                    owned + 'GSL_7-27 --subnet 9.2.7.0/24',
                    owned + 'GS_26 --subnet 9.26.26.0/24',
                    'docker network create unrelated --subnet 192.168.50.0/24',
                    'docker network connect GSL_7-27 node',
                    'docker network rm GSL_13-27']
        for flag in ('0', '1'):
            with mock.patch.dict(orchestrater.os.environ,
                                 {'STARRYNET_DISABLE_MASQUERADE': flag}), \
                    mock.patch.object(orchestrater.subprocess, 'run') as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                for command in commands:
                    orchestrater.sn_checked_system(command)
                actual = [c[0][0] for c in run.call_args_list]
            for original, executed in zip(commands, actual):
                expected = original
                if flag == '1' and original.startswith(owned):
                    expected += ' --opt com.docker.network.bridge.enable_ip_masquerade=false'
                self.assertEqual(executed, expected)

    def test_worker_environment_does_not_leak_to_other_executors(self):
        from starrynet.local import LocalExecutor
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch('starrynet.local.subprocess.run', return_value=mock.Mock(
                    returncode=0, stdout='', stderr='')) as run:
            replay_executor = LocalExecutor(directory)
            replay_executor.env_overrides['STARRYNET_DISABLE_MASQUERADE'] = '1'
            with mock.patch.dict('os.environ', {'STARRYNET_DISABLE_MASQUERADE': '0'}):
                replay_executor.run('true')
                other_executor = LocalExecutor(directory)
                other_executor.run('true')
                self.assertEqual(run.call_args_list[0][1]['env']['STARRYNET_DISABLE_MASQUERADE'], '1')
                self.assertEqual(run.call_args_list[1][1]['env']['STARRYNET_DISABLE_MASQUERADE'], '0')

    def test_real_dynamic_gsl_command_path_uses_local_no_masquerade_policy(self):
        from starrynet.local import LocalExecutor
        from starrynet import sn_utils
        for flag, loss in (('0', 1), ('1', 1), ('1', 0)):
            with tempfile.TemporaryDirectory() as directory:
                executor = LocalExecutor(directory)
                executor.env_overrides['STARRYNET_DISABLE_MASQUERADE'] = flag
                def fake_run(command, **kwargs):
                    return mock.Mock(returncode=0, stderr='',
                        stdout='eth2@if100\n' if 'ip addr' in command else '')
                with mock.patch('starrynet.local.subprocess.run', side_effect=fake_run) as run, \
                        contextlib.redirect_stdout(io.StringIO()):
                    sn_utils._sn_establish_new_GSL(
                        ['node-' + str(i) for i in range(27)],
                        [[1] * 27 for _ in range(27)], 25, 5, loss, 7, 27, executor)
                creation = [c[0][0] for c in run.call_args_list
                            if c[0][0].startswith('docker network create ')]
                self.assertEqual(len(creation), 1)
                self.assertIn('GSL_7-27 --subnet 9.2.7.0/24', creation[0])
                self.assertEqual('enable_ip_masquerade=false' in creation[0], flag == '1')
                shaping = [c[0][0] for c in run.call_args_list if 'tc qdisc replace' in c[0][0]]
                self.assertEqual(len(shaping), 2)
                self.assertTrue(all('loss ' + str(loss) + '%' in c for c in shaping))
                recorded = [json.loads(x)['command'] for x in
                    (Path(directory) / 'commands.jsonl').read_text().splitlines()]
                self.assertIn(creation[0], recorded)

    def test_local_network_policy_preserves_unowned_and_already_correct_commands(self):
        from starrynet.local import LocalExecutor
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch('starrynet.local.subprocess.run', return_value=mock.Mock(
                    returncode=0, stdout='', stderr='')) as run:
            executor = LocalExecutor(directory)
            executor.env_overrides['STARRYNET_DISABLE_MASQUERADE'] = '1'
            commands = ['docker network create unrelated',
                        'docker network connect GSL_7-27 node',
                        'docker network create --label starrynet.owner=constellation-test GS_26 '
                        '--opt com.docker.network.bridge.enable_ip_masquerade=false']
            for command in commands:
                executor.run(command)
                self.assertEqual(run.call_args[0][0], command)
            with self.assertRaisesRegex(ValueError, 'enables masquerade'):
                executor.run(commands[-1].replace('=false', '=true'))

    def test_tcp_info_decoder_handles_kernel_extensions_and_short_prefix(self):
        data = bytearray(232)
        data[0] = 1
        for offset, value in [(8, 200000), (24, 9), (68, 10000), (80, 12),
                              (100, 5), (144, 1234), (228, 64256)]:
            struct.pack_into('=I', data, offset, value)
        struct.pack_into('=Q', data, 120, 9876543210)
        prefix = agent.decode_tcp_info(bytes(data[:104]))
        self.assertEqual(prefix['rto_us'], 200000)
        self.assertEqual(prefix['unacked_segments'], 9)
        self.assertEqual(prefix['snd_cwnd_segments'], 12)
        self.assertEqual(prefix['total_retrans'], 5)
        self.assertIsNone(prefix['notsent_bytes'])
        full = agent.decode_tcp_info(bytes(data))
        self.assertEqual(full['bytes_acked'], 9876543210)
        self.assertEqual(full['notsent_bytes'], 1234)
        self.assertEqual(full['peer_snd_wnd_bytes'], 64256)
        with self.assertRaises(ValueError):
            agent.decode_tcp_info(b'\0' * 7)

    def test_failed_tcp_info_queries_are_unknown_and_fail_diagnostic_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.jsonl'
            connection = mock.Mock()
            def getsockopt(level, option, *args):
                if level == socket.IPPROTO_TCP:
                    raise OSError('unsupported TCP_INFO')
                return 65536
            connection.getsockopt.side_effect = getsockopt
            sampler = agent.TCPStateSampler(connection, path,
                {'role': 'remote', 'sample_id': '18-8'}, lambda: None, 100)
            with mock.patch.object(agent.fcntl, 'ioctl', return_value=struct.pack('=I', 123)):
                sampler.start()
                status = sampler.close()
            self.assertEqual(status['tcp_info_rows'], 0)
            self.assertTrue(status['errors'])
            rows = [json.loads(x) for x in path.read_text().splitlines()]
            self.assertTrue(all(x['tcp_info'] is None for x in rows))
            metadata = replay.validate_tcp_state_log(path, 'remote')
            self.assertEqual(metadata['valid_sample_ids'], [])
            with self.assertRaisesRegex(replay.ReplayError, 'diagnostics incomplete'):
                replay.require_tcp_state_diagnostics({
                    'sample_results': [{'sample_id': '18-8'}],
                    'tcp_state_logs': {'client': metadata, 'remote': metadata}})

    def test_diagnostic_gate_requires_both_roles_and_every_sample(self):
        summary = {'sample_results': [{'sample_id': 'a'}, {'sample_id': 'b'}],
                   'tcp_state_logs': {role: {'valid_sample_ids': ['a', 'b'], 'errors': []}
                                      for role in ('client', 'remote')}}
        replay.require_tcp_state_diagnostics(summary)
        summary['tcp_state_logs']['remote']['valid_sample_ids'] = ['a']
        with self.assertRaisesRegex(replay.ReplayError, 'remote'):
            replay.require_tcp_state_diagnostics(summary)

    def test_tcp_setup_failure_records_stage_and_closes_socket(self):
        with mock.patch.object(agent.socket, 'socket') as factory, \
                mock.patch.object(agent, 'emit') as emit:
            connection = factory.return_value
            connection.connect.side_effect = socket.timeout('timed out')
            connection.getsockname.return_value = ('9.26.26.10', 45000)
            endpoint = agent.TCPEndpoint('client', '9.27.27.10', 19999, 20000,
                                         512, '9.26.26.10')
            with self.assertRaises(socket.timeout) as error:
                endpoint.prepare_sample(123)
            self.assertEqual(error.exception.tcp_stage, 'connect')
            failure = emit.call_args[0][0]
            self.assertEqual(failure['type'], 'tcp_prepare_failed')
            self.assertEqual(failure['stage'], 'connect')
            self.assertEqual(failure['local_address'], ('9.26.26.10', 45000))
            self.assertEqual(failure['sample_token'], 123)
            self.assertIsNone(endpoint.connection)
            connection.close.assert_called_once_with()

    def test_routed_network_inspection_rejects_default_masquerade(self):
        networks = [{'Name': 'GS_26', 'Id': 'a', 'Driver': 'bridge',
                     'Options': {'com.docker.network.bridge.enable_ip_masquerade': 'false'}}]
        for wrong in (False, True):
            if wrong:
                networks[0]['Options'] = {}
            with mock.patch.object(replay, 'docker_command', side_effect=[
                    mock.Mock(stdout=b'a\n'),
                    mock.Mock(stdout=json.dumps(networks).encode())]) as command:
                if wrong:
                    with self.assertRaisesRegex(replay.ReplayError, 'no masquerade.*GS_26'):
                        replay.inspect_replay_bridges()
                else:
                    self.assertEqual(replay.inspect_replay_bridges()[0]['name'], 'GS_26')
                    self.assertEqual(command.call_args_list[1][0], ('network', 'inspect', 'a'))

    def test_tcp_incomplete_delivery_is_failure_even_without_socket_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "0-0"
            source.write_text("0.0\t1\n0.1\t-1\n")
            sample = dict(replay.read_trace(source), sample_id="0-0", source_path=str(source),
                          source_sha256=replay.sha256_file(source), start_second=0.0)
            client = {"finished_ns": 300, "records": [
                {"action": "send", "direction": 1, "sequence": 0, "observed_ns": 100,
                 "send_completed_ns": 150, "scheduled_offset_ns": 0},
                {"action": "recv", "direction": -1, "sequence": 1,
                 "observed_ns": 200, "scheduled_offset_ns": 100000000}]}
            remote = {"records": [{"action": "send", "direction": -1, "sequence": 1,
                                   "observed_ns": 180, "scheduled_offset_ns": 100000000}]}
            evidence = replay.write_sample_result(
                {"run_id": "test", "run_dir": str(root), "transport": "tcp"},
                sample, "test", "attempt-1", client, remote, 0, {})
            self.assertEqual(evidence["error_type"], "tcp_incomplete_reception")
            self.assertEqual(evidence["status"], "failure")
            self.assertEqual(evidence["client_record_count"], 2)
            self.assertEqual(evidence["event_verification"]["transport_scope"],
                             "strict_tcp_application_events")
            self.assertFalse(evidence["event_verification"]["passed"])
            self.assertEqual(evidence["client_finished_ns"], 300)
            self.assertEqual(evidence["trace_semantics"], "client_application_events")

    def test_partial_tcp_frame_is_preserved_as_measurement_not_legacy_udp_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "0-0"
            source.write_text("0.0\t1\n0.1\t-1\n")
            sample = dict(replay.read_trace(source), sample_id="0-0", source_path=str(source),
                          source_sha256=replay.sha256_file(source), start_second=0.0)
            manifest = {"run_id": "test", "run_dir": str(root), "transport": "tcp"}
            client = {"records": [], "send_errors": [
                {"error": "connection reset", "sequence": 0, "bytes_submitted": 32}]}
            evidence = replay.write_sample_result(manifest, sample, "test", "attempt-1",
                                                  client, {"records": []}, 0, {})
            self.assertEqual(evidence["status"], "failure")
            self.assertEqual(evidence["error_type"], "tcp_incomplete_reception")
            replay.append_attempt(manifest, {"sample_id": "0-0", "attempt_id": "attempt-1",
                                           "status": "failure", "retryable": False})
            self.assertFalse(replay.retry_allowed(manifest, "0-0"))

    def test_tcp_preflight_cannot_pass_incomplete_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "0-0"
            source.write_text("0.0\t1\n0.1\t-1\n")
            manifest = {"run_dir": str(root), "transport": "tcp", "speed": 1,
                        "source_rows": [{"sample_id": "0-" + str(i),
                                         "source_path": str(source),
                                         "source_sha256": replay.sha256_file(source)}
                                        for i in range(3)]}
            with mock.patch.object(replay, "load_manifest", return_value=manifest), \
                    mock.patch.object(replay, "check_frozen_config"), \
                    mock.patch.object(replay, "check_docker_capabilities"), \
                    mock.patch.object(replay, "run_session", return_value={
                        "status": "completed", "sample_results": [
                            {"status": "success"}, {"status": "failure"}, {"status": "success"}]}):
                with self.assertRaisesRegex(replay.ReplayError, "TCP preflight samples incomplete"):
                    replay.cmd_preflight(type("Args", (), {"manifest": root / "manifest.json"})())

    def test_new_preflight_requires_state_coverage_and_dynamic_bridge_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = []
            for i in range(3):
                source = root / ('0-' + str(i));source.write_text('0\t1\n0.1\t-1\n')
                sources.append({'sample_id': source.name, 'source_path': str(source),
                                'source_sha256': replay.sha256_file(source)})
            ids = ['preflight-0-' + str(i) for i in range(3)]
            for missing in ('state', 'bridge', None):
                manifest = {'run_dir': str(root), 'manifest_path': str(root / 'manifest.json'),
                            'transport': 'tcp', 'tcp_state_interval_seconds': .5,
                            'speed': 1, 'source_rows': sources}
                summary = {'status': 'completed', 'sample_results': [
                    {'sample_id': sid, 'status': 'success'} for sid in ids],
                    'tcp_state_logs': {role: {'valid_sample_ids': ids, 'errors': []}
                                       for role in ('client', 'remote')},
                    'bridge_networks_after': 'bridge_networks_after.json',
                    'new_bridge_names': ['GSL_7-27'],
                    'dynamic_matrix_changed': True, 'handover_count': 1}
                if missing == 'state': summary['tcp_state_logs'] = {}
                if missing == 'bridge': summary['new_bridge_names'] = []
                with mock.patch.object(replay, 'load_manifest', return_value=manifest), \
                        mock.patch.object(replay, 'check_frozen_config'), \
                        mock.patch.object(replay, 'check_docker_capabilities'), \
                        mock.patch.object(replay, 'run_session', return_value=summary), \
                        contextlib.redirect_stdout(io.StringIO()):
                    args = replay.argparse.Namespace(manifest=root / 'manifest.json')
                    if missing:
                        with self.assertRaisesRegex(replay.ReplayError,
                            'state diagnostics' if missing == 'state' else 'dynamic bridge'):
                            replay.cmd_preflight(args)
                    else:
                        self.assertEqual(replay.cmd_preflight(args), 0)
                        self.assertEqual(manifest['status'], 'preflight_passed')


class TCPLoopbackTests(unittest.TestCase):
    def setUp(self):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", 0))
            finally:
                probe.close()
        except OSError as exc:
            self.skipTest("local TCP sockets unavailable: " + str(exc))

    def prepared_pair(self, grace=1.0):
        remote = agent.TCPEndpoint("remote", "127.0.0.1", 0, 0, 512,
                                   "127.0.0.1", grace, 2.0)
        self.addCleanup(remote.close)
        client = agent.TCPEndpoint("client", "127.0.0.1", 0,
                                   remote.listener.getsockname()[1], 512,
                                   "127.0.0.1", grace, 2.0)
        self.addCleanup(client.close)
        failures = []
        def prepare():
            try:
                remote.prepare_sample(123)
            except BaseException as exc:
                failures.append(exc)
        thread = threading.Thread(target=prepare, daemon=True)
        thread.start()
        client.prepare_sample(123)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        return client, remote

    def test_tcp_drains_after_original_udp_tail(self):
        client, remote = self.prepared_pair(grace=1.2)
        original_receive = client.receive_frames
        def delayed_receive(*args):
            time.sleep(0.65)
            original_receive(*args)
        client.receive_frames = delayed_receive
        events = [{"sequence": 0, "direction": 1, "offset_ns": 0},
                  {"sequence": 1, "direction": -1, "offset_ns": 0}]
        outputs, failures = [], []
        def run(endpoint, start):
            try:
                endpoint.run_sample("test", 123, start, events)
            except BaseException as exc:
                failures.append(exc)
        start = agent.monotonic_ns() + 30000000
        with mock.patch.object(agent, "emit", side_effect=outputs.append):
            threads = [threading.Thread(target=run, args=(x, start), daemon=True)
                       for x in (client, remote)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3)
                self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(outputs), 2)
        for row in outputs:
            self.assertFalse(row["send_errors"] or row["receive_errors"])
            self.assertEqual(len(row["records"]), 2)
        client_row = next(x for x in outputs if x["role"] == "client")
        self.assertGreater(client_row["finished_ns"] - start, 500000000)

    def test_state_sampler_runs_during_pending_write_and_stops_before_socket_close(self):
        client, remote = self.prepared_pair(grace=1.5)
        with tempfile.TemporaryDirectory() as directory:
            for endpoint in (client, remote):
                endpoint.state_log_path = str(Path(directory) / (endpoint.role + '.jsonl'))
                endpoint.state_interval = .02
            original_send = remote.send_frame
            def delayed_send(*args):
                time.sleep(.15)
                return original_send(*args)
            remote.send_frame = delayed_send
            events = [{'sequence': 0, 'direction': -1, 'offset_ns': 0},
                      {'sequence': 1, 'direction': 1, 'offset_ns': 10000000}]
            outputs, failures = [], []
            def run(endpoint, start):
                try:
                    endpoint.run_sample('pending', 123, start, events)
                except BaseException as exc:
                    failures.append(exc)
            start = agent.monotonic_ns() + 30000000
            with mock.patch.object(agent, 'emit', side_effect=outputs.append):
                threads = [threading.Thread(target=run, args=(x, start), daemon=True)
                           for x in (client, remote)]
                for thread in threads: thread.start()
                for thread in threads:
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(outputs), 2)
            for row in outputs:
                self.assertEqual(len(row['records']), 2)
                self.assertFalse(row['tcp_state_summary']['errors'])
            records = [json.loads(x) for x in (Path(directory) / 'remote.jsonl').read_text().splitlines()]
            pending = [x for x in records if x['reason'] == 'periodic' and x['active_write']]
            self.assertTrue(any(x['active_write']['sequence'] == 0 for x in pending))
            self.assertTrue(all(x['sample_id'] == 'pending' for x in records))
            self.assertTrue(all(x['tcp_info']['rto_us'] is not None for x in records))
            self.assertTrue(all(x['sndbuf_bytes'] > 0 for x in records))
            self.assertEqual(records[-1]['reason'], 'final')
            self.assertFalse(any(t.name == 'tcp-state' and t.is_alive()
                                 for t in threading.enumerate()))

    def test_stalled_peer_times_out_and_preserves_submitted_event(self):
        client, _ = self.prepared_pair(grace=0.15)
        events = [{"sequence": 0, "direction": 1, "offset_ns": 0},
                  {"sequence": 1, "direction": -1, "offset_ns": 0}]
        started = time.monotonic()
        with mock.patch.object(agent, "emit") as emit:
            client.run_sample("test", 123, agent.monotonic_ns(), events)
        self.assertLess(time.monotonic() - started, 1.0)
        row = emit.call_args[0][0]
        self.assertTrue(row["receive_errors"])
        self.assertEqual(len(row["records"]), 1)
        self.assertEqual(row["records"][0]["action"], "send")

    def test_agent_command_protocol_prepares_starts_and_repeats_tcp_samples(self):
        # Exercise the real stdin/stdout agent protocol on localhost. Disable
        # only route monitoring so this test never opens host Netlink sockets.
        bootstrap = """import sys
sys.path.insert(0, {tools_path!r})
import e_replay_agent as agent
class QuietMonitor:
    def __init__(self, *args): pass
    def start(self): pass
    def close(self): pass
agent.RouteMonitor = QuietMonitor
sys.exit(agent.main())
""".format(tools_path=str(Path(__file__).resolve().parent))
        with tempfile.TemporaryDirectory() as directory:
            processes = []
            def start(role, peer_port):
                endpoint = replay.AgentProcess("local", role, "127.0.0.1", directory,
                                                0, peer_port, "tcp", "127.0.0.1")
                endpoint.process = subprocess.Popen([
                    sys.executable, "-c", bootstrap, "--role", role, "--peer", "127.0.0.1",
                    "--listen-port", "0", "--peer-port", str(peer_port),
                    "--bind-address", "127.0.0.1", "--transport", "tcp",
                    "--tcp-completion-timeout", "1", "--tcp-connect-timeout", "2",
                    "--tcp-state-log", str(Path(directory) / (role + '_state.jsonl')),
                    "--tcp-state-interval", "0.02"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, bufsize=1)
                processes.append(endpoint)
                endpoint._thread = threading.Thread(target=endpoint._read_output, daemon=True)
                endpoint._thread.start()
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with endpoint.output_lock:
                        ready = next((x for x in endpoint.output if x.get("type") == "ready"), None)
                    if ready:
                        return endpoint, ready
                    if endpoint.process.poll() is not None:
                        break
                    time.sleep(0.01)
                self.fail("agent did not become ready")
            try:
                remote, ready = start("remote", 0)
                client, client_ready = start("client", ready["listen_port"])
                self.assertIsNone(client_ready["listen_port"])
                for token in (123, 124):
                    events = [{"sequence": i, "direction": 1 if i % 2 == 0 else -1,
                               "offset_ns": i * 1000000} for i in range(10)]
                    sample_id = "test-" + str(token)
                    client.prepare_sample(sample_id, token, events)
                    remote.prepare_sample(sample_id, token, events)
                    for endpoint in (client, remote):
                        prepared = endpoint.wait_prepared(sample_id, 3)
                        self.assertEqual(prepared["transport"], "tcp")
                        self.assertEqual(prepared["local_address"][0], "127.0.0.1")
                    start_ns = agent.monotonic_ns() + 150000000
                    client.start_sample(sample_id, start_ns)
                    remote.start_sample(sample_id, start_ns)
                    for endpoint in (client, remote):
                        completed = endpoint.wait_sample(sample_id, 3)
                        self.assertEqual(len(completed["records"]), 10)
                        self.assertFalse(completed["send_errors"] or completed["receive_errors"])
                        self.assertFalse(completed['tcp_state_summary']['errors'])
                        self.assertGreaterEqual(completed['tcp_state_summary']['tcp_info_rows'], 2)
                for role in ('client', 'remote'):
                    metadata = replay.validate_tcp_state_log(
                        Path(directory) / (role + '_state.jsonl'), role)
                    self.assertEqual(metadata['valid_sample_ids'], ['test-123', 'test-124'])
                    self.assertEqual(metadata['errors'], [])
            finally:
                for endpoint in processes:
                    endpoint.stop()
                    endpoint.process.stdout.close()
                    endpoint.process.stderr.close()
            self.assertTrue(all(x.process.returncode == 0 and not x.errors for x in processes))

    def test_bidirectional_samples_reconnect_and_preserve_events(self):
        remote = agent.TCPEndpoint("remote", "127.0.0.1", 0, 0, 512,
                                   "127.0.0.1", 1.0, 2.0)
        port = remote.listener.getsockname()[1]
        client = agent.TCPEndpoint("client", "127.0.0.1", 0, port, 512,
                                   "127.0.0.1", 1.0, 2.0)
        errors, outputs = [], []
        def guarded(function, *args):
            try:
                function(*args)
            except BaseException as exc:
                errors.append(exc)
        events = [{"sequence": i, "direction": 1 if i % 2 == 0 else -1,
                   "offset_ns": (i // 20) * 1000000} for i in range(200)]
        try:
            with mock.patch.object(agent, "emit", side_effect=outputs.append):
                for token in (123, 124):
                    prepare = threading.Thread(target=guarded, args=(remote.prepare_sample, token), daemon=True)
                    prepare.start()
                    client.prepare_sample(token)
                    prepare.join(3)
                    self.assertFalse(prepare.is_alive())
                    self.assertEqual(errors, [])
                    start = agent.monotonic_ns() + 30000000
                    threads = [threading.Thread(target=guarded, args=(endpoint.run_sample,
                               "sample-" + str(token), token, start, events), daemon=True)
                               for endpoint in (client, remote)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(3)
                        self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])
            self.assertEqual(set(x['type'] for x in outputs),
                             {'tcp_prepare_started', 'sample_done'})
            self.assertEqual(sum(x['type'] == 'tcp_prepare_started' for x in outputs), 4)
            completed = [x for x in outputs if x['type'] == 'sample_done']
            self.assertEqual(len(completed), 4)
            for row in completed:
                self.assertEqual(row["receive_errors"], [])
                self.assertEqual(row["send_errors"], [])
                self.assertEqual(sum(x["action"] == "send" for x in row["records"]), 100)
                self.assertEqual(sum(x["action"] == "recv" for x in row["records"]), 100)
        finally:
            client.close()
            remote.close()


if __name__ == "__main__":
    unittest.main()
