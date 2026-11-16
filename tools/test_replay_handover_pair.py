"""Offline planning, anchor observation and shared-session wiring tests."""
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import replay_handover_pair as pair
import replay_trace_over_starrynet as replay


class HandoverPairTests(unittest.TestCase):
    def topology(self):
        return {'handover_seconds': [53], 'handover_count': 1, 'matrix_changed_count': 1,
            'handover_ground_stations_by_second': {'53': [27]},
            'attachments_by_ground_station': {'27': {'1': [12], '53': [6]}},
            'attachments_by_second': {'1': [6], '53': [6]}}

    def fixture(self, root):
        source = root / 'input'
        source.mkdir()
        (source / '18-8').write_text('0.0\t1\n0.1\t-1\n')
        args = replay.parse_args(['plan', '--input', str(source), '--pilot',
            '--run-root', str(root / 'base'), '--dataset-output', str(root / 'dataset'),
            '--session-seconds', '900', '--seed', '2025', '--link-loss-percent', '0'])
        with contextlib.redirect_stdout(io.StringIO()):
            replay.cmd_plan(args)
        baseline = next((root / 'base').glob('*/manifest.json'))
        return pair.create_plan(root / 'pair', baseline)

    def context(self, root):
        return {'session_dir': root, 'session_anchor_ns': int(10e9),
                'remote_cid': 'remote-node', 'topology': self.topology(), 'emulation_errors': []}

    def command(self, **overrides):
        row = {'command': 'docker exec -i remote-node ip link set dev B27-eth13 down',
               'start_monotonic_ns': int(99.8e9), 'end_monotonic_ns': int(100e9),
               'returncode': 0, 'clock_domain': 'CLOCK_MONOTONIC'}
        row.update(overrides)
        return row

    def test_plan_is_one_source_two_losses_with_frozen_phase_and_no_runtime(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(replay, 'run_session') as run:
            path = self.fixture(Path(directory))
            spec, arms = pair.load_pair(path)
            run.assert_not_called()
            self.assertEqual(spec['profile'], pair.PROFILE)
            self.assertEqual([m['source_count'] for m in arms], [1, 1])
            self.assertEqual([m['source_rows'][0]['sample_id'] for m in arms], ['18-8', '18-8'])
            self.assertTrue(all(m['session_seconds'] == 180 and m['mode'] == 'diagnostic' for m in arms))
            self.assertEqual(arms[0]['sessions'], arms[1]['sessions'])
            source_copy = Path(arms[0]['run_dir']) / 'source/replay_handover_pair.py'
            self.assertEqual(replay.sha256_file(source_copy), spec['runner_sha256'])

    def test_contract_rejects_manifest_and_source_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.fixture(root)
            source = root / 'input/18-8'
            source.write_text(source.read_text() + '0.2\t1\n')
            with self.assertRaisesRegex(replay.ReplayError, 'source file changed'):
                pair.load_pair(path)
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            m = Path(pair.read_json(path)['arms'][0]['manifest'])
            m.write_text(m.read_text() + ' ')
            with self.assertRaisesRegex(replay.ReplayError, 'manifest changed'):
                pair.load_pair(path)

    def test_anchor_is_actual_successful_command_end_plus_one_second(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stale = self.command(end_monotonic_ns=int(5e9))
            wrong = self.command(command='docker exec -i other-node ip link set dev B27-eth13 down')
            row = self.command()
            (root / 'commands.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in (stale, wrong, row)))
            with mock.patch.object(replay, 'monotonic_ns', return_value=int(100.02e9)):
                start, meta = pair.wait_for_anchor(self.context(root), pair.PROFILE)
            self.assertEqual(start, int(101e9))
            self.assertEqual(meta['anchor_command'], row)
            self.assertEqual(meta['sample_start_monotonic_ns'], start)

    def test_anchor_tails_partial_record_and_never_runs_a_network_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'commands.jsonl'
            text = json.dumps(self.command()) + '\n'
            path.write_text(text[:20])
            def complete(_seconds):
                with path.open('a') as f:
                    f.write(text[20:])
            with mock.patch.object(pair.time, 'sleep', side_effect=complete), \
                    mock.patch.object(replay, 'monotonic_ns', return_value=int(100.03e9)), \
                    mock.patch.object(replay, 'docker_command') as docker:
                start, _ = pair.wait_for_anchor(self.context(root), pair.PROFILE)
                docker.assert_not_called()
            self.assertEqual(start, int(101e9))

    def test_wrong_event_failed_command_late_anchor_and_timeout_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'commands.jsonl'
            path.write_text(json.dumps(self.command()) + '\n')
            context = self.context(root)
            context['topology']['attachments_by_ground_station']['27']['53'] = [8]
            with self.assertRaisesRegex(replay.ReplayError, 'differs from frozen'):
                pair.wait_for_anchor(context, pair.PROFILE)
            path.write_text(json.dumps(self.command(returncode=1)) + '\n')
            with self.assertRaisesRegex(replay.ReplayError, 'command failed'):
                pair.wait_for_anchor(self.context(root), pair.PROFILE)
            path.write_text(json.dumps(self.command()) + '\n')
            with mock.patch.object(replay, 'monotonic_ns', return_value=int(100.8e9)):
                with self.assertRaisesRegex(replay.ReplayError, 'missed diagnostic anchor'):
                    pair.wait_for_anchor(self.context(root), pair.PROFILE)
            with self.assertRaisesRegex(replay.ReplayError, 'timed out'):
                pair.wait_for_anchor(self.context(root), dict(pair.PROFILE, anchor_wait_timeout_seconds=0))

    def test_pair_comparability_fails_when_actual_phases_differ(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            values = [{'alignment_verified': True, 'observed_start_offset_seconds': 1.01},
                      {'alignment_verified': False, 'observed_start_offset_seconds': 1.25}]
            with mock.patch.object(pair, 'verify_arm', side_effect=values):
                result = pair.verify_pair(path)
            self.assertTrue(result['diagnostic_pair_completed'])
            self.assertFalse(result['passed'])
            self.assertFalse(result['alignment_verified'])

    def test_existing_pair_evidence_is_not_overwritten_or_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            _, manifests = pair.load_pair(path)
            (Path(manifests[0]['run_dir']) / 'sessions').mkdir()
            with mock.patch.object(replay, 'run_session') as run, \
                    mock.patch.object(replay, 'check_docker_capabilities') as check:
                with self.assertRaisesRegex(replay.ReplayError, 'existing diagnostic evidence retained'):
                    pair.run_pair(path)
                run.assert_not_called(); check.assert_not_called()

    def test_anchor_metadata_is_saved_in_real_sample_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            _, manifests = pair.load_pair(path)
            m = manifests[0]; sample = m['sessions'][0]['samples'][0]
            c = [{'sequence': 0, 'direction': 1, 'action': 'send', 'observed_ns': int(101e9),
                  'scheduled_offset_ns': 0, 'send_completed_ns': int(101e9) + 100},
                 {'sequence': 1, 'direction': -1, 'action': 'recv', 'observed_ns': int(101.11e9),
                  'scheduled_offset_ns': int(.1e9)}]
            r = [{'sequence': 0, 'direction': 1, 'action': 'recv', 'observed_ns': int(101.01e9),
                  'scheduled_offset_ns': 0},
                 {'sequence': 1, 'direction': -1, 'action': 'send', 'observed_ns': int(101.1e9),
                  'scheduled_offset_ns': int(.1e9), 'send_completed_ns': int(101.1e9) + 100}]
            control = {'profile': pair.PROFILE, 'anchor_command': self.command(),
                       'sample_start_monotonic_ns': int(101e9)}
            e = replay.write_sample_result(m, sample, 'session-0001', 'attempt-1',
                {'records': c}, {'records': r}, 0, {'handover_control': control})
            self.assertEqual(e['status'], 'success')
            self.assertEqual(pair.read_json(Path(m['run_dir']) / 'samples/18-8/evidence.json')['handover_control'], control)

    def test_shared_session_resolves_start_after_both_agents_are_prepared(self):
        # Execute the real coordinator sequence; every Docker/topology action is mocked.
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            _, manifests = pair.load_pair(path)
            m = manifests[0]; session = m['sessions'][0]
            sd = Path(m['run_dir']) / 'sessions/session-0001'
            sn = mock.Mock(configuration_file_path=directory, file_path='topology')
            sn.remote_ssh.env_overrides = {}
            client, remote = mock.Mock(transport='tcp'), mock.Mock(transport='tcp')
            for agent in (client, remote):
                agent.wait_sample.return_value = {'tcp_state_summary': {'tcp_info_rows': 1, 'errors': []}}
                agent.write_log.return_value = sd / 'agent.jsonl'
                agent.write_tcp_state_log.return_value = {'path': str(sd / 'state.jsonl'),
                    'sha256': 'fixture', 'rows': 1, 'valid_sample_ids': ['18-8'], 'errors': []}
            target = []
            control = {'profile': pair.PROFILE, 'anchor_command': self.command()}
            def resolver(context):
                self.assertTrue(client.wait_prepared.called and remote.wait_prepared.called)
                self.assertEqual(context['remote_cid'], 'remote')
                target.append(replay.monotonic_ns() + int(1e9))
                return target[-1], control
            route = {'route': 'satellite', 'satellite_route': True}
            bridges = [{'name': 'GS_26', 'options': {'com.docker.network.bridge.enable_ip_masquerade': 'false'}}]
            patches = {
                'docker_inventory': mock.Mock(return_value={}),
                'starrynet_resources_cleared': mock.Mock(return_value=True),
                'get_container_ids': mock.Mock(return_value=('client', 'remote')),
                'find_peer_ip': mock.Mock(return_value='9.27.27.10'),
                'find_client_ip': mock.Mock(return_value='9.26.26.10'),
                'topology_summary': mock.Mock(return_value=self.topology()),
                'wait_for_satellite_route': mock.Mock(return_value=route),
                'final_route_snapshot': mock.Mock(return_value=route),
                'inspect_replay_bridges': mock.Mock(return_value=bridges),
                'start_capture': mock.Mock(return_value=None),
                'AgentProcess': mock.Mock(side_effect=[client, remote]),
                'start_heartbeat': mock.Mock(return_value=(mock.Mock(), mock.Mock(), sd / 'heartbeat.jsonl')),
                'wait_for_starrynet_cleanup': mock.Mock(return_value={}),
                'write_sample_result': mock.Mock(return_value={'status': 'success', 'attempt_id': 'attempt-1',
                    'trace_sha256': 'fixture', 'client_observed_event_count': 2}),
            }
            with mock.patch('starrynet.sn_synchronizer.StarryNet', return_value=sn), \
                    mock.patch.multiple(replay, **patches), mock.patch.object(replay.time, 'sleep'):
                summary = replay.run_session(m, session, session['samples'], sd, 180,
                    session_tail_seconds=0, sample_start_resolver=resolver)
            self.assertEqual(summary['status'], 'completed')
            client.start_sample.assert_called_once_with('18-8', target[0])
            remote.start_sample.assert_called_once_with('18-8', target[0])
            self.assertEqual(patches['write_sample_result'].call_args[0][-1]['handover_control'], control)
            sn.start_emulation.assert_called_once()

    def completed_fixture(self, manifest):
        run = Path(manifest['run_dir']); sd = run / 'sessions/session-0001'
        sd.mkdir(parents=True)
        sample = manifest['sessions'][0]['samples'][0]
        start = int(101e9)
        command = self.command()
        c = [{'sequence': 0, 'direction': 1, 'action': 'send', 'observed_ns': start,
              'scheduled_offset_ns': 0, 'send_completed_ns': start + 100},
             {'sequence': 1, 'direction': -1, 'action': 'recv', 'observed_ns': start + int(.11e9),
              'scheduled_offset_ns': int(.1e9)}]
        r = [{'sequence': 0, 'direction': 1, 'action': 'recv', 'observed_ns': start + int(.01e9),
              'scheduled_offset_ns': 0},
             {'sequence': 1, 'direction': -1, 'action': 'send', 'observed_ns': start + int(.1e9),
              'scheduled_offset_ns': int(.1e9), 'send_completed_ns': start + int(.1e9) + 100}]
        state_summary = {'tcp_info_rows': 1, 'errors': []}
        replay.write_sample_result(manifest, sample, 'session-0001', 'attempt-1',
            {'records': c, 'tcp_state_summary': state_summary},
            {'records': r, 'tcp_state_summary': state_summary}, 0,
            {'handover_control': {'profile': pair.PROFILE, 'anchor_command': command,
                                  'sample_start_monotonic_ns': start, 'clock_domain': 'CLOCK_MONOTONIC'}})
        logs = {}
        for role in ('client', 'remote'):
            row = {'type': 'tcp_state', 'role': role, 'sample_id': '18-8',
                   'clock_domain': 'CLOCK_MONOTONIC',
                   'sample_start_ns': start, 'errors': [], 'outq_bytes': 0, 'sndbuf_bytes': 425984,
                   'tcp_info': {'rto_us': 200000, 'unacked_segments': 0,
                                'snd_cwnd_segments': 10, 'total_retrans': 0}}
            path = sd / (role + '_tcp_state.jsonl')
            path.write_text(json.dumps(row) + '\n')
            logs[role] = replay.validate_tcp_state_log(path, role)
            (sd / (role + '_agent.jsonl')).write_text('')
        loss = manifest['topology']['config']['sat-ground loss ("X"% )']
        shaping = [dict(command, command='docker exec -i node tc qdisc replace dev ' + interface +
                        ' root netem delay 1ms loss ' + str(loss) + '% rate 5Gbit')
                   for interface in ('B7-eth27', 'B27-eth7')]
        (sd / 'commands.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in [command] + shaping))
        replay.atomic_write_json(sd / 'config.json', manifest['topology']['config'])
        bridges = [{'name': 'GSL_7-27', 'options': {'com.docker.network.bridge.enable_ip_masquerade': 'false'}}]
        replay.atomic_write_json(sd / 'bridge_networks_after.json', bridges)
        ip = bytearray(20); ip[0] = 0x45; ip[2:4] = struct.pack('!H', 41); ip[9] = 6
        tcp = bytearray(20); tcp[:4] = struct.pack('!HH', 20000, 19999); tcp[12] = 0x50
        frame = bytes(ip + tcp) + b'x'
        capture = struct.pack('<IHHiiii', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        capture += struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame
        (sd / 'client.pcap').write_bytes(capture)
        summary = {'status': 'completed', 'cleanup_verified': True, 'topology': self.topology(),
                   'sample_results': [{'sample_id': '18-8', 'status': 'success'}],
                   'tcp_state_logs': logs, 'pcap': replay.validate_pcap(sd / 'client.pcap'),
                   'new_bridge_names': ['GSL_7-27'],
                   'bridge_networks_after': str(sd / 'bridge_networks_after.json'),
                   'bridge_networks_after_sha256': replay.sha256_file(sd / 'bridge_networks_after.json')}
        replay.atomic_write_json(sd / 'summary.json', summary)

    def test_real_offline_verifier_accepts_complete_anchored_evidence_and_rejects_moved_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            _, manifests = pair.load_pair(path)
            m = manifests[0]
            self.completed_fixture(m)
            result = pair.verify_arm(m, pair.PROFILE)
            self.assertTrue(result['delivery_complete'] and result['alignment_verified'])
            self.assertEqual(result['phase_errors_seconds'], {'client': 0, 'remote': 0})
            epath = Path(m['run_dir']) / 'samples/18-8/evidence.json'
            e = pair.read_json(epath); e['handover_control']['sample_start_monotonic_ns'] += 1
            replay.atomic_write_json(epath, e)
            with self.assertRaisesRegex(replay.ReplayError, 'start moved'):
                pair.verify_arm(m, pair.PROFILE)

    def test_unknown_tcp_state_cannot_pass_paired_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory))
            _, manifests = pair.load_pair(path)
            m = manifests[0]; self.completed_fixture(m)
            sd = Path(m['run_dir']) / 'sessions/session-0001'
            log = sd / 'remote_tcp_state.jsonl'
            row = pair.read_rows(log)[0]; row['tcp_info']['rto_us'] = None
            log.write_text(json.dumps(row) + '\n')
            s = pair.read_json(sd / 'summary.json')
            s['tcp_state_logs']['remote'] = replay.validate_tcp_state_log(log, 'remote')
            replay.atomic_write_json(sd / 'summary.json', s)
            with self.assertRaisesRegex(replay.ReplayError, 'diagnostics incomplete'):
                pair.verify_arm(m, pair.PROFILE)


if __name__ == '__main__':
    unittest.main()
