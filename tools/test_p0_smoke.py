import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from starrynet.local import LocalExecutor, LocalFiles
from starrynet import sn_utils, sn_orchestrater
sys.path.insert(0, str(ROOT / 'tools'))
from p0_smoke import ping_result
from starrynet.sn_thread import CheckedThread, WORKER_ERRORS


class SmokeSafetyTests(unittest.TestCase):
    def tearDown(self):
        WORKER_ERRORS.clear()

    def test_worker_failure_reaches_join_and_error_list(self):
        def fail():
            raise RuntimeError('worker failed')
        thread = CheckedThread(target=fail)
        thread.start()
        with self.assertRaisesRegex(RuntimeError, 'worker failed'):
            thread.join()
        self.assertIn('worker failed', WORKER_ERRORS)

    def test_subclass_worker_failure_is_also_propagated(self):
        class Worker(CheckedThread):
            def run(self):
                raise RuntimeError('subclass failed')
        worker = Worker()
        worker.start()
        with self.assertRaisesRegex(RuntimeError, 'subclass failed'):
            worker.join()

    def test_standalone_upload_includes_thread_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            sn_utils.sn_upload_orchestrater(LocalFiles(directory), 'remote')
            remote = Path(directory) / 'remote'
            self.assertTrue((remote / 'sn_thread.py').is_file())
            subprocess.check_output([sys.executable, '-c',
                "import runpy; runpy.run_path('sn_orchestrater.py', run_name='compat_check')"],
                cwd=str(remote), universal_newlines=True)

    def test_explicit_config_path(self):
        with tempfile.TemporaryDirectory() as directory:
            config = json.loads((ROOT / 'config.json').read_text())
            config['Duration (s)'] = 37
            path = Path(directory) / 'different.json'
            path.write_text(json.dumps(config))
            self.assertEqual(sn_utils.sn_load_file(path, [[0, 0]], []).duration, 37)

    def test_only_service_containers_and_numeric_order(self):
        rows = ['id10 ovs_container_10\n', 'id2 ovs_container_2\n', 'id1 ovs_container_1\n']
        with patch.object(sn_utils, 'sn_remote_cmd', return_value=rows) as call:
            self.assertEqual(sn_utils.sn_get_container_info(object()), ['id1', 'id2', 'id10'])
        self.assertIn('--filter label=com.docker.swarm.service.name=constellation-test', call.call_args[0][1])

    def test_service_task_slot_order(self):
        with patch.object(sn_utils, 'sn_remote_cmd', return_value=[
                'id10 constellation-test.10.xyz\n', 'id2 constellation-test.2.xyz\n']):
            self.assertEqual(sn_utils.sn_get_container_info(object()), ['id2', 'id10'])

    def test_cleanup_is_scoped(self):
        with patch.object(subprocess, 'check_output', side_effect=[
                'unrelated-service\nconstellation-test\n', 'owned-container\n', 'owned-network\n']) as output, \
                patch.object(subprocess, 'run') as run, patch.object(sn_orchestrater, 'sleep'):
            sn_orchestrater.sn_stop_emulation()
        self.assertEqual([c[0][0] for c in run.call_args_list], [
            ['docker', 'service', 'rm', 'constellation-test'],
            ['docker', 'rm', '-f', 'owned-container'],
            ['docker', 'network', 'rm', 'owned-network']])
        self.assertIn('label=com.docker.swarm.service.name=constellation-test', output.call_args_list[1][0][0])
        self.assertIn('label=starrynet.owner=constellation-test', output.call_args_list[2][0][0])

    def test_local_copy_preserves_source_and_blocks_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.txt'
            source.write_text('evidence')
            files = LocalFiles(root)
            files.put(source, 'source.txt')
            files.put(source, 'nested/copy.txt')
            self.assertEqual((root / 'nested/copy.txt').read_text(), 'evidence')
            with self.assertRaises(ValueError):
                files.put(source, '../escape.txt')

    def test_local_command_failure_propagates(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = LocalExecutor(directory)
            with self.assertRaises(RuntimeError):
                executor.run('exit 7')
            self.assertIn('exit 7', (Path(directory) / 'commands.log').read_text())

    def test_delay_update_retains_rate_and_loss(self):
        with patch.object(subprocess, 'check_output', return_value=
                'qdisc netem 1: root delay 6ms loss 1% rate 5Gbit\n'), \
                patch.object(subprocess, 'run') as run:
            sn_orchestrater.sn_delay_change(0, 25, '7.5', ['node'] * 27, 25)
        self.assertEqual(len(run.call_args_list), 2)
        for call in run.call_args_list:
            self.assertEqual(call[0][0][-6:], ['delay', '7.5ms', 'loss', '1%', 'rate', '5Gbit'])

    def test_handover_uses_one_complete_qdisc_per_endpoint(self):
        def output(remote, command):
            if 'birdc show protocols' in command:
                return ['kernel1 Kernel master4 up now\n']
            if 'ip -4 route show' in command:
                return []
            return ['eth2@if42\n']
        with patch.object(sn_utils, 'sn_remote_cmd', side_effect=output) as call:
            sn_utils.sn_establish_new_GSL(['node'] * 27, [['6'] * 27] * 27,
                                        25, 5, 1, 7, 27, object())
        qdiscs = [c[0][1] for c in call.call_args_list if 'tc qdisc add' in c[0][1]]
        self.assertEqual(len(qdiscs), 2)
        self.assertTrue(all('delay 6ms loss 1% rate 5Gbit' in c for c in qdiscs))

    def test_handover_pauses_both_exports_before_connect_and_restores_on_error(self):
        commands = []
        def output(remote, command):
            commands.append(command)
            if 'birdc show protocols' in command:
                return ['kernel1 Kernel master4 up now\n']
            if 'ip -4 route show' in command:
                return ['9.2.7.0/24 via 9.2.13.50 proto bird\n']
            if 'docker network connect' in command and 'ground' in command:
                raise RuntimeError('connect failed')
            return ['eth2@if42\n']
        ids = ['sat'] * 27
        ids[26] = 'ground'
        with patch.object(sn_utils, 'sn_remote_cmd', side_effect=output):
            with self.assertRaisesRegex(RuntimeError, 'connect failed'):
                sn_utils.sn_establish_new_GSL(ids, [['6'] * 27] * 27,
                                            25, 5, 1, 7, 27, object())
        first_connect = next(i for i, c in enumerate(commands) if c.startswith('docker network connect'))
        self.assertEqual(sum('birdc disable kernel1' in c for c in commands[:first_connect]), 2)
        self.assertEqual(sum('birdc enable kernel1' in c for c in commands), 2)
        deletions = [c for c in commands if 'ip -4 route del' in c]
        self.assertEqual(len(deletions), 2)
        self.assertTrue(all(c.endswith('ip -4 route del 9.2.7.0/24 proto bird') for c in deletions))

    def test_handover_leaves_disabled_kernel_protocol_disabled(self):
        def output(remote, command):
            if 'birdc show protocols' in command:
                return ['kernel1 Kernel master4 down now\n']
            return []
        with patch.object(sn_utils, 'sn_remote_cmd', side_effect=output) as call:
            with sn_utils.sn_pause_kernel_exports(object(), ['sat', 'ground'], '9.2.7.0/24'):
                pass
        self.assertFalse(any('birdc enable' in c[0][1] or 'birdc disable' in c[0][1]
                             for c in call.call_args_list))

    def test_ping_outage_is_only_accepted_near_a_real_handover(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ping-26-27_55.txt'
            path.write_text('connect: Network is unreachable\n')
            self.assertEqual(ping_result(path, [53])['received'], 0)
            with self.assertRaises(RuntimeError):
                ping_result(path, [])
            later = Path(directory) / 'ping-26-27_65.txt'
            later.write_text(path.read_text())
            with self.assertRaises(RuntimeError):
                ping_result(later, [53])

    def test_ping_failure_retains_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            lines = LocalExecutor(directory).run("echo 'Network is unreachable' >&2; exit 2",
                                                 allowed_returncodes=(0, 1, 2))
            self.assertEqual(lines, ['Network is unreachable\n'])


if __name__ == '__main__':
    unittest.main()
