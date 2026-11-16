"""Offline checks for run-scoped StarryNet Docker resources."""
import io
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from starrynet import local
from starrynet import clean
from starrynet import resource_scope as scope
from starrynet import sn_orchestrater as orchestrater
from starrynet import sn_utils


class ResourceScopeTests(unittest.TestCase):
    def test_legacy_defaults_keep_service_name_but_define_owner(self):
        self.assertEqual(scope.resource_identity({}),
                         ('constellation-test', 'constellation-test'))

    def test_batch_identity_overrides_legacy_arguments(self):
        self.assertEqual(scope.resource_identity(
            {'STARRYNET_OWNER': 'batch-42', 'STARRYNET_SERVICE': 'replay-42'},
            service='constellation-test'), ('batch-42', 'replay-42'))

    def test_rejects_unsafe_docker_identity(self):
        for value in ('', '../other', 'two words', 'x;docker rm -f'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scope.resource_identity({'STARRYNET_OWNER': value})

    def test_remote_command_exports_identity_for_orchestrater(self):
        ssh = Mock()
        stdout = Mock()
        stdout.readlines.return_value = ['ok\n']
        stdout.channel.recv_exit_status.return_value = 0
        ssh.exec_command.return_value = (None, stdout, io.BytesIO())
        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-42',
                                    'STARRYNET_SERVICE': 'replay-42'}):
            self.assertEqual(sn_utils.sn_remote_cmd(ssh, 'python3 worker.py'),
                             ['ok\n'])
        ssh.exec_command.assert_called_once_with(
            'export STARRYNET_OWNER=batch-42; export STARRYNET_SERVICE=replay-42; '
            'python3 worker.py', get_pty=True)

    def test_local_executor_receives_identity_overrides(self):
        with tempfile.TemporaryDirectory() as root:
            executor = local.LocalExecutor(root)
            executor.env_overrides.update({'STARRYNET_OWNER': 'batch-42',
                                           'STARRYNET_SERVICE': 'replay-42'})
            result = Mock(returncode=0, stdout='ok\n', stderr='')
            with patch('starrynet.local.subprocess.run', return_value=result) as run:
                executor.run('true')
            environment = run.call_args[1]['env']
            self.assertEqual(environment['STARRYNET_OWNER'], 'batch-42')
            self.assertEqual(environment['STARRYNET_SERVICE'], 'replay-42')

    def test_local_executor_scopes_network_creation_for_batch_identity(self):
        with tempfile.TemporaryDirectory() as root:
            executor = local.LocalExecutor(root)
            executor.env_overrides.update({
                'STARRYNET_OWNER': 'batch-42',
                'STARRYNET_SERVICE': 'replay-42',
                'STARRYNET_DISABLE_MASQUERADE': '1',
            })
            result = Mock(returncode=0, stdout='', stderr='')
            with patch('starrynet.local.subprocess.run', return_value=result) as run:
                executor.run('docker network create GS_26 --subnet 9.26.26.0/24')
        command = run.call_args[0][0]
        self.assertEqual(command,
            'docker network create --label starrynet.owner=batch-42 GS_26 '
            '--subnet 9.26.26.0/24 --opt '
            'com.docker.network.bridge.enable_ip_masquerade=false')

    def test_container_query_filters_service_and_owner_and_preserves_node_order(self):
        rows = ['cid3 replay-42.3.hash', 'cid1 replay-42.1.hash',
                'cid2 replay-42.2.hash']
        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-42',
                                    'STARRYNET_SERVICE': 'replay-42'}), \
                patch.object(sn_utils, 'sn_remote_cmd', return_value=rows) as command:
            self.assertEqual(sn_utils.sn_get_container_info(None),
                             ['cid1', 'cid2', 'cid3'])
        query = command.call_args[0][1]
        self.assertIn('label=com.docker.swarm.service.name=replay-42', query)
        self.assertIn('label=starrynet.owner=batch-42', query)

    def test_network_creation_uses_dynamic_owner_and_local_masquerade_option(self):
        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-42',
                                    'STARRYNET_SERVICE': 'replay-42',
                                    'STARRYNET_DISABLE_MASQUERADE': '1'}), \
                patch.object(orchestrater.subprocess, 'run') as run:
            orchestrater.sn_checked_system(
                'docker network create --label starrynet.owner=constellation-test '
                'GS_26 --subnet 9.26.26.0/24')
        command = run.call_args[0][0]
        self.assertEqual(command,
            'docker network create --label starrynet.owner=batch-42 GS_26 '
            '--subnet 9.26.26.0/24 --opt '
            'com.docker.network.bridge.enable_ip_masquerade=false')
        self.assertIn('--label starrynet.owner=batch-42', command)
        self.assertIn('--opt com.docker.network.bridge.enable_ip_masquerade=false',
                      command)
        self.assertNotIn('starrynet.owner=constellation-test', command)

    def test_owned_network_cleanup_filters_by_label_not_name_fragment(self):
        calls = []
        def command(arguments, check=True):
            arguments = list(arguments)
            calls.append(arguments)
            if arguments[:2] == ['network', 'ls']:
                return ['owned-id'] if sum(1 for item in calls
                                           if item[:2] == ['network', 'ls']) == 1 else []
            return []
        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-42',
                                    'STARRYNET_SERVICE': 'replay-42'}), \
                patch.object(orchestrater, 'sn_docker_cleanup_command',
                             side_effect=command):
            orchestrater.sn_stop_emulation()
        network_query = next(args for args in calls if args[:2] == ['network', 'ls'])
        self.assertIn('label=starrynet.owner=batch-42', network_query)
        self.assertIn(['network', 'rm', 'owned-id'], calls)
        self.assertFalse(any(args[:3] == ['network', 'rm', 'GSL_1-26']
                             for args in calls))

    def test_orchestrater_upload_includes_scope_module(self):
        ftp = Mock()
        sn_utils.sn_upload_orchestrater(ftp, 'session')
        names = [call[0][1].rsplit('/', 1)[-1] for call in ftp.put.call_args_list]
        self.assertIn('resource_scope.py', names)

    def test_clean_cli_delegates_to_owner_scoped_cleanup(self):
        with patch.object(clean, 'sn_stop_emulation') as stop:
            clean.cleanup()
        stop.assert_called_once_with()

    def test_qdisc_delay_update_keeps_other_netem_options(self):
        observed = ('qdisc netem 1: root refcnt 2 limit 1000 '
                    'delay 12ms 10ms distribution normal loss random 0.1% 25% '
                    'duplicate 1% 25% reorder 2% 50% gap 5 rate 5Gbit')
        with patch.object(orchestrater.subprocess, 'check_output',
                          return_value=observed), \
                patch.object(orchestrater.subprocess, 'run') as run:
            orchestrater.sn_delay_change(0, 1, 25, ['node1', 'node2'], 1)
        first = run.call_args_list[0][0][0]
        self.assertEqual(first[first.index('netem') + 1:], [
            'limit', '1000', 'delay', '25ms', '10ms', 'distribution', 'normal',
            'loss', 'random', '0.1%', '25%', 'duplicate', '1%', '25%',
            'reorder', '2%', '50%', 'gap', '5', 'rate', '5Gbit'])


if __name__ == '__main__':
    unittest.main()
