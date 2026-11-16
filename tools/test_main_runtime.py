"""Offline regressions for remote interpreter and route-query failures."""
import io
import json
import unittest
import os
import subprocess
import tempfile
import ipaddress
from pathlib import Path
from unittest.mock import Mock, patch

from starrynet import sn_utils as u
from starrynet import sn_orchestrater as o
from starrynet import sn_observer as observer
from starrynet import clean


class RuntimeTests(unittest.TestCase):
    def test_cleanup_excludes_system_and_unrelated_networks(self):
        for name in ['bridge', 'host', 'none', 'ingress', 'docker_gwbridge',
                     'NAME', 'my_GS_backup', 'La_project', 'Le_1-2_3-4_extra']:
            self.assertFalse(o.sn_is_emulation_network(name), name)
        for name in ['GS_26', 'GSL_7-27', 'La_0-1_0-2', 'Le_4-0_0-0']:
            self.assertTrue(o.sn_is_emulation_network(name), name)

    def test_cleanup_only_removes_service_members_and_matching_networks(self):
        calls = []
        owner = 'batch-123'
        service = 'starrynet-batch-123'

        def command(arguments, check=True):
            arguments = list(arguments)
            calls.append(arguments)
            if arguments[:2] == ['service', 'inspect']:
                return [owner] if sum(1 for call in calls
                                      if call[:2] == ['service', 'inspect']) == 1 else []
            if arguments[:2] == ['ps', '-aq']:
                return ['owned-container'] if sum(1 for call in calls if call[:2] == ['ps', '-aq']) == 1 else []
            if arguments[:3] == ['network', 'ls', '--filter']:
                return ['owned-network'] if sum(1 for call in calls if call[:2] == ['network', 'ls']) == 1 else []
            return []

        with patch.dict(os.environ, {'STARRYNET_OWNER': owner,
                                    'STARRYNET_SERVICE': service}), \
                patch.object(o, 'sn_docker_cleanup_command', side_effect=command), \
                patch.object(o, 'sleep'):
            o.sn_stop_emulation()
        self.assertIn(['service', 'rm', service], calls)
        self.assertIn(['rm', '-f', 'owned-container'], calls)
        self.assertIn(['network', 'rm', 'owned-network'], calls)
        self.assertTrue(all('-a' not in args for args in calls))
        scoped_container_queries = [args for args in calls if args[:2] == ['ps', '-aq']]
        self.assertTrue(scoped_container_queries)
        self.assertTrue(all('label=starrynet.owner=' + owner in args and
                            'label=com.docker.swarm.service.name=' + service in args
                            for args in scoped_container_queries))

    def test_cleanup_does_not_delete_unmarked_legacy_service_or_containers(self):
        calls = []

        def command(arguments, check=True):
            arguments = list(arguments)
            calls.append(arguments)
            if arguments[:2] == ['service', 'inspect']:
                return [''] if sum(1 for call in calls
                                   if call[:2] == ['service', 'inspect']) == 1 else []
            return []

        with patch.dict(os.environ, {}, clear=True), \
                patch.object(o, 'sn_docker_cleanup_command', side_effect=command), \
                self.assertRaisesRegex(RuntimeError, 'unmarked'):
            o.sn_stop_emulation()
        self.assertNotIn(['service', 'rm', 'constellation-test'], calls)
        self.assertFalse(any(args[:2] in (['rm', '-f'], ['network', 'rm'])
                             for args in calls))

    def test_cleanup_does_not_delete_same_named_service_owned_by_another_batch(self):
        calls = []

        def command(arguments, check=True):
            arguments = list(arguments)
            calls.append(arguments)
            if arguments[:2] == ['service', 'inspect']:
                return ['batch-previous'] if sum(
                    1 for call in calls if call[:2] == ['service', 'inspect']) == 1 else []
            return []

        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-current',
                                    'STARRYNET_SERVICE': 'same-service'}), \
                patch.object(o, 'sn_docker_cleanup_command', side_effect=command), \
                self.assertRaisesRegex(RuntimeError, 'batch-previous'):
            o.sn_stop_emulation()
        self.assertNotIn(['service', 'rm', 'same-service'], calls)

        # The legacy CLI follows the same guarded implementation.
        with patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-current',
                                    'STARRYNET_SERVICE': 'same-service'}), \
                patch.object(clean, 'sn_stop_emulation', wraps=o.sn_stop_emulation) as stop, \
                patch.object(o, 'sn_docker_cleanup_command', side_effect=command), \
                self.assertRaisesRegex(RuntimeError, 'batch-previous'):
            calls[:] = []
            clean.cleanup()
        stop.assert_called_once_with()
        self.assertNotIn(['service', 'rm', 'same-service'], calls)

    def test_cleanup_empty_environment_is_repeatable(self):
        with patch.object(o, 'sn_docker_cleanup_command', return_value=[]) as command:
            o.sn_stop_emulation()
            o.sn_stop_emulation()
        self.assertTrue(all(c[0][0][0] not in ('rm',) for c in command.call_args_list))

    def test_cleanup_rejects_system_network_deletion(self):
        with self.assertRaises(ValueError), patch.object(o, 'sn_docker_cleanup_command') as command:
            o.sn_del_network('ingress')
        command.assert_not_called()

    def test_cleanup_reports_remaining_resources(self):
        calls = []
        def command(arguments, check=True):
            arguments = list(arguments)
            calls.append(arguments)
            if arguments[:2] == ['network', 'ls']:
                return ['leftover']
            return []
        with patch.object(o, 'sn_docker_cleanup_command', side_effect=command):
            with self.assertRaisesRegex(RuntimeError, 'cleanup incomplete'):
                o.sn_stop_emulation()

    def test_gsl_route_conflict_retries_only_exact_bird_subnet(self):
        with patch.object(u, 'sn_remote_cmd', side_effect=[
                [], RuntimeError('conflicts with existing route'), [], []]) as command:
            u.sn_connect_gsl(None, 'GSL_7-27', 'gs27', '9.2.7.60')
        self.assertEqual([c[0][1] for c in command.call_args_list], [
            'docker exec -i gs27 ip route flush proto bird exact 9.2.7.0/24',
            'docker network connect --ip 9.2.7.60 GSL_7-27 gs27',
            'docker exec -i gs27 ip route flush proto bird exact 9.2.7.0/24',
            'docker network connect --ip 9.2.7.60 GSL_7-27 gs27'])

    def test_gsl_unrelated_failure_is_not_retried(self):
        with patch.object(u, 'sn_remote_cmd', side_effect=[
                [], RuntimeError('network not found')]) as command:
            with self.assertRaisesRegex(RuntimeError, 'network not found'):
                u.sn_connect_gsl(None, 'GSL_7-27', 'gs27', '9.2.7.60')
        self.assertEqual(command.call_count, 2)

    def test_gsl_parameters_applied_together_after_interface_rename(self):
        addresses = ['5: eth3@if6 inet 9.2.7.60/24 scope global eth3\r\n']
        with patch.object(u, 'sn_remote_cmd', side_effect=[addresses, [], [], [], []]) as command:
            u.sn_configure_gsl(None, 'gs27', '9.2.7.60', 'B27-eth7', 12, 5, 1)
        commands = [c[0][1] for c in command.call_args_list]
        self.assertIn('docker exec -i gs27 ip link set dev eth3 name B27-eth7', commands)
        self.assertEqual(commands[-1], 'docker exec -i gs27 tc qdisc replace dev '
                         'B27-eth7 root netem delay 12ms loss 1% rate 5Gbit')
        self.assertTrue(all('exec -d' not in c for c in commands))

    def test_missing_gsl_interface_stops_configuration(self):
        with patch.object(u, 'sn_remote_cmd', return_value=[] ) as command:
            with self.assertRaisesRegex(RuntimeError, 'Missing GSL address'):
                u.sn_configure_gsl(None, 'gs27', '9.2.7.60', 'B27-eth7', 12, 5, 1)
        self.assertEqual(command.call_count, 1)

    def test_measurement_error_is_reported_to_joiner(self):
        def fail():
            raise RuntimeError('iperf failure')
        worker = u.MeasurementThread(target=fail)
        worker.start()
        with self.assertRaises(RuntimeError) as caught:
            worker.join()
        self.assertIn('iperf failure', str(caught.exception.__cause__))

    def test_perf_uses_parsed_ip_and_writes_measurement(self):
        with tempfile.TemporaryDirectory() as base:
            (Path(base) / 'run').mkdir()
            with patch.object(u, 'sn_interface_ipv4',
                    return_value=ipaddress.ip_interface('10.0.5.40/24')), \
                    patch.object(u, 'sn_remote_cmd', return_value=['measured throughput\n']) as command:
                u.sn_perf(1, 2, 4, 25, ['node1', 'node2'], 'run', base, None)
            self.assertIn('iperf3 -c 10.0.5.40 -t 5', command.call_args[0][1])
            self.assertEqual((Path(base) / 'run/perf-1-2_4.txt').read_text(),
                             'measured throughput\n')

    def test_service_creation_uses_service_create_registry_flag(self):
        with patch.object(u, 'sn_remote_cmd', return_value=[] ) as command, \
                patch.object(u, 'sn_delete_remote_network_bridge'), \
                patch.object(u, 'sn_get_container_info', return_value=['a'] * 27):
            u.sn_reset_docker_env(None, 'constellation-test', 27)
        create = next(call[0][1] for call in command.call_args_list
                      if call[0][1].startswith('docker service create '))
        self.assertEqual(create,
            'docker service create --replicas 27 --name constellation-test '
            '--label starrynet.owner=constellation-test '
            '--container-label starrynet.owner=constellation-test '
            '--cap-add ALL --no-resolve-image --detach=true '
            'lwsen/starlab_node:1.0 sleep infinity')

    def test_reset_refuses_service_with_unmarked_or_different_owner(self):
        for actual_owner, expected_error in (('', 'unmarked'),
                                             ('batch-previous', 'batch-previous')):
            with self.subTest(actual_owner=actual_owner), \
                    patch.dict(os.environ, {'STARRYNET_OWNER': 'batch-current',
                                            'STARRYNET_SERVICE': 'constellation-test'}), \
                    patch.object(u, 'sn_remote_cmd',
                                 side_effect=[[actual_owner]]) as command, \
                    patch.object(u, 'sn_delete_remote_network_bridge'):
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    u.sn_reset_docker_env(None, 'constellation-test', 27)
            self.assertEqual(command.call_count, 1)
            self.assertIn('docker service inspect', command.call_args[0][1])

    def test_directory_initialization_repeats_with_partial_directory(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            (root / 'run' / 'mid_files').mkdir(parents=True)
            old = root / 'run' / 'old.txt'
            old.write_text('old measurement')
            worker = u.sn_init_directory_thread('run', base, None)
            with patch.object(u, 'sn_remote_cmd'):
                worker.run_checked()
                worker.run_checked()
            self.assertTrue((root / 'run' / 'delay').is_dir())
            self.assertTrue((root / 'run' / 'mid_files').is_dir())
            self.assertFalse(old.exists())

    def test_routing_directories_can_already_exist_remotely(self):
        with tempfile.TemporaryDirectory() as base:
            remote_home = Path(base) / 'remote'
            remote_conf = remote_home / 'run' / 'conf' / 'bird-25-2'
            remote_conf.mkdir(parents=True)
            instance = observer.Observer.__new__(observer.Observer)
            instance.configuration_file_path = str(Path(base) / 'local')
            instance.file_path = 'run'
            instance.intra_routing = 'OSPF'
            instance.orbit_number = instance.sat_number = 5
            instance.GS_lat_long = [[0, 0], [1, 1]]
            instance.AS = []
            def execute(ssh, command):
                return subprocess.check_output(command, shell=True,
                    env=dict(os.environ, HOME=str(remote_home))).decode().splitlines(True)
            with patch.object(observer, 'sn_remote_cmd', side_effect=execute), \
                    patch.object(observer, 'sn_get_param', return_value=[]):
                instance.generate_conf(None, None)
                instance.generate_conf(None, None)
            self.assertTrue(remote_conf.is_dir())
            self.assertTrue((Path(base) / 'local/run/conf/bird-25-2').is_dir())

    def test_remote_failure_exposes_original_error(self):
        ssh = Mock()
        stdout = Mock()
        stdout.readlines.return_value = []
        stdout.channel.recv_exit_status.return_value = 1
        ssh.exec_command.return_value = (None, stdout, io.BytesIO(b'No module named numpy'))
        with self.assertRaisesRegex(RuntimeError, 'No module named numpy'):
            u.sn_remote_cmd(ssh, 'python3 script.py')

    def test_expected_nonzero_measurement_can_be_recorded(self):
        ssh = Mock()
        stdout = Mock()
        stdout.readlines.return_value = ['100% packet loss\n']
        stdout.channel.recv_exit_status.return_value = 1
        ssh.exec_command.return_value = (None, stdout, io.BytesIO())
        self.assertEqual(u.sn_remote_cmd(ssh, 'ping', check=False), ['100% packet loss\n'])

    def test_worker_failure_reaches_joiner(self):
        class Failing(u.CheckedThread):
            def run_checked(self):
                raise ValueError('original error')
        worker = Failing()
        worker.start()
        with self.assertRaises(RuntimeError) as caught:
            worker.join()
        self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_node_mapping_uses_numeric_order(self):
        with patch.object(u, 'sn_remote_cmd', return_value=[
                'ccc ovs_container_27\n', 'bbb ovs_container_2\n', 'aaa ovs_container_1\n']):
            self.assertEqual(u.sn_get_container_info(None), ['aaa', 'bbb', 'ccc'])

    def test_remote_mapping_matches_controller(self):
        with patch('subprocess.check_output', return_value=(
                b'ccc ovs_container_27\nbbb ovs_container_2\naaa ovs_container_1\n')):
            self.assertEqual(o.sn_get_container_info(), ['aaa', 'bbb', 'ccc'])

    def test_missing_address_is_explicit(self):
        with patch.object(u, 'sn_remote_cmd', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'No IPv4 address'):
                u.sn_interface_ipv4(None, 'node27', 'B27-default')

    def test_route_uses_ground_station_subnet_and_atomic_replace(self):
        dest = ['2: eth0 inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0',
                '3: B27-eth13 inet 9.2.13.60/24 scope global B27-eth13',
                '4: B27-default inet 9.27.27.10/24 scope global B27-default']
        gateway = ['3: B2-eth1 inet 10.0.1.10/24 scope global B2-eth1']
        with patch.object(u, 'sn_remote_cmd', side_effect=[
                dest, gateway, []]) as cmd:
            u.sn_sr(1, 27, 2, ['node{}'.format(i) for i in range(1, 28)], None)
            self.assertEqual(cmd.call_args[0][1],
                'docker exec -i node1 ip route replace 9.27.27.0/24 dev B1-eth2 via 10.0.1.10')

    def test_satellite_destination_still_supported(self):
        addresses = ['3: B3-eth4@if5 inet 10.0.5.40/24 scope global B3-eth4']
        with patch.object(u, 'sn_remote_cmd', return_value=addresses):
            self.assertEqual(str(u.sn_interface_ipv4(None, 'node3').network), '10.0.5.0/24')

    def test_cleanup_uses_configured_interpreter(self):
        ssh = Mock()
        ssh.starrynet_python = '/env/starrynet/bin/python'
        with patch.object(u, 'sn_remote_cmd') as cmd:
            worker = u.sn_Emulation_Stop_Thread(ssh, Mock(), 'run')
            worker.run_checked()
            self.assertEqual(cmd.call_args[0][1],
                '/env/starrynet/bin/python run/sn_orchestrater.py')


if __name__ == '__main__':
    unittest.main()
