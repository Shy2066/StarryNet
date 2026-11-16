import os
import threading
import json
import copy
import argparse
import os
from time import sleep
import time
import numpy
import random
import shlex
import ipaddress
from contextlib import contextmanager
from starrynet.sn_thread import CheckedThread
from starrynet.resource_scope import (
    OWNER_ENV, SERVICE_ENV, configure_executor, environment_for, owner_filter, owner_label,
    resource_identity, scoped_shell, service_filter)
"""
Starrynet utils that are used in sn_synchronizer
author: Yangtao Deng (dengyt21@mails.tsinghua.edu.cn) and Zeqi Lai (zeqilai@tsinghua.edu.cn)
"""
try:
    import threading
except ImportError:
    os.system("pip3 install threading")
    import threading

try:
    import paramiko
except ImportError:
    os.system("pip3 install paramiko")
    import paramiko

try:
    import requests
except ImportError:
    os.system("pip3 install requests")
    import requests


def get_right_satellite(current_sat_id, current_orbit_id, orbit_num):
    if current_orbit_id == orbit_num - 1:
        return [current_sat_id, 0]
    else:
        return [current_sat_id, current_orbit_id + 1]


def get_down_satellite(current_sat_id, current_orbit_id, sat_num):
    if current_sat_id == sat_num - 1:
        return [0, current_orbit_id]
    else:
        return [current_sat_id + 1, current_orbit_id]


def sn_load_file(path, GS_lat_long, argv=None):
    with open(path, "r", encoding='utf8') as f:
        table = json.load(f)
    data = {}
    data['cons_name'] = table["Name"]
    data['altitude'] = table["Altitude (km)"]
    data['cycle'] = table["Cycle (s)"]
    data['inclination'] = table["Inclination"]
    data['phase_shift'] = table["Phase shift"]
    data['orbit'] = table["# of orbit"]
    data['sat'] = table["# of satellites"]
    data['link'] = table["Satellite link"]
    data['duration'] = table["Duration (s)"]
    data['ip'] = table["IP version"]
    data['intra_as_routing'] = table["Intra-AS routing"]
    data['inter_as_routing'] = table["Inter-AS routing"]
    data['link_policy'] = table["Link policy"]
    data['handover_policy'] = table["Handover policy"]
    data['update_time'] = table["update_time (s)"]
    data['sat_bw'] = table["satellite link bandwidth (\"X\" Gbps)"]
    data['sat_ground_bw'] = table["sat-ground bandwidth (\"X\" Gbps)"]
    data['sat_loss'] = table["satellite link loss (\"X\"% )"]
    data['sat_ground_loss'] = table["sat-ground loss (\"X\"% )"]
    data['ground_num'] = table["GS number"]
    data['multi_machine'] = table[
        "multi-machine (\"0\" for no, \"1\" for yes)"]
    data['antenna_number'] = table["antenna number"]
    data['antenna_inclination'] = table["antenna_inclination_angle"]
    data['remote_machine_IP'] = table["remote_machine_IP"]
    data['remote_machine_username'] = table["remote_machine_username"]
    data['remote_machine_password'] = table["remote_machine_password"]

    parser = argparse.ArgumentParser(description='manual to this script')
    parser.add_argument('--cons_name', type=str, default=data['cons_name'])
    parser.add_argument('--satellite_altitude',
                        type=int,
                        default=data['altitude'])
    parser.add_argument('--inclination', type=int, default=data['inclination'])
    parser.add_argument('--orbit_number', type=int, default=data['orbit'])
    parser.add_argument('--sat_number', type=int, default=data['sat'])
    parser.add_argument('--fac_num', type=int, default=len(GS_lat_long))
    parser.add_argument('--link_style', type=str, default=data['link'])
    parser.add_argument('--IP_version', type=str, default=data['ip'])
    parser.add_argument('--link_policy', type=str, default=data['link_policy'])
    # link delay updating granularity
    parser.add_argument('--update_interval',
                        type=int,
                        default=data['update_time'])
    parser.add_argument('--duration', type=int, default=data['duration'])
    parser.add_argument('--inter_routing',
                        type=str,
                        default=data['inter_as_routing'])
    parser.add_argument('--intra_routing',
                        type=str,
                        default=data['intra_as_routing'])
    parser.add_argument('--cycle', type=int, default=data['cycle'])
    parser.add_argument('--time_slot', type=int, default=100)
    parser.add_argument('--sat_bandwidth', type=int, default=data['sat_bw'])
    parser.add_argument('--sat_ground_bandwidth',
                        type=int,
                        default=data['sat_ground_bw'])
    parser.add_argument('--sat_loss', type=int, default=data['sat_loss'])
    parser.add_argument('--sat_ground_loss',
                        type=int,
                        default=data['sat_ground_loss'])
    parser.add_argument('--ground_num', type=int, default=data['ground_num'])
    parser.add_argument('--multi_machine',
                        type=int,
                        default=data['multi_machine'])
    parser.add_argument('--antenna_number',
                        type=int,
                        default=data['antenna_number'])
    parser.add_argument('--antenna_inclination',
                        type=int,
                        default=data['antenna_inclination'])
    parser.add_argument('--user_num', type=int, default=0)
    parser.add_argument('--remote_machine_IP',
                        type=str,
                        default=data['remote_machine_IP'])
    parser.add_argument('--remote_machine_username',
                        type=str,
                        default=data['remote_machine_username'])
    parser.add_argument('--remote_machine_password',
                        type=str,
                        default=data['remote_machine_password'])

    parser.add_argument('--path',
                        '-p',
                        type=str,
                        default="starrynet/config.xls")
    parser.add_argument('--hello_interval', '-i', type=int, default=10)
    parser.add_argument('--node_number', '-n', type=int, default=27)
    parser.add_argument('--GS',
                        '-g',
                        type=str,
                        default="50.110924/8.682127/46.635700/14.311817")

    sn_args = parser.parse_args(argv)
    return sn_args


def sn_get_param(file_):
    f = open(file_)
    ADJ = f.readlines()
    for i in range(len(ADJ)):
        ADJ[i] = ADJ[i].strip('\n')
    ADJ = [x.split(',') for x in ADJ]
    f.close()
    return ADJ


def sn_init_remote_machine(host, username, password):
    # transport = paramiko.Transport((host, 37619))
    # transport.connect(username=username, password=password)
    remote_machine_ssh = paramiko.SSHClient()
    # remote_machine_ssh._transport = transport
    remote_machine_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    remote_machine_ssh.connect(hostname=host,
                               port=37619,
                               username=username,
                               password=password)
    transport = paramiko.Transport((host, 37619))
    transport.connect(username=username, password=password)
    return remote_machine_ssh, transport
    # transport.close()


def sn_init_remote_ftp(transport):
    ftp_client = paramiko.SFTPClient.from_transport(transport)  ## ftp client
    return ftp_client


def sn_upload_orchestrater(remote_ftp, file_path):
    for name in ('sn_orchestrater.py', 'sn_thread.py', 'resource_scope.py'):
        remote_ftp.put(os.path.join(os.path.dirname(__file__), name),
                       file_path + '/' + name)


def sn_remote_cmd(remote_ssh, cmd, check=True):
    """Run a command with this run's resource identity in either executor."""
    environment = environment_for(remote_ssh)
    owner, service = resource_identity(environment)
    if getattr(remote_ssh, 'is_local_executor', False) is True:
        remote_ssh.env_overrides[OWNER_ENV] = owner
        remote_ssh.env_overrides[SERVICE_ENV] = service
        allowed = (0,) if check else tuple(range(256))
        return remote_ssh.run(cmd, allowed_returncodes=allowed,
                              include_stderr_on_failure=check)

    remote_command = scoped_shell(cmd, environment)
    _stdin, stdout, stderr = remote_ssh.exec_command(remote_command,
                                                     get_pty=True)
    lines = [line.decode('utf8', 'replace') if isinstance(line, bytes) else line
             for line in stdout.readlines()]
    errors = [line.decode('utf8', 'replace') if isinstance(line, bytes) else line
              for line in stderr.readlines()]
    exit_status = stdout.channel.recv_exit_status()
    if check and exit_status != 0:
        raise RuntimeError("remote command failed ({}): {}{}".format(
            exit_status, ''.join(errors), ''.join(lines)))
    return lines


def sn_remote_checked_cmd(remote_ssh, cmd):
    """Run a remote command and raise when it exits unsuccessfully."""
    return sn_remote_cmd(remote_ssh, cmd, check=True)


# A thread designed for initializing working directory.
class sn_init_directory_thread(CheckedThread):

    def __init__(self, file_path, configuration_file_path, remote_ssh):
        CheckedThread.__init__(self)
        self.file_path = file_path
        self.remote_ssh = remote_ssh
        self.configuration_file_path = configuration_file_path

    def run(self):
        if getattr(self.remote_ssh, 'is_local_executor', False) is True:
            from pathlib import Path
            base = Path(self.configuration_file_path) / self.file_path
            for name in ('delay', 'mid_files'):
                (base / name).mkdir(parents=True, exist_ok=True)
            return
        # Reset docker environment.
        os.system("rm " + self.configuration_file_path + "/" + self.file_path +
                  "/*.txt")
        if os.path.exists(self.file_path + "/mid_files") == False:
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path)
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path + "/delay")
            os.system("mkdir " + self.configuration_file_path + "/" +
                      self.file_path + "/mid_files")
        sn_remote_cmd(self.remote_ssh, "mkdir ~/" + self.file_path)
        sn_remote_cmd(self.remote_ssh, "mkdir ~/" + self.file_path + "/delay")


# A thread designed for initializing constellation nodes.
class sn_Node_Init_Thread(CheckedThread):

    def __init__(self, remote_ssh, docker_service_name, node_size,
                 container_id_list, container_global_idx):
        CheckedThread.__init__(self)
        self.remote_ssh = remote_ssh
        self.docker_service_name = docker_service_name
        self.node_size = node_size
        self.container_global_idx = container_global_idx
        self.container_id_list = copy.deepcopy(container_id_list)

    def run(self):

        # Reset docker environment.
        sn_reset_docker_env(self.remote_ssh, self.docker_service_name,
                            self.node_size)
        # Get container list in each machine.
        self.container_id_list = sn_get_container_info(self.remote_ssh)
        # Rename all containers with the global idx
        sn_rename_all_container(self.remote_ssh, self.container_id_list,
                                self.container_global_idx)


def _sn_container_index(row):
    fields = row.split()
    if len(fields) < 2:
        raise RuntimeError('Unexpected Docker container listing: ' + row)
    name = fields[1]
    try:
        if name.startswith('ovs_container_'):
            return int(name.rsplit('_', 1)[1])
        return int(name.split('.')[1])
    except (IndexError, ValueError):
        raise RuntimeError('Cannot determine StarryNet node order from ' + name)


def sn_get_container_info(remote_machine_ssh, docker_service_name=None,
                          owner=None):
    environment = environment_for(remote_machine_ssh)
    resolved_owner, service = resource_identity(
        environment, service=docker_service_name, owner=owner)
    rows = sn_remote_cmd(remote_machine_ssh,
        "docker ps --filter " + shlex.quote(service_filter(service)) +
        " --filter " + shlex.quote(owner_filter(resolved_owner)) +
        " --format '{{.ID}} {{.Names}}'")
    return [row.split()[0] for row in sorted(rows, key=_sn_container_index)]


def sn_delete_remote_network_bridge(remote_ssh, owner=None):
    environment = environment_for(remote_ssh)
    resolved_owner, _service = resource_identity(environment, owner=owner)
    for line in sn_remote_cmd(remote_ssh,
            "docker network ls --filter " + shlex.quote(owner_filter(resolved_owner)) +
            " --format '{{.ID}}'"):
        network_id = line.strip()
        if network_id:
            sn_remote_checked_cmd(remote_ssh,
                                   'docker network rm ' + shlex.quote(network_id))


def sn_reset_docker_env(remote_ssh, docker_service_name, node_size):
    environment = environment_for(remote_ssh)
    owner, service = resource_identity(environment, service=docker_service_name)
    configure_executor(remote_ssh, owner, service)
    print("Reset docker environment for constellation emulation ...")
    print("Remove only resources owned by this run.")
    owner_output = sn_remote_cmd(remote_ssh,
        "docker service inspect --format " +
        shlex.quote('{{ if .Spec.Labels }}{{ index .Spec.Labels "starrynet.owner" }}{{ else }}UNOWNED{{ end }}') + " " +
        shlex.quote(service) + ' 2>/dev/null', check=False)
    if owner_output:
        actual_owner = owner_output[0].strip() if owner_output else ''
        if actual_owner != owner:
            raise RuntimeError(
                'Refusing to replace service {!r}: owner is {!r}, expected {!r}'.format(
                    service, actual_owner or 'unmarked', owner))
        sn_remote_checked_cmd(remote_ssh,
                              "docker service rm " + shlex.quote(service))
        sleep(3)
    container_ids = sn_remote_cmd(remote_ssh,
        "docker ps -aq --filter " + shlex.quote(service_filter(service)) +
        " --filter " + shlex.quote(owner_filter(owner)))
    for cid in container_ids:
        container_id = cid.strip()
        if container_id:
            sn_remote_checked_cmd(remote_ssh,
                "docker rm -f " + shlex.quote(container_id))
    print("Remove this owner's emulated links.")
    sn_delete_remote_network_bridge(remote_ssh, owner=owner)
    print("Creating new containers...")
    service_command = ["docker", "service", "create", "--replicas",
                       str(node_size), "--name", str(service),
                       "--label", owner_label(owner),
                       "--container-label", owner_label(owner),
                       "--cap-add", "ALL", "--no-resolve-image",
                       "--detach=true", "lwsen/starlab_node:1.0", "sleep",
                       "infinity"]
    sn_remote_checked_cmd(remote_ssh, " ".join(
        shlex.quote(arg) for arg in service_command))
    started = time.monotonic()
    progress_deadline = started + 90
    absolute_deadline = started + 300
    last_ready = -1
    while True:
        ready = len(sn_get_container_info(remote_ssh, service, owner))
        if ready == node_size:
            break
        now = time.monotonic()
        if ready > last_ready:
            last_ready = ready
            progress_deadline = now + 90
        if now > progress_deadline or now > absolute_deadline:
            raise RuntimeError(
                'StarryNet containers did not become ready: {0}/{1} ready; '
                'no progress for 90 seconds or 300-second absolute limit reached'.format(
                    ready, node_size))
        sleep(1)


def sn_rename_all_container(remote_ssh, container_id_list, new_idx):
    print("Rename all containers ...")
    new_idx = 1
    for container_id in container_id_list:
        sn_remote_cmd(
            remote_ssh, "docker rename " + str(container_id) +
            " ovs_container_" + str(new_idx))
        new_idx = new_idx + 1


# A thread designed for initializing constellation links.
class sn_Link_Init_Thread(CheckedThread):

    def __init__(self, remote_ssh, remote_ftp, orbit_num, sat_num,
                 constellation_size, fac_num, file_path,
                 configuration_file_path, sat_bandwidth, sat_ground_bandwidth,
                 sat_loss, sat_ground_loss):
        CheckedThread.__init__(self)
        self.remote_ssh = remote_ssh
        self.constellation_size = constellation_size
        self.fac_num = fac_num
        self.orbit_num = orbit_num
        self.sat_num = sat_num
        self.file_path = file_path
        self.configuration_file_path = configuration_file_path
        self.sat_bandwidth = sat_bandwidth
        self.sat_ground_bandwidth = sat_ground_bandwidth
        self.sat_loss = sat_loss
        self.sat_ground_loss = sat_ground_loss
        self.remote_ftp = remote_ftp

    def run(self):
        print('Run in link init thread.')
        sn_upload_orchestrater(self.remote_ftp, self.file_path)
        self.remote_ftp.put(
            self.configuration_file_path + "/" + self.file_path +
            '/delay/1.txt', self.file_path + "/1.txt")
        print('Initializing links ...')
        sn_remote_cmd(
            self.remote_ssh, "python3 " + self.file_path +
            "/sn_orchestrater.py" + " " + str(self.orbit_num) + " " +
            str(self.sat_num) + " " + str(self.constellation_size) + " " +
            str(self.fac_num) + " " + str(self.sat_bandwidth) + " " +
            str(self.sat_loss) + " " + str(self.sat_ground_bandwidth) + " " +
            str(self.sat_ground_loss) + " " + self.file_path + "/1.txt")


# A thread designed for initializing bird routing.
class sn_Routing_Init_Thread(CheckedThread):

    def __init__(self, remote_ssh, remote_ftp, orbit_num, sat_num,
                 constellation_size, fac_num, file_path, sat_bandwidth,
                 sat_ground_bandwidth, sat_loss, sat_ground_loss):
        CheckedThread.__init__(self)
        self.remote_ssh = remote_ssh
        self.constellation_size = constellation_size
        self.fac_num = fac_num
        self.orbit_num = orbit_num
        self.sat_num = sat_num
        self.file_path = file_path
        self.sat_bandwidth = sat_bandwidth
        self.sat_ground_bandwidth = sat_ground_bandwidth
        self.sat_loss = sat_loss
        self.sat_ground_loss = sat_ground_loss
        self.remote_ftp = remote_ftp

    def run(self):
        print(
            "Copy bird configuration file to each container and run routing process."
        )
        sn_upload_orchestrater(self.remote_ftp, self.file_path)
        print('Initializing routing ...')
        sn_remote_cmd(
            self.remote_ssh, "python3 " + self.file_path +
            "/sn_orchestrater.py" + " " + str(self.constellation_size) + " " +
            str(self.fac_num) + " " + self.file_path)
        print("Routing initialized!")


# A thread designed for emulation.
class sn_Emulation_Start_Thread(CheckedThread):

    def __init__(self, remote_ssh, remote_ftp, sat_loss, sat_ground_bw,
                 sat_ground_loss, container_id_list, file_path,
                 configuration_file_path, update_interval, constellation_size,
                 ping_src, ping_des, ping_time, sr_src, sr_des, sr_target,
                 sr_time, damage_ratio, damage_time, damage_list,
                 recovery_time, route_src, route_time, duration,
                 utility_checking_time, perf_src, perf_des, perf_time):
        CheckedThread.__init__(self)
        self.remote_ssh = remote_ssh
        self.remote_ftp = remote_ftp
        self.sat_loss = sat_loss
        self.sat_ground_bw = sat_ground_bw
        self.sat_ground_loss = sat_ground_loss
        self.container_id_list = copy.deepcopy(container_id_list)
        self.file_path = file_path
        self.configuration_file_path = configuration_file_path
        self.update_interval = update_interval
        self.constellation_size = constellation_size
        self.ping_src = ping_src
        self.ping_des = ping_des
        self.ping_time = ping_time
        self.perf_src = perf_src
        self.perf_des = perf_des
        self.perf_time = perf_time
        self.sr_src = sr_src
        self.sr_des = sr_des
        self.sr_target = sr_target
        self.sr_time = sr_time
        self.damage_ratio = damage_ratio
        self.damage_time = damage_time
        self.damage_list = damage_list
        self.recovery_time = recovery_time
        self.route_src = route_src
        self.route_time = route_time
        self.duration = duration
        self.utility_checking_time = utility_checking_time
        self._stop_event = threading.Event()
        if self.container_id_list == []:
            self.container_id_list = sn_get_container_info(self.remote_ssh)

    def request_stop(self):
        self._stop_event.set()

    def run(self):
        ping_threads = []
        perf_threads = []
        timeptr = 2  # current emulating time
        topo_change_file_path = self.configuration_file_path + "/" + self.file_path + '/Topo_leo_change.txt'
        fi = open(topo_change_file_path, 'r')
        line = fi.readline()
        while line:  # starting reading change information and emulating
            if self._stop_event.is_set():
                return
            words = line.split()
            if words[0] == 'time':
                print('Emulation in No.' + str(timeptr) + ' second.')
                # the time when the new change occurrs
                current_time = str(int(words[1][:-1]))
                while int(current_time) > timeptr:
                    if self._stop_event.is_set():
                        return
                    start_time = time.time()
                    if timeptr in self.utility_checking_time:
                        sn_check_utility(
                            timeptr, self.remote_ssh,
                            self.configuration_file_path + "/" +
                            self.file_path)
                    if timeptr % self.update_interval == 0:
                        # updating link delays after link changes
                        sn_update_delay(self.file_path,
                                        self.configuration_file_path, timeptr,
                                        self.constellation_size,
                                        self.remote_ssh, self.remote_ftp)
                    if timeptr in self.damage_time:
                        sn_damage(
                            self.damage_ratio[self.damage_time.index(timeptr)],
                            self.damage_list, self.constellation_size,
                            self.remote_ssh, self.remote_ftp, self.file_path,
                            self.configuration_file_path)
                    if timeptr in self.recovery_time:
                        sn_recover(self.damage_list, self.sat_loss,
                                   self.remote_ssh, self.remote_ftp,
                                   self.file_path,
                                   self.configuration_file_path)
                    if timeptr in self.sr_time:
                        index = [
                            i for i, val in enumerate(self.sr_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            sn_sr(self.sr_src[index_num],
                                  self.sr_des[index_num],
                                  self.sr_target[index_num],
                                  self.container_id_list, self.remote_ssh)
                    if timeptr in self.ping_time:
                        if timeptr in self.ping_time:
                            index = [
                                i for i, val in enumerate(self.ping_time)
                                if val == timeptr
                            ]
                            for index_num in index:
                                ping_thread = CheckedThread(
                                    target=sn_ping,
                                    args=(self.ping_src[index_num],
                                          self.ping_des[index_num],
                                          self.ping_time[index_num],
                                          self.constellation_size,
                                          self.container_id_list,
                                          self.file_path,
                                          self.configuration_file_path,
                                          self.remote_ssh))
                                ping_thread.start()
                                ping_threads.append(ping_thread)
                    if timeptr in self.perf_time:
                        if timeptr in self.perf_time:
                            index = [
                                i for i, val in enumerate(self.perf_time)
                                if val == timeptr
                            ]
                            for index_num in index:
                                perf_thread = CheckedThread(
                                    target=sn_perf,
                                    args=(self.perf_src[index_num],
                                          self.perf_des[index_num],
                                          self.perf_time[index_num],
                                          self.constellation_size,
                                          self.container_id_list,
                                          self.file_path,
                                          self.configuration_file_path,
                                          self.remote_ssh))
                                perf_thread.start()
                                perf_threads.append(perf_thread)
                    if timeptr in self.route_time:
                        index = [
                            i for i, val in enumerate(self.route_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            sn_route(self.route_src[index_num],
                                     self.route_time[index_num],
                                     self.file_path,
                                     self.configuration_file_path,
                                     self.container_id_list, self.remote_ssh)
                    timeptr += 1
                    end_time = time.time()
                    passed_time = (
                        end_time -
                        start_time) if (end_time - start_time) < 1 else 1
                    sleep(1 - passed_time)
                    if timeptr >= self.duration:
                        return
                    print('Emulation in No.' + str(timeptr) + ' second.')
                print("A change in time " + current_time + ':')
                line = fi.readline()
                words = line.split()
                line = fi.readline()
                line = fi.readline()
                words = line.split()
                while words[0] != 'del:':  # addlink
                    if self._stop_event.is_set():
                        return
                    word = words[0].split('-')
                    s = int(word[0])
                    f = int(word[1])
                    if s > f:
                        tmp = s
                        s = f
                        f = tmp
                    print("add link", s, f)
                    current_topo_path = self.configuration_file_path + "/" + self.file_path + '/delay/' + str(
                        current_time) + '.txt'
                    matrix = sn_get_param(current_topo_path)
                    sn_establish_new_GSL(self.container_id_list, matrix,
                                         self.constellation_size,
                                         self.sat_ground_bw,
                                         self.sat_ground_loss, s, f,
                                         self.remote_ssh)
                    line = fi.readline()
                    words = line.split()
                line = fi.readline()
                words = line.split()
                if len(words) == 0:
                    return
                while words[0] != 'time':  # delete link
                    if self._stop_event.is_set():
                        return
                    word = words[0].split('-')
                    s = int(word[0])
                    f = int(word[1])
                    if s > f:
                        tmp = s
                        s = f
                        f = tmp
                    print("del link " + str(s) + "-" + str(f) + "\n")
                    sn_del_link(s, f, self.container_id_list, self.remote_ssh)
                    line = fi.readline()
                    words = line.split()
                    if len(words) == 0:
                        return
                if timeptr in self.utility_checking_time:
                    sn_check_utility(
                        timeptr, self.remote_ssh,
                        self.configuration_file_path + "/" + self.file_path)
                if timeptr % self.update_interval == 0:
                    # updating link delays after link changes
                    sn_update_delay(self.file_path,
                                    self.configuration_file_path, timeptr,
                                    self.constellation_size, self.remote_ssh,
                                    self.remote_ftp)
                if timeptr in self.damage_time:
                    sn_damage(
                        self.damage_ratio[self.damage_time.index(timeptr)],
                        self.damage_list, self.constellation_size,
                        self.remote_ssh, self.remote_ftp, self.file_path,
                        self.configuration_file_path)
                if timeptr in self.recovery_time:
                    sn_recover(self.damage_list, self.sat_loss,
                               self.remote_ssh, self.remote_ftp,
                               self.file_path, self.configuration_file_path)
                if timeptr in self.sr_time:
                    index = [
                        i for i, val in enumerate(self.sr_time)
                        if val == timeptr
                    ]
                    for index_num in index:
                        sn_sr(self.sr_src[index_num], self.sr_des[index_num],
                              self.sr_target[index_num],
                              self.container_id_list, self.remote_ssh)
                if timeptr in self.ping_time:
                    if timeptr in self.ping_time:
                        index = [
                            i for i, val in enumerate(self.ping_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            ping_thread = CheckedThread(
                                target=sn_ping,
                                args=(self.ping_src[index_num],
                                      self.ping_des[index_num],
                                      self.ping_time[index_num],
                                      self.constellation_size,
                                      self.container_id_list, self.file_path,
                                      self.configuration_file_path,
                                      self.remote_ssh))
                            ping_thread.start()
                            ping_threads.append(ping_thread)
                if timeptr in self.perf_time:
                    if timeptr in self.perf_time:
                        index = [
                            i for i, val in enumerate(self.perf_time)
                            if val == timeptr
                        ]
                        for index_num in index:
                            perf_thread = CheckedThread(
                                target=sn_perf,
                                args=(self.perf_src[index_num],
                                      self.perf_des[index_num],
                                      self.perf_time[index_num],
                                      self.constellation_size,
                                      self.container_id_list, self.file_path,
                                      self.configuration_file_path,
                                      self.remote_ssh))
                            perf_thread.start()
                            perf_threads.append(perf_thread)
                if timeptr in self.route_time:
                    index = [
                        i for i, val in enumerate(self.route_time)
                        if val == timeptr
                    ]
                    for index_num in index:
                        sn_route(self.route_src[index_num],
                                 self.route_time[index_num], self.file_path,
                                 self.configuration_file_path,
                                 self.container_id_list, self.remote_ssh)
                timeptr += 1  # current emulating time
                if self._stop_event.is_set():
                    return
                if timeptr >= self.duration:
                    return
        fi.close()
        for ping_thread in ping_threads:
            ping_thread.join()
        for perf_thread in perf_threads:
            perf_thread.join()


def sn_check_utility(time_index, remote_ssh, file_path):
    result = sn_remote_cmd(remote_ssh, "vmstat")
    f = open(file_path + "/utility-info" + "_" + str(time_index) + ".txt", "w")
    f.writelines(result)
    f.close()


def sn_update_delay(file_path, configuration_file_path, timeptr,
                    constellation_size, remote_ssh,
                    remote_ftp):  # updating delays
    sn_upload_orchestrater(remote_ftp, file_path)
    remote_ftp.put(
        configuration_file_path + "/" + file_path + '/delay/' + str(timeptr) +
        '.txt', file_path + '/' + str(timeptr) + '.txt')
    sn_remote_cmd(
        remote_ssh,
        "python3 " + file_path + "/sn_orchestrater.py " + file_path + '/' +
        str(timeptr) + '.txt ' + str(constellation_size) + " update")
    print("Delay updating done.\n")


def sn_damage(ratio, damage_list, constellation_size, remote_ssh, remote_ftp,
              file_path, configuration_file_path):
    print("Randomly setting damaged links...\n")
    random_list = []
    cumulated_damage_list = damage_list
    while len(random_list) < (int(constellation_size * ratio)):
        target = int(random.uniform(0, constellation_size - 1))
        random_list.append(target)
        cumulated_damage_list.append(target)
    numpy.savetxt(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', random_list)
    sn_upload_orchestrater(remote_ftp, file_path)
    remote_ftp.put(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', file_path + "/damage_list.txt")
    sn_remote_cmd(remote_ssh,
                  "python3 " + file_path + "/sn_orchestrater.py " + file_path)
    print("Damage done.\n")


def sn_recover(damage_list, sat_loss, remote_ssh, remote_ftp, file_path,
               configuration_file_path):
    print("Recovering damaged links...\n")
    cumulated_damage_list = damage_list
    numpy.savetxt(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', cumulated_damage_list)
    sn_upload_orchestrater(remote_ftp, file_path)
    remote_ftp.put(
        configuration_file_path + "/" + file_path +
        '/mid_files/damage_list.txt', file_path + "/damage_list.txt")
    sn_remote_cmd(
        remote_ssh, "python3 " + file_path + "/sn_orchestrater.py " +
        file_path + " " + str(sat_loss))
    cumulated_damage_list.clear()
    print("Link recover done.\n")


MeasurementThread = CheckedThread


def sn_interface_ipv4(remote_ssh, container_id, interface=None):
    """Return a parsed IPv4 interface from one StarryNet node."""
    command = 'docker exec -i {} ip -4 -o addr show'.format(
        shlex.quote(str(container_id)))
    if interface:
        command += ' dev ' + shlex.quote(interface)
    rows = sn_remote_cmd(remote_ssh, command)
    candidates = []
    for row in rows:
        fields = row.split()
        for index, field in enumerate(fields):
            if field == 'inet' and index + 1 < len(fields):
                try:
                    parsed = ipaddress.ip_interface(fields[index + 1])
                except ValueError:
                    continue
                iface = fields[1].split('@')[0] if len(fields) > 1 else ''
                if interface and iface != interface:
                    continue
                if iface not in ('lo', 'eth0'):
                    candidates.append((iface, parsed))
    if not candidates:
        raise RuntimeError('No IPv4 address found on {}{}'.format(
            container_id, ' interface ' + interface if interface else ''))
    if interface:
        return candidates[0][1]
    for iface, parsed in candidates:
        if iface.endswith('-default'):
            return parsed
    return candidates[0][1]


def sn_connect_gsl(remote_ssh, network_name, container_id, address):
    """Connect a GS endpoint, retrying only a BIRD route conflict once."""
    if '/' in address:
        subnet = str(ipaddress.ip_interface(address).network)
    else:
        subnet = str(ipaddress.ip_network(address + '/24', strict=False))
    flush = ('docker exec -i {} ip route flush proto bird exact {}'.format(
        shlex.quote(str(container_id)), shlex.quote(subnet)))
    connect = ('docker network connect --ip {} {} {}'.format(
        shlex.quote(address), shlex.quote(network_name),
        shlex.quote(str(container_id))))
    sn_remote_cmd(remote_ssh, flush)
    try:
        sn_remote_cmd(remote_ssh, connect)
    except RuntimeError as exc:
        if 'conflicts with existing route' not in str(exc).lower():
            raise
        sn_remote_cmd(remote_ssh, flush)
        sn_remote_cmd(remote_ssh, connect)


def sn_configure_gsl(remote_ssh, container_id, address, interface_name,
                     delay, bandwidth, loss):
    """Rename a new ground link and apply all link parameters atomically."""
    rows = sn_remote_cmd(remote_ssh,
        'docker exec -i {} ip -4 -o addr show'.format(
            shlex.quote(str(container_id))))
    target_interface = None
    for row in rows:
        fields = row.split()
        if 'inet' not in fields:
            continue
        address_index = fields.index('inet') + 1
        if (address_index < len(fields) and
                fields[address_index].split('/')[0] == address):
            target_interface = fields[1].split('@')[0] if len(fields) > 1 else None
            break
    if target_interface is None:
        raise RuntimeError('Missing GSL address {} on {}'.format(
            address, container_id))
    old = shlex.quote(target_interface)
    new = shlex.quote(interface_name)
    node = shlex.quote(str(container_id))
    commands = (
        'docker exec -i {} ip link set dev {} down'.format(node, old),
        'docker exec -i {} ip link set dev {} name {}'.format(node, old, new),
        'docker exec -i {} ip link set dev {} up'.format(node, new),
        'docker exec -i {} tc qdisc replace dev {} root netem delay {}ms loss {}% rate {}Gbit'.format(
            node, new, delay, loss, bandwidth),
    )
    for command in commands:
        sn_remote_checked_cmd(remote_ssh, command)


def sn_sr(src, des, target, container_id_list, remote_ssh):
    destination = sn_interface_ipv4(remote_ssh,
        container_id_list[des - 1], 'B{}-default'.format(des))
    gateway = sn_interface_ipv4(remote_ssh, container_id_list[target - 1],
                                'B{}-eth{}'.format(target, src))
    command = ('docker exec -i {} ip route replace {} dev B{}-eth{} via {}'.format(
        shlex.quote(str(container_id_list[src - 1])), destination.network,
        src, target, gateway.ip))
    sn_remote_checked_cmd(remote_ssh, command)
    print(command)

def sn_ping(src, des, time_index, constellation_size, container_id_list,
            file_path, configuration_file_path, remote_ssh):
    if des <= constellation_size:
        ifconfig_output = sn_remote_cmd(
            remote_ssh, "docker exec -i " + str(container_id_list[des - 1]) +
            " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'")
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -i " + str(container_id_list[des - 1]) +
            " ifconfig " + ifconfig_output[0][:-1] +
            "|awk -F '[ :]+' 'NR==2{print $4}'")
    else:
        des_IP = sn_remote_cmd(
            remote_ssh, "docker exec -i " + str(container_id_list[des - 1]) +
            " ifconfig B" + str(des) +
            "-default |awk -F '[ :]+' 'NR==2{print $4}'")
    ping_command = ("docker exec -i " + str(container_id_list[src - 1]) +
                    " ping " + str(des_IP[0][:-1]) + " -c 4 -i 0.01 ")
    if getattr(remote_ssh, 'is_local_executor', False) is True:
        # A ping timeout or unreachable route is a measurement, not a worker crash.
        ping_result = remote_ssh.run(ping_command, allowed_returncodes=(0, 1, 2))
    else:
        ping_result = sn_remote_cmd(remote_ssh, ping_command, check=False)
    f = open(
        configuration_file_path + "/" + file_path + "/ping-" + str(src) + "-" +
        str(des) + "_" + str(time_index) + ".txt", "w")
    f.writelines(ping_result)
    f.close()


def sn_perf(src, des, time_index, constellation_size, container_id_list,
            file_path, configuration_file_path, remote_ssh):
    interface = ('B{}-default'.format(des) if des > constellation_size else None)
    destination = sn_interface_ipv4(remote_ssh,
                                    container_id_list[des - 1], interface)
    sn_remote_cmd(
        remote_ssh,
        "docker exec -i -d " + str(container_id_list[des - 1]) + " iperf3 -s -1 ")
    print("iperf server success")
    perf_result = sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[src - 1]) +
        " iperf3 -c " + str(destination.ip) + " -t 5 ")
    print("iperf client success")
    f = open(
        configuration_file_path + "/" + file_path + "/perf-" + str(src) + "-" +
        str(des) + "_" + str(time_index) + ".txt", "w")
    f.writelines(perf_result)
    f.close()

def sn_route(src, time_index, file_path, configuration_file_path,
             container_id_list, remote_ssh):
    route_result = sn_remote_cmd(
        remote_ssh,
        "docker exec -i " + str(container_id_list[src - 1]) + " route -n ")
    f = open(
        configuration_file_path + "/" + file_path + "/route-" + str(src) +
        "_" + str(time_index) + ".txt", "w")
    f.writelines(route_result)
    f.close()


@contextmanager
def sn_pause_kernel_exports(remote_ssh, container_ids, subnet):
    """Keep OSPF running while Docker attaches a directly connected subnet.

    BIRD can learn the new subnet via the first endpoint before Docker attaches
    the second endpoint. Suspend kernel export at both ends to close that race.
    """
    paused = []
    try:
        for cid in container_ids:
            prefix = 'docker exec -i ' + shlex.quote(cid) + ' '
            protocols = sn_remote_cmd(remote_ssh, prefix + 'birdc show protocols')
            kernels = [row.split() for row in protocols
                       if len(row.split()) >= 4 and row.split()[1] == 'Kernel']
            if not kernels:
                raise RuntimeError('No BIRD kernel protocol found on ' + cid)
            for fields in kernels:
                if fields[3] == 'up':
                    name = fields[0]
                    sn_remote_cmd(remote_ssh, prefix + 'birdc disable ' + shlex.quote(name))
                    paused.append((cid, name))
            # Restrict deletion to BIRD routes for exactly the incoming subnet.
            routes = sn_remote_cmd(remote_ssh, prefix +
                                  'ip -4 route show exact ' + subnet + ' proto bird')
            for route in routes:
                if route.strip():
                    sn_remote_cmd(remote_ssh, prefix +
                                  'ip -4 route del ' + subnet + ' proto bird')
        yield
    finally:
        restore_errors = []
        for cid, name in reversed(paused):
            try:
                sn_remote_cmd(remote_ssh, 'docker exec -i ' + shlex.quote(cid) +
                              ' birdc enable ' + shlex.quote(name))
            except Exception as exc:
                restore_errors.append(str(exc))
        if restore_errors:
            raise RuntimeError('Failed to restore BIRD kernel export: ' + '; '.join(restore_errors))


def sn_establish_new_GSL(container_id_list, matrix, constellation_size, bw,
                         loss, sat_index, GS_index, remote_ssh):
    subnet = '9.{}.{}.0/24'.format((GS_index - constellation_size) & 0xff,
                                 sat_index & 0xff)
    endpoints = [container_id_list[sat_index - 1], container_id_list[GS_index - 1]]
    with sn_pause_kernel_exports(remote_ssh, endpoints, subnet):
        _sn_establish_new_GSL(container_id_list, matrix, constellation_size, bw,
                             loss, sat_index, GS_index, remote_ssh)


def _sn_establish_new_GSL(container_id_list, matrix, constellation_size, bw,
                          loss, sat_index, GS_index, remote_ssh):
    i = sat_index
    j = GS_index
    # IP address  (there is a link between i and j)
    delay = str(matrix[i - 1][j - 1])
    address_16_23 = (j - constellation_size) & 0xff
    address_8_15 = i & 0xff
    GSL_name = "GSL_" + str(i) + "-" + str(j)
    owner, _service = resource_identity(environment_for(remote_ssh))
    # Create internal network in docker.
    sn_remote_cmd(
        remote_ssh, 'docker network create --label ' +
        shlex.quote(owner_label(owner)) + ' ' + shlex.quote(GSL_name) + " --subnet 9." +
        str(address_16_23) + "." + str(address_8_15) + ".0/24")
    print('[Create GSL:]' + 'docker network create --label ' + owner_label(owner) + ' ' + GSL_name +
          " --subnet 9." + str(address_16_23) + "." + str(address_8_15) +
          ".0/24")
    sn_remote_cmd(
        remote_ssh, 'docker network connect ' + GSL_name + " " +
        str(container_id_list[i - 1]) + " --ip 9." + str(address_16_23) + "." +
        str(address_8_15) + ".50")
    ifconfig_output = sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[i - 1]) +
        " ip addr | grep -B 2 9." + str(address_16_23) + "." +
        str(address_8_15) +
        ".50 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]")
    target_interface = str(ifconfig_output[0]).split("@")[0]
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[i - 1]) +
        " ip link set dev " + target_interface + " down")
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[i - 1]) +
        " ip link set dev " + target_interface + " name " + "B" +
        str(i - 1 + 1) + "-eth" + str(j))
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[i - 1]) +
        " ip link set dev B" + str(i - 1 + 1) + "-eth" + str(j) + " up")
    command = ["docker", "exec", "-i", str(container_id_list[i - 1]),
               "tc", "qdisc", "replace", "dev", "B{}-eth{}".format(i, j),
               "root", "netem", "delay", str(delay) + "ms", "loss",
               str(loss) + "%", "rate", str(bw) + "Gbit"]
    sn_remote_checked_cmd(remote_ssh, " ".join(
        shlex.quote(part) for part in command))
    print('[Add current node:]' + 'docker network connect ' + GSL_name + " " +
          str(container_id_list[i - 1]) + " --ip 9." + str(address_16_23) +
          "." + str(address_8_15) + ".50")
    sn_remote_cmd(
        remote_ssh, 'docker network connect ' + GSL_name + " " +
        str(container_id_list[j - 1]) + " --ip 9." + str(address_16_23) + "." +
        str(address_8_15) + ".60")
    ifconfig_output = sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[j - 1]) +
        " ip addr | grep -B 2 9." + str(address_16_23) + "." +
        str(address_8_15) +
        ".60 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]")
    target_interface = str(ifconfig_output[0]).split("@")[0]
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[j - 1]) +
        " ip link set dev " + target_interface + " down")
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[j - 1]) +
        " ip link set dev " + target_interface + " name " + "B" + str(j) +
        "-eth" + str(i - 1 + 1))
    sn_remote_cmd(
        remote_ssh, "docker exec -i " + str(container_id_list[j - 1]) +
        " ip link set dev B" + str(j) + "-eth" + str(i - 1 + 1) + " up")
    command = ["docker", "exec", "-i", str(container_id_list[j - 1]),
               "tc", "qdisc", "replace", "dev", "B{}-eth{}".format(j, i),
               "root", "netem", "delay", str(delay) + "ms", "loss",
               str(loss) + "%", "rate", str(bw) + "Gbit"]
    sn_remote_checked_cmd(remote_ssh, " ".join(
        shlex.quote(part) for part in command))
    print('[Add right node:]' + 'docker network connect ' + GSL_name + " " +
          str(container_id_list[j - 1]) + " --ip 9." + str(address_16_23) +
          "." + str(address_8_15) + ".60")


def sn_del_link(first_index, second_index, container_id_list, remote_ssh):
    sn_remote_cmd(
        remote_ssh, "docker exec -i " +
        str(container_id_list[second_index - 1]) + " ip link set dev B" +
        str(second_index) + "-eth" + str(first_index) + " down")
    sn_remote_cmd(
        remote_ssh, "docker exec -i " +
        str(container_id_list[first_index - 1]) + " ip link set dev B" +
        str(first_index) + "-eth" + str(second_index) + " down")
    GSL_name = "GSL_" + str(first_index) + "-" + str(second_index)
    sn_remote_cmd(
        remote_ssh, 'docker network disconnect ' + GSL_name + " " +
        str(container_id_list[first_index - 1]))
    sn_remote_cmd(
        remote_ssh, 'docker network disconnect ' + GSL_name + " " +
        str(container_id_list[second_index - 1]))
    environment = environment_for(remote_ssh)
    owner, _service = resource_identity(environment)
    owner_output = sn_remote_cmd(remote_ssh,
        "docker network inspect --format " +
        shlex.quote('{{ index .Labels "starrynet.owner" }}') + " " +
        shlex.quote(GSL_name), check=False)
    actual_owner = owner_output[0].strip() if owner_output else ''
    if actual_owner != owner:
        raise ValueError('Refusing to remove network {!r}: owner is {!r}, expected {!r}'.format(
            GSL_name, actual_owner or 'unmarked', owner))
    sn_remote_checked_cmd(remote_ssh,
                          'docker network rm ' + shlex.quote(GSL_name))


# A thread designed for stopping the emulation.
class sn_Emulation_Stop_Thread(CheckedThread):

    def __init__(self, remote_ssh, remote_ftp, file_path):
        CheckedThread.__init__(self)
        self.remote_ssh = remote_ssh
        self.remote_ftp = remote_ftp
        self.file_path = file_path

    def run(self):
        print("Deleting all native bridges and containers...")
        sn_upload_orchestrater(self.remote_ftp, self.file_path)
        interpreter = getattr(self.remote_ssh, 'starrynet_python', 'python3')
        sn_remote_cmd(self.remote_ssh,
                      shlex.quote(interpreter) + " " +
                      shlex.quote(self.file_path + "/sn_orchestrater.py"))
