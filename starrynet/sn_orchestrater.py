import os
import threading
import sys
from time import sleep
import numpy
import subprocess
import shlex

try:
    from starrynet.sn_thread import CheckedThread, WORKER_ERRORS
    from starrynet.resource_scope import (
        OWNER_ENV, SERVICE_ENV, environment_for, owner_filter, owner_label,
        resource_identity, service_filter, should_scope_network_create)
except ImportError:
    from sn_thread import CheckedThread, WORKER_ERRORS
    from resource_scope import (
        OWNER_ENV, SERVICE_ENV, environment_for, owner_filter, owner_label,
        resource_identity, service_filter, should_scope_network_create)

def sn_checked_system(command):
    """Run a checked command, attaching this run's owner to every network."""
    arguments = shlex.split(command)
    if should_scope_network_create(arguments):
        owner, _service = resource_identity(os.environ)
        cleaned = []
        index = 3
        while index < len(arguments):
            if arguments[index] == '--label' and index + 1 < len(arguments):
                label = arguments[index + 1]
                if label.split('=', 1)[0] != 'starrynet.owner':
                    cleaned.extend(arguments[index:index + 2])
                index += 2
                continue
            cleaned.append(arguments[index])
            index += 1
        arguments = arguments[:3] + cleaned
        arguments[3:3] = ['--label', owner_label(owner)]
        # Routed replay traffic must retain end-to-end TCP addresses. This is
        # scoped to networks created by this replay process.
        if os.environ.get('STARRYNET_DISABLE_MASQUERADE') == '1':
            if 'com.docker.network.bridge.enable_ip_masquerade=true' in arguments:
                raise ValueError('Replay network explicitly enables masquerade')
            if 'com.docker.network.bridge.enable_ip_masquerade=false' not in arguments:
                arguments.extend(['--opt',
                                  'com.docker.network.bridge.enable_ip_masquerade=false'])
        command = ' '.join(shlex.quote(part) for part in arguments)
    subprocess.run(command, shell=True, executable='/bin/bash', check=True)

"""
Used in the remote machine for link updating, initializing links, damaging and recovering links and other functionalities。
author: Yangtao Deng (dengyt21@mails.tsinghua.edu.cn) and Zeqi Lai (zeqilai@tsinghua.edu.cn) 
"""


def sn_get_right_satellite(current_sat_id, current_orbit_id, orbit_num):
    if current_orbit_id == orbit_num - 1:
        return [current_sat_id, 0]
    else:
        return [current_sat_id, current_orbit_id + 1]


def sn_get_down_satellite(current_sat_id, current_orbit_id, sat_num):
    if current_sat_id == sat_num - 1:
        return [0, current_orbit_id]
    else:
        return [current_sat_id + 1, current_orbit_id]


def sn_ISL_establish(current_sat_id, current_orbit_id, container_id_list,
                     orbit_num, sat_num, constellation_size, matrix, bw, loss):
    current_id = current_orbit_id * sat_num + current_sat_id
    isl_idx = current_id * 2 + 1
    # Establish intra-orbit ISLs
    # (Down):
    [down_sat_id,
     down_orbit_id] = sn_get_down_satellite(current_sat_id, current_orbit_id,
                                            sat_num)
    print("[" + str(isl_idx) + "/" + str(constellation_size * 2) +
          "] Establish intra-orbit ISL from: (" + str(current_sat_id) + "," +
          str(current_orbit_id) + ") to (" + str(down_sat_id) + "," +
          str(down_orbit_id) + ")")
    ISL_name = "Le_" + str(current_sat_id) + "-" + str(current_orbit_id) + \
        "_" + str(down_sat_id) + "-" + str(down_orbit_id)
    address_16_23 = isl_idx >> 8
    address_8_15 = isl_idx & 0xff
    # Create internal network in docker.
    sn_checked_system('docker network create --label starrynet.owner=constellation-test ' + ISL_name + " --subnet 10." +
              str(address_16_23) + "." + str(address_8_15) + ".0/24")
    print('[Create ISL:]' + 'docker network create --label starrynet.owner=constellation-test ' + ISL_name +
          " --subnet 10." + str(address_16_23) + "." + str(address_8_15) +
          ".0/24")
    sn_checked_system('docker network connect ' + ISL_name + " " +
              str(container_id_list[current_orbit_id * sat_num +
                                    current_sat_id]) + " --ip 10." +
              str(address_16_23) + "." + str(address_8_15) + ".40")
    delay = matrix[current_orbit_id * sat_num +
                   current_sat_id][down_orbit_id * sat_num + down_sat_id]
    with os.popen(
            "docker exec -i " +
            str(container_id_list[current_orbit_id * sat_num +
                                  current_sat_id]) +
            " ip addr | grep -B 2 10." + str(address_16_23) + "." +
            str(address_8_15) +
            ".40 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]") as f:
        ifconfig_output = f.readline()
        target_interface = str(ifconfig_output).split("@")[0]
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev " + target_interface + " down")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev " + target_interface + " name " + "B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(down_orbit_id * sat_num + down_sat_id + 1))
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(down_orbit_id * sat_num + down_sat_id + 1) +
                  " up")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " tc qdisc add dev B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(down_orbit_id * sat_num + down_sat_id + 1) +
                  " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbit")
    print('[Add current node:]' + 'docker network connect ' + ISL_name + " " +
          str(container_id_list[current_orbit_id * sat_num + current_sat_id]) +
          " --ip 10." + str(address_16_23) + "." + str(address_8_15) + ".40")
    sn_checked_system('docker network connect ' + ISL_name + " " +
              str(container_id_list[down_orbit_id * sat_num + down_sat_id]) +
              " --ip 10." + str(address_16_23) + "." + str(address_8_15) +
              ".10")
    with os.popen(
            "docker exec -i " +
            str(container_id_list[down_orbit_id * sat_num + down_sat_id]) +
            " ip addr | grep -B 2 10." + str(address_16_23) + "." +
            str(address_8_15) +
            ".10 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]") as f:
        ifconfig_output = f.readline()
        target_interface = str(ifconfig_output).split("@")[0]
        sn_checked_system("docker exec -i " +
                  str(container_id_list[down_orbit_id * sat_num +
                                        down_sat_id]) + " ip link set dev " +
                  target_interface + " down")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[down_orbit_id * sat_num +
                                        down_sat_id]) + " ip link set dev " +
                  target_interface + " name " + "B" +
                  str(down_orbit_id * sat_num + down_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1))
        sn_checked_system("docker exec -i " +
                  str(container_id_list[down_orbit_id * sat_num +
                                        down_sat_id]) + " ip link set dev B" +
                  str(down_orbit_id * sat_num + down_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) + " up")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[down_orbit_id * sat_num +
                                        down_sat_id]) + " tc qdisc add dev B" +
                  str(down_orbit_id * sat_num + down_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbit")
    print('[Add down node:]' + 'docker network connect ' + ISL_name + " " +
          str(container_id_list[down_orbit_id * sat_num + down_sat_id]) +
          " --ip 10." + str(address_16_23) + "." + str(address_8_15) + ".10")

    print("Add 10." + str(address_16_23) + "." + str(address_8_15) +
          ".40/24 and 10." + str(address_16_23) + "." + str(address_8_15) +
          ".10/24 to (" + str(current_sat_id) + "," + str(current_orbit_id) +
          ") to (" + str(down_sat_id) + "," + str(down_orbit_id) + ")")
    isl_idx = isl_idx + 1

    # Establish inter-orbit ISLs
    # (Right):
    [right_sat_id,
     right_orbit_id] = sn_get_right_satellite(current_sat_id, current_orbit_id,
                                              orbit_num)
    print("[" + str(isl_idx) + "/" + str(constellation_size * 2) +
          "] Establish inter-orbit ISL from: (" + str(current_sat_id) + "," +
          str(current_orbit_id) + ") to (" + str(right_sat_id) + "," +
          str(right_orbit_id) + ")")
    ISL_name = "La_" + str(current_sat_id) + "-" + str(current_orbit_id) + \
        "_" + str(right_sat_id) + "-" + str(right_orbit_id)
    address_16_23 = isl_idx >> 8
    address_8_15 = isl_idx & 0xff
    # Create internal network in docker.
    sn_checked_system('docker network create --label starrynet.owner=constellation-test ' + ISL_name + " --subnet 10." +
              str(address_16_23) + "." + str(address_8_15) + ".0/24")
    print('[Create ISL:]' + 'docker network create --label starrynet.owner=constellation-test ' + ISL_name +
          " --subnet 10." + str(address_16_23) + "." + str(address_8_15) +
          ".0/24")
    sn_checked_system('docker network connect ' + ISL_name + " " +
              str(container_id_list[current_orbit_id * sat_num +
                                    current_sat_id]) + " --ip 10." +
              str(address_16_23) + "." + str(address_8_15) + ".30")
    delay = matrix[current_orbit_id * sat_num +
                   current_sat_id][right_orbit_id * sat_num + right_sat_id]
    with os.popen(
            "docker exec -i " +
            str(container_id_list[current_orbit_id * sat_num +
                                  current_sat_id]) +
            " ip addr | grep -B 2 10." + str(address_16_23) + "." +
            str(address_8_15) +
            ".30 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]") as f:
        ifconfig_output = f.readline()
        target_interface = str(ifconfig_output).split("@")[0]
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev " + target_interface + " down")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev " + target_interface + " name " + "B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(right_orbit_id * sat_num + right_sat_id + 1))
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " ip link set dev B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(right_orbit_id * sat_num + right_sat_id + 1) +
                  " up")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[current_orbit_id * sat_num +
                                        current_sat_id]) +
                  " tc qdisc add dev B" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  "-eth" + str(right_orbit_id * sat_num + right_sat_id + 1) +
                  " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbit")
    print('[Add current node:]' + 'docker network connect ' + ISL_name + " " +
          str(container_id_list[current_orbit_id * sat_num + current_sat_id]) +
          " --ip 10." + str(address_16_23) + "." + str(address_8_15) + ".30")
    sn_checked_system('docker network connect ' + ISL_name + " " +
              str(container_id_list[right_orbit_id * sat_num + right_sat_id]) +
              " --ip 10." + str(address_16_23) + "." + str(address_8_15) +
              ".20")

    with os.popen(
            "docker exec -i " +
            str(container_id_list[right_orbit_id * sat_num + right_sat_id]) +
            " ip addr | grep -B 2 10." + str(address_16_23) + "." +
            str(address_8_15) +
            ".20 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]") as f:
        ifconfig_output = f.readline()
        target_interface = str(ifconfig_output).split("@")[0]
        sn_checked_system("docker exec -i " +
                  str(container_id_list[right_orbit_id * sat_num +
                                        right_sat_id]) + " ip link set dev " +
                  target_interface + " down")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[right_orbit_id * sat_num +
                                        right_sat_id]) + " ip link set dev " +
                  target_interface + " name " + "B" +
                  str(right_orbit_id * sat_num + right_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1))
        sn_checked_system("docker exec -i " +
                  str(container_id_list[right_orbit_id * sat_num +
                                        right_sat_id]) + " ip link set dev B" +
                  str(right_orbit_id * sat_num + right_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) + " up")
        sn_checked_system("docker exec -i " +
                  str(container_id_list[right_orbit_id * sat_num +
                                        right_sat_id]) +
                  " tc qdisc add dev B" +
                  str(right_orbit_id * sat_num + right_sat_id + 1) + "-eth" +
                  str(current_orbit_id * sat_num + current_sat_id + 1) +
                  " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbit")
    print('[Add right node:]' + 'docker network connect ' + ISL_name + " " +
          str(container_id_list[right_orbit_id * sat_num + right_sat_id]) +
          " --ip 10." + str(address_16_23) + "." + str(address_8_15) + ".20")

    print("Add 10." + str(address_16_23) + "." + str(address_8_15) +
          ".30/24 and 10." + str(address_16_23) + "." + str(address_8_15) +
          ".20/24 to (" + str(current_sat_id) + "," + str(current_orbit_id) +
          ") to (" + str(right_sat_id) + "," + str(right_orbit_id) + ")")


def sn_establish_ISLs(container_id_list, matrix, orbit_num, sat_num,
                      constellation_size, bw, loss):
    ISL_threads = []
    for current_orbit_id in range(0, orbit_num):
        for current_sat_id in range(0, sat_num):
            ISL_thread = CheckedThread(
                target=sn_ISL_establish,
                args=(current_sat_id, current_orbit_id, container_id_list,
                      orbit_num, sat_num, constellation_size, matrix, bw,
                      loss))
            ISL_threads.append(ISL_thread)
    for ISL_thread in ISL_threads:
        ISL_thread.start()
    for ISL_thread in ISL_threads:
        ISL_thread.join()


def sn_get_param(file_):
    f = open(file_)
    ADJ = f.readlines()
    for i in range(len(ADJ)):
        ADJ[i] = ADJ[i].strip('\n')
    ADJ = [x.split(',') for x in ADJ]
    f.close()
    return ADJ


def sn_get_container_info():
    owner, service = resource_identity(os.environ)
    rows = subprocess.check_output([
        'docker', 'ps', '--filter', service_filter(service), '--filter',
        owner_filter(owner), '--format', '{{.ID}} {{.Names}}'],
        universal_newlines=True).splitlines()
    rows = [row.decode('utf8', 'replace') if isinstance(row, bytes) else row
            for row in rows]

    def node_index(row):
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

    return [row.split()[0] for row in sorted(rows, key=node_index)]


def sn_establish_GSL(container_id_list, matrix, GS_num, constellation_size, bw,
                     loss):
    # starting links among satellites and ground stations
    for i in range(1, constellation_size + 1):
        for j in range(constellation_size + 1,
                       constellation_size + GS_num + 1):
            # matrix[i-1][j-1])==1 means a link between node i and node j
            if ((float(matrix[i - 1][j - 1])) <= 0.01):
                continue
            # IP address  (there is a link between i and j)
            delay = str(matrix[i - 1][j - 1])
            address_16_23 = (j - constellation_size) & 0xff
            address_8_15 = i & 0xff
            GSL_name = "GSL_" + str(i) + "-" + str(j)
            # Create internal network in docker.
            sn_checked_system('docker network create --label starrynet.owner=constellation-test ' + GSL_name + " --subnet 9." +
                      str(address_16_23) + "." + str(address_8_15) + ".0/24")
            print('[Create GSL:]' + 'docker network create --label starrynet.owner=constellation-test ' + GSL_name +
                  " --subnet 9." + str(address_16_23) + "." +
                  str(address_8_15) + ".0/24")
            sn_checked_system('docker network connect ' + GSL_name + " " +
                      str(container_id_list[i - 1]) + " --ip 9." +
                      str(address_16_23) + "." + str(address_8_15) + ".50")
            with os.popen(
                    "docker exec -i " + str(container_id_list[i - 1]) +
                    " ip addr | grep -B 2 9." + str(address_16_23) + "." +
                    str(address_8_15) +
                    ".50 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]"
            ) as f:
                ifconfig_output = f.readline()
                target_interface = str(ifconfig_output).split("@")[0]
                sn_checked_system("docker exec -i " + str(container_id_list[i - 1]) +
                          " ip link set dev " + target_interface + " down")
                sn_checked_system("docker exec -i " + str(container_id_list[i - 1]) +
                          " ip link set dev " + target_interface + " name " +
                          "B" + str(i - 1 + 1) + "-eth" + str(j))
                sn_checked_system("docker exec -i " + str(container_id_list[i - 1]) +
                          " ip link set dev B" + str(i - 1 + 1) + "-eth" +
                          str(j) + " up")
                sn_checked_system("docker exec -i " + str(container_id_list[i - 1]) +
                          " tc qdisc add dev B" + str(i - 1 + 1) + "-eth" +
                          str(j) + " root netem delay " + str(delay) + "ms loss " + str(loss) + "% rate " + str(bw) + "Gbit")
            print('[Add current node:]' + 'docker network connect ' +
                  GSL_name + " " + str(container_id_list[i - 1]) + " --ip 9." +
                  str(address_16_23) + "." + str(address_8_15) + ".50")

            sn_checked_system('docker network connect ' + GSL_name + " " +
                      str(container_id_list[j - 1]) + " --ip 9." +
                      str(address_16_23) + "." + str(address_8_15) + ".60")
            with os.popen(
                    "docker exec -i " + str(container_id_list[j - 1]) +
                    " ip addr | grep -B 2 9." + str(address_16_23) + "." +
                    str(address_8_15) +
                    ".60 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]"
            ) as f:
                ifconfig_output = f.readline()
                target_interface = str(ifconfig_output).split("@")[0]
                sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                          " ip link set dev " + target_interface + " down")
                sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                          " ip link set dev " + target_interface + " name " +
                          "B" + str(j) + "-eth" + str(i - 1 + 1))
                sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                          " ip link set dev B" + str(j) + "-eth" +
                          str(i - 1 + 1) + " up")
                sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                          " tc qdisc add dev B" + str(j) + "-eth" +
                          str(i - 1 + 1) + " root netem delay " + str(delay) +
                          "ms loss " + str(loss) + "% rate " + str(bw) +
                          "Gbit")
            print('[Add right node:]' + 'docker network connect ' + GSL_name +
                  " " + str(container_id_list[j - 1]) + " --ip 9." +
                  str(address_16_23) + "." + str(address_8_15) + ".60")
    for j in range(constellation_size + 1, constellation_size + GS_num + 1):
        GS_name = "GS_" + str(j)
        # Create default network and interface for GS.
        sn_checked_system('docker network create --label starrynet.owner=constellation-test ' + GS_name + " --subnet 9." +
                  str(j) + "." + str(j) + ".0/24")
        print('[Create GS network:]' + 'docker network create --label starrynet.owner=constellation-test ' + GS_name +
              " --subnet 9." + str(j) + "." + str(j) + ".10/24")
        sn_checked_system('docker network connect ' + GS_name + " " +
                  str(container_id_list[j - 1]) + " --ip 9." + str(j) + "." +
                  str(j) + ".10")
        with os.popen(
                "docker exec -i " + str(container_id_list[j - 1]) +
                " ip addr | grep -B 2 9." + str(j) + "." + str(j) +
                ".10 | head -n 1 | awk -F: '{ print $2 }' | tr -d [:blank:]"
        ) as f:
            ifconfig_output = f.readline()
            target_interface = str(ifconfig_output).split("@")[0]
            sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                      " ip link set dev " + target_interface + " down")
            sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                      " ip link set dev " + target_interface + " name " + "B" +
                      str(j - 1 + 1) + "-default")
            sn_checked_system("docker exec -i " + str(container_id_list[j - 1]) +
                      " ip link set dev B" + str(j - 1 + 1) + "-default" +
                      " up")
        print('[Add current node:]' + 'docker network connect ' + GS_name +
              " " + str(container_id_list[j - 1]) + " --ip 9." + str(j) + "." +
              str(j) + ".10")


def sn_copy_run_conf(container_idx, Path, current, total):
    sn_checked_system("docker cp " + Path + "/B" + str(current + 1) + ".conf " +
              str(container_idx) + ":/B" + str(current + 1) + ".conf")
    print("[" + str(current + 1) + "/" + str(total) + "]" +
          " docker cp bird.conf " + str(container_idx) + ":/bird.conf")
    sn_checked_system("docker exec -i " + str(container_idx) + " bird -c B" +
              str(current + 1) + ".conf")
    print("[" + str(current + 1) + "/" + str(total) +
          "] Bird routing process for container: " + str(container_idx) +
          " has started. ")


def sn_copy_run_conf_to_each_container(container_id_list, sat_node_number,
                                       fac_node_number, path):
    print(
        "Copy bird configuration file to each container and run routing process."
    )
    total = len(container_id_list)
    copy_threads = []
    for current in range(0, total):
        copy_thread = CheckedThread(
            target=sn_copy_run_conf,
            args=(container_id_list[current], path + "/conf/bird-" +
                  str(sat_node_number) + "-" + str(fac_node_number), current,
                  total))
        copy_threads.append(copy_thread)
    for copy_thread in copy_threads:
        copy_thread.start()
    for copy_thread in copy_threads:
        copy_thread.join()
    print("Initializing routing...")
    sleep(120)
    print("Routing initialized!")


def sn_damage_link(sat_index, container_id_list):
    with os.popen(
            "docker exec -i " + str(container_id_list[sat_index]) +
            " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'") as f:
        ifconfig_output = f.readlines()
        for intreface in range(0, len(ifconfig_output), 2):
            sn_checked_system("docker exec -i " + str(container_id_list[sat_index]) +
                      " tc qdisc change dev " +
                      ifconfig_output[intreface][:-1] +
                      " root netem loss 100%")
            print("docker exec -i " + str(container_id_list[sat_index]) +
                  " tc qdisc change dev " + ifconfig_output[intreface][:-1] +
                  " root netem loss 100%")


def sn_damage(random_list, container_id_list):
    damage_threads = []
    for random_satellite in random_list:
        damage_thread = CheckedThread(target=sn_damage_link,
                                         args=(int(random_satellite),
                                               container_id_list))
        damage_threads.append(damage_thread)
    for damage_thread in damage_threads:
        damage_thread.start()
    for damage_thread in damage_threads:
        damage_thread.join()


def sn_recover_link(
    damaged_satellite,
    container_id_list,
    sat_loss,
):
    with os.popen(
            "docker exec -i " + str(container_id_list[damaged_satellite]) +
            " ifconfig | sed 's/[ \t].*//;/^\(eth0\|\)\(lo\|\)$/d'") as f:
        ifconfig_output = f.readlines()
        for i in range(0, len(ifconfig_output), 2):
            sn_checked_system("docker exec -i " +
                      str(container_id_list[damaged_satellite]) +
                      " tc qdisc change dev " + ifconfig_output[i][:-1] +
                      " root netem loss " + str(sat_loss) + "%")
            print("docker exec -i " +
                  str(container_id_list[damaged_satellite]) +
                  " tc qdisc change dev " + ifconfig_output[i][:-1] +
                  " root netem loss " + str(sat_loss) + "%")


def sn_del_network(network_name):
    protected = {'bridge', 'host', 'none', 'ingress', 'docker_gwbridge'}
    if network_name in protected:
        raise ValueError('Refusing to remove Docker system network: ' + network_name)
    owner, _service = resource_identity(os.environ)
    actual_owner = sn_docker_cleanup_command([
        'network', 'inspect', '--format',
        '{{ index .Labels "starrynet.owner" }}', network_name])
    if not actual_owner or actual_owner[0].strip() != owner:
        raise ValueError('Refusing to remove network {!r}: owner is {!r}, expected {!r}'.format(
            network_name, actual_owner[0].strip() if actual_owner else 'unmarked', owner))
    sn_docker_cleanup_command(['network', 'rm', network_name])


def sn_docker_cleanup_command(arguments, check=True):
    """Run one Docker query/action used by scoped cleanup; split query output."""
    try:
        output = subprocess.check_output(
            ['docker'] + list(arguments), universal_newlines=True,
            stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        if check:
            raise RuntimeError('Docker cleanup command failed: {}: {}'.format(
                ' '.join(arguments), exc.stderr or exc.output or ''))
        return []
    return output.splitlines()


def sn_docker_service_owner(service):
    """Return owner for an exact service, or None when it is absent.

    Use the successful Swarm service list to distinguish absence from an
    unlabelled service. A blank template line from ``service inspect`` must
    still be treated as an existing service with no owner.
    """
    list_args = ['service', 'ls', '--format', '{{.Name}}']
    names = sn_docker_cleanup_command(list_args)
    if not any(name.strip() == service for name in names):
        return None
    template = ('{{ if .Spec.Labels }}{{ index .Spec.Labels '
                '"starrynet.owner" }}{{ else }}UNOWNED{{ end }}')
    try:
        output = sn_docker_cleanup_command([
            'service', 'inspect', '--format', template, service])
    except RuntimeError:
        # Tolerate a service concurrently removed after listing it, but do not
        # turn an inspect/daemon failure into apparent absence.
        names = sn_docker_cleanup_command(list_args)
        if any(name.strip() == service for name in names):
            raise
        return None
    return ''.join(output).strip()


def sn_is_emulation_network(network_name):
    """Return whether a name has one of StarryNet's exact legacy link forms."""
    import re
    return bool(re.match(r'^(?:GS_[0-9]+|GSL_[0-9]+-[0-9]+|'
                         r'La_[0-9]+-[0-9]+_[0-9]+-[0-9]+|'
                         r'Le_[0-9]+-[0-9]+_[0-9]+-[0-9]+)$', network_name))


def sn_stop_emulation():
    owner, service = resource_identity(os.environ)
    refusal = None
    actual_owner = sn_docker_service_owner(service)
    if actual_owner is not None:
        if actual_owner != owner:
            refusal = ('Refusing to remove service {!r}: owner is {!r}, expected {!r}'.format(
                service, actual_owner or 'unmarked', owner))
        else:
            sn_docker_cleanup_command(['service', 'rm', service], check=False)
            # Swarm removes tasks asynchronously. Query again with both labels
            # so a stale task from another service or run cannot be selected.
            sleep(3)

    containers = sn_docker_cleanup_command([
        'ps', '-aq', '--filter', service_filter(service), '--filter',
        owner_filter(owner)])
    for container_id in containers:
        if container_id.strip():
            sn_docker_cleanup_command(['rm', '-f', container_id.strip()],
                                      check=False)

    networks = sn_docker_cleanup_command([
        'network', 'ls', '--filter', owner_filter(owner), '--format', '{{.ID}}'])
    for network_id in networks:
        if network_id.strip():
            sn_docker_cleanup_command(['network', 'rm', network_id.strip()],
                                      check=False)

    remaining_containers = sn_docker_cleanup_command([
        'ps', '-aq', '--filter', service_filter(service), '--filter',
        owner_filter(owner)])
    remaining_networks = sn_docker_cleanup_command([
        'network', 'ls', '--filter', owner_filter(owner), '--format', '{{.ID}}'])
    remaining_services = [name for name in sn_docker_cleanup_command([
        'service', 'ls', '--format', '{{.Name}}'])
        if name.strip() == service]
    if refusal:
        raise RuntimeError(refusal)
    if remaining_containers or remaining_networks or remaining_services:
        raise RuntimeError('StarryNet cleanup incomplete for owner {!r}: '
                           'services={}, containers={}, networks={}'.format(
                               owner, remaining_services, remaining_containers,
                               remaining_networks))


def sn_recover(damage_list, container_id_list, sat_loss):
    recover_threads = []
    for damaged_satellite in damage_list:
        recover_thread = CheckedThread(target=sn_recover_link,
                                          args=(int(damaged_satellite),
                                                container_id_list, sat_loss))
        recover_threads.append(recover_thread)
    for recover_thread in recover_threads:
        recover_thread.start()
    for recover_thread in recover_threads:
        recover_thread.join()


def sn_update_delay(matrix, container_id_list,
                    constellation_size):  # updating delays
    delay_threads = []
    for row in range(len(matrix)):
        for col in range(row, len(matrix[row])):
            if float(matrix[row][col]) > 0:
                if row < col:
                    delay_thread = CheckedThread(
                        target=sn_delay_change,
                        args=(row, col, matrix[row][col], container_id_list,
                              constellation_size))
                    delay_threads.append(delay_thread)
                else:
                    delay_thread = CheckedThread(
                        target=sn_delay_change,
                        args=(col, row, matrix[col][row], container_id_list,
                              constellation_size))
                    delay_threads.append(delay_thread)
    for delay_thread in delay_threads:
        delay_thread.start()
    for delay_thread in delay_threads:
        delay_thread.join()
    print("Delay updating done.\n")


def sn_delay_change(link_x, link_y, delay, container_id_list,
                    constellation_size):  # multi-thread updating delays
    for node, peer in ((link_x, link_y), (link_y, link_x)):
        cid = container_id_list[node]
        iface = "B" + str(node + 1) + "-eth" + str(peer + 1)
        # Reapply the full qdisc; handover may have recreated this interface.
        existing = subprocess.check_output([
            'docker', 'exec', cid, 'tc', 'qdisc', 'show', 'dev', iface], universal_newlines=True)
        fields = shlex.split(existing)
        try:
            raw_options = fields[fields.index('netem') + 1:]
            option_names = {'limit', 'delay', 'loss', 'duplicate', 'corrupt',
                            'reorder', 'rate', 'slot', 'seed', 'ecn', 'gap',
                            'distribution'}
            start = next((index for index, value in enumerate(raw_options)
                          if value in option_names), len(raw_options))
            options = raw_options[start:]
        except ValueError:
            options = []
        if 'delay' in options:
            delay_index = options.index('delay')
            if delay_index + 1 < len(options):
                options[delay_index + 1] = str(delay) + 'ms'
            else:
                options.append(str(delay) + 'ms')
        else:
            options[0:0] = ['delay', str(delay) + 'ms']
        subprocess.run(['docker', 'exec', cid, 'tc', 'qdisc', 'replace',
                        'dev', iface, 'root', 'netem'] + options, check=True)


if __name__ == '__main__':
    if len(sys.argv) == 10:
        orbit_num = int(sys.argv[1])
        sat_num = int(sys.argv[2])
        constellation_size = int(sys.argv[3])
        GS_num = int(sys.argv[4])
        sat_bandwidth = float(sys.argv[5])
        sat_loss = float(sys.argv[6])
        sat_ground_bandwidth = float(sys.argv[7])
        sat_ground_loss = float(sys.argv[8])
        current_topo_path = sys.argv[9]
        matrix = sn_get_param(current_topo_path)
        container_id_list = sn_get_container_info()
        sn_establish_ISLs(container_id_list, matrix, orbit_num, sat_num,
                          constellation_size, sat_bandwidth, sat_loss)
        sn_establish_GSL(container_id_list, matrix, GS_num, constellation_size,
                         sat_ground_bandwidth, sat_ground_loss)
    elif len(sys.argv) == 4:
        if sys.argv[3] == "update":
            current_delay_path = sys.argv[1]
            constellation_size = int(sys.argv[2])
            matrix = sn_get_param(current_delay_path)
            container_id_list = sn_get_container_info()
            sn_update_delay(matrix, container_id_list, constellation_size)
        else:
            constellation_size = int(sys.argv[1])
            GS_num = int(sys.argv[2])
            path = sys.argv[3]
            container_id_list = sn_get_container_info()
            sn_copy_run_conf_to_each_container(container_id_list,
                                               constellation_size, GS_num,
                                               path)
    elif len(sys.argv) == 2:
        path = sys.argv[1]
        random_list = numpy.loadtxt(path + "/damage_list.txt")
        container_id_list = sn_get_container_info()
        sn_damage(random_list, container_id_list)
    elif len(sys.argv) == 3:
        path = sys.argv[1]
        sat_loss = float(sys.argv[2])
        damage_list = numpy.loadtxt(path + "/damage_list.txt")
        container_id_list = sn_get_container_info()
        sn_recover(damage_list, container_id_list, sat_loss)
    elif len(sys.argv) == 1:
        sn_stop_emulation()

    if WORKER_ERRORS:
        raise RuntimeError("StarryNet orchestration worker failed") from WORKER_ERRORS[0]
