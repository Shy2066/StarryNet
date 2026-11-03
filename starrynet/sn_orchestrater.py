import os
import sys
import json
import shlex
from time import sleep
import numpy
import subprocess

try:
    from starrynet.sn_thread import CheckedThread, WORKER_ERRORS
except ImportError:
    from sn_thread import CheckedThread, WORKER_ERRORS

try:
    from starrynet.sn_link_profile import (direction_for_nodes, netem_arguments,
                                           profile_for)
except ImportError:
    from sn_link_profile import (direction_for_nodes, netem_arguments,
                                 profile_for)

def sn_checked_system(command):
    subprocess.run(command, shell=True, executable='/bin/bash', check=True)


def sn_apply_link_qdisc(container_id, interface, delay, bandwidth, loss,
                         profile=None):
    if profile is None:
        options = ["delay", str(delay) + "ms", "loss", str(loss) + "%",
                   "rate", str(bandwidth) + "Gbit"]
    else:
        options = netem_arguments(float(delay), profile)
    command = ["docker", "exec", "-i", str(container_id), "tc", "qdisc",
               "replace", "dev", interface, "root", "netem"] + options
    sn_checked_system(" ".join(shlex.quote(str(item)) for item in command))

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
                     orbit_num, sat_num, constellation_size, matrix, bw, loss,
                     link_profile=None):
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
        sn_apply_link_qdisc(
            container_id_list[current_orbit_id * sat_num + current_sat_id],
            "B{}-eth{}".format(current_orbit_id * sat_num + current_sat_id + 1,
                                down_orbit_id * sat_num + down_sat_id + 1),
            delay, bw, loss,
            profile_for(link_profile, "inter_satellite", "a_to_b"))
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
        sn_apply_link_qdisc(
            container_id_list[down_orbit_id * sat_num + down_sat_id],
            "B{}-eth{}".format(down_orbit_id * sat_num + down_sat_id + 1,
                                current_orbit_id * sat_num + current_sat_id + 1),
            delay, bw, loss,
            profile_for(link_profile, "inter_satellite", "b_to_a"))
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
        sn_apply_link_qdisc(
            container_id_list[current_orbit_id * sat_num + current_sat_id],
            "B{}-eth{}".format(current_orbit_id * sat_num + current_sat_id + 1,
                                right_orbit_id * sat_num + right_sat_id + 1),
            delay, bw, loss,
            profile_for(link_profile, "inter_satellite", "a_to_b"))
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
        sn_apply_link_qdisc(
            container_id_list[right_orbit_id * sat_num + right_sat_id],
            "B{}-eth{}".format(right_orbit_id * sat_num + right_sat_id + 1,
                                current_orbit_id * sat_num + current_sat_id + 1),
            delay, bw, loss,
            profile_for(link_profile, "inter_satellite", "b_to_a"))
    print('[Add right node:]' + 'docker network connect ' + ISL_name + " " +
          str(container_id_list[right_orbit_id * sat_num + right_sat_id]) +
          " --ip 10." + str(address_16_23) + "." + str(address_8_15) + ".20")

    print("Add 10." + str(address_16_23) + "." + str(address_8_15) +
          ".30/24 and 10." + str(address_16_23) + "." + str(address_8_15) +
          ".20/24 to (" + str(current_sat_id) + "," + str(current_orbit_id) +
          ") to (" + str(right_sat_id) + "," + str(right_orbit_id) + ")")


def sn_establish_ISLs(container_id_list, matrix, orbit_num, sat_num,
                      constellation_size, bw, loss, link_profile=None):
    ISL_threads = []
    for current_orbit_id in range(0, orbit_num):
        for current_sat_id in range(0, sat_num):
            ISL_thread = CheckedThread(
                target=sn_ISL_establish,
                args=(current_sat_id, current_orbit_id, container_id_list,
                      orbit_num, sat_num, constellation_size, matrix, bw,
                      loss, link_profile))
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
    rows = subprocess.check_output([
        'docker', 'ps', '--filter',
        'label=com.docker.swarm.service.name=constellation-test',
        '--format', '{{.ID}} {{.Names}}'], universal_newlines=True).splitlines()
    def index(row):
        name = row.split()[1]
        return int(name.rsplit('_', 1)[1]) if name.startswith('ovs_container_') else int(name.split('.')[1])
    return [row.split()[0] for row in sorted(rows, key=index)]


def sn_establish_GSL(container_id_list, matrix, GS_num, constellation_size, bw,
                     loss, link_profile=None):
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
                sn_apply_link_qdisc(
                    container_id_list[i - 1], "B{}-eth{}".format(i, j),
                    delay, bw, loss,
                    profile_for(link_profile, "satellite_ground",
                                "satellite_to_ground"))
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
                sn_apply_link_qdisc(
                    container_id_list[j - 1], "B{}-eth{}".format(j, i),
                    delay, bw, loss,
                    profile_for(link_profile, "satellite_ground",
                                "ground_to_satellite"))
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
            " ifconfig | sed 's/[ \t].*//;/^\\(eth0\\|\\)\\(lo\\|\\)$/d'") as f:
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
            " ifconfig | sed 's/[ \t].*//;/^\\(eth0\\|\\)\\(lo\\|\\)$/d'") as f:
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
    sn_checked_system('docker network rm ' + network_name)


def sn_stop_emulation():
    services = subprocess.check_output(['docker', 'service', 'ls', '--format', '{{.Name}}'], universal_newlines=True).splitlines()
    if 'constellation-test' in services:
        # Deletion is best-effort because Swarm removes tasks asynchronously;
        # the caller verifies the complete resource inventory afterward.
        subprocess.run(['docker', 'service', 'rm', 'constellation-test'], check=False)
        sleep(3)
    ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter',
        'label=com.docker.swarm.service.name=constellation-test'], universal_newlines=True).split()
    if ids:
        subprocess.run(['docker', 'rm', '-f', *ids], check=False)
    networks = subprocess.check_output(['docker', 'network', 'ls', '--filter',
        'label=starrynet.owner=constellation-test', '--format', '{{.ID}}'], universal_newlines=True).split()
    for network in networks:
        subprocess.run(['docker', 'network', 'rm', network], check=False)


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
                    constellation_size, link_profile=None):  # updating delays
    delay_threads = []
    for row in range(len(matrix)):
        for col in range(row, len(matrix[row])):
            if float(matrix[row][col]) > 0:
                if row < col:
                    delay_thread = CheckedThread(
                        target=sn_delay_change,
                        args=(row, col, matrix[row][col], container_id_list,
                              constellation_size, link_profile))
                    delay_threads.append(delay_thread)
                else:
                    delay_thread = CheckedThread(
                        target=sn_delay_change,
                        args=(col, row, matrix[col][row], container_id_list,
                              constellation_size, link_profile))
                    delay_threads.append(delay_thread)
    for delay_thread in delay_threads:
        delay_thread.start()
    for delay_thread in delay_threads:
        delay_thread.join()
    print("Delay updating done.\n")


def sn_delay_change(link_x, link_y, delay, container_id_list,
                    constellation_size, link_profile=None):  # multi-thread updating delays
    import re
    for node, peer in ((link_x, link_y), (link_y, link_x)):
        cid = container_id_list[node]
        iface = "B" + str(node + 1) + "-eth" + str(peer + 1)
        # Preserve configured impairment values. ``replace`` is idempotent when
        # Docker has recreated an interface but its root qdisc is not yet (or
        # is still) in the state expected by the topology scheduler.
        existing = subprocess.check_output([
            'docker', 'exec', cid, 'tc', 'qdisc', 'show', 'dev', iface], universal_newlines=True)
        if link_profile is not None:
            link_type, first_direction, second_direction = direction_for_nodes(
                link_x, link_y, constellation_size)
            direction = first_direction if node == link_x else second_direction
            settings = profile_for(link_profile, link_type, direction)
            options = netem_arguments(float(delay), settings)
        else:
            options = ["delay", str(delay) + "ms"]
            jitter_match = re.search(
                r"\bdelay\s+[0-9.]+ms\s+([0-9.]+ms)", existing)
            if jitter_match:
                options.append(jitter_match.group(1))
                distribution_match = re.search(
                    r"\bdistribution\s+(\w+)", existing)
                if distribution_match:
                    options.extend(["distribution", distribution_match.group(1)])
            for option, pattern in (
                    ("loss", r"\bloss\s+([0-9.]+%)"),
                    ("rate", r"\brate\s+([0-9.]+[KMGT]?bit)"),
                    ("limit", r"\blimit\s+(\d+)")):
                match = re.search(pattern, existing)
                if match:
                    options.extend([option, match.group(1)])
        command = ['docker', 'exec', cid, 'tc', 'qdisc', 'replace',
                   'dev', iface, 'root', 'netem'] + options
        subprocess.run(command, check=True)


if __name__ == '__main__':
    if len(sys.argv) in (10, 11):
        orbit_num = int(sys.argv[1])
        sat_num = int(sys.argv[2])
        constellation_size = int(sys.argv[3])
        GS_num = int(sys.argv[4])
        sat_bandwidth = float(sys.argv[5])
        sat_loss = float(sys.argv[6])
        sat_ground_bandwidth = float(sys.argv[7])
        sat_ground_loss = float(sys.argv[8])
        current_topo_path = sys.argv[9]
        link_profile = json.loads(sys.argv[10]) if len(sys.argv) == 11 else None
        matrix = sn_get_param(current_topo_path)
        container_id_list = sn_get_container_info()
        sn_establish_ISLs(container_id_list, matrix, orbit_num, sat_num,
                          constellation_size, sat_bandwidth, sat_loss,
                          link_profile)
        sn_establish_GSL(container_id_list, matrix, GS_num, constellation_size,
                         sat_ground_bandwidth, sat_ground_loss, link_profile)
    elif len(sys.argv) in (4, 5):
        if sys.argv[3] == "update":
            current_delay_path = sys.argv[1]
            constellation_size = int(sys.argv[2])
            link_profile = json.loads(sys.argv[4]) if len(sys.argv) == 5 else None
            matrix = sn_get_param(current_delay_path)
            container_id_list = sn_get_container_info()
            sn_update_delay(matrix, container_id_list, constellation_size,
                            link_profile)
        elif len(sys.argv) == 4:
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
