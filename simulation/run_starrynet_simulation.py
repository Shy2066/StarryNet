#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Complete StarryNet simulation with real network emulation.

This script integrates with StarryNet's real network emulation to simulate
satellite traffic from fiber traffic traces.

Usage:
    python simulation/run_starrynet_simulation.py --mode small_test
    python simulation/run_starrynet_simulation.py --mode full --max_files 100
"""

import os
import sys
import argparse
import json
import time
import numpy as np
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulation.traffic_injector import TrafficInjector, load_fiber_traces
from simulation.feature_analyzer import FeatureAnalyzer, quick_compare

# Import StarryNet modules
from starrynet.sn_observer import *
from starrynet.sn_orchestrater import *
from starrynet.sn_synchronizer import *


class StarryNetTrafficSimulation:
    """Complete StarryNet simulation with traffic injection and capture."""

    def __init__(self, config_file: str = 'config.json'):
        """
        Initialize StarryNet traffic simulation.

        Args:
            config_file: Path to StarryNet configuration file
        """
        self.config_file = config_file
        self.output_dir = 'starrynet_simulation_output'
        self.data_dir = 'dataset'
        self.fiber_dir = os.path.join(self.data_dir, 'tor_fiber')
        self.satellite_dir = os.path.join(self.output_dir, 'tor_satellite')

        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.satellite_dir, exist_ok=True)

        # StarryNet components
        self.sn = None
        self.container_id_list = []

        # Configuration
        self.GS_lat_long = [
            [50.110924, 8.682127],  # Frankfurt
            [46.635700, 14.311817]  # Austria
        ]
        self.AS = [[1, 27]]  # Node #1 to #27 in same AS
        self.hello_interval = 1

        # Feature analyzer
        self.feature_analyzer = FeatureAnalyzer()

    def initialize_starrynet(self):
        """Initialize StarryNet simulation environment."""
        print("=" * 60)
        print("Initializing StarryNet Simulation")
        print("=" * 60)

        # Initialize StarryNet
        self.sn = StarryNet(
            self.config_file,
            self.GS_lat_long,
            self.hello_interval,
            self.AS
        )

        print("StarryNet initialized successfully")
        print(f"Constellation: {self.sn.name}")
        print(f"Satellites: {self.sn.orbit_number} orbits × {self.sn.sat_number} satellites")
        print(f"Ground stations: {self.sn.fac_num}")
        print(f"Duration: {self.sn.duration}s")

    def create_emulation_environment(self):
        """Create Docker containers and network links."""
        print("\n[Step 1] Creating emulation environment...")

        # Create nodes (Docker containers)
        print("  Creating nodes...")
        self.sn.create_nodes()
        self.container_id_list = self.sn.container_id_list
        print(f"  Created {len(self.container_id_list)} containers")

        # Create links (ISL and GSL)
        print("  Creating links...")
        self.sn.create_links()
        print("  Links created")

        # Run routing daemon (BIRD)
        print("  Starting routing daemon...")
        self.sn.run_routing_deamon()
        print("  Routing daemon started")

    def get_node_ip(self, node_index: int) -> str:
        """
        Get IP address of a node.

        Args:
            node_index: Node index (1-based)

        Returns:
            IP address string
        """
        if node_index <= self.sn.constellation_size:
            # Satellite node
            ifconfig_output = sn_remote_cmd(
                self.sn.remote_ssh,
                f"docker exec -it {self.container_id_list[node_index - 1]} "
                f"ifconfig | sed 's/[ \\t].*//;/^\\(eth0\\|\\)\\(lo\\|\\)$/d'"
            )
            if ifconfig_output:
                interface = ifconfig_output[0].strip()
                ip_output = sn_remote_cmd(
                    self.sn.remote_ssh,
                    f"docker exec -it {self.container_id_list[node_index - 1]} "
                    f"ifconfig {interface} | awk -F '[ :]+' 'NR==2{{print $4}}'"
                )
                if ip_output:
                    return ip_output[0].strip()
        else:
            # Ground station
            ip_output = sn_remote_cmd(
                self.sn.remote_ssh,
                f"docker exec -it {self.container_id_list[node_index - 1]} "
                f"ifconfig B{node_index}-default | awk -F '[ :]+' 'NR==2{{print $4}}'"
            )
            if ip_output:
                return ip_output[0].strip()
        return None

    def inject_traffic_to_container(
        self,
        container_id: str,
        trace_file: str,
        target_ip: str,
        duration: float
    ) -> List[Dict]:
        """
        Inject traffic into a Docker container.

        Args:
            container_id: Docker container ID
            trace_file: Path to traffic trace file
            target_ip: Target IP address
            duration: Simulation duration in seconds

        Returns:
            List of injection results
        """
        injector = TrafficInjector(trace_file)
        results = []

        # Create traffic generation script
        script_content = f"""#!/bin/bash
# Traffic injection script
TARGET_IP="{target_ip}"
DURATION={duration}

# Generate traffic based on trace file
"""
        # Add packet generation commands based on trace
        for i, packet in enumerate(injector.packets):
            if packet['time'] > duration:
                break

            # Calculate delay
            delay = packet['time']
            if i > 0:
                delay = packet['time'] - injector.packets[i-1]['time']

            # Generate packet
            if packet['direction'] == 1:  # Send
                script_content += f"sleep {delay}\n"
                script_content += f"echo 'Packet {i}' | nc -u -w1 $TARGET_IP 12345 &\n"
            else:  # Receive (simulate by waiting)
                script_content += f"sleep {delay}\n"

        # Write script to container
        script_path = f"/tmp/inject_traffic_{os.getpid()}.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)

        # Copy script to container
        sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker cp {script_path} {container_id}:/tmp/inject_traffic.sh"
        )

        # Execute script
        sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker exec -d {container_id} bash /tmp/inject_traffic.sh"
        )

        return results

    def capture_traffic_from_container(
        self,
        container_id: str,
        output_file: str,
        duration: float
    ) -> str:
        """
        Capture traffic from a Docker container.

        Args:
            container_id: Docker container ID
            output_file: Output file path
            duration: Capture duration in seconds

        Returns:
            Path to captured traffic file
        """
        # Start tcpdump in container
        pcap_file = f"/tmp/capture_{os.getpid()}.pcap"
        sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker exec -d {container_id} tcpdump -i any -w {pcap_file} "
            f"-G {duration} -W 1"
        )

        # Wait for capture
        time.sleep(duration + 1)

        # Copy pcap file from container
        local_pcap = f"/tmp/capture_{os.getpid()}.pcap"
        sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker cp {container_id}:{pcap_file} {local_pcap}"
        )

        # Convert pcap to trace format
        self._convert_pcap_to_trace(local_pcap, output_file)

        return output_file

    def _convert_pcap_to_trace(self, pcap_file: str, output_file: str):
        """
        Convert pcap file to trace format.

        Args:
            pcap_file: Path to pcap file
            output_file: Path to output trace file
        """
        # Use tshark to extract timestamps and directions
        cmd = (
            f"tshark -r {pcap_file} -T fields -e frame.time_relative -e ip.src "
            f"2>/dev/null | awk '{{print $1, ($2 == \"10.0.0.1\" ? 1 : -1)}}' "
            f"> {output_file}"
        )
        os.system(cmd)

    def run_single_trace_simulation(
        self,
        trace_file: str,
        trace_id: str,
        client_node: int,
        server_node: int,
        duration: float
    ) -> str:
        """
        Run simulation for a single trace.

        Args:
            trace_file: Path to fiber trace file
            trace_id: Trace identifier
            client_node: Client node index
            server_node: Server node index
            duration: Simulation duration

        Returns:
            Path to simulated trace file
        """
        print(f"  Simulating trace {trace_id}...")

        # Get IPs
        client_ip = self.get_node_ip(client_node)
        server_ip = self.get_node_ip(server_node)

        if not client_ip or not server_ip:
            print(f"    Warning: Could not get IPs for nodes {client_node}, {server_node}")
            return None

        print(f"    Client: {client_node} ({client_ip})")
        print(f"    Server: {server_node} ({server_ip})")

        # Start capture on server
        output_file = os.path.join(self.satellite_dir, trace_id)
        self.capture_traffic_from_container(
            self.container_id_list[server_node - 1],
            output_file,
            duration
        )

        # Inject traffic on client
        self.inject_traffic_to_container(
            self.container_id_list[client_node - 1],
            trace_file,
            server_ip,
            duration
        )

        # Wait for completion
        time.sleep(duration + 2)

        print(f"    Output: {output_file}")
        return output_file

    def run_small_test(self, max_files: int = 10):
        """
        Run small test simulation.

        Args:
            max_files: Maximum number of traces to process
        """
        print("=" * 60)
        print("Running Small Test Simulation")
        print("=" * 60)

        # Initialize StarryNet
        self.initialize_starrynet()
        self.create_emulation_environment()

        # Load fiber traces
        fiber_files = load_fiber_traces(self.fiber_dir, max_files)
        print(f"\nProcessing {len(fiber_files)} traces...")

        # Use first satellite as client, second as server
        # Or use ground stations
        client_node = 1  # First satellite
        server_node = 27  # Last ground station

        # Process each trace
        for i, trace_file in enumerate(fiber_files):
            trace_id = os.path.basename(trace_file)
            print(f"\n[Trace {i+1}/{len(fiber_files)}] {trace_id}")

            # Get trace duration
            injector = TrafficInjector(trace_file)
            stats = injector.get_trace_stats()
            duration = min(stats['duration'], 30)  # Cap at 30 seconds

            # Run simulation
            output_file = self.run_single_trace_simulation(
                trace_file, trace_id, client_node, server_node, duration
            )

            if output_file and os.path.exists(output_file):
                print(f"    ✓ Completed: {output_file}")
            else:
                print(f"    ✗ Failed")

        # Generate comparison
        print("\n[Step 4] Generating comparison...")
        comparison_dir = os.path.join(self.output_dir, 'comparison')
        similarity_score = quick_compare(
            self.fiber_dir,
            self.satellite_dir,
            comparison_dir,
            max_files
        )

        print(f"\n{'=' * 60}")
        print("Simulation Complete!")
        print(f"{'=' * 60}")
        print(f"Similarity score: {similarity_score:.4f}")

    def run_full_simulation(self, max_files: Optional[int] = None):
        """
        Run full simulation.

        Args:
            max_files: Maximum number of traces to process
        """
        print("=" * 60)
        print("Running Full StarryNet Simulation")
        print("=" * 60)

        # Initialize StarryNet
        self.initialize_starrynet()
        self.create_emulation_environment()

        # Load fiber traces
        fiber_files = load_fiber_traces(self.fiber_dir, max_files)
        print(f"\nProcessing {len(fiber_files)} traces...")

        # Use ground stations for full simulation
        client_node = 26  # First ground station
        server_node = 27  # Second ground station

        # Process each trace
        start_time = time.time()
        for i, trace_file in enumerate(fiber_files):
            trace_id = os.path.basename(trace_file)
            print(f"\n[Trace {i+1}/{len(fiber_files)}] {trace_id}")

            # Get trace duration
            injector = TrafficInjector(trace_file)
            stats = injector.get_trace_stats()
            duration = min(stats['duration'], 60)  # Cap at 60 seconds

            # Run simulation
            output_file = self.run_single_trace_simulation(
                trace_file, trace_id, client_node, server_node, duration
            )

            # Print progress
            if (i + 1) % 10 == 0 or (i + 1) == len(fiber_files):
                elapsed = time.time() - start_time
                print(f"\n  Progress: {i+1}/{len(fiber_files)} traces")
                print(f"  Elapsed: {elapsed:.2f}s")

        # Generate comparison
        print("\n[Step 4] Generating comparison...")
        comparison_dir = os.path.join(self.output_dir, 'comparison')
        similarity_score = quick_compare(
            self.fiber_dir,
            self.satellite_dir,
            comparison_dir,
            max_files
        )

        # Save summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'config_file': self.config_file,
            'num_traces_processed': len(fiber_files),
            'similarity_score': similarity_score,
            'elapsed_time': time.time() - start_time
        }

        summary_file = os.path.join(self.output_dir, 'simulation_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n{'=' * 60}")
        print("Full Simulation Complete!")
        print(f"{'=' * 60}")
        print(f"Output directory: {self.output_dir}")
        print(f"Similarity score: {similarity_score:.4f}")
        print(f"Total time: {time.time() - start_time:.2f}s")
        print(f"Summary: {summary_file}")

    def cleanup(self):
        """Clean up StarryNet resources."""
        if self.sn:
            print("\nCleaning up...")
            self.sn.stop_emulation()
            print("Cleanup complete")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='StarryNet Traffic Simulation with Real Network Emulation'
    )
    parser.add_argument(
        '--mode',
        choices=['small_test', 'full'],
        default='small_test',
        help='Simulation mode'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config.json',
        help='StarryNet configuration file'
    )
    parser.add_argument(
        '--max_files',
        type=int,
        help='Maximum number of files to process'
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        help='Output directory'
    )

    args = parser.parse_args()

    # Create simulation
    simulation = StarryNetTrafficSimulation(args.config)

    if args.output_dir:
        simulation.output_dir = args.output_dir
        simulation.satellite_dir = os.path.join(args.output_dir, 'tor_satellite')
        os.makedirs(simulation.satellite_dir, exist_ok=True)

    try:
        # Run simulation
        if args.mode == 'small_test':
            simulation.run_small_test(args.max_files or 10)
        elif args.mode == 'full':
            simulation.run_full_simulation(args.max_files)
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user")
    except Exception as e:
        print(f"\n\nSimulation failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        simulation.cleanup()


if __name__ == '__main__':
    main()
