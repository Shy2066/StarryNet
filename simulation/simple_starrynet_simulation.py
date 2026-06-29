#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Simple StarryNet simulation using iperf3 for traffic generation.

This script uses StarryNet's existing iperf3 functionality to generate
traffic that simulates fiber traffic patterns.

Usage:
    python simulation/simple_starrynet_simulation.py --mode small_test
    python simulation/simple_starrynet_simulation.py --mode full --max_files 100
"""

import os
import sys
import json
import time
import numpy as np
from typing import List, Dict, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Parse arguments BEFORE importing StarryNet to avoid argparse conflicts
def parse_args():
    """Parse command line arguments."""
    mode = 'small_test'
    config = 'config.json'
    max_files = 10
    output_dir = None

    # Save original argv
    original_argv = sys.argv.copy()

    # Parse our custom arguments
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--mode' and i + 1 < len(sys.argv):
            mode = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--config' and i + 1 < len(sys.argv):
            config = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--max_files' and i + 1 < len(sys.argv):
            max_files = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--output_dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    # Remove our custom arguments from sys.argv to avoid conflicts with StarryNet's argparse
    sys.argv = [sys.argv[0]]

    return mode, config, max_files, output_dir

# Parse arguments first
SIM_MODE, SIM_CONFIG, SIM_MAX_FILES, SIM_OUTPUT_DIR = parse_args()

# Now import simulation modules
from simulation.traffic_injector import TrafficInjector, load_fiber_traces
from simulation.feature_analyzer import FeatureAnalyzer, quick_compare

# Import StarryNet modules (this will trigger argparse in sn_load_file)
from starrynet.sn_observer import *
from starrynet.sn_orchestrater import *
from starrynet.sn_synchronizer import *


class SimpleStarryNetSimulation:
    """Simple StarryNet simulation using iperf3 for traffic generation."""

    def __init__(self, config_file: str = 'config.json'):
        """
        Initialize simulation.

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

    def generate_traffic_pattern(self, trace_file: str) -> Dict:
        """
        Generate traffic pattern from trace file.

        Args:
            trace_file: Path to trace file

        Returns:
            Traffic pattern dictionary
        """
        injector = TrafficInjector(trace_file)
        stats = injector.get_trace_stats()

        # Calculate traffic parameters
        duration = stats['duration']
        total_packets = stats['num_packets']
        send_ratio = stats['send_ratio']

        # Estimate bandwidth (assuming 1500 bytes per packet)
        avg_packet_size = 1500  # bytes
        total_bytes = total_packets * avg_packet_size
        bandwidth_bps = (total_bytes * 8) / duration  # bits per second
        bandwidth_mbps = bandwidth_bps / 1e6  # Mbps

        # Calculate burst pattern
        iat_mean = stats['mean_iat']
        iat_std = stats['std_iat']

        return {
            'duration': duration,
            'bandwidth_mbps': min(bandwidth_mbps, 100),  # Cap at 100 Mbps
            'total_packets': total_packets,
            'send_ratio': send_ratio,
            'iat_mean': iat_mean,
            'iat_std': iat_std,
            'burst_pattern': self._calculate_burst_pattern(injector)
        }

    def _calculate_burst_pattern(self, injector: TrafficInjector) -> List[Dict]:
        """
        Calculate burst pattern from traffic trace.

        Args:
            injector: TrafficInjector instance

        Returns:
            List of burst patterns
        """
        bursts = []
        current_burst = {
            'start': 0,
            'packets': 0,
            'bytes': 0
        }

        for i, packet in enumerate(injector.packets):
            if i > 0:
                iat = packet['time'] - injector.packets[i-1]['time']
                if iat > 0.1:  # New burst if gap > 100ms
                    if current_burst['packets'] > 0:
                        bursts.append(current_burst)
                    current_burst = {
                        'start': packet['time'],
                        'packets': 0,
                        'bytes': 0
                    }

            current_burst['packets'] += 1
            current_burst['bytes'] += injector.packet_sizes[i]

        if current_burst['packets'] > 0:
            bursts.append(current_burst)

        return bursts

    def run_iperf3_test(
        self,
        src_node: int,
        dst_node: int,
        duration: float,
        bandwidth_mbps: float
    ) -> Dict:
        """
        Run iperf3 test between two nodes.

        Args:
            src_node: Source node index
            dst_node: Destination node index
            duration: Test duration in seconds
            bandwidth_mbps: Bandwidth in Mbps

        Returns:
            Test results dictionary
        """
        print(f"    Running iperf3: {src_node} -> {dst_node}")
        print(f"    Duration: {duration}s, Bandwidth: {bandwidth_mbps:.2f} Mbps")

        # Get destination IP
        dst_ip = self.get_node_ip(dst_node)
        if not dst_ip:
            print(f"    Warning: Could not get IP for node {dst_node}")
            return None

        # Start iperf3 server on destination
        sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker exec -d {self.container_id_list[dst_node - 1]} iperf3 -s"
        )

        # Run iperf3 client on source
        bandwidth_kbps = int(bandwidth_mbps * 1000)
        result = sn_remote_cmd(
            self.sn.remote_ssh,
            f"docker exec -i {self.container_id_list[src_node - 1]} "
            f"iperf3 -c {dst_ip} -t {int(duration)} -b {bandwidth_kbps}K -J"
        )

        # Parse result
        try:
            if result:
                result_str = ''.join(result)
                result_json = json.loads(result_str)
                return {
                    'success': True,
                    'bandwidth_mbps': result_json.get('end', {}).get('sum_sent', {}).get('bits_per_second', 0) / 1e6,
                    'duration': duration,
                    'bytes_sent': result_json.get('end', {}).get('sum_sent', {}).get('bytes', 0)
                }
        except:
            pass

        return {
            'success': False,
            'bandwidth_mbps': bandwidth_mbps,
            'duration': duration
        }

    def simulate_trace_with_iperf(
        self,
        trace_file: str,
        trace_id: str,
        src_node: int,
        dst_node: int
    ) -> str:
        """
        Simulate a trace using iperf3.

        Args:
            trace_file: Path to fiber trace file
            trace_id: Trace identifier
            src_node: Source node index
            dst_node: Destination node index

        Returns:
            Path to simulated trace file
        """
        print(f"  Simulating trace {trace_id}...")

        # Generate traffic pattern
        pattern = self.generate_traffic_pattern(trace_file)
        print(f"    Duration: {pattern['duration']:.2f}s")
        print(f"    Bandwidth: {pattern['bandwidth_mbps']:.2f} Mbps")
        print(f"    Packets: {pattern['total_packets']}")

        # Run iperf3 test
        result = self.run_iperf3_test(
            src_node, dst_node,
            pattern['duration'],
            pattern['bandwidth_mbps']
        )

        if not result or not result['success']:
            print(f"    Warning: iperf3 test failed")
            return None

        # Generate simulated trace
        output_file = os.path.join(self.satellite_dir, trace_id)
        self._generate_simulated_trace(pattern, result, output_file)

        print(f"    ✓ Completed: {output_file}")
        return output_file

    def _generate_simulated_trace(
        self,
        pattern: Dict,
        iperf_result: Dict,
        output_file: str
    ):
        """
        Generate simulated trace file.

        Args:
            pattern: Traffic pattern
            iperf_result: iperf3 test results
            output_file: Output file path
        """
        # Generate packets based on pattern
        packets = []
        current_time = 0

        # Add network delay (satellite latency)
        base_delay = 0.05  # 50ms base delay
        jitter = 0.01  # 10ms jitter

        for burst in pattern['burst_pattern']:
            # Generate packets in burst
            for i in range(burst['packets']):
                # Calculate timing
                if i > 0:
                    iat = pattern['iat_mean'] + np.random.normal(0, pattern['iat_std'])
                    iat = max(0.001, iat)  # Minimum 1ms
                    current_time += iat

                # Add network delay
                delay = base_delay + np.random.uniform(-jitter, jitter)
                delay = max(0, delay)

                # Determine direction (based on send_ratio)
                direction = 1 if np.random.random() < pattern['send_ratio'] else -1

                # Record packet
                packets.append({
                    'time': current_time + delay,
                    'direction': direction
                })

        # Sort by time
        packets.sort(key=lambda x: x['time'])

        # Write to file
        with open(output_file, 'w') as f:
            for i, packet in enumerate(packets):
                line = f"{packet['time']:.10f}\t{packet['direction']}\n"
                f.write(line)

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

        # Use ground stations for testing
        src_node = 26  # First ground station
        dst_node = 27  # Second ground station

        # Process each trace
        for i, trace_file in enumerate(fiber_files):
            trace_id = os.path.basename(trace_file)
            print(f"\n[Trace {i+1}/{len(fiber_files)}] {trace_id}")

            # Run simulation
            output_file = self.simulate_trace_with_iperf(
                trace_file, trace_id, src_node, dst_node
            )

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

        # Use ground stations
        src_node = 26  # First ground station
        dst_node = 27  # Second ground station

        # Process each trace
        start_time = time.time()
        for i, trace_file in enumerate(fiber_files):
            trace_id = os.path.basename(trace_file)
            print(f"\n[Trace {i+1}/{len(fiber_files)}] {trace_id}")

            # Run simulation
            output_file = self.simulate_trace_with_iperf(
                trace_file, trace_id, src_node, dst_node
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
    # Use pre-parsed arguments
    mode = SIM_MODE
    config = SIM_CONFIG
    max_files = SIM_MAX_FILES
    output_dir = SIM_OUTPUT_DIR

    # Create simulation
    simulation = SimpleStarryNetSimulation(config)

    if output_dir:
        simulation.output_dir = output_dir
        simulation.satellite_dir = os.path.join(output_dir, 'tor_satellite')
        os.makedirs(simulation.satellite_dir, exist_ok=True)

    try:
        # Run simulation
        if mode == 'small_test':
            simulation.run_small_test(max_files)
        elif mode == 'full':
            simulation.run_full_simulation(max_files)
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
