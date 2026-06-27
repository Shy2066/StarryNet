#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Main simulation script for StarryNet traffic emulation.

Orchestrates the complete simulation workflow:
1. Load fiber traffic traces
2. Inject traffic into satellite network simulation
3. Capture simulated traffic
4. Analyze and compare features

Usage:
    python simulation/run_simulation.py --mode small_test
    python simulation/run_simulation.py --mode full --max_files 100
"""

import os
import sys
import argparse
import json
import time
import numpy as np
from typing import List, Dict, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulation.traffic_injector import TrafficInjector, BatchTrafficInjector, load_fiber_traces
from simulation.traffic_capture import TrafficCapture, NetworkSimulator, BatchTrafficCapture
from simulation.feature_analyzer import FeatureAnalyzer, quick_compare


class StarryNetSimulation:
    """Main simulation class for StarryNet traffic emulation."""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize simulation.

        Args:
            config_file: Path to configuration file (optional)
        """
        self.config = self._load_config(config_file)
        self.output_dir = self.config.get('output_dir', 'simulation_output')
        self.data_dir = self.config.get('data_dir', 'dataset')
        self.fiber_dir = os.path.join(self.data_dir, 'tor_fiber')
        self.satellite_dir = os.path.join(self.output_dir, 'tor_satellite')

        # Create output directories
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.satellite_dir, exist_ok=True)

        # Initialize components
        self.network_simulator = NetworkSimulator(
            base_delay=self.config.get('base_delay', 0.05),
            jitter=self.config.get('jitter', 0.01),
            loss_rate=self.config.get('loss_rate', 0.01),
            bandwidth_mbps=self.config.get('bandwidth_mbps', 100)
        )
        self.feature_analyzer = FeatureAnalyzer()

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """
        Load configuration from file.

        Args:
            config_file: Path to configuration file

        Returns:
            Configuration dictionary
        """
        default_config = {
            'output_dir': 'simulation_output',
            'data_dir': 'dataset',
            'base_delay': 0.05,  # 50ms
            'jitter': 0.01,      # 10ms
            'loss_rate': 0.01,   # 1%
            'bandwidth_mbps': 100,
            'max_files': None,
            'small_test_files': 10
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)

        return default_config

    def run_small_test(self):
        """Run a small test simulation with limited files."""
        print("=" * 60)
        print("Running Small Test Simulation")
        print("=" * 60)

        max_files = self.config.get('small_test_files', 10)
        self._run_simulation(max_files)

    def run_full_simulation(self, max_files: Optional[int] = None):
        """
        Run full simulation.

        Args:
            max_files: Maximum number of files to process (None for all)
        """
        print("=" * 60)
        print("Running Full Simulation")
        print("=" * 60)

        self._run_simulation(max_files)

    def _run_simulation(self, max_files: Optional[int] = None):
        """
        Run the simulation.

        Args:
            max_files: Maximum number of files to process
        """
        start_time = time.time()

        # Step 1: Load fiber traces
        print("\n[Step 1] Loading fiber traces...")
        fiber_files = load_fiber_traces(self.fiber_dir, max_files)
        print(f"  Found {len(fiber_files)} trace files")

        # Step 2: Process each trace
        print("\n[Step 2] Processing traces...")
        batch_capture = BatchTrafficCapture(self.satellite_dir)

        for i, fiber_file in enumerate(fiber_files):
            print(f"\n  Processing trace {i+1}/{len(fiber_files)}: {os.path.basename(fiber_file)}")

            # Load fiber trace
            injector = TrafficInjector(fiber_file)
            stats = injector.get_trace_stats()
            print(f"    Packets: {stats['num_packets']}, Duration: {stats['duration']:.3f}s")

            # Create capture for this trace
            trace_id = os.path.basename(fiber_file)
            capture = batch_capture.create_capture(trace_id)

            # Simulate network effects
            capture.start_capture('simulated_node')

            # Process packets with network effects
            for j, packet in enumerate(injector.packets):
                # Apply network effects
                delay = self.network_simulator.base_delay + np.random.uniform(
                    -self.network_simulator.jitter,
                    self.network_simulator.jitter
                )
                delay = max(0, delay)

                # Simulate packet loss
                if np.random.random() < self.network_simulator.loss_rate:
                    continue

                # Record packet
                capture.record_packet_from_network(
                    original_time=packet['time'],
                    direction=packet['direction'],
                    size=injector.packet_sizes[j],
                    network_delay=delay,
                    jitter=self.network_simulator.jitter
                )

            capture.stop_capture()

            # Export trace
            capture.export_trace(trace_id)

            # Print progress
            if (i + 1) % 10 == 0 or (i + 1) == len(fiber_files):
                elapsed = time.time() - start_time
                print(f"    Progress: {i+1}/{len(fiber_files)} traces processed")
                print(f"    Elapsed time: {elapsed:.2f}s")

        # Step 3: Generate comparison
        print("\n[Step 3] Generating comparison...")
        comparison_dir = os.path.join(self.output_dir, 'comparison')
        similarity_score = quick_compare(
            self.fiber_dir,
            self.satellite_dir,
            comparison_dir,
            max_files
        )

        # Step 4: Save summary
        print("\n[Step 4] Saving summary...")
        summary = {
            'timestamp': datetime.now().isoformat(),
            'config': self.config,
            'num_traces_processed': len(fiber_files),
            'similarity_score': similarity_score,
            'elapsed_time': time.time() - start_time
        }

        summary_file = os.path.join(self.output_dir, 'simulation_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n{'=' * 60}")
        print("Simulation Complete!")
        print(f"{'=' * 60}")
        print(f"Output directory: {self.output_dir}")
        print(f"Similarity score: {similarity_score:.4f}")
        print(f"Total time: {time.time() - start_time:.2f}s")
        print(f"Summary saved to: {summary_file}")

    def analyze_results(self):
        """Analyze simulation results."""
        print("\n[Analysis] Analyzing simulation results...")

        comparison_dir = os.path.join(self.output_dir, 'comparison')
        if not os.path.exists(comparison_dir):
            print("No comparison results found. Run simulation first.")
            return

        # Load and display comparison report
        report_file = os.path.join(comparison_dir, 'comparison_report.txt')
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                print(f.read())

        # Display plots
        print(f"\nComparison plots saved to: {comparison_dir}")
        print("  - feature_comparison.png")
        print("  - cdf_comparison.png")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='StarryNet Traffic Simulation')
    parser.add_argument('--mode', choices=['small_test', 'full', 'analyze'],
                       default='small_test', help='Simulation mode')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--max_files', type=int, help='Maximum number of files to process')
    parser.add_argument('--output_dir', type=str, help='Output directory')
    parser.add_argument('--data_dir', type=str, help='Data directory')

    args = parser.parse_args()

    # Update config with command line arguments
    config = {}
    if args.config:
        config['config_file'] = args.config
    if args.max_files:
        config['max_files'] = args.max_files
    if args.output_dir:
        config['output_dir'] = args.output_dir
    if args.data_dir:
        config['data_dir'] = args.data_dir

    # Create simulation
    simulation = StarryNetSimulation(args.config)

    # Run simulation
    if args.mode == 'small_test':
        simulation.run_small_test()
    elif args.mode == 'full':
        simulation.run_full_simulation(args.max_files)
    elif args.mode == 'analyze':
        simulation.analyze_results()


if __name__ == '__main__':
    main()
