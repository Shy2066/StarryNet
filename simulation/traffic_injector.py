#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Traffic injector for StarryNet simulation.

Loads ground truth traffic traces and injects them into the satellite network
simulation with adaptive time scaling.

Usage:
    from traffic_injector import TrafficInjector
    injector = TrafficInjector('dataset/tor_fiber/0-0')
    injector.inject_to_network(client_node, server_node, get_delay_func)
"""

import time
import numpy as np
from typing import List, Dict, Callable, Optional


class TrafficInjector:
    """Injects traffic traces into StarryNet simulation."""

    def __init__(self, trace_file: str, base_delay: float = 0.1):
        """
        Initialize traffic injector.

        Args:
            trace_file: Path to traffic trace file
            base_delay: Base delay reference value (seconds) for adaptive scaling
        """
        self.trace_file = trace_file
        self.base_delay = base_delay
        self.packets = self._load_trace(trace_file)
        self.packet_sizes = self._generate_packet_sizes()

    def _load_trace(self, file_path: str) -> List[Dict]:
        """
        Load traffic trace file.

        Args:
            file_path: Path to trace file

        Returns:
            List of packet dictionaries with 'time' and 'direction'
        """
        packets = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) != 2:
                    continue
                try:
                    timestamp = float(parts[0])
                    direction = int(parts[1])
                    packets.append({
                        'time': timestamp,
                        'direction': direction
                    })
                except ValueError:
                    continue
        return packets

    def _generate_packet_sizes(self) -> List[int]:
        """
        Generate realistic packet sizes based on direction.

        Returns:
            List of packet sizes in bytes
        """
        sizes = []
        for packet in self.packets:
            if packet['direction'] == 1:  # Send
                # Sending packets: mix of small (ACK) and large (data)
                if np.random.random() < 0.3:
                    size = np.random.randint(40, 100)  # Small ACK packets
                else:
                    size = np.random.randint(500, 1500)  # Data packets
            else:  # Receive
                # Receiving packets: typically larger
                if np.random.random() < 0.2:
                    size = np.random.randint(40, 100)  # Small ACK packets
                else:
                    size = np.random.randint(500, 1500)  # Data packets
            sizes.append(size)
        return sizes

    def adaptive_time_scale(self, current_delay: float) -> float:
        """
        Calculate adaptive time scale based on current network delay.

        Args:
            current_delay: Current network delay in seconds

        Returns:
            Time scale factor (0.1 to 10.0)
        """
        if current_delay <= 0:
            current_delay = 0.001
        delay_factor = self.base_delay / current_delay
        return min(max(delay_factor, 0.1), 10.0)

    def inject_to_network(
        self,
        client_node: str,
        server_node: str,
        get_delay_func: Callable[[], float],
        send_func: Optional[Callable] = None,
        capture_func: Optional[Callable] = None
    ) -> List[Dict]:
        """
        Inject traffic into the simulation network.

        Args:
            client_node: Client node identifier
            server_node: Server node identifier
            get_delay_func: Function to get current network delay
            send_func: Function to send packets (optional)
            capture_func: Function to capture packets (optional)

        Returns:
            List of captured packets with timing information
        """
        captured_packets = []
        start_time = time.time()

        for i, packet in enumerate(self.packets):
            # Get current delay and calculate time scale
            current_delay = get_delay_func()
            time_scale = self.adaptive_time_scale(current_delay)

            # Calculate wait time
            if i > 0:
                original_interval = packet['time'] - self.packets[i-1]['time']
                adjusted_interval = original_interval * time_scale
                time.sleep(adjusted_interval)

            # Record packet information
            packet_info = {
                'index': i,
                'original_time': packet['time'],
                'injection_time': time.time() - start_time,
                'direction': packet['direction'],
                'size': self.packet_sizes[i],
                'client': client_node,
                'server': server_node,
                'delay': current_delay,
                'time_scale': time_scale
            }

            # Send packet if function provided
            if send_func:
                try:
                    send_func(
                        src=client_node if packet['direction'] == 1 else server_node,
                        dst=server_node if packet['direction'] == 1 else client_node,
                        size=self.packet_sizes[i]
                    )
                except Exception as e:
                    packet_info['error'] = str(e)

            captured_packets.append(packet_info)

        return captured_packets

    def get_trace_stats(self) -> Dict:
        """
        Get statistics about the loaded trace.

        Returns:
            Dictionary with trace statistics
        """
        if not self.packets:
            return {}

        timestamps = [p['time'] for p in self.packets]
        directions = [p['direction'] for p in self.packets]

        return {
            'num_packets': len(self.packets),
            'duration': timestamps[-1] - timestamps[0],
            'send_count': sum(1 for d in directions if d == 1),
            'receive_count': sum(1 for d in directions if d == -1),
            'send_ratio': sum(1 for d in directions if d == 1) / len(directions),
            'mean_iat': np.mean(np.diff(timestamps)),
            'std_iat': np.std(np.diff(timestamps))
        }


class BatchTrafficInjector:
    """Manages batch injection of multiple traffic traces."""

    def __init__(self, trace_files: List[str], base_delay: float = 0.1):
        """
        Initialize batch traffic injector.

        Args:
            trace_files: List of trace file paths
            base_delay: Base delay reference value
        """
        self.trace_files = trace_files
        self.base_delay = base_delay
        self.injectors = []

    def load_traces(self, max_files: Optional[int] = None):
        """
        Load multiple trace files.

        Args:
            max_files: Maximum number of files to load (None for all)
        """
        files_to_load = self.trace_files[:max_files] if max_files else self.trace_files
        self.injectors = []

        for trace_file in files_to_load:
            try:
                injector = TrafficInjector(trace_file, self.base_delay)
                self.injectors.append(injector)
            except Exception as e:
                print(f"Warning: Could not load {trace_file}: {e}")

    def inject_batch(
        self,
        client_node: str,
        server_node: str,
        get_delay_func: Callable[[], float],
        send_func: Optional[Callable] = None
    ) -> List[List[Dict]]:
        """
        Inject all loaded traces into the network.

        Args:
            client_node: Client node identifier
            server_node: Server node identifier
            get_delay_func: Function to get current network delay
            send_func: Function to send packets

        Returns:
            List of captured packets for each trace
        """
        all_captured = []

        for i, injector in enumerate(self.injectors):
            print(f"Injecting trace {i+1}/{len(self.injectors)}: {injector.trace_file}")
            captured = injector.inject_to_network(
                client_node, server_node, get_delay_func, send_func
            )
            all_captured.append(captured)

        return all_captured

    def get_batch_stats(self) -> List[Dict]:
        """
        Get statistics for all loaded traces.

        Returns:
            List of trace statistics
        """
        return [injector.get_trace_stats() for injector in self.injectors]


def load_fiber_traces(data_dir: str, max_files: Optional[int] = None) -> List[str]:
    """
    Load fiber traffic trace files from directory.

    Args:
        data_dir: Directory containing trace files
        max_files: Maximum number of files to load

    Returns:
        List of trace file paths
    """
    import os
    files = sorted([
        os.path.join(data_dir, f)
        for f in os.listdir(data_dir)
        if os.path.isfile(os.path.join(data_dir, f))
    ])
    return files[:max_files] if max_files else files


if __name__ == '__main__':
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python traffic_injector.py <trace_file>")
        sys.exit(1)

    trace_file = sys.argv[1]
    injector = TrafficInjector(trace_file)

    stats = injector.get_trace_stats()
    print(f"Trace Statistics:")
    print(f"  Packets: {stats['num_packets']}")
    print(f"  Duration: {stats['duration']:.3f} s")
    print(f"  Send ratio: {stats['send_ratio']:.4f}")
    print(f"  Mean IAT: {stats['mean_iat']*1000:.4f} ms")
    print(f"  Std IAT: {stats['std_iat']*1000:.4f} ms")
