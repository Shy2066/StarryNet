#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Traffic capture module for StarryNet simulation.

Captures traffic from the satellite network simulation and saves it in the
same format as the original dataset for analysis.

Usage:
    from traffic_capture import TrafficCapture
    capture = TrafficCapture('output/tor_satellite')
    capture.start_capture(node)
    # ... run simulation ...
    capture.stop_capture()
    capture.export_trace('0-0')
"""

import os
import time
import numpy as np
from typing import List, Dict, Optional, Tuple
from datetime import datetime


class TrafficCapture:
    """Captures and records traffic from StarryNet simulation."""

    def __init__(self, output_dir: str):
        """
        Initialize traffic capture.

        Args:
            output_dir: Directory to save captured traces
        """
        self.output_dir = output_dir
        self.captured_packets: List[Dict] = []
        self.is_capturing = False
        self.start_time: Optional[float] = None
        self.capture_node: Optional[str] = None

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

    def start_capture(self, capture_node: str):
        """
        Start capturing traffic.

        Args:
            capture_node: Node to capture traffic from
        """
        self.capture_node = capture_node
        self.captured_packets = []
        self.is_capturing = True
        self.start_time = time.time()
        print(f"Started capturing traffic on node {capture_node}")

    def stop_capture(self):
        """Stop capturing traffic."""
        self.is_capturing = False
        print(f"Stopped capturing. Captured {len(self.captured_packets)} packets")

    def record_packet(
        self,
        timestamp: float,
        direction: int,
        size: int,
        src: Optional[str] = None,
        dst: Optional[str] = None
    ):
        """
        Record a captured packet.

        Args:
            timestamp: Packet timestamp (relative to capture start)
            direction: Packet direction (1 for send, -1 for receive)
            size: Packet size in bytes
            src: Source node (optional)
            dst: Destination node (optional)
        """
        if not self.is_capturing:
            return

        packet_info = {
            'timestamp': timestamp,
            'direction': direction,
            'size': size,
            'src': src,
            'dst': dst,
            'capture_time': time.time() - self.start_time if self.start_time else 0
        }
        self.captured_packets.append(packet_info)

    def record_packet_from_network(
        self,
        original_time: float,
        direction: int,
        size: int,
        network_delay: float,
        jitter: float = 0.0
    ):
        """
        Record a packet with network effects applied.

        Args:
            original_time: Original packet timestamp
            direction: Packet direction
            size: Packet size
            network_delay: Network delay to apply
            jitter: Random jitter to add
        """
        if not self.is_capturing:
            return

        # Apply network delay and jitter
        adjusted_time = original_time + network_delay + np.random.uniform(-jitter, jitter)
        adjusted_time = max(0, adjusted_time)  # Ensure non-negative

        self.record_packet(
            timestamp=adjusted_time,
            direction=direction,
            size=size
        )

    def export_trace(self, trace_id: str) -> str:
        """
        Export captured packets to trace file.

        Args:
            trace_id: Trace identifier (e.g., '0-0')

        Returns:
            Path to exported trace file
        """
        if not self.captured_packets:
            print("Warning: No packets captured")
            return ""

        # Sort by timestamp
        sorted_packets = sorted(self.captured_packets, key=lambda x: x['timestamp'])

        # Export to file
        output_file = os.path.join(self.output_dir, trace_id)
        with open(output_file, 'w') as f:
            for i, packet in enumerate(sorted_packets):
                # Format: timestamp\tdirection
                line = f"{packet['timestamp']:.10f}\t{packet['direction']}\n"
                f.write(line)

        print(f"Exported {len(sorted_packets)} packets to {output_file}")
        return output_file

    def export_trace_with_sizes(self, trace_id: str) -> str:
        """
        Export captured packets with size information.

        Args:
            trace_id: Trace identifier

        Returns:
            Path to exported trace file
        """
        if not self.captured_packets:
            print("Warning: No packets captured")
            return ""

        # Sort by timestamp
        sorted_packets = sorted(self.captured_packets, key=lambda x: x['timestamp'])

        # Export to file with sizes
        output_file = os.path.join(self.output_dir, f"{trace_id}_sized")
        with open(output_file, 'w') as f:
            for i, packet in enumerate(sorted_packets):
                # Format: timestamp\tdirection\tsize
                line = f"{packet['timestamp']:.10f}\t{packet['direction']}\t{packet['size']}\n"
                f.write(line)

        print(f"Exported {len(sorted_packets)} packets with sizes to {output_file}")
        return output_file

    def get_capture_stats(self) -> Dict:
        """
        Get statistics about captured traffic.

        Returns:
            Dictionary with capture statistics
        """
        if not self.captured_packets:
            return {}

        timestamps = [p['timestamp'] for p in self.captured_packets]
        directions = [p['direction'] for p in self.captured_packets]
        sizes = [p['size'] for p in self.captured_packets]

        return {
            'num_packets': len(self.captured_packets),
            'duration': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'send_count': sum(1 for d in directions if d == 1),
            'receive_count': sum(1 for d in directions if d == -1),
            'send_ratio': sum(1 for d in directions if d == 1) / len(directions),
            'total_bytes': sum(sizes),
            'mean_packet_size': np.mean(sizes),
            'std_packet_size': np.std(sizes)
        }

    def clear(self):
        """Clear captured packets."""
        self.captured_packets = []
        self.is_capturing = False
        self.start_time = None


class BatchTrafficCapture:
    """Manages batch capture of multiple traffic traces."""

    def __init__(self, output_dir: str):
        """
        Initialize batch traffic capture.

        Args:
            output_dir: Base directory for output
        """
        self.output_dir = output_dir
        self.captures: List[TrafficCapture] = []

    def create_capture(self, trace_id: str) -> TrafficCapture:
        """
        Create a new capture instance.

        Args:
            trace_id: Trace identifier

        Returns:
            New TrafficCapture instance
        """
        # Use the same output directory for all captures
        capture = TrafficCapture(self.output_dir)
        self.captures.append(capture)
        return capture

    def export_all(self) -> List[str]:
        """
        Export all captured traces.

        Returns:
            List of exported file paths
        """
        exported_files = []
        for i, capture in enumerate(self.captures):
            trace_id = f"{i}-{i}"
            file_path = capture.export_trace(trace_id)
            if file_path:
                exported_files.append(file_path)
        return exported_files

    def get_summary(self) -> Dict:
        """
        Get summary of all captures.

        Returns:
            Summary statistics
        """
        total_packets = sum(len(c.captured_packets) for c in self.captures)
        return {
            'num_traces': len(self.captures),
            'total_packets': total_packets,
            'avg_packets_per_trace': total_packets / len(self.captures) if self.captures else 0
        }


if __name__ == '__main__':
    # Example usage
    import sys

    # Create a simple test
    capture = TrafficCapture('test_output')
    capture.start_capture('test_node')

    # Simulate some packets
    for i in range(100):
        capture.record_packet(
            timestamp=i * 0.01,
            direction=1 if i % 2 == 0 else -1,
            size=np.random.randint(100, 1500)
        )

    capture.stop_capture()
    stats = capture.get_capture_stats()

    print(f"Capture Statistics:")
    print(f"  Packets: {stats['num_packets']}")
    print(f"  Duration: {stats['duration']:.3f} s")
    print(f"  Send ratio: {stats['send_ratio']:.4f}")
    print(f"  Total bytes: {stats['total_bytes']}")

    # Export trace
    capture.export_trace('test-0')
