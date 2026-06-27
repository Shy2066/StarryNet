# StarryNet Traffic Simulation Module

This module provides tools for simulating satellite network traffic from ground truth fiber traffic data.

## Overview

The simulation workflow:

1. **Load fiber traffic traces** from `dataset/tor_fiber/`
2. **Inject traffic** into simulated satellite network with network effects
3. **Capture simulated traffic** with realistic delays, jitter, and packet loss
4. **Analyze and compare** features between original and simulated traffic

## Simulation Modes

### 1. Simple Simulation (Mathematical Model)

Uses mathematical models to simulate network effects without real StarryNet emulation.

**Files:**
- `run_simulation.py` - Main simulation script
- `traffic_injector.py` - Traffic injection module
- `traffic_capture.py` - Traffic capture module
- `feature_analyzer.py` - Feature analysis module

**Usage:**
```bash
# Run small test
python simulation/run_simulation.py --mode small_test

# Run full simulation
python simulation/run_simulation.py --mode full
```

### 2. Complete StarryNet Simulation (Real Network Emulation)

Uses StarryNet's real network emulation with Docker containers, tc netem, and BIRD routing.

**Files:**
- `run_starrynet_simulation.py` - Full StarryNet simulation
- `simple_starrynet_simulation.py` - Simplified version using iperf3

**Usage:**
```bash
# Run small test with full StarryNet
python simulation/run_starrynet_simulation.py --mode small_test

# Run simplified StarryNet simulation
python simulation/simple_starrynet_simulation.py --mode small_test
```

## Modules

### 1. Traffic Injector (`traffic_injector.py`)

Loads and injects traffic traces into the simulation.

**Key Features:**
- Loads trace files in TSV format (timestamp, direction)
- Adaptive time scaling based on network conditions
- Batch processing support

**Usage:**
```python
from simulation.traffic_injector import TrafficInjector

injector = TrafficInjector('dataset/tor_fiber/0-0')
stats = injector.get_trace_stats()
print(f"Packets: {stats['num_packets']}")
```

### 2. Traffic Capture (`traffic_capture.py`)

Captures and records traffic from the simulation.

**Key Features:**
- Records packets with timing information
- Exports traces in original dataset format

**Usage:**
```python
from simulation.traffic_capture import TrafficCapture

capture = TrafficCapture('output/tor_satellite')
capture.start_capture('node1')

# Record packets
capture.record_packet(timestamp=0.1, direction=1, size=1000)

capture.stop_capture()
capture.export_trace('0-0')
```

### 3. Feature Analyzer (`feature_analyzer.py`)

Analyzes and compares traffic features.

**Key Features:**
- Extracts comprehensive traffic features
- Statistical comparison (KS test, Mann-Whitney U test)
- Generates comparison plots and reports

**Usage:**
```python
from simulation.feature_analyzer import FeatureAnalyzer

analyzer = FeatureAnalyzer()
fiber_features = analyzer.extract_features_from_directory('dataset/tor_fiber')
sim_features = analyzer.extract_features_from_directory('simulation_output/tor_satellite')

comparison = analyzer.compare_features(fiber_features, sim_features)
similarity_score = analyzer.calculate_similarity_score(comparison)
```

## Complete StarryNet Simulation

### Prerequisites

1. **Docker** must be installed on the remote server
2. **StarryNet** must be configured in `config.json`
3. **Remote server** must be accessible via SSH

### Configuration

Update `config.json` with your server information:

```json
{
    "remote_machine_IP": "your_server_ip",
    "remote_machine_username": "your_username",
    "remote_machine_password": "your_password"
}
```

### Running Complete Simulation

```bash
# Small test (10 traces)
python simulation/run_starrynet_simulation.py --mode small_test

# Full simulation
python simulation/run_starrynet_simulation.py --mode full --max_files 100

# Simplified version using iperf3
python simulation/simple_starrynet_simulation.py --mode small_test
```

### Simulation Process

1. **Initialize StarryNet**: Creates constellation and calculates delays
2. **Create Environment**: Sets up Docker containers and network links
3. **Inject Traffic**: Sends fiber traffic through satellite network
4. **Capture Traffic**: Records traffic at destination
5. **Analyze Results**: Compares features with ground truth

## Output Structure

```
simulation_output/
├── tor_satellite/              # Simulated traffic traces
│   ├── 0-0
│   ├── 0-1
│   └── ...
├── comparison/                 # Comparison results
│   ├── feature_comparison.png
│   ├── cdf_comparison.png
│   └── comparison_report.txt
└── simulation_summary.json    # Simulation summary
```

## Network Parameters

The simulation uses the following network parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| base_delay | 0.05s | Base network delay (50ms) |
| jitter | 0.01s | Random jitter (10ms) |
| loss_rate | 0.01 | Packet loss rate (1%) |
| bandwidth_mbps | 100 | Bandwidth in Mbps |

These parameters can be adjusted via configuration file to match different satellite network conditions.

## Example Workflow

### Simple Simulation

```python
from simulation.traffic_injector import TrafficInjector, load_fiber_traces
from simulation.feature_analyzer import FeatureAnalyzer

# 1. Load fiber traces
fiber_files = load_fiber_traces('dataset/tor_fiber', max_files=10)

# 2. Process each trace using StarryNet simulation
# See simple_starrynet_simulation.py for complete implementation

# 3. Analyze results
analyzer = FeatureAnalyzer()
similarity = quick_compare('dataset/tor_fiber', 'output/tor_satellite', 'output/comparison')
print(f"Similarity score: {similarity:.4f}")
```

### Complete StarryNet Simulation

```python
from simulation.simple_starrynet_simulation import SimpleStarryNetSimulation

# Create simulation
sim = SimpleStarryNetSimulation('config.json')

# Run simulation
sim.run_small_test(max_files=10)

# Cleanup
sim.cleanup()
```

## References

- Original dataset: `dataset/tor_fiber/` and `dataset/tor_starlink/`
- Analysis script: `dataset/analyze_traffic.py`
- StarryNet configuration: `config.json`
- StarryNet documentation: `README.md`
