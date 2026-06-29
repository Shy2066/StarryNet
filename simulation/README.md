# StarryNet Traffic Simulation Module

This module provides tools for simulating satellite network traffic from ground truth fiber traffic data.

## Overview

The simulation workflow:

1. **Load fiber traffic traces** from `dataset/tor_fiber/`
2. **Inject traffic** into simulated satellite network with network effects
3. **Capture simulated traffic** with realistic delays, jitter, and packet loss
4. **Analyze and compare** features between original and simulated traffic

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
- Applies network effects (delay, jitter, loss)
- Exports traces in original dataset format

**Usage:**
```python
from simulation.traffic_capture import TrafficCapture, NetworkSimulator

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

## Running Simulations

### Quick Start

```bash
# Run small test (10 traces)
python simulation/run_simulation.py --mode small_test

# Run full simulation
python simulation/run_simulation.py --mode full

# Analyze existing results
python simulation/run_simulation.py --mode analyze
```

### Command Line Options

```bash
python simulation/run_simulation.py \
    --mode small_test|full|analyze \
    --config config.json \
    --max_files 100 \
    --output_dir simulation_output \
    --data_dir dataset
```

### Configuration File

Create a JSON configuration file:

```json
{
    "output_dir": "simulation_output",
    "data_dir": "dataset",
    "base_delay": 0.05,
    "jitter": 0.01,
    "loss_rate": 0.01,
    "bandwidth_mbps": 100,
    "small_test_files": 10
}
```

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

## Integration with StarryNet

To integrate with the full StarryNet simulation:

1. **Configure StarryNet** in `config.json`
2. **Run StarryNet simulation** to get network topology
3. **Use this module** to inject and capture traffic
4. **Analyze results** to compare with ground truth

## Example Workflow

```python
from simulation.traffic_injector import TrafficInjector, load_fiber_traces
from simulation.traffic_capture import TrafficCapture, NetworkSimulator
from simulation.feature_analyzer import FeatureAnalyzer

# 1. Load fiber traces
fiber_files = load_fiber_traces('dataset/tor_fiber', max_files=10)

# 2. Create network simulator
network = NetworkSimulator(base_delay=0.05, jitter=0.01)

# 3. Process each trace
for fiber_file in fiber_files:
    injector = TrafficInjector(fiber_file)

    # Create capture
    capture = TrafficCapture('output/tor_satellite')
    capture.start_capture('sim_node')

    # Apply network effects
    for packet in injector.packets:
        network.apply_network_effects([packet], capture)

    capture.stop_capture()
    capture.export_trace(os.path.basename(fiber_file))

# 4. Analyze results
analyzer = FeatureAnalyzer()
similarity = quick_compare('dataset/tor_fiber', 'output/tor_satellite', 'output/comparison')
print(f"Similarity score: {similarity:.4f}")
```

## References

- Original dataset: `dataset/tor_fiber/` and `dataset/tor_starlink/`
- Analysis script: `dataset/analyze_traffic.py`
- StarryNet configuration: `config.json`
