#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Feature analyzer for comparing traffic before and after simulation.

Extracts and compares features between ground truth fiber traffic and
simulated satellite traffic.

Usage:
    from feature_analyzer import FeatureAnalyzer
    analyzer = FeatureAnalyzer()
    fiber_features = analyzer.extract_features_from_file('dataset/tor_fiber/0-0')
    sim_features = analyzer.extract_features_from_file('simulation_output/tor_satellite/0-0')
    comparison = analyzer.compare_features(fiber_features, sim_features)
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from typing import List, Dict, Tuple, Optional
from scipy import stats
from collections import defaultdict


class FeatureAnalyzer:
    """Analyzes and compares traffic features."""

    def __init__(self):
        """Initialize feature analyzer."""
        self.feature_names = [
            'n_packets', 'duration', 'pkt_rate', 'send_ratio',
            'iat_mean', 'iat_std', 'iat_min', 'iat_max', 'iat_median', 'iat_cv'
        ]

    def load_trace(self, file_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load a trace file.

        Args:
            file_path: Path to trace file

        Returns:
            Tuple of (timestamps, labels)
        """
        ts, labels = [], []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                try:
                    ts.append(float(parts[0]))
                    labels.append(int(parts[1]))
                except ValueError:
                    continue
        return np.array(ts), np.array(labels)

    def extract_features(self, ts: np.ndarray, labels: np.ndarray) -> Optional[Dict]:
        """
        Extract features from a single trace.

        Args:
            ts: Timestamps array
            labels: Direction labels array

        Returns:
            Dictionary of features, or None if invalid
        """
        n = len(ts)
        if n < 2:
            return None

        duration = ts[-1] - ts[0]
        if duration <= 0:
            duration = 1e-9

        iat = np.diff(ts)
        send_mask = labels == 1

        features = {
            'n_packets': n,
            'duration': duration,
            'pkt_rate': n / duration,
            'n_send': int(np.sum(send_mask)),
            'send_ratio': float(np.sum(send_mask)) / n,
            'iat_mean': np.mean(iat),
            'iat_std': np.std(iat),
            'iat_min': np.min(iat),
            'iat_max': np.max(iat),
            'iat_median': np.median(iat),
            'iat_cv': np.std(iat) / np.mean(iat) if np.mean(iat) > 0 else 0,
        }
        return features

    def extract_features_from_file(self, file_path: str) -> Optional[Dict]:
        """
        Extract features from a trace file.

        Args:
            file_path: Path to trace file

        Returns:
            Dictionary of features
        """
        ts, labels = self.load_trace(file_path)
        return self.extract_features(ts, labels)

    def extract_features_from_directory(
        self,
        data_dir: str,
        max_files: Optional[int] = None
    ) -> List[Dict]:
        """
        Extract features from all traces in a directory.

        Args:
            data_dir: Directory containing trace files
            max_files: Maximum number of files to process

        Returns:
            List of feature dictionaries
        """
        files = sorted([
            f for f in os.listdir(data_dir)
            if os.path.isfile(os.path.join(data_dir, f))
        ])

        if max_files:
            files = files[:max_files]

        features_list = []
        for fname in files:
            filepath = os.path.join(data_dir, fname)
            feat = self.extract_features_from_file(filepath)
            if feat is not None:
                features_list.append(feat)

        return features_list

    def compare_features(
        self,
        features1: List[Dict],
        features2: List[Dict],
        labels: Tuple[str, str] = ('Fiber', 'SimSatellite')
    ) -> Dict:
        """
        Compare features between two datasets.

        Args:
            features1: First dataset features
            features2: Second dataset features
            labels: Labels for the two datasets

        Returns:
            Comparison results dictionary
        """
        comparison = {}

        for feature_name in self.feature_names:
            vals1 = np.array([f[feature_name] for f in features1])
            vals2 = np.array([f[feature_name] for f in features2])

            # Convert IAT features to milliseconds
            if feature_name.startswith('iat_') and feature_name != 'iat_cv':
                vals1 = vals1 * 1000
                vals2 = vals2 * 1000

            # Calculate statistics
            comparison[feature_name] = {
                f'{labels[0]}_mean': np.mean(vals1),
                f'{labels[0]}_std': np.std(vals1),
                f'{labels[1]}_mean': np.mean(vals2),
                f'{labels[1]}_std': np.std(vals2),
                'mean_diff': abs(np.mean(vals1) - np.mean(vals2)),
                'mean_diff_pct': abs(np.mean(vals1) - np.mean(vals2)) / np.mean(vals1) * 100 if np.mean(vals1) != 0 else 0,
            }

            # Statistical tests
            try:
                # Kolmogorov-Smirnov test
                ks_stat, ks_p = stats.ks_2samp(vals1, vals2)
                comparison[feature_name]['ks_statistic'] = ks_stat
                comparison[feature_name]['ks_p_value'] = ks_p

                # Mann-Whitney U test
                mw_stat, mw_p = stats.mannwhitneyu(vals1, vals2, alternative='two-sided')
                comparison[feature_name]['mw_statistic'] = mw_stat
                comparison[feature_name]['mw_p_value'] = mw_p
            except Exception as e:
                comparison[feature_name]['ks_statistic'] = None
                comparison[feature_name]['ks_p_value'] = None
                comparison[feature_name]['mw_statistic'] = None
                comparison[feature_name]['mw_p_value'] = None

        return comparison

    def calculate_similarity_score(self, comparison: Dict) -> float:
        """
        Calculate overall similarity score.

        Args:
            comparison: Comparison results dictionary

        Returns:
            Similarity score (0-1, higher is better)
        """
        scores = []

        for feature_name in self.feature_names:
            if feature_name in comparison:
                # Use KS statistic as similarity measure (lower is better)
                ks_stat = comparison[feature_name].get('ks_statistic')
                if ks_stat is not None:
                    # Convert to similarity (1 - ks_stat)
                    scores.append(1 - ks_stat)

        return np.mean(scores) if scores else 0.0

    def plot_comparison(
        self,
        features1: List[Dict],
        features2: List[Dict],
        output_dir: str,
        labels: Tuple[str, str] = ('Fiber', 'SimSatellite')
    ):
        """
        Generate comparison plots.

        Args:
            features1: First dataset features
            features2: Second dataset features
            output_dir: Output directory for plots
            labels: Labels for the two datasets
        """
        os.makedirs(output_dir, exist_ok=True)

        # Feature distribution comparison
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        plot_features = ['iat_mean', 'iat_std', 'iat_cv', 'pkt_rate', 'duration', 'send_ratio']

        for idx, feature_name in enumerate(plot_features):
            ax = axes[idx // 3, idx % 3]

            vals1 = [f[feature_name] for f in features1]
            vals2 = [f[feature_name] for f in features2]

            # Convert IAT to milliseconds
            if feature_name.startswith('iat_') and feature_name != 'iat_cv':
                vals1 = [v * 1000 for v in vals1]
                vals2 = [v * 1000 for v in vals2]

            ax.hist(vals1, bins=50, alpha=0.5, label=labels[0], density=True)
            ax.hist(vals2, bins=50, alpha=0.5, label=labels[1], density=True)
            ax.set_xlabel(feature_name)
            ax.set_ylabel('Density')
            ax.set_title(f'{feature_name} Distribution')
            ax.legend()

        fig.suptitle('Feature Distribution Comparison', fontsize=14, fontweight='bold')
        plt.tight_layout()
        fig.savefig(os.path.join(output_dir, 'feature_comparison.png'))
        plt.close(fig)

        # CDF comparison
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))

        for idx, feature_name in enumerate(plot_features):
            ax = axes[idx // 3, idx % 3]

            vals1 = sorted([f[feature_name] for f in features1])
            vals2 = sorted([f[feature_name] for f in features2])

            # Convert IAT to milliseconds
            if feature_name.startswith('iat_') and feature_name != 'iat_cv':
                vals1 = [v * 1000 for v in vals1]
                vals2 = [v * 1000 for v in vals2]

            cdf1 = np.arange(1, len(vals1) + 1) / len(vals1)
            cdf2 = np.arange(1, len(vals2) + 1) / len(vals2)

            ax.plot(vals1, cdf1, label=labels[0], linewidth=2)
            ax.plot(vals2, cdf2, label=labels[1], linewidth=2)
            ax.set_xlabel(feature_name)
            ax.set_ylabel('CDF')
            ax.set_title(f'{feature_name} CDF')
            ax.legend()
            ax.grid(True, alpha=0.3)

        fig.suptitle('CDF Comparison', fontsize=14, fontweight='bold')
        plt.tight_layout()
        fig.savefig(os.path.join(output_dir, 'cdf_comparison.png'))
        plt.close(fig)

    def generate_report(
        self,
        features1: List[Dict],
        features2: List[Dict],
        output_file: str,
        labels: Tuple[str, str] = ('Fiber', 'SimSatellite')
    ):
        """
        Generate comparison report.

        Args:
            features1: First dataset features
            features2: Second dataset features
            output_file: Output file path
            labels: Labels for the two datasets
        """
        comparison = self.compare_features(features1, features2, labels)
        similarity_score = self.calculate_similarity_score(comparison)

        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("Traffic Feature Comparison Report\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Dataset 1: {labels[0]} ({len(features1)} traces)\n")
            f.write(f"Dataset 2: {labels[1]} ({len(features2)} traces)\n\n")

            f.write(f"Overall Similarity Score: {similarity_score:.4f}\n\n")

            f.write("-" * 60 + "\n")
            f.write(f"{'Feature':<20} {labels[0]:>12} {labels[1]:>12} {'Diff%':>10} {'KS-p':>10}\n")
            f.write("-" * 60 + "\n")

            for feature_name in self.feature_names:
                if feature_name in comparison:
                    comp = comparison[feature_name]
                    mean1 = comp[f'{labels[0]}_mean']
                    mean2 = comp[f'{labels[1]}_mean']
                    diff_pct = comp['mean_diff_pct']
                    ks_p = comp.get('ks_p_value', None)

                    # Format values
                    if feature_name.startswith('iat_') and feature_name != 'iat_cv':
                        mean1_str = f"{mean1:.4f} ms"
                        mean2_str = f"{mean2:.4f} ms"
                    elif feature_name == 'duration':
                        mean1_str = f"{mean1:.3f} s"
                        mean2_str = f"{mean2:.3f} s"
                    else:
                        mean1_str = f"{mean1:.4f}"
                        mean2_str = f"{mean2:.4f}"

                    ks_p_str = f"{ks_p:.4f}" if ks_p is not None else "N/A"

                    f.write(f"{feature_name:<20} {mean1_str:>12} {mean2_str:>12} {diff_pct:>9.2f}% {ks_p_str:>10}\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("Interpretation:\n")
            f.write("- KS-p < 0.05: Statistically significant difference\n")
            f.write("- Diff% < 10%: Good similarity\n")
            f.write("- Diff% 10-30%: Moderate similarity\n")
            f.write("- Diff% > 30%: Poor similarity\n")
            f.write("=" * 60 + "\n")

        print(f"Report saved to {output_file}")


def quick_compare(
    fiber_dir: str,
    sim_dir: str,
    output_dir: str,
    max_files: Optional[int] = None
):
    """
    Quick comparison between fiber and simulated traffic.

    Args:
        fiber_dir: Directory containing fiber traces
        sim_dir: Directory containing simulated traces
        output_dir: Output directory for results
        max_files: Maximum number of files to process
    """
    analyzer = FeatureAnalyzer()

    print(f"Loading fiber traces from {fiber_dir}...")
    fiber_features = analyzer.extract_features_from_directory(fiber_dir, max_files)
    print(f"  Loaded {len(fiber_features)} traces")

    print(f"Loading simulated traces from {sim_dir}...")
    sim_features = analyzer.extract_features_from_directory(sim_dir, max_files)
    print(f"  Loaded {len(sim_features)} traces")

    # Generate plots
    print("Generating comparison plots...")
    analyzer.plot_comparison(fiber_features, sim_features, output_dir)

    # Generate report
    report_file = os.path.join(output_dir, 'comparison_report.txt')
    print(f"Generating report to {report_file}...")
    analyzer.generate_report(fiber_features, sim_features, report_file)

    # Calculate and print similarity score
    comparison = analyzer.compare_features(fiber_features, sim_features)
    similarity_score = analyzer.calculate_similarity_score(comparison)
    print(f"\nOverall Similarity Score: {similarity_score:.4f}")

    return similarity_score


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 3:
        print("Usage: python feature_analyzer.py <fiber_dir> <sim_dir> [output_dir]")
        sys.exit(1)

    fiber_dir = sys.argv[1]
    sim_dir = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else 'comparison_results'

    quick_compare(fiber_dir, sim_dir, output_dir)
