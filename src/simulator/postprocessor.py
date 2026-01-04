"""
Experiment Results Postprocessing Module

This module provides analysis and visualization capabilities for experiment results.
It calculates performance metrics, estimates attack success probabilities, and
generates visualizations for the research report.
"""
import statistics
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from src.config.config import GROUP_SEED

# Set up the plotting style
plt.style.use('default')
sns.set_palette("husl")


@dataclass
class AttackMetrics:
    """Container for calculated attack performance metrics."""
    total_attempts: int
    successful_attempts: int
    blocked_attempts: int
    requests_per_second: float
    success_rate: float
    estimated_success_time: Optional[float]
    # New metrics for the assignment requirements
    median_latency: float = 0.0
    p90_latency: float = 0.0
    avg_latency: float = 0.0


@dataclass
class PasswordStrengthAnalysis:
    """Analysis results for password strength classes."""
    weak_passwords: List[str]
    medium_passwords: List[str]
    strong_passwords: List[str]
    alphabet_sizes: Dict[str, int]
    theoretical_keyspace: Dict[str, int]


class ResultsPostprocessor:
    """
    Postprocessing and analysis engine for experiment results.
    
    This class provides functionality to calculate attack performance metrics,
    estimate theoretical attack times, and generate visualizations suitable for
    an academic report.
    """

    def __init__(self, results: Dict[str, Any], users: List[Dict[str, Any]],
                 password_config: Any, output_dir: str = "results"):
        """
        Initialize the postprocessor with experiment data.
        
        Args:
            results: Complete experiment results dictionary
            users: List of user accounts used in the experiment
            password_config: Password generation configuration
            output_dir: Directory for saving results and visualizations
        """
        self.results = results
        self.users = users
        self.password_config = password_config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Analyze password characteristics
        self.password_analysis = self._analyze_password_strengths()

        # Initialize color schemes for consistent visualization
        self.defense_colors = {
            'baseline': '#1f77b4',  # Blue
            'mfa': '#ff7f0e',  # Orange
            'rate_limit': '#2ca02c',  # Green
            'account_lockout': '#d62728',  # Red
            'captcha': '#9467bd',  # Purple
            'combination': '#8c564b',  # Brown
            'comprehensive': '#e377c2'  # Pink
        }

        self.hasher_colors = {
            'PlainText': '#ff0000',  # Red - dangerous
            'BCrypt': '#ffa500',  # Orange - legacy
            'Argon2ID': '#008000'  # Green - modern
        }

    def _analyze_password_strengths(self) -> PasswordStrengthAnalysis:
        """Analyze password characteristics by strength class."""
        weak_passwords = [u['password'] for u in self.users if u['strength_class'] == 'weak']
        medium_passwords = [u['password'] for u in self.users if u['strength_class'] == 'medium']
        strong_passwords = [u['password'] for u in self.users if u['strength_class'] == 'strong']

        alphabet_sizes = {
            'weak': len(self.password_config.weak_alphabet),
            'medium': len(self.password_config.medium_alphabet),
            'strong': len(self.password_config.strong_alphabet)
        }

        theoretical_keyspace = {
            'weak': alphabet_sizes['weak'] ** self.password_config.weak_length,
            'medium': alphabet_sizes['medium'] ** self.password_config.medium_length,
            'strong': alphabet_sizes['strong'] ** self.password_config.strong_length
        }

        return PasswordStrengthAnalysis(
            weak_passwords=weak_passwords,
            medium_passwords=medium_passwords,
            strong_passwords=strong_passwords,
            alphabet_sizes=alphabet_sizes,
            theoretical_keyspace=theoretical_keyspace
        )

    def _calculate_attack_metrics(self, attack_summary: Dict[str, Any],
                                  attack_time: float, attack_type: str) -> AttackMetrics:
        """
        Calculate comprehensive metrics for an attack result.
        
        Args:
            attack_summary: Attack result summary from attackers
            attack_time: Total time taken for the attack
            attack_type: Type of attack ('brute_force' or 'password_spray')
            
        Returns:
            AttackMetrics containing calculated performance indicators
        """
        total_attempts = 0
        successful_attempts = 0
        blocked_attempts = 0

        collected_medians = []

        for target_name, target_data in attack_summary.items():
            # Retrieve pre-calculated median from _run_attacks
            if 'latency_median' in target_data:
                collected_medians.append(target_data['latency_median'])

            for key, value in target_data.items():
                if isinstance(value, int):
                    total_attempts += value
                    if key == 'SUCCESS':
                        successful_attempts += value
                    elif key in ['RATE_LIMIT', 'ACCOUNT_LOCKOUT', 'CAPTCHA', 'MFA']:
                        blocked_attempts += value

        # Use the mean of medians to represent the overall case latency
        median_lat = statistics.mean(collected_medians) if collected_medians else 0.0
        avg_lat = median_lat
        p90_lat = max(collected_medians) if collected_medians else 0.0

        requests_per_second = total_attempts / attack_time if attack_time > 0 else 0
        success_rate = successful_attempts / total_attempts if total_attempts > 0 else 0

        estimated_success_time = None
        if attack_type == 'brute_force' and requests_per_second > 0:
            expected_attempts = self.password_analysis.theoretical_keyspace['weak'] / 2
            estimated_success_time = expected_attempts / requests_per_second

        return AttackMetrics(
            total_attempts=total_attempts,
            successful_attempts=successful_attempts,
            blocked_attempts=blocked_attempts,
            requests_per_second=requests_per_second,
            success_rate=success_rate,
            estimated_success_time=estimated_success_time,
            median_latency=median_lat,
            p90_latency=p90_lat,
            avg_latency=avg_lat
        )



    @staticmethod
    def _categorize_case(case_name: str) -> str:
        """Categorize a test case for visualization grouping."""
        case_lower = case_name.lower()

        if 'baseline' in case_lower or 'control' in case_lower:
            return 'baseline'
        elif 'comprehensive' in case_lower:
            return 'comprehensive'
        elif 'combination' in case_lower or 'hybrid' in case_lower:
            return 'combination'
        elif 'mfa' in case_lower:
            return 'mfa'
        elif 'rate' in case_lower:
            return 'rate_limit'
        elif 'lockout' in case_lower:
            return 'account_lockout'
        elif 'captcha' in case_lower:
            return 'captcha'
        else:
            return 'other'

    def process_results(self) -> Dict[str, Any]:
        """
        Process all experiment results and add calculated metrics.
        
        Returns:
            Enhanced results dictionary with additional metrics
        """
        enhanced_results = {}

        for case_name, case_result in self.results.items():
            if 'error' in case_result:
                enhanced_results[case_name] = case_result
                continue

            enhanced_case = case_result.copy()

            # Calculate brute force metrics
            if 'brute_force' in case_result:
                bf_metrics = self._calculate_attack_metrics(
                    case_result['brute_force'],
                    case_result['brute_force_time'],
                    'brute_force'
                )
                enhanced_case['brute_force_metrics'] = {
                    'total_attempts': bf_metrics.total_attempts,
                    'successful_attempts': bf_metrics.successful_attempts,
                    'blocked_attempts': bf_metrics.blocked_attempts,
                    'requests_per_second': bf_metrics.requests_per_second,
                    'success_rate': bf_metrics.success_rate,
                    'median_latency': bf_metrics.median_latency,
                    'p90_latency': bf_metrics.p90_latency,
                    'estimated_success_time_seconds': bf_metrics.estimated_success_time,
                    'estimated_success_time_hours': bf_metrics.estimated_success_time / 3600 if bf_metrics.estimated_success_time else None
                }

            # Calculate password spray metrics
            if 'password_spray' in case_result:
                ps_metrics = self._calculate_attack_metrics(
                    case_result['password_spray'],
                    case_result['password_spray_time'],
                    'password_spray'
                )
                enhanced_case['password_spray_metrics'] = {
                    'total_attempts': ps_metrics.total_attempts,
                    'successful_attempts': ps_metrics.successful_attempts,
                    'blocked_attempts': ps_metrics.blocked_attempts,
                    'median_latency': bf_metrics.median_latency,
                    'p90_latency': bf_metrics.p90_latency,
                    'requests_per_second': ps_metrics.requests_per_second,
                    'success_rate': ps_metrics.success_rate
                }

            # Add case categorization for analysis
            enhanced_case['case_category'] = self._categorize_case(case_name)

            enhanced_results[case_name] = enhanced_case

        return enhanced_results

    def save_results(self, enhanced_results: Dict[str, Any]) -> None:
        """
        Save enhanced results to JSON file with metadata.
        
        Args:
            enhanced_results: Processed results with calculated metrics
        """
        output_data = {
            'GROUP SEED': GROUP_SEED,
            'experiment_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_cases': len(enhanced_results),
                'successful_cases': len([r for r in enhanced_results.values() if 'error' not in r]),
                'failed_cases': len([r for r in enhanced_results.values() if 'error' in r]),
                'password_analysis': {
                    'weak_count': len(self.password_analysis.weak_passwords),
                    'medium_count': len(self.password_analysis.medium_passwords),
                    'strong_count': len(self.password_analysis.strong_passwords),
                    'theoretical_keyspace': self.password_analysis.theoretical_keyspace,
                    'alphabet_sizes': self.password_analysis.alphabet_sizes
                }
            },
            'results': enhanced_results
        }

        output_file = self.output_dir / f"experiment_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)

        print(f"Results saved to: {output_file}")

    def generate_visualizations(self, enhanced_results: Dict[str, Any]) -> None:
        """
        Generate comprehensive visualization suite for the experiment results.
        
        Args:
            enhanced_results: Processed results with calculated metrics
        """
        print("Generating visualizations...")

        # Filter out failed cases for visualization
        valid_results = {k: v for k, v in enhanced_results.items() if 'error' not in v}

        if not valid_results:
            print("No valid results to visualize")
            return

        # Generate individual plots
        self._plot_latency_p90_comparison(valid_results)
        self._plot_requests_per_second_comparison(valid_results)
        self._plot_success_rate_comparison(valid_results)
        self._plot_estimated_attack_time(valid_results)
        self._plot_defense_effectiveness_heatmap(valid_results)
        self._plot_hasher_performance_comparison(valid_results)
        self._plot_attack_outcome_distribution(valid_results)

        print(f"All visualizations saved to: {self.output_dir}")

    def _plot_requests_per_second_comparison(self, results: Dict[str, Any]) -> None:
        """Generate requests per second comparison chart."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        cases = list(results.keys())
        bf_rps = [results[case].get('brute_force_metrics', {}).get('requests_per_second', 0) for case in cases]
        ps_rps = [results[case].get('password_spray_metrics', {}).get('requests_per_second', 0) for case in cases]

        colors = [self.defense_colors.get(results[case]['case_category'], '#888888') for case in cases]

        # Brute Force RPS
        bars1 = ax1.barh(range(len(cases)), bf_rps, color=colors, alpha=0.7)
        ax1.set_yticks(range(len(cases)))
        ax1.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax1.set_xlabel('Requests per Second', fontsize=12)
        ax1.set_title('Brute Force Attack Performance', fontsize=14, fontweight='bold')
        ax1.grid(axis='x', alpha=0.3)

        # Add value labels
        for i, (bar, value) in enumerate(zip(bars1, bf_rps)):
            if value > 0:
                ax1.text(value + max(bf_rps) * 0.01, i, f'{value:.1f}',
                         va='center', fontsize=9)

        # Password Spray RPS
        bars2 = ax2.barh(range(len(cases)), ps_rps, color=colors, alpha=0.7)
        ax2.set_yticks(range(len(cases)))
        ax2.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax2.set_xlabel('Requests per Second', fontsize=12)
        ax2.set_title('Password Spray Attack Performance', fontsize=14, fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)

        # Add value labels
        for i, (bar, value) in enumerate(zip(bars2, ps_rps)):
            if value > 0:
                ax2.text(value + max(ps_rps) * 0.01, i, f'{value:.1f}',
                         va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'requests_per_second_comparison.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    import matplotlib.pyplot as plt
    import numpy as np
    import statistics
    from typing import Dict, Any

    def _plot_latency_p90_comparison(self, results: Dict[str, Any]) -> None:
        """Generates a Bar Plot comparing Median and 90th Percentile latency."""
        plt.figure(figsize=(14, 8))

        cases = []
        medians = []
        p90s = []
        colors = []

        for case_name, case_result in results.items():
            case_p90s = []
            case_medians = []

            # Determine the primary attack data to visualize
            attack_type = 'brute_force' if 'brute_force' in case_result else 'password_spray'

            if attack_type in case_result:
                for target_data in case_result[attack_type].values():
                    if 'latency_p90' in target_data:
                        case_p90s.append(target_data['latency_p90'])
                        case_medians.append(target_data['latency_median'])

            if case_p90s:
                cases.append(case_name.replace('_', ' ').title())
                p90s.append(statistics.mean(case_p90s))
                medians.append(statistics.mean(case_medians))

                # Use your existing color categorization
                category = self._categorize_case(case_name)
                colors.append(self.defense_colors.get(category, '#888888'))

        if not cases:
            return

        y = np.arange(len(cases))
        height = 0.35

        fig, ax = plt.subplots(figsize=(12, 8))

        # Plotting both metrics for distribution comparison
        rects1 = ax.barh(y - height / 2, medians, height, label='Median (P50)', color='#3498db', alpha=0.8)
        rects2 = ax.barh(y + height / 2, p90s, height, label='90th Percentile (P90)', color='#e74c3c', alpha=0.8)

        ax.set_xlabel('Latency (Seconds)')
        ax.set_title('Latency Distribution Analysis: Median vs. P90', fontsize=14, fontweight='bold')
        ax.set_yticks(y)
        ax.set_yticklabels(cases)
        ax.legend()

        # Add data labels
        for i, p in enumerate(p90s):
            ax.text(p, i + height / 2, f' {p:.4f}s', va='center', fontsize=9, color='darkred', fontweight='bold')

        for i, m in enumerate(medians):
            ax.text(m, i - height / 2, f' {m:.4f}s', va='center', fontsize=9, color='darkblue')

        plt.grid(axis='x', linestyle='--', alpha=0.6)
        plt.tight_layout()
        plt.savefig(self.output_dir / 'latency_distribution_p90.png', dpi=300)
        plt.close()

    def _plot_success_rate_comparison(self, results: Dict[str, Any]) -> None:
        """Generate success rate comparison chart."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        cases = list(results.keys())
        bf_success = [results[case].get('brute_force_metrics', {}).get('success_rate', 0) * 100 for case in cases]
        ps_success = [results[case].get('password_spray_metrics', {}).get('success_rate', 0) * 100 for case in cases]

        colors = [self.defense_colors.get(results[case]['case_category'], '#888888') for case in cases]

        # Brute Force Success Rate
        bars1 = ax1.barh(range(len(cases)), bf_success, color=colors, alpha=0.7)
        ax1.set_yticks(range(len(cases)))
        ax1.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax1.set_xlabel('Success Rate (%)', fontsize=12)
        ax1.set_title('Brute Force Attack Success Rate', fontsize=14, fontweight='bold')
        ax1.set_xlim(0, 100)
        ax1.grid(axis='x', alpha=0.3)

        # Add value labels
        for i, (bar, value) in enumerate(zip(bars1, bf_success)):
            ax1.text(value + 1, i, f'{value:.1f}%', va='center', fontsize=9)

        # Password Spray Success Rate
        bars2 = ax2.barh(range(len(cases)), ps_success, color=colors, alpha=0.7)
        ax2.set_yticks(range(len(cases)))
        ax2.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax2.set_xlabel('Success Rate (%)', fontsize=12)
        ax2.set_title('Password Spray Attack Success Rate', fontsize=14, fontweight='bold')
        ax2.set_xlim(0, 100)
        ax2.grid(axis='x', alpha=0.3)

        # Add value labels
        for i, (bar, value) in enumerate(zip(bars2, ps_success)):
            ax2.text(value + 1, i, f'{value:.1f}%', va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'success_rate_comparison.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_estimated_attack_time(self, results: Dict[str, Any]) -> None:
        """Generate estimated attack time visualization."""
        fig, ax = plt.subplots(1, 1, figsize=(14, 10))

        cases = []
        times_hours = []
        colors_list = []

        for case_name, case_result in results.items():
            bf_metrics = case_result.get('brute_force_metrics', {})
            time_hours = bf_metrics.get('estimated_success_time_hours')

            if time_hours is not None and time_hours > 0:
                cases.append(case_name)
                times_hours.append(time_hours)
                colors_list.append(self.defense_colors.get(case_result['case_category'], '#888888'))

        if not cases:
            return

        # Use log scale for better visualization of large time differences
        bars = ax.barh(range(len(cases)), times_hours, color=colors_list, alpha=0.7)
        ax.set_yscale('linear')
        ax.set_xscale('log')
        ax.set_yticks(range(len(cases)))
        ax.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax.set_xlabel('Estimated Time to Success (Hours, Log Scale)', fontsize=12)
        ax.set_title('Theoretical Brute Force Attack Time (Weak Passwords)',
                     fontsize=14, fontweight='bold')
        ax.grid(axis='x', alpha=0.3)

        # Add time labels with appropriate units
        for i, (bar, time_h) in enumerate(zip(bars, times_hours)):
            if time_h < 1:
                label = f'{time_h * 60:.1f} min'
            elif time_h < 24:
                label = f'{time_h:.1f} h'
            elif time_h < 8760:  # Less than a year
                label = f'{time_h / 24:.1f} days'
            else:
                label = f'{time_h / 8760:.1f} years'

            ax.text(time_h * 1.1, i, label, va='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'estimated_attack_time.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_defense_effectiveness_heatmap(self, results: Dict[str, Any]) -> None:
        """Generate defense effectiveness heatmap."""
        # Prepare data for heatmap
        defense_categories = ['baseline', 'mfa', 'rate_limit', 'account_lockout', 'captcha', 'combination',
                              'comprehensive']
        metrics = ['Brute Force Success Rate', 'Password Spray Success Rate', 'Brute Force RPS', 'Password Spray RPS']

        # Create matrix
        data_matrix = []
        case_labels = []

        for category in defense_categories:
            category_cases = [case for case, result in results.items()
                              if result.get('case_category') == category]

            if not category_cases:
                continue

            # Average metrics for this category
            bf_success_avg = np.mean([results[case].get('brute_force_metrics', {}).get('success_rate', 0) * 100
                                      for case in category_cases])
            ps_success_avg = np.mean([results[case].get('password_spray_metrics', {}).get('success_rate', 0) * 100
                                      for case in category_cases])
            bf_rps_avg = np.mean([results[case].get('brute_force_metrics', {}).get('requests_per_second', 0)
                                  for case in category_cases])
            ps_rps_avg = np.mean([results[case].get('password_spray_metrics', {}).get('requests_per_second', 0)
                                  for case in category_cases])

            data_matrix.append([bf_success_avg, ps_success_avg, bf_rps_avg, ps_rps_avg])
            case_labels.append(category.replace('_', ' ').title())

        if not data_matrix:
            return

        # Normalize data for better visualization (0-100 scale)
        data_array = np.array(data_matrix)
        normalized_data = np.zeros_like(data_array)

        for i in range(data_array.shape[1]):
            col_max = np.max(data_array[:, i])
            if col_max > 0:
                normalized_data[:, i] = (data_array[:, i] / col_max) * 100

        # Create heatmap
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        im = ax.imshow(normalized_data, cmap='RdYlGn_r', aspect='auto', vmin=0, vmax=100)

        # Set ticks and labels
        ax.set_xticks(range(len(metrics)))
        ax.set_xticklabels(metrics, rotation=45, ha='right')
        ax.set_yticks(range(len(case_labels)))
        ax.set_yticklabels(case_labels)

        # Add text annotations with actual values
        for i in range(len(case_labels)):
            for j in range(len(metrics)):
                if j < 2:  # Success rates
                    text = f'{data_array[i, j]:.1f}%'
                else:  # RPS
                    text = f'{data_array[i, j]:.1f}'
                ax.text(j, i, text, ha='center', va='center',
                        color='white' if normalized_data[i, j] > 50 else 'black',
                        fontweight='bold', fontsize=10)

        ax.set_title('Defense Effectiveness Heatmap\n(Higher values indicate less effective defense)',
                     fontsize=14, fontweight='bold')

        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        cbar.set_label('Normalized Performance (0-100)', fontsize=12)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'defense_effectiveness_heatmap.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_hasher_performance_comparison(self, results: Dict[str, Any]) -> None:
        """Generate hasher performance comparison."""
        hasher_data = {}

        for case_name, case_result in results.items():
            if 'hasher' not in case_result:
                continue

            hasher_type = str(case_result['hasher'].hasher_type).split('.')[-1]  # Get enum name

            if hasher_type not in hasher_data:
                hasher_data[hasher_type] = {
                    'bf_rps': [],
                    'ps_rps': [],
                    'bf_success': [],
                    'ps_success': []
                }

            bf_metrics = case_result.get('brute_force_metrics', {})
            ps_metrics = case_result.get('password_spray_metrics', {})

            hasher_data[hasher_type]['bf_rps'].append(bf_metrics.get('requests_per_second', 0))
            hasher_data[hasher_type]['ps_rps'].append(ps_metrics.get('requests_per_second', 0))
            hasher_data[hasher_type]['bf_success'].append(bf_metrics.get('success_rate', 0) * 100)
            hasher_data[hasher_type]['ps_success'].append(ps_metrics.get('success_rate', 0) * 100)

        if not hasher_data:
            return

        # Create subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))

        hashers = list(hasher_data.keys())
        positions = range(len(hashers))
        colors = [self.hasher_colors.get(h, '#888888') for h in hashers]

        # Brute Force RPS
        bf_rps_avg = [np.mean(hasher_data[h]['bf_rps']) for h in hashers]
        bf_rps_std = [np.std(hasher_data[h]['bf_rps']) for h in hashers]
        ax1.bar(positions, bf_rps_avg, yerr=bf_rps_std, color=colors, alpha=0.7, capsize=5)
        ax1.set_xticks(positions)
        ax1.set_xticklabels(hashers)
        ax1.set_ylabel('Requests per Second')
        ax1.set_title('Brute Force Performance by Hasher', fontweight='bold')
        ax1.grid(axis='y', alpha=0.3)

        # Password Spray RPS
        ps_rps_avg = [np.mean(hasher_data[h]['ps_rps']) for h in hashers]
        ps_rps_std = [np.std(hasher_data[h]['ps_rps']) for h in hashers]
        ax2.bar(positions, ps_rps_avg, yerr=ps_rps_std, color=colors, alpha=0.7, capsize=5)
        ax2.set_xticks(positions)
        ax2.set_xticklabels(hashers)
        ax2.set_ylabel('Requests per Second')
        ax2.set_title('Password Spray Performance by Hasher', fontweight='bold')
        ax2.grid(axis='y', alpha=0.3)

        # Success rates
        bf_success_avg = [np.mean(hasher_data[h]['bf_success']) for h in hashers]
        bf_success_std = [np.std(hasher_data[h]['bf_success']) for h in hashers]
        ax3.bar(positions, bf_success_avg, yerr=bf_success_std, color=colors, alpha=0.7, capsize=5)
        ax3.set_xticks(positions)
        ax3.set_xticklabels(hashers)
        ax3.set_ylabel('Success Rate (%)')
        ax3.set_title('Brute Force Success Rate by Hasher', fontweight='bold')
        ax3.set_ylim(0, 100)
        ax3.grid(axis='y', alpha=0.3)

        ps_success_avg = [np.mean(hasher_data[h]['ps_success']) for h in hashers]
        ps_success_std = [np.std(hasher_data[h]['ps_success']) for h in hashers]
        ax4.bar(positions, ps_success_avg, yerr=ps_success_std, color=colors, alpha=0.7, capsize=5)
        ax4.set_xticks(positions)
        ax4.set_xticklabels(hashers)
        ax4.set_ylabel('Success Rate (%)')
        ax4.set_title('Password Spray Success Rate by Hasher', fontweight='bold')
        ax4.set_ylim(0, 100)
        ax4.grid(axis='y', alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'hasher_performance_comparison.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_attack_outcome_distribution(self, results: Dict[str, Any]) -> None:
        """Generate attack outcome distribution charts."""
        all_outcomes = set()
        case_outcomes = {}

        for case_name, case_result in results.items():
            case_outcomes[case_name] = {}

            if 'brute_force' in case_result:
                for target_results in case_result['brute_force'].values():
                    for outcome, count in target_results.items():
                        # Skip latency list to avoid TypeError during summation
                        if outcome == 'latencies':
                            continue

                        all_outcomes.add(outcome)
                        case_outcomes[case_name][outcome] = case_outcomes[case_name].get(outcome, 0) + count

        outcomes_list = sorted(list(all_outcomes))

        if len(outcomes_list) <= 1:
            return

        fig, ax = plt.subplots(1, 1, figsize=(16, 10))
        cases = list(case_outcomes.keys())
        bottom = np.zeros(len(cases))

        outcome_colors = {
            'SUCCESS': '#ff4444',
            'INVALID_CREDENTIALS': '#ffaa44',
            'MFA': '#44ff44',
            'RATE_LIMIT': '#4444ff',
            'ACCOUNT_LOCKOUT': '#ff44ff',
            'CAPTCHA': '#44ffff',
            'USERNAME_NOT_FOUND': '#888888',
            'INTERNAL_SERVER_ERROR': '#000000'
        }

        for outcome in outcomes_list:
            values = [case_outcomes[case].get(outcome, 0) for case in cases]
            color = outcome_colors.get(outcome, '#cccccc')

            ax.barh(range(len(cases)), values, left=bottom,
                    label=outcome.replace('_', ' ').title(),
                    color=color, alpha=0.8)
            bottom += values

        ax.set_yticks(range(len(cases)))
        ax.set_yticklabels([case.replace('_', ' ').title() for case in cases], fontsize=10)
        ax.set_xlabel('Number of Attempts', fontsize=12)
        ax.set_title('Attack Outcome Distribution (Brute Force)', fontsize=14, fontweight='bold')
        ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        ax.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'attack_outcome_distribution.png',
                    dpi=300, bbox_inches='tight')
        plt.close()

    def generate_summary_report(self, enhanced_results: Dict[str, Any]) -> None:
        """
        Generate a text summary report of key findings.
        
        Args:
            enhanced_results: Processed results with calculated metrics
        """
        report_path = self.output_dir / 'experiment_summary.txt'

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("PASSWORD SECURITY EXPERIMENT SUMMARY REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Overall statistics
            valid_results = {k: v for k, v in enhanced_results.items() if 'error' not in v}
            f.write(f"Total test cases: {len(enhanced_results)}\n")
            f.write(f"Successful cases: {len(valid_results)}\n")
            f.write(f"Failed cases: {len(enhanced_results) - len(valid_results)}\n\n")

            # Password analysis
            f.write("PASSWORD STRENGTH ANALYSIS\n")
            f.write("-" * 30 + "\n")
            f.write(f"Weak passwords (n={len(self.password_analysis.weak_passwords)}): "
                    f"{self.password_analysis.theoretical_keyspace['weak']:,} possible combinations\n")
            f.write(f"Medium passwords (n={len(self.password_analysis.medium_passwords)}): "
                    f"{self.password_analysis.theoretical_keyspace['medium']:,} possible combinations\n")
            f.write(f"Strong passwords (n={len(self.password_analysis.strong_passwords)}): "
                    f"{self.password_analysis.theoretical_keyspace['strong']:,} possible combinations\n\n")

            # Top performers
            if valid_results:
                # Most effective defense (lowest success rate)
                bf_success_rates = [(case, result.get('brute_force_metrics', {}).get('success_rate', 1))
                                    for case, result in valid_results.items()]
                bf_success_rates.sort(key=lambda x: x[1])

                f.write("MOST EFFECTIVE DEFENSES (Brute Force)\n")
                f.write("-" * 40 + "\n")
                for case, rate in bf_success_rates[:3]:
                    f.write(f"{case}: {rate * 100:.1f}% success rate\n")
                f.write("\n")

                # Fastest attacks (highest RPS)
                bf_rps = [(case, result.get('brute_force_metrics', {}).get('requests_per_second', 0))
                          for case, result in valid_results.items()]
                bf_rps.sort(key=lambda x: x[1], reverse=True)

                f.write("FASTEST ATTACK SCENARIOS (Requests/Second)\n")
                f.write("-" * 45 + "\n")
                for case, rps in bf_rps[:3]:
                    f.write(f"{case}: {rps:.1f} requests/second\n")
                f.write("\n")

        print(f"Summary report saved to: {report_path}")


def run_postprocessing(results: Dict[str, Any], users: List[Dict[str, Any]],
                       password_config: Any, output_dir: str = "results") -> Dict[str, Any]:
    """
    Main entry point for results postprocessing.
    
    Args:
        results: Raw experiment results
        users: User account data
        password_config: Password generation configuration
        output_dir: Output directory for results and visualizations
        
    Returns:
        Enhanced results dictionary with calculated metrics
    """
    print("Starting postprocessing...")

    processor = ResultsPostprocessor(results, users, password_config, output_dir)

    # Process results and calculate metrics
    enhanced_results = processor.process_results()

    # Save enhanced results
    processor.save_results(enhanced_results)

    # Generate visualizations
    processor.generate_visualizations(enhanced_results)

    # Generate summary report
    processor.generate_summary_report(enhanced_results)

    print("Postprocessing completed!")
    return enhanced_results
