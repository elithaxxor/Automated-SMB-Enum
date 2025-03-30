import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from plotly.subplots import make_subplots
import base64
from io import BytesIO
import ipaddress
import asyncio
import aiofiles
import re


class NetworkDataProcessor:
    """
    Processes network reconnaissance data for visualization and analysis.
    """
    def __init__(self, results_dir: str = "recon_results"):
        self.results_dir = results_dir
        self.data = {}
        self.metrics = {}

    async def load_scan_results(self, target: str, scan_types: Optional[List[str]] = None) -> Dict:
        """
        Load scan results for the specified target.
        
        :param target: The target IP address or domain to load results for.
        :param scan_types: Optional list of scan types to filter by.
        :return: A dictionary containing the loaded scan data.
        """
        result_files = []

        # Find all result files for the target
        for filename in os.listdir(self.results_dir):
            if target in filename and filename.endswith('.json'):
                # Filter by scan type if specified
                if scan_types:
                    if any(scan_type in filename for scan_type in scan_types):
                        result_files.append(os.path.join(self.results_dir, filename))
                else:
                    result_files.append(os.path.join(self.results_dir, filename))

        # Process each result file
        for file_path in result_files:
            try:
                async with aiofiles.open(file_path, 'r') as f:
                    content = await f.read()
                    result_data = json.loads(content)

                    # Extract scan type from filename
                    scan_type = os.path.basename(file_path).split('_')[0]
                    if scan_type not in self.data:
                        self.data[scan_type] = {}

                    self.data[scan_type][target] = result_data
            except Exception as e:
                print(f"Error loading {file_path}: {str(e)}")

        return self.data

    def extract_metrics(self) -> Dict:
        """
        Extract key metrics from loaded scan data.
        
        :return: A dictionary containing the extracted metrics.
        """
        self.metrics = {
            'ports': {},            # Open ports by target
            'services': {},         # Services by target
            'vulnerabilities': {},  # Vulnerabilities by target
            'response_times': {},   # Response times by target
            'subdomains': {},       # Subdomains by target
            'traceroute_hops': {},  # Traceroute hop counts by target
            'security_score': {}    # Calculated security score (lower is better)
        }

        # Process each scan type and target
        for scan_type, targets in self.data.items():
            for target, data in targets.items():
                # Initialize target metrics if not exist
                if target not in self.metrics['ports']:
                    self.metrics['ports'][target] = []
                if target not in self.metrics['services']:
                    self.metrics['services'][target] = []
                if target not in self.metrics['vulnerabilities']:
                    self.metrics['vulnerabilities'][target] = []
                if target not in self.metrics['response_times']:
                    self.metrics['response_times'][target] = None
                if target not in self.metrics['subdomains']:
                    self.metrics['subdomains'][target] = []
                if target not in self.metrics['traceroute_hops']:
                    self.metrics['traceroute_hops'][target] = 0

                # Process SMB info
                if 'smb_info' in data:
                    # Extract vulnerabilities
                    if 'vulnerabilities' in data['smb_info']:
                        self.metrics['vulnerabilities'][target].extend(data['smb_info']['vulnerabilities'])

                    # Extract open ports from shares
                    if 'shares' in data['smb_info']:
                        self.metrics['ports'][target].append(445)  # SMB port

                # Process scan results
                if 'scan_results' in data:
                    for scanner, scan_result in data['scan_results'].items():
                        # Extract from Nmap scans
                        if 'nmap' in scanner.lower() and 'output' in scan_result:
                            self._extract_nmap_metrics(target, scan_result['output'])

                        # Extract from ping
                        if scanner.lower() == 'ping' and 'output' in scan_result:
                            self._extract_ping_metrics(target, scan_result['output'])

                        # Extract from traceroute
                        if scanner.lower() == 'traceroute' and 'output' in scan_result:
                            self._extract_traceroute_metrics(target, scan_result['output'])

                        # Extract from sublist3r
                        if scanner.lower() == 'sublist3r' and 'output_file' in scan_result:
                            self._extract_subdomain_metrics(target, scan_result['output_file'])

        # Calculate security score
        self._calculate_security_scores()

        return self.metrics

    def _extract_nmap_metrics(self, target: str, output: str) -> None:
        """
        Extract metrics from Nmap output.
        
        :param target: The target IP address or domain.
        :param output: The Nmap scan output.
        """
        if not output:
            return

        # Extract open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)?'
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            service = match.group(2) if match.group(2) else "unknown"

            if port not in self.metrics['ports'][target]:
                self.metrics['ports'][target].append(port)

            service_entry = {"port": port, "name": service}
            if service_entry not in self.metrics['services'][target]:
                self.metrics['services'][target].append(service_entry)

        # Extract vulnerabilities
        if "VULNERABLE" in output:
            for line in output.splitlines():
                if "VULNERABLE" in line:
                    vuln_name = line.strip()
                    if vuln_name not in self.metrics['vulnerabilities'][target]:
                        self.metrics['vulnerabilities'][target].append(vuln_name)

    def _extract_ping_metrics(self, target: str, output: str) -> None:
        """
        Extract metrics from ping output.
        
        :param target: The target IP address or domain.
        :param output: The ping scan output.
        """
        if not output:
            return

        # Extract average response time
        avg_match = re.search(r'= [^/]*/([^/]*)/[^/]*/[^/]*\s', output)
        if avg_match:
            try:
                avg_time = float(avg_match.group(1))
                self.metrics['response_times'][target] = avg_time
            except (ValueError, TypeError):
                pass

    def _extract_traceroute_metrics(self, target: str, output: str) -> None:
        """
        Extract metrics from traceroute output.
        
        :param target: The target IP address or domain.
        :param output: The traceroute scan output.
        """
        if not output:
            return

        # Count the number of hops
        hop_count = output.count('Hop #')
        if hop_count > 0:
            self.metrics['traceroute_hops'][target] = hop_count

    def _extract_subdomain_metrics(self, target: str, output_file: str) -> None:
        """
        Extract metrics from Sublist3r output file.
        
        :param target: The target IP address or domain.
        :param output_file: The path to the Sublist3r output file.
        """
        if not output_file or not os.path.exists(output_file):
            return

        try:
            with open(output_file, 'r') as f:
                content = f.read()
                subdomains = [line.strip() for line in content.splitlines() if line.strip()]
                self.metrics['subdomains'][target].extend(subdomains)
        except Exception as e:
            print(f"Error reading subdomains file: {str(e)}")

    def _calculate_security_scores(self) -> None:
        """
        Calculate security scores based on vulnerabilities and open ports.
        """
        for target in self.metrics['ports'].keys():
            # Start with a baseline score
            score = 100

            # Subtract for each vulnerability (high impact)
            vuln_count = len(self.metrics['vulnerabilities'][target])
            score -= vuln_count * 15

            # Subtract for each open port (medium impact)
            port_count = len(self.metrics['ports'][target])
            score -= port_count * 5

            # Subtract for certain high-risk ports if open
            high_risk_ports = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
            for port in high_risk_ports:
                if port in self.metrics['ports'][target]:
                    score -= 3

            # Ensure score doesn't go below 0
            score = max(0, score)

            self.metrics['security_score'][target] = score

    def prepare_data_for_regression(self) -> Tuple[pd.DataFrame, List[str]]:
        """
        Prepare metrics data for regression analysis.
        
        :return: A tuple containing the DataFrame and list of features.
        """
        # Create a list of dictionaries for each target
        data_list = []

        for target in self.metrics['ports'].keys():
            target_data = {
                'target': target,
                'ports_open': len(self.metrics['ports'][target]),
                'vulns_found': len(self.metrics['vulnerabilities'][target]),
                'response_time': self.metrics['response_times'][target] or 0,
                'traceroute_hops': self.metrics['traceroute_hops'][target],
                'subdomain_count': len(self.metrics['subdomains'][target]),
                'security_score': self.metrics['security_score'][target]
            }
            data_list.append(target_data)

        # Convert to DataFrame
        df = pd.DataFrame(data_list)

        # List of features for regression
        features = ['ports_open', 'vulns_found', 'response_time', 'traceroute_hops', 'subdomain_count']

        return df, features


class RegressionAnalyzer:
    """
    Performs regression analysis on network scan metrics.
    """
    def __init__(self, data: pd.DataFrame, features: List[str], target_col: str = 'security_score'):
        self.data = data
        self.features = features
        self.target_col = target_col
        self.model = LinearRegression()
        self.coefficients = {}
        self.mse = 0
        self.r2 = 0

    def perform_regression(self) -> Dict:
        """
        Perform regression analysis on the data.
        
        :return: A dictionary containing the regression results.
        """
        if len(self.data) < 2:
            print("Insufficient data for regression analysis. Need at least 2 samples.")
            return None

        # Prepare data
        X = self.data[self.features]
        y = self.data[self.target_col]

        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Fit model
        self.model.fit(X_scaled, y)

        # Make predictions
        y_pred = self.model.predict(X_scaled)

        # Calculate metrics
        self.mse = mean_squared_error(y, y_pred)
        self.r2 = r2_score(y, y_pred)

        # Store coefficients
        for i, feature in enumerate(self.features):
            self.coefficients[feature] = self.model.coef_[i]

        # Prepare results
        results = {
            'coefficients': self.coefficients,
            'mse': self.mse,
            'r2': self.r2,
            'importance': sorted([(feat, abs(coef)) for feat, coef in self.coefficients.items()], 
                                key=lambda x: x[1], reverse=True)
        }

        return results


class NetworkVisualizer:
    """
    Creates visual representations of network reconnaissance data.
    """
    def __init__(self, metrics: Dict, output_dir: str = "visual_reports"):
        self.metrics = metrics
        self.output_dir = output_dir
        self.report_data = {}

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

    def create_open_ports_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """
        Create a bar chart showing open ports by target.
        
        :param targets: Optional list of targets to include in the chart.
        :return: A dictionary containing details about the generated chart.
        """
        if not targets:
            targets = list(self.metrics['ports'].keys())

        # Count open ports for each target
        port_counts = {target: len(ports) for target, ports in self.metrics['ports'].items() if target in targets}

        # Sort data for better visualization
        sorted_items = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]

        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color='cornflowerblue'
        ))

        fig.update_layout(
            title="Open Ports by Target",
            xaxis_title="Target",
            yaxis_title="Number of Open Ports",
            template="plotly_white"
        )

        # Save to output directory
        output_file = os.path.join(self.output_dir, "open_ports_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b
