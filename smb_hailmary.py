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
    Processes network reconnaissance data for visualization and analysis
    """
    def __init__(self, results_dir: str = "recon_results"):
        self.results_dir = results_dir
        self.data = {}
        self.metrics = {}
        
    async def load_scan_results(self, target: str, scan_types: Optional[List[str]] = None) -> Dict:
        """Load scan results for the specified target"""
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
        """Extract key metrics from loaded scan data"""
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
        """Extract metrics from Nmap output"""
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
        """Extract metrics from ping output"""
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
        """Extract metrics from traceroute output"""
        if not output:
            return
            
        # Count the number of hops
        hop_count = output.count('Hop #')
        if hop_count > 0:
            self.metrics['traceroute_hops'][target] = hop_count
    
    def _extract_subdomain_metrics(self, target: str, output_file: str) -> None:
        """Extract metrics from Sublist3r output file"""
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
        """Calculate security scores based on vulnerabilities and open ports"""
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
        """Prepare metrics data for regression analysis"""
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
    Performs regression analysis on network scan metrics
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
        """Perform regression analysis on the data"""
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
    Creates visual representations of network reconnaissance data
    """
    def __init__(self, metrics: Dict, output_dir: str = "visual_reports"):
        self.metrics = metrics
        self.output_dir = output_dir
        self.report_data = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
    
    def create_open_ports_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a bar chart showing open ports by target"""
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
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Open Ports by Target'
        }
        
        self.report_data['open_ports_chart'] = result
        return result
    
    def create_vulnerability_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a bar chart showing vulnerabilities by target"""
        if not targets:
            targets = list(self.metrics['vulnerabilities'].keys())
        
        # Count vulnerabilities for each target
        vuln_counts = {target: len(vulns) for target, vulns in self.metrics['vulnerabilities'].items() if target in targets}
        
        # Create color scale based on severity (more vulnerabilities = more severe)
        max_vulns = max(vuln_counts.values()) if vuln_counts else 1
        colors = [f'rgba(255, {max(0, 255 - int(255 * count / max_vulns))}, 0, 0.7)' for count in vuln_counts.values()]
        
        # Sort data for better visualization
        sorted_items = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color=colors
        ))
        
        fig.update_layout(
            title="Vulnerabilities by Target",
            xaxis_title="Target",
            yaxis_title="Number of Vulnerabilities",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "vulnerability_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Vulnerabilities by Target'
        }
        
        self.report_data['vulnerability_chart'] = result
        return result
    
    def create_security_score_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a gauge chart showing security scores by target"""
        if not targets:
            targets = list(self.metrics['security_score'].keys())
        
        # Get security scores for each target
        scores = {target: score for target, score in self.metrics['security_score'].items() if target in targets}
        
        # Create subplots for each target
        fig = make_subplots(
            rows=1, 
            cols=len(scores),
            specs=[[{"type": "indicator"} for _ in range(len(scores))]],
            subplot_titles=list(scores.keys())
        )
        
        # Add a gauge for each target
        for i, (target, score) in enumerate(scores.items(), 1):
            # Determine color based on score
            if score >= 80:
                color = "green"
            elif score >= 60:
                color = "yellow"
            elif score >= 40:
                color = "orange"
            else:
                color = "red"
                
            fig.add_trace(
                go.Indicator(
                    mode="gauge+number",
                    value=score,
                    domain={'row': 0, 'column': i-1},
                    title={'text': f"{target}"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': color},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgray"},
                            {'range': [40, 60], 'color': "gray"},
                            {'range': [60, 80], 'color': "lightgray"},
                            {'range': [80, 100], 'color': "white"}
                        ]
                    }
                ),
                row=1, col=i
            )
        
        fig.update_layout(
            title_text="Security Scores by Target (Higher is Better)",
            height=400,
            width=250 * len(scores)
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "security_score_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'gauge',
            'title': 'Security Scores by Target'
        }
        
        self.report_data['security_score_chart'] = result
        return result
    
    def create_ports_heatmap(self, targets: Optional[List[str]] = None, max_ports: int = 20) -> Dict:
        """Create a heatmap showing common open ports across targets"""
        if not targets:
            targets = list(self.metrics['ports'].keys())
        
        # Get all unique ports across all targets
        all_ports = set()
        for target in targets:
            if target in self.metrics['ports']:
                all_ports.update(self.metrics['ports'][target])
        
        # Sort ports and limit to max_ports most common
        port_frequency = {}
        for port in all_ports:
            port_frequency[port] = sum(1 for target in targets if target in self.metrics['ports'] and port in self.metrics['ports'][target])
        
        common_ports = sorted(port_frequency.items(), key=lambda x: x[1], reverse=True)[:max_ports]
        common_ports = [item[0] for item in common_ports]
        
        # Create matrix for heatmap
        heatmap_data = []
        for target in targets:
            target_data = []
            for port in common_ports:
                if target in self.metrics['ports'] and port in self.metrics['ports'][target]:
                    target_data.append(1)  # Port is open
                else:
                    target_data.append(0)  # Port is closed
            heatmap_data.append(target_data)
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data,
            x=common_ports,
            y=targets,
            colorscale='Reds',
            showscale=True
        ))
        
        fig.update_layout(
            title="Open Ports Across Targets",
            xaxis_title="Port Number",
            yaxis_title="Target",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "ports_heatmap.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'heatmap',
            'title': 'Open Ports Across Targets'
        }
        
        self.report_data['ports_heatmap'] = result
        return result
    
    def create_response_time_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a line chart showing response times by target"""
        if not targets:
            targets = list(self.metrics['response_times'].keys())
        
        # Filter targets with response times
        response_times = {target: time for target, time in self.metrics['response_times'].items() 
                         if target in targets and time is not None}
        
        if not response_times:
            print("No response time data available")
            return None
        
        # Sort data for better visualization
        sorted_items = sorted(response_times.items(), key=lambda x: x[1])
        sorted_targets = [item[0] for item in sorted_items]
        sorted_times = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_times,
            marker_color='lightgreen'
        ))
        
        fig.update_layout(
            title="Response Times by Target",
            xaxis_title="Target",
            yaxis_title="Response Time (ms)",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "response_time_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Response Times by Target'
        }
        
        self.report_data['response_time_chart'] = result
        return result
    
    def create_regression_chart(self, regression_results: Dict, feature_data: pd.DataFrame) -> Dict:
        """Create a chart visualizing regression analysis results"""
        if not regression_results or 'coefficients' not in regression_results:
            print("No regression results available")
            return None
        
        # Get coefficients and sort by absolute value
        coefficients = regression_results['coefficients']
        sorted_coefs = sorted(coefficients.items(), key=lambda x: abs(x[1]), reverse=True)
        
        features = [item[0] for item in sorted_coefs]
        coef_values = [item[1] for item in sorted_coefs]
        
        # Create color map based on coefficient sign
        colors = ['red' if c < 0 else 'green' for c in coef_values]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=features,
            y=coef_values,
            marker_color=colors
        ))
        
        fig.update_layout(
            title=f"Feature Importance for Security Score (R² = {regression_results['r2']:.2f})",
            xaxis_title="Feature",
            yaxis_title="Coefficient",
            template="plotly_white"
        )
        
        # Add annotation explaining the meaning
        fig.add_annotation(
            x=0.5, y=-0.15,
            xref="paper", yref="paper",
            text="Green bars show positive impact on security score, red bars show negative impact",
            showarrow=False,
            font=dict(size=10)
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "regression_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Regression Analysis Results',
            'r2': regression_results['r2'],
            'mse': regression_results['mse']
        }
        
        self.report_data['regression_chart'] = result
        return result
    
    def create_subdomain_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing subdomains by target"""
        if not targets:
            targets = list(self.metrics['subdomains'].keys())
        
        # Count subdomains for each target
        subdomain_counts = {target: len(subdomains) for target, subdomains in self.metrics['subdomains'].items() 
                          if target in targets and subdomains}
        
        if not subdomain_counts:
            print("No subdomain data available")
            return None
        
        # Sort data for better visualization
        sorted_items = sorted(subdomain_counts.items(), key=lambda x: x[1], reverse=True)
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color='purple'
        ))
        
        fig.update_layout(
            title="Subdomains by Target",
            xaxis_title="Target",
            yaxis_title="Number of Subdomains",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "subdomain_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Subdomains by Target'
        }
        
        self.report_data['subdomain_chart'] = result
        return result
    
    def create_traceroute_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing traceroute hop counts by target"""
        if not targets:
            targets = list(self.metrics['traceroute_hops'].keys())
        
        # Get hop counts for each target
        hop_counts = {target: hops for target, hops in self.metrics['traceroute_hops'].items() 
                     if target in targets and hops > 0}
        
        if not hop_counts:
            print("No traceroute data available")
            return None
        
        # Sort data for better visualization
        sorted_items = sorted(hop_counts.items(), key=lambda x: x[1])
        sorted_targets = [item[0] for item in sorted_items]
        sorted_counts = [item[1] for item in sorted_items]
        
        # Create bar chart
        fig = go.Figure(go.Bar(
            x=sorted_targets,
            y=sorted_counts,
            marker_color='teal'
        ))
        
        fig.update_layout(
            title="Network Distance (Hop Count) by Target",
            xaxis_title="Target",
            yaxis_title="Number of Hops",
            template="plotly_white"
        )
        
        # Save to output directory
        output_file = os.path.join(self.output_dir, "traceroute_chart.html")
        pio.write_html(fig, file=output_file, auto_open=False)
        
        # Convert to base64 for embedding in reports
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode('utf-8')
        
        result = {
            'html_file': output_file,
            'base64_image': img_base64,
            'chart_type': 'bar',
            'title': 'Network Distance by Target'
        }
        
        self.report_data['traceroute_chart'] = result
        return result
    
    def generate_all_charts(self, targets: Optional[List[str]] = None) -> Dict:
        """Generate all available charts for the given targets"""
        self.create_open_ports_chart(targets)
        self.create_vulnerability_chart(targets)
        self.create_security_score_chart(targets)
        self.create_ports_heatmap(targets)
        self.create_response_time_chart(targets)
        self.create_subdomain_chart(targets)
        self.create_traceroute_chart(targets)
        
        return self.report_data


class HTMLReportGenerator:
    """
    Generates HTML reports from network reconnaissance data and visualizations
    """
    def __init__(self, metrics: Dict, charts: Dict, regression_results: Optional[Dict] = None):
        self.metrics = metrics
        self.charts = charts
        self.regression_results = regression_results
    
    def generate_html_report(self, output_file: str, title: str = "Network Reconnaissance Report") -> str:
        """Generate a comprehensive HTML report with all charts and data"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        .chart-container {{
            margin: 20px 0;
            text-align: center;
        }}
        .chart-container img {{
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .footer {{
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }}
        .alert {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .alert-danger {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }}
        .alert-warning {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
        }}
        .alert-success {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Executive Summary</h2>
        {self._generate_executive_summary()}
        
        <h2>Security Scores</h2>
        {self._generate_security_score_section()}
        
        <h2>Vulnerability Analysis</h2>
        {self._generate_vulnerability_section()}
        
        <h2>Network Analysis</h2>
        {self._generate_network_section()}
        
        <h2>Open Ports Analysis</h2>
        {self._generate_ports_section()}
        
        <h2>OSINT Data</h2>
        {self._generate_osint_section()}
        
        <h2>Statistical Analysis</h2>
        {self._generate_regression_section()}
        
        <div class="footer">
            <p>This report was automatically generated by the Network Reconnaissance and Vulnerability Assessment Tool</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html)
        
        return output_file
    
    def _generate_executive_summary(self) -> str:
        """Generate the executive summary section"""
        # Count the total number of targets
        target_count = len(self.metrics['security_score'])
        
        # Count total vulnerabilities
        total_vulns = sum(len(vulns) for vulns in self.metrics['vulnerabilities'].values())
        
        # Get average security score
        avg_score = sum(self.metrics['security_score'].values()) / target_count if target_count > 0 else 0
        
        # Determine overall risk level
        if avg_score >= 90:
            risk_level = '<span style="color:green">Low Risk</span>'
            alert_class = 'alert-success'
        elif avg_score >= 70:
            risk_level = '<span style="color:#FFA500">Moderate Risk</span>'
            alert_class = 'alert-warning'
        elif avg_score >= 50:
            risk_level = '<span style="color:orange">Significant Risk</span>'
            alert_class = 'alert-warning'
        else:
            risk_level = '<span style="color:red">High Risk</span>'
            alert_class = 'alert-danger'
        
        # Find most vulnerable target
        most_vulnerable_target = None
        lowest_score = 101  # Scores are 0-100
        
        for target, score in self.metrics['security_score'].items():
            if score < lowest_score:
                lowest_score = score
                most_vulnerable_target = target
        
        html = f"""
        <div class="alert {alert_class}">
            <strong>Overall Risk Assessment: {risk_level}</strong>
            <p>Average Security Score: {avg_score:.1f}/100</p>
        </div>
        
        <p>This report analyzed <strong>{target_count}</strong> targets and found a total of <strong>{total_vulns}</strong> potential vulnerabilities.</p>
        
        {'<p>The most vulnerable target is <strong>' + most_vulnerable_target + '</strong> with a security score of <strong>' + str(lowest_score) + '/100</strong>.</p>' if most_vulnerable_target else ''}
        
        <p>Key findings:</p>
        <ul>
            <li>{'<span style="color:red"><strong>' + str(total_vulns) + '</strong> potential vulnerabilities were identified</span>' if total_vulns > 0 else 'No vulnerabilities were identified'}</li>
            <li>Average network response time: {self._calculate_avg_response_time():.2f} ms</li>
            <li>Most common open ports: {', '.join(map(str, self._get_most_common_ports(5)))}</li>
        </ul>
        """
        
        return html
    
    def _generate_security_score_section(self) -> str:
        """Generate the security score section"""
        html = ""
        
        # Add security score chart if available
        if 'security_score_chart' in self.charts and self.charts['security_score_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['security_score_chart']['base64_image']}" alt="Security Scores Chart">
                <p>Security scores across all targets. Higher scores indicate better security.</p>
            </div>
            """
        
        # Add security score table
        html += """
        <table>
            <tr>
                <th>Target</th>
                <th>Security Score</th>
                <th>Risk Level</th>
            </tr>
        """
        
        for target, score in sorted(self.metrics['security_score'].items(), key=lambda x: x[1]):
            # Determine risk level
            if score >= 90:
                risk_level = '<span style="color:green">Low Risk</span>'
            elif score >= 70:
                risk_level = '<span style="color:#FFA500">Moderate Risk</span>'
            elif score >= 50:
                risk_level = '<span style="color:orange">Significant Risk</span>'
            else:
                risk_level = '<span style="color:red">High Risk</span>'
            
            html += f"""
            <tr>
                <td>{target}</td>
                <td>{score}/100</td>
                <td>{risk_level}</td>
            </tr>
            """
        
        html += """
        </table>
        
        <p><strong>Note:</strong> Security scores are calculated based on the number of open ports, detected vulnerabilities, and other security factors. Higher scores indicate better security posture.</p>
        """
        
        return html
    
    def _generate_vulnerability_section(self) -> str:
        """Generate the vulnerability analysis section"""
        html = ""
        
        # Add vulnerability chart if available
        if 'vulnerability_chart' in self.charts and self.charts['vulnerability_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['vulnerability_chart']['base64_image']}" alt="Vulnerabilities Chart">
                <p>Number of potential vulnerabilities detected per target.</p>
            </div>
            """
        
        # Add vulnerability details table
        html += """
        <h3>Vulnerability Details</h3>
        <table>
            <tr>
                <th>Target</th>
                <th>Vulnerability</th>
                <th>Severity</th>
            </tr>
        """
        
        has_vulnerabilities = False
        
        for target, vulns in self.metrics['vulnerabilities'].items():
            if not vulns:
                continue
                
            has_vulnerabilities = True
            
            for i, vuln in enumerate(vulns):
                # Estimate severity based on the vulnerability name
                severity = "High"
                if any(term in vuln.lower() for term in ["critical", "rce", "remote code", "overflow"]):
                    severity = "Critical"
                elif any(term in vuln.lower() for term in ["medium", "disclosure"]):
                    severity = "Medium"
                elif any(term in vuln.lower() for term in ["low", "info"]):
                    severity = "Low"
                
                # Determine color based on severity
                color = "red"
                if severity == "Medium":
                    color = "orange"
                elif severity == "Low":
                    color = "goldenrod"
                elif severity == "Critical":
                    color = "darkred"
                
                html += f"""
                <tr>
                    <td>{target if i == 0 else ''}</td>
                    <td>{vuln}</td>
                    <td style="color:{color}"><strong>{severity}</strong></td>
                </tr>
                """
        
        if not has_vulnerabilities:
            html += """
            <tr>
                <td colspan="3" style="text-align:center;">No vulnerabilities detected</td>
            </tr>
            """
        
        html += """
        </table>
        
        <p><strong>Note:</strong> Vulnerabilities are potential security issues that were detected during scanning. They should be verified manually before remediation.</p>
        """
        
        return html
    
    def _generate_network_section(self) -> str:
        """Generate the network analysis section"""
        html = ""
        
        # Add response time chart if available
        if 'response_time_chart' in self.charts and self.charts['response_time_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['response_time_chart']['base64_image']}" alt="Response Times Chart">
                <p>Network response times for each target.</p>
            </div>
            """
        
        # Add traceroute chart if available
        if 'traceroute_chart' in self.charts and self.charts['traceroute_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['traceroute_chart']['base64_image']}" alt="Traceroute Chart">
                <p>Network distance (measured in hops) to each target.</p>
            </div>
            """
        
        # Add network details table
        html += """
        <h3>Network Details</h3>
        <table>
            <tr>
                <th>Target</th>
                <th>Response Time (ms)</th>
                <th>Network Hops</th>
            </tr>
        """
        
        for target in self.metrics['response_times'].keys():
            response_time = self.metrics['response_times'][target]
            hop_count = self.metrics['traceroute_hops'][target]
            
            html += f"""
            <tr>
                <td>{target}</td>
                <td>{response_time if response_time is not None else 'N/A'}</td>
                <td>{hop_count if hop_count > 0 else 'N/A'}</td>
            </tr>
            """
        
        html += """
        </table>
        """
        
        return html
    
    def _generate_ports_section(self) -> str:
        """Generate the open ports analysis section"""
        html = ""
        
        # Add open ports chart if available
        if 'open_ports_chart' in self.charts and self.charts['open_ports_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['open_ports_chart']['base64_image']}" alt="Open Ports Chart">
                <p>Number of open ports discovered on each target.</p>
            </div>
            """
        
        # Add ports heatmap if available
        if 'ports_heatmap' in self.charts and self.charts['ports_heatmap']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['ports_heatmap']['base64_image']}" alt="Ports Heatmap">
                <p>Heatmap showing which ports are open (red) across all targets.</p>
            </div>
            """
        
        # Add open ports details table
        html += """
        <h3>Open Ports Details</h3>
        <table>
            <tr>
                <th>Target</th>
                <th>Port</th>
                <th>Service</th>
                <th>Risk Level</th>
            </tr>
        """
        
        high_risk_ports = [21, 22, 23, 25, 53, 139, 445, 1433, 3306, 3389, 5900]
        medium_risk_ports = [20, 80, 110, 111, 135, 143, 443, 993, 995, 1723, 3306, 8080]
        
        has_ports = False
        
        for target, services in self.metrics['services'].items():
            if not services:
                continue
                
            has_ports = True
            
            for i, service in enumerate(services):
                port = service.get('port', 0)
                service_name = service.get('name', 'unknown')
                
                # Determine risk level based on port
                if port in high_risk_ports:
                    risk_level = '<span style="color:red">High</span>'
                elif port in medium_risk_ports:
                    risk_level = '<span style="color:orange">Medium</span>'
                else:
                    risk_level = '<span style="color:green">Low</span>'
                
                html += f"""
                <tr>
                    <td>{target if i == 0 else ''}</td>
                    <td>{port}</td>
                    <td>{service_name}</td>
                    <td>{risk_level}</td>
                </tr>
                """
        
        if not has_ports:
            html += """
            <tr>
                <td colspan="4" style="text-align:center;">No open ports detected</td>
            </tr>
            """
        
        html += """
        </table>
        
        <p><strong>Note:</strong> Some ports may represent higher security risks depending on the services running on them and their exposure to the internet.</p>
        """
        
        return html
    
    def _generate_osint_section(self) -> str:
        """Generate the OSINT data section"""
        html = ""
        
        # Add subdomain chart if available
        if 'subdomain_chart' in self.charts and self.charts['subdomain_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['subdomain_chart']['base64_image']}" alt="Subdomains Chart">
                <p>Number of subdomains discovered for each target domain.</p>
            </div>
            """
        
        # Add subdomain details table
        html += """
        <h3>Subdomain Details</h3>
        <table>
            <tr>
                <th>Target</th>
                <th>Subdomain</th>
            </tr>
        """
        
        has_subdomains = False
        
        for target, subdomains in self.metrics['subdomains'].items():
            if not subdomains:
                continue
                
            has_subdomains = True
            
            for i, subdomain in enumerate(subdomains[:20]):  # Limit to first 20 subdomains
                html += f"""
                <tr>
                    <td>{target if i == 0 else ''}</td>
                    <td>{subdomain}</td>
                </tr>
                """
            
            if len(subdomains) > 20:
                html += f"""
                <tr>
                    <td></td>
                    <td><em>... and {len(subdomains) - 20} more</em></td>
                </tr>
                """
        
        if not has_subdomains:
            html += """
            <tr>
                <td colspan="2" style="text-align:center;">No subdomains discovered</td>
            </tr>
            """
        
        html += """
        </table>
        """
        
        return html
    
    def _generate_regression_section(self) -> str:
        """Generate the statistical analysis section"""
        html = ""
        
        # Add regression chart if available
        if 'regression_chart' in self.charts and self.charts['regression_chart']:
            html += f"""
            <div class="chart-container">
                <img src="data:image/png;base64,{self.charts['regression_chart']['base64_image']}" alt="Regression Analysis Chart">
                <p>Regression analysis showing the impact of different factors on security scores.</p>
            </div>
            """
            
            # Add regression details if available
            if self.regression_results:
                html += """
                <h3>Regression Analysis Details</h3>
                <p>The following factors were analyzed for their correlation with security scores:</p>
                <table>
                    <tr>
                        <th>Factor</th>
                        <th>Impact on Security</th>
                        <th>Significance</th>
                    </tr>
                """
                
                # Sort coefficients by absolute value
                if 'coefficients' in self.regression_results:
                    sorted_coefs = sorted(self.regression_results['coefficients'].items(), 
                                          key=lambda x: abs(x[1]), reverse=True)
                    
                    for feature, coef in sorted_coefs:
                        # Determine impact direction
                        if coef > 0:
                            impact = '<span style="color:green">Positive</span>'
                        else:
                            impact = '<span style="color:red">Negative</span>'
                        
                        # Determine significance based on coefficient magnitude
                        abs_coef = abs(coef)
                        if abs_coef > 0.5:
                            significance = "High"
                        elif abs_coef > 0.2:
                            significance = "Medium"
                        else:
                            significance = "Low"
                        
                        html += f"""
                        <tr>
                            <td>{feature.replace('_', ' ').title()}</td>
                            <td>{impact} ({coef:.3f})</td>
                            <td>{significance}</td>
                        </tr>
                        """
                
                html += """
                </table>
                """
                
                # Add model quality metrics
                if 'r2' in self.regression_results and 'mse' in self.regression_results:
                    r2 = self.regression_results['r2']
                    mse = self.regression_results['mse']
                    
                    html += f"""
                    <p><strong>Model Quality:</strong></p>
                    <ul>
                        <li>R² Score: {r2:.3f} (measures how well the model explains the variation in security scores)</li>
                        <li>Mean Squared Error: {mse:.3f} (measures the average squared difference between predicted and actual scores)</li>
                    </ul>
                    
                    <p><strong>Interpretation:</strong> {'This model provides a strong explanation of security factors.' if r2 > 0.7 else 'This model provides a moderate explanation of security factors.' if r2 > 0.5 else 'This model provides a limited explanation of security factors.'}</p>
                    """
        else:
            html += """
            <p>Insufficient data for statistical analysis. Regression analysis requires data from multiple targets.</p>
            """
        
        return html
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate the average response time across all targets"""
        response_times = [time for time in self.metrics['response_times'].values() if time is not None]
        return sum(response_times) / len(response_times) if response_times else 0
    
    def _get_most_common_ports(self, limit: int = 5) -> List[int]:
        """Get the most common open ports across all targets"""
        port_counts = {}
        
        for target, ports in self.metrics['ports'].items():
            for port in ports:
                if port not in port_counts:
                    port_counts[port] = 0
                port_counts[port] += 1
        
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)
        return [port for port, _ in sorted_ports[:limit]]


async def main():
    """Main function to demonstrate usage"""
    # Set up argument parser
    import argparse
    parser = argparse.ArgumentParser(description="Generate visual reports from network reconnaissance data")
    parser.add_argument("-t", "--targets", nargs="+", help="Target IP address(es) or domain(s) to include in the report")
    parser.add_argument("--results-dir", type=str, default="recon_results", help="Directory with scan results")
    parser.add_argument("--output-dir", type=str, default="visual_reports", help="Directory for output reports")
    parser.add_argument("--report-title", type=str, default="Network Reconnaissance Report", help="Title for the report")
    args = parser.parse_args()
    
    # Ensure directories exist
    os.makedirs(args.results_dir, exist_ok=True)
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Process data
    processor = NetworkDataProcessor(args.results_dir)
    await processor.load_scan_results(args.targets[0] if args.targets else None)
    metrics = processor.extract_metrics()
    
    # Create visualizations
    visualizer = NetworkVisualizer(metrics, args.output_dir)
    charts = visualizer.generate_all_charts(args.targets)
    
    # Run regression analysis if enough targets
    regression_results = None
    if len(metrics['security_score']) >= 2:
        df, features = processor.prepare_data_for_regression()
        analyzer = RegressionAnalyzer(df, features)
        regression_results = analyzer.perform_regression()
        if regression_results:
            visualizer.create_regression_chart(regression_results, df)
    
    # Generate HTML report
    report_generator = HTMLReportGenerator(metrics, charts, regression_results)
    report_file = os.path.join(args.output_dir, f"network_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    output_file = report_generator.generate_html_report(report_file, args.report_title)
    
    print(f"Report generated successfully: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
