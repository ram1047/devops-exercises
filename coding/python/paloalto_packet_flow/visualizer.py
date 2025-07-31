"""
Flow Visualizer Module
=====================

This module provides visualization capabilities for packet flows,
creating interactive network diagrams, charts, and reports.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import base64
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches
    from matplotlib.sankey import Sankey
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.offline as pyo
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

from .analyzer import FlowRecord, FlowAnalysisResult


class VisualizationError(Exception):
    """Custom exception for visualization errors."""
    pass


class FlowVisualizer:
    """Main visualization class for packet flow analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the visualizer with configuration."""
        self.config = config
        self.color_schemes = {
            'action': {
                'allow': '#2E8B57',      # Sea green
                'deny': '#DC143C',       # Crimson
                'drop': '#FF4500',       # Orange red
                'reset': '#FF6347',      # Tomato
                'unknown': '#708090'     # Slate gray
            },
            'severity': {
                'critical': '#8B0000',   # Dark red
                'high': '#FF0000',       # Red
                'medium': '#FFA500',     # Orange
                'low': '#FFFF00',        # Yellow
                'info': '#00BFFF'        # Deep sky blue
            },
            'application': {
                'web-browsing': '#4169E1',  # Royal blue
                'ssl': '#006400',           # Dark green
                'dns': '#9932CC',           # Dark orchid
                'ssh': '#B22222',           # Fire brick
                'ftp': '#FF8C00',           # Dark orange
                'smtp': '#32CD32',          # Lime green
                'unknown': '#A9A9A9'        # Dark gray
            }
        }
    
    def create_visualization(self, data_source: str, layout: str = 'hierarchical', 
                           output_format: str = 'html') -> str:
        """Create a comprehensive flow visualization."""
        print(f"Creating {layout} visualization in {output_format} format...")
        
        # Load data
        if isinstance(data_source, str):
            if data_source.endswith('.json'):
                with open(data_source, 'r') as f:
                    data = json.load(f)
            else:
                raise VisualizationError(f"Unsupported data format: {data_source}")
        else:
            data = data_source
        
        if output_format == 'html':
            return self._create_html_dashboard(data, layout)
        elif output_format == 'svg':
            return self._create_svg_diagram(data, layout)
        elif output_format == 'png':
            return self._create_png_chart(data, layout)
        else:
            raise VisualizationError(f"Unsupported output format: {output_format}")
    
    def _create_html_dashboard(self, data: Dict[str, Any], layout: str) -> str:
        """Create an interactive HTML dashboard."""
        if not PLOTLY_AVAILABLE:
            return self._create_basic_html_dashboard(data)
        
        # Create subplots
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=[
                'Traffic Flow Overview', 'Top Applications',
                'Security Events Timeline', 'Geographic Distribution',
                'Bandwidth Usage', 'Anomaly Detection'
            ],
            specs=[
                [{"type": "scatter"}, {"type": "bar"}],
                [{"type": "scatter"}, {"type": "pie"}],
                [{"type": "bar"}, {"type": "scatter"}]
            ]
        )
        
        # Traffic flow network diagram
        if 'flows' in data:
            flows = data['flows']
            self._add_network_diagram(fig, flows, 1, 1)
        
        # Top applications
        if 'top_applications' in data:
            apps = data['top_applications']
            self._add_application_chart(fig, apps, 1, 2)
        
        # Security events timeline
        if 'security_events' in data:
            events = data['security_events']
            self._add_security_timeline(fig, events, 2, 1)
        
        # Geographic distribution
        if 'geographic_distribution' in data:
            geo_data = data['geographic_distribution']
            self._add_geographic_chart(fig, geo_data, 2, 2)
        
        # Bandwidth usage
        if 'bandwidth_stats' in data:
            bandwidth = data['bandwidth_stats']
            self._add_bandwidth_chart(fig, bandwidth, 3, 1)
        
        # Anomalies
        if 'anomalies' in data:
            anomalies = data['anomalies']
            self._add_anomaly_chart(fig, anomalies, 3, 2)
        
        # Update layout
        fig.update_layout(
            title="Palo Alto Packet Flow Analysis Dashboard",
            height=1200,
            showlegend=True,
            template="plotly_white"
        )
        
        return pyo.plot(fig, output_type='div', include_plotlyjs=True)
    
    def _create_basic_html_dashboard(self, data: Dict[str, Any]) -> str:
        """Create a basic HTML dashboard without advanced libraries."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Palo Alto Packet Flow Analysis</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e7f3ff; }}
                .anomaly {{ background-color: #ffe7e7; padding: 10px; margin: 5px 0; }}
                .event {{ background-color: #fff7e7; padding: 10px; margin: 5px 0; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Palo Alto Packet Flow Analysis Dashboard</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Summary Statistics</h2>
                <div class="metric">Total Flows: {data.get('total_flows', 0):,}</div>
                <div class="metric">Unique Sessions: {data.get('unique_sessions', 0):,}</div>
                <div class="metric">Anomalies: {len(data.get('anomalies', []))}</div>
                <div class="metric">Security Events: {len(data.get('security_events', []))}</div>
            </div>
            
            <div class="section">
                <h2>Top Applications</h2>
                <table>
                    <tr><th>Application</th><th>Flow Count</th></tr>
        """
        
        for app, count in list(data.get('top_applications', {}).items())[:10]:
            html_content += f"<tr><td>{app}</td><td>{count:,}</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h2>Flow Distribution</h2>
                <table>
                    <tr><th>Action</th><th>Count</th></tr>
        """
        
        for action, count in data.get('flow_distribution', {}).items():
            html_content += f"<tr><td>{action}</td><td>{count:,}</td></tr>"
        
        html_content += "</table></div>"
        
        # Add anomalies section
        if data.get('anomalies'):
            html_content += '<div class="section"><h2>Critical Anomalies</h2>'
            for anomaly in data['anomalies'][:10]:
                html_content += f'<div class="anomaly"><strong>{anomaly.get("type", "Unknown")}</strong>: {anomaly.get("description", "No description")}</div>'
            html_content += '</div>'
        
        # Add security events section
        if data.get('security_events'):
            html_content += '<div class="section"><h2>Recent Security Events</h2>'
            for event in data['security_events'][:10]:
                html_content += f'<div class="event"><strong>{event.get("type", "Unknown")}</strong>: {event.get("description", "No description")}</div>'
            html_content += '</div>'
        
        html_content += "</body></html>"
        return html_content
    
    def _create_svg_diagram(self, data: Dict[str, Any], layout: str) -> str:
        """Create an SVG network diagram."""
        if not NETWORKX_AVAILABLE or not MATPLOTLIB_AVAILABLE:
            return self._create_basic_svg_diagram(data)
        
        # Create network graph
        G = nx.DiGraph()
        
        # Add nodes and edges from flow data
        if 'flows' in data:
            for flow in data['flows'][:100]:  # Limit for readability
                G.add_edge(flow['source_ip'], flow['dest_ip'], 
                          action=flow['action'], 
                          application=flow.get('application', 'unknown'))
        
        # Set layout
        if layout == 'circular':
            pos = nx.circular_layout(G)
        elif layout == 'force':
            pos = nx.spring_layout(G, k=1, iterations=50)
        else:  # hierarchical
            pos = nx.spring_layout(G, k=2, iterations=100)
        
        # Create matplotlib figure
        plt.figure(figsize=(16, 12))
        
        # Draw nodes
        node_colors = [self.color_schemes['action'].get('allow', '#2E8B57') for _ in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.8)
        
        # Draw edges with different colors based on action
        edge_colors = []
        for edge in G.edges(data=True):
            action = edge[2].get('action', 'unknown')
            edge_colors.append(self.color_schemes['action'].get(action, '#708090'))
        
        nx.draw_networkx_edges(G, pos, edge_color=edge_colors, alpha=0.6, arrows=True)
        
        # Add labels
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        plt.title("Network Flow Diagram", size=16)
        plt.axis('off')
        
        # Save to SVG
        svg_path = 'temp_diagram.svg'
        plt.savefig(svg_path, format='svg', bbox_inches='tight', dpi=300)
        plt.close()
        
        # Read SVG content
        with open(svg_path, 'r') as f:
            svg_content = f.read()
        
        # Clean up temporary file
        os.remove(svg_path)
        
        return svg_content
    
    def _create_basic_svg_diagram(self, data: Dict[str, Any]) -> str:
        """Create a basic SVG diagram without advanced libraries."""
        width, height = 800, 600
        
        svg_content = f'''
        <svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
            <rect width="100%" height="100%" fill="white"/>
            <text x="400" y="30" text-anchor="middle" font-size="20" font-weight="bold">
                Network Flow Overview
            </text>
        '''
        
        # Add some basic shapes representing network nodes
        y_pos = 100
        for i, (app, count) in enumerate(list(data.get('top_applications', {}).items())[:5]):
            x_pos = 100 + i * 130
            svg_content += f'''
            <circle cx="{x_pos}" cy="{y_pos}" r="30" fill="#4169E1" opacity="0.7"/>
            <text x="{x_pos}" y="{y_pos + 5}" text-anchor="middle" font-size="10" fill="white">
                {app[:8]}
            </text>
            <text x="{x_pos}" y="{y_pos + 60}" text-anchor="middle" font-size="12">
                {count:,} flows
            </text>
            '''
        
        # Add flow distribution visualization
        y_pos = 250
        colors = ['#2E8B57', '#DC143C', '#FF4500', '#708090']
        x_start = 50
        
        for i, (action, count) in enumerate(data.get('flow_distribution', {}).items()):
            width_bar = min(count / max(data.get('flow_distribution', {}).values()) * 600, 600)
            color = colors[i % len(colors)]
            
            svg_content += f'''
            <rect x="{x_start}" y="{y_pos + i * 40}" width="{width_bar}" height="30" 
                  fill="{color}" opacity="0.8"/>
            <text x="{x_start + 10}" y="{y_pos + i * 40 + 20}" font-size="12" fill="white">
                {action}: {count:,}
            </text>
            '''
        
        svg_content += '</svg>'
        return svg_content
    
    def _create_png_chart(self, data: Dict[str, Any], layout: str) -> str:
        """Create PNG charts and return base64 encoded data."""
        if not MATPLOTLIB_AVAILABLE:
            raise VisualizationError("Matplotlib is required for PNG output")
        
        # Create figure with subplots
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Palo Alto Packet Flow Analysis', fontsize=16, fontweight='bold')
        
        # Top applications pie chart
        if data.get('top_applications'):
            apps = list(data['top_applications'].keys())[:8]
            counts = list(data['top_applications'].values())[:8]
            axes[0, 0].pie(counts, labels=apps, autopct='%1.1f%%', startangle=90)
            axes[0, 0].set_title('Top Applications')
        
        # Flow distribution bar chart
        if data.get('flow_distribution'):
            actions = list(data['flow_distribution'].keys())
            counts = list(data['flow_distribution'].values())
            colors = [self.color_schemes['action'].get(action, '#708090') for action in actions]
            axes[0, 1].bar(actions, counts, color=colors)
            axes[0, 1].set_title('Flow Distribution by Action')
            axes[0, 1].tick_params(axis='x', rotation=45)
        
        # Bandwidth usage
        if data.get('bandwidth_stats') and data['bandwidth_stats'].get('top_consumers'):
            consumers = data['bandwidth_stats']['top_consumers'][:10]
            ips = [consumer[0] for consumer in consumers]
            bandwidth = [consumer[1] for consumer in consumers]
            axes[1, 0].barh(ips, bandwidth)
            axes[1, 0].set_title('Top Bandwidth Consumers')
            axes[1, 0].set_xlabel('Bytes')
        
        # Anomaly severity distribution
        if data.get('anomalies'):
            severities = [anomaly.get('severity', 'unknown') for anomaly in data['anomalies']]
            severity_counts = Counter(severities)
            severities_list = list(severity_counts.keys())
            counts_list = list(severity_counts.values())
            colors = [self.color_schemes['severity'].get(sev, '#A9A9A9') for sev in severities_list]
            axes[1, 1].bar(severities_list, counts_list, color=colors)
            axes[1, 1].set_title('Anomaly Distribution by Severity')
        
        plt.tight_layout()
        
        # Save to temporary file and encode as base64
        temp_path = 'temp_chart.png'
        plt.savefig(temp_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        with open(temp_path, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')
        
        os.remove(temp_path)
        
        return f"data:image/png;base64,{image_data}"
    
    def _add_network_diagram(self, fig, flows: List[Dict], row: int, col: int):
        """Add network diagram to plotly subplot."""
        # Extract unique IPs and create network layout
        ips = set()
        connections = []
        
        for flow in flows[:50]:  # Limit for performance
            ips.add(flow['source_ip'])
            ips.add(flow['dest_ip'])
            connections.append((flow['source_ip'], flow['dest_ip'], flow.get('action', 'unknown')))
        
        ip_list = list(ips)
        positions = self._calculate_positions(ip_list)
        
        # Add nodes
        x_coords = [pos[0] for pos in positions.values()]
        y_coords = [pos[1] for pos in positions.values()]
        
        fig.add_trace(
            go.Scatter(
                x=x_coords, y=y_coords,
                mode='markers+text',
                text=ip_list,
                textposition="middle center",
                marker=dict(size=10, color='lightblue'),
                name='Network Nodes'
            ),
            row=row, col=col
        )
        
        # Add edges
        for src, dst, action in connections:
            if src in positions and dst in positions:
                x0, y0 = positions[src]
                x1, y1 = positions[dst]
                
                color = self.color_schemes['action'].get(action, '#708090')
                
                fig.add_trace(
                    go.Scatter(
                        x=[x0, x1, None], y=[y0, y1, None],
                        mode='lines',
                        line=dict(color=color, width=1),
                        showlegend=False
                    ),
                    row=row, col=col
                )
    
    def _add_application_chart(self, fig, apps: Dict[str, int], row: int, col: int):
        """Add application usage chart."""
        applications = list(apps.keys())[:10]
        counts = list(apps.values())[:10]
        
        fig.add_trace(
            go.Bar(x=applications, y=counts, name='Applications'),
            row=row, col=col
        )
    
    def _add_security_timeline(self, fig, events: List[Dict], row: int, col: int):
        """Add security events timeline."""
        if not events:
            return
        
        # Group events by hour
        hourly_events = defaultdict(int)
        for event in events:
            try:
                timestamp = event.get('timestamp', '')
                if timestamp:
                    hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
                    hourly_events[hour] += 1
            except:
                continue
        
        hours = sorted(hourly_events.keys())
        counts = [hourly_events[hour] for hour in hours]
        
        fig.add_trace(
            go.Scatter(x=hours, y=counts, mode='lines+markers', name='Security Events'),
            row=row, col=col
        )
    
    def _add_geographic_chart(self, fig, geo_data: Dict[str, int], row: int, col: int):
        """Add geographic distribution chart."""
        regions = list(geo_data.keys())
        counts = list(geo_data.values())
        
        fig.add_trace(
            go.Pie(labels=regions, values=counts, name='Geographic Distribution'),
            row=row, col=col
        )
    
    def _add_bandwidth_chart(self, fig, bandwidth: Dict[str, Any], row: int, col: int):
        """Add bandwidth usage chart."""
        if 'bandwidth_by_application' in bandwidth:
            apps = list(bandwidth['bandwidth_by_application'].keys())[:10]
            usage = list(bandwidth['bandwidth_by_application'].values())[:10]
            
            fig.add_trace(
                go.Bar(x=apps, y=usage, name='Bandwidth by Application'),
                row=row, col=col
            )
    
    def _add_anomaly_chart(self, fig, anomalies: List[Dict], row: int, col: int):
        """Add anomaly distribution chart."""
        if not anomalies:
            return
        
        # Count anomalies by type
        anomaly_types = [anomaly.get('type', 'unknown') for anomaly in anomalies]
        type_counts = Counter(anomaly_types)
        
        types = list(type_counts.keys())
        counts = list(type_counts.values())
        
        # Assign severity-based colors
        colors = []
        for anomaly_type in types:
            # Find corresponding severity
            severity = 'medium'  # default
            for anomaly in anomalies:
                if anomaly.get('type') == anomaly_type:
                    severity = anomaly.get('severity', 'medium')
                    break
            colors.append(self.color_schemes['severity'].get(severity, '#FFA500'))
        
        fig.add_trace(
            go.Scatter(
                x=types, y=counts,
                mode='markers',
                marker=dict(size=counts, color=colors, sizemode='area', sizeref=max(counts)/50),
                name='Anomalies'
            ),
            row=row, col=col
        )
    
    def _calculate_positions(self, nodes: List[str]) -> Dict[str, Tuple[float, float]]:
        """Calculate positions for network nodes."""
        import math
        
        positions = {}
        n = len(nodes)
        
        if n == 0:
            return positions
        
        # Arrange nodes in a circle
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            x = math.cos(angle)
            y = math.sin(angle)
            positions[node] = (x, y)
        
        return positions
    
    def save(self, visualization_content: str, output_path: str):
        """Save visualization to file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(visualization_content)
        
        print(f"Visualization saved to: {output_path}")
    
    def create_flow_sankey(self, flows: List[FlowRecord]) -> str:
        """Create a Sankey diagram showing flow patterns."""
        if not PLOTLY_AVAILABLE:
            raise VisualizationError("Plotly is required for Sankey diagrams")
        
        # Prepare data for Sankey diagram
        source_nodes = set()
        target_nodes = set()
        links = defaultdict(int)
        
        for flow in flows:
            source = f"src_{flow.source_ip}"
            target = f"dst_{flow.dest_ip}"
            source_nodes.add(source)
            target_nodes.add(target)
            links[(source, target)] += 1
        
        # Create node list
        all_nodes = list(source_nodes | target_nodes)
        node_dict = {node: i for i, node in enumerate(all_nodes)}
        
        # Prepare link data
        source_indices = []
        target_indices = []
        values = []
        
        for (source, target), count in links.items():
            source_indices.append(node_dict[source])
            target_indices.append(node_dict[target])
            values.append(count)
        
        # Create Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=all_nodes
            ),
            link=dict(
                source=source_indices,
                target=target_indices,
                value=values
            )
        )])
        
        fig.update_layout(title_text="Network Flow Sankey Diagram", font_size=10)
        
        return pyo.plot(fig, output_type='div', include_plotlyjs=True)