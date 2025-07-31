"""
Packet Flow Analyzer Module
===========================

This module provides comprehensive analysis capabilities for packet flows
in Palo Alto Networks firewalls, including flow state analysis, security
policy evaluation, and anomaly detection.
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import ipaddress
import re
import os


@dataclass
class FlowRecord:
    """Represents a single packet flow record."""
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    action: str
    policy_name: str
    application: str
    session_id: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration: float
    zone_from: str
    zone_to: str
    threat_name: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None


@dataclass
class FlowAnalysisResult:
    """Container for flow analysis results."""
    total_flows: int
    unique_sessions: int
    top_applications: Dict[str, int]
    top_policies: Dict[str, int]
    flow_distribution: Dict[str, int]
    anomalies: List[Dict[str, Any]]
    security_events: List[Dict[str, Any]]
    bandwidth_stats: Dict[str, Any]
    geographic_distribution: Dict[str, int]
    time_patterns: Dict[str, Any]


class PacketFlowAnalyzer:
    """Main analyzer class for packet flow analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the analyzer with configuration."""
        self.config = config
        self.suspicious_ports = config.get('suspicious_ports', [22, 23, 135, 139, 445, 1433, 3389])
        self.anomaly_thresholds = config.get('anomaly_thresholds', {
            'bytes_per_second': 10000000,  # 10MB/s
            'packets_per_second': 1000,
            'session_duration': 3600,  # 1 hour
            'failed_connections': 10
        })
        self.known_malicious_ips = set(config.get('malicious_ips', []))
        
    def analyze(self, flows: List[FlowRecord]) -> FlowAnalysisResult:
        """Perform comprehensive analysis of packet flows."""
        print(f"Analyzing {len(flows)} flows...")
        
        # Basic statistics
        total_flows = len(flows)
        unique_sessions = len(set(flow.session_id for flow in flows))
        
        # Application and policy analysis
        app_counter = Counter(flow.application for flow in flows)
        policy_counter = Counter(flow.policy_name for flow in flows)
        
        # Flow distribution by action
        action_counter = Counter(flow.action for flow in flows)
        
        # Detect anomalies
        anomalies = self._detect_anomalies(flows)
        
        # Security event analysis
        security_events = self._analyze_security_events(flows)
        
        # Bandwidth analysis
        bandwidth_stats = self._analyze_bandwidth(flows)
        
        # Geographic analysis (simplified)
        geographic_dist = self._analyze_geographic_distribution(flows)
        
        # Time pattern analysis
        time_patterns = self._analyze_time_patterns(flows)
        
        return FlowAnalysisResult(
            total_flows=total_flows,
            unique_sessions=unique_sessions,
            top_applications=dict(app_counter.most_common(10)),
            top_policies=dict(policy_counter.most_common(10)),
            flow_distribution=dict(action_counter),
            anomalies=anomalies,
            security_events=security_events,
            bandwidth_stats=bandwidth_stats,
            geographic_distribution=geographic_dist,
            time_patterns=time_patterns
        )
    
    def _detect_anomalies(self, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        """Detect anomalous flow patterns."""
        anomalies = []
        
        # Group flows by source IP for analysis
        ip_flows = defaultdict(list)
        for flow in flows:
            ip_flows[flow.source_ip].append(flow)
        
        for src_ip, ip_flow_list in ip_flows.items():
            # Check for high bandwidth usage
            total_bytes = sum(flow.bytes_sent + flow.bytes_received for flow in ip_flow_list)
            total_duration = sum(flow.duration for flow in ip_flow_list)
            
            if total_duration > 0:
                bytes_per_second = total_bytes / total_duration
                if bytes_per_second > self.anomaly_thresholds['bytes_per_second']:
                    anomalies.append({
                        'type': 'high_bandwidth',
                        'source_ip': src_ip,
                        'bytes_per_second': bytes_per_second,
                        'severity': 'medium',
                        'description': f'High bandwidth usage detected from {src_ip}'
                    })
            
            # Check for port scanning
            dest_ports = set(flow.dest_port for flow in ip_flow_list)
            if len(dest_ports) > 20:  # Accessing many different ports
                anomalies.append({
                    'type': 'port_scan',
                    'source_ip': src_ip,
                    'port_count': len(dest_ports),
                    'severity': 'high',
                    'description': f'Potential port scan from {src_ip} targeting {len(dest_ports)} ports'
                })
            
            # Check for suspicious destinations
            dest_ips = set(flow.dest_ip for flow in ip_flow_list)
            for dest_ip in dest_ips:
                if dest_ip in self.known_malicious_ips:
                    anomalies.append({
                        'type': 'malicious_destination',
                        'source_ip': src_ip,
                        'dest_ip': dest_ip,
                        'severity': 'critical',
                        'description': f'Connection to known malicious IP {dest_ip} from {src_ip}'
                    })
            
            # Check for failed connection attempts
            failed_flows = [f for f in ip_flow_list if f.action in ['deny', 'drop', 'reset']]
            if len(failed_flows) > self.anomaly_thresholds['failed_connections']:
                anomalies.append({
                    'type': 'excessive_failures',
                    'source_ip': src_ip,
                    'failed_count': len(failed_flows),
                    'severity': 'medium',
                    'description': f'Excessive failed connections from {src_ip}: {len(failed_flows)} failures'
                })
        
        return anomalies
    
    def _analyze_security_events(self, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        """Analyze flows for security-related events."""
        security_events = []
        
        for flow in flows:
            # Check for threats
            if flow.threat_name:
                security_events.append({
                    'type': 'threat_detected',
                    'threat_name': flow.threat_name,
                    'source_ip': flow.source_ip,
                    'dest_ip': flow.dest_ip,
                    'severity': flow.severity or 'unknown',
                    'timestamp': flow.timestamp,
                    'description': f'Threat {flow.threat_name} detected'
                })
            
            # Check for suspicious ports
            if flow.dest_port in self.suspicious_ports:
                security_events.append({
                    'type': 'suspicious_port',
                    'port': flow.dest_port,
                    'source_ip': flow.source_ip,
                    'dest_ip': flow.dest_ip,
                    'severity': 'medium',
                    'timestamp': flow.timestamp,
                    'description': f'Access to suspicious port {flow.dest_port}'
                })
            
            # Check for denied traffic
            if flow.action in ['deny', 'drop']:
                security_events.append({
                    'type': 'blocked_traffic',
                    'source_ip': flow.source_ip,
                    'dest_ip': flow.dest_ip,
                    'port': flow.dest_port,
                    'policy': flow.policy_name,
                    'severity': 'low',
                    'timestamp': flow.timestamp,
                    'description': f'Traffic blocked by policy {flow.policy_name}'
                })
        
        return security_events
    
    def _analyze_bandwidth(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """Analyze bandwidth usage patterns."""
        total_bytes_sent = sum(flow.bytes_sent for flow in flows)
        total_bytes_received = sum(flow.bytes_received for flow in flows)
        total_packets = sum(flow.packets_sent + flow.packets_received for flow in flows)
        
        # Top bandwidth consumers
        ip_bandwidth = defaultdict(int)
        for flow in flows:
            ip_bandwidth[flow.source_ip] += flow.bytes_sent + flow.bytes_received
        
        top_consumers = sorted(ip_bandwidth.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Application bandwidth
        app_bandwidth = defaultdict(int)
        for flow in flows:
            app_bandwidth[flow.application] += flow.bytes_sent + flow.bytes_received
        
        return {
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_received': total_bytes_received,
            'total_packets': total_packets,
            'top_consumers': top_consumers,
            'bandwidth_by_application': dict(sorted(app_bandwidth.items(), 
                                                   key=lambda x: x[1], reverse=True)[:10])
        }
    
    def _analyze_geographic_distribution(self, flows: List[FlowRecord]) -> Dict[str, int]:
        """Analyze geographic distribution of traffic (simplified)."""
        # This is a simplified implementation
        # In practice, you'd use a GeoIP database
        regions = defaultdict(int)
        
        for flow in flows:
            try:
                dest_ip = ipaddress.ip_address(flow.dest_ip)
                if dest_ip.is_private:
                    regions['Internal'] += 1
                elif dest_ip.is_loopback:
                    regions['Loopback'] += 1
                else:
                    # Simple classification based on IP ranges
                    if str(dest_ip).startswith(('8.8.', '1.1.1.')):
                        regions['DNS_Servers'] += 1
                    elif str(dest_ip).startswith('10.'):
                        regions['Internal'] += 1
                    else:
                        regions['External'] += 1
            except ValueError:
                regions['Unknown'] += 1
        
        return dict(regions)
    
    def _analyze_time_patterns(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """Analyze temporal patterns in traffic."""
        hourly_distribution = defaultdict(int)
        daily_distribution = defaultdict(int)
        
        for flow in flows:
            try:
                # Parse timestamp (assuming ISO format)
                dt = datetime.fromisoformat(flow.timestamp.replace('Z', '+00:00'))
                hourly_distribution[dt.hour] += 1
                daily_distribution[dt.strftime('%A')] += 1
            except ValueError:
                continue
        
        return {
            'hourly_distribution': dict(hourly_distribution),
            'daily_distribution': dict(daily_distribution),
            'peak_hour': max(hourly_distribution.items(), key=lambda x: x[1])[0] if hourly_distribution else None,
            'peak_day': max(daily_distribution.items(), key=lambda x: x[1])[0] if daily_distribution else None
        }
    
    def save_results(self, results: FlowAnalysisResult, output_dir: str, format_type: str = 'json'):
        """Save analysis results to specified format."""
        os.makedirs(output_dir, exist_ok=True)
        
        if format_type == 'json':
            output_file = os.path.join(output_dir, 'analysis_results.json')
            with open(output_file, 'w') as f:
                json.dump(asdict(results), f, indent=2, default=str)
        
        elif format_type == 'csv':
            # Save summary to CSV
            output_file = os.path.join(output_dir, 'analysis_summary.csv')
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                writer.writerow(['Total Flows', results.total_flows])
                writer.writerow(['Unique Sessions', results.unique_sessions])
                writer.writerow(['Anomalies Found', len(results.anomalies)])
                writer.writerow(['Security Events', len(results.security_events)])
            
            # Save anomalies to separate CSV
            if results.anomalies:
                anomaly_file = os.path.join(output_dir, 'anomalies.csv')
                with open(anomaly_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=results.anomalies[0].keys())
                    writer.writeheader()
                    writer.writerows(results.anomalies)
        
        elif format_type == 'xml':
            output_file = os.path.join(output_dir, 'analysis_results.xml')
            root = ET.Element('FlowAnalysisResults')
            
            # Add basic stats
            stats = ET.SubElement(root, 'Statistics')
            ET.SubElement(stats, 'TotalFlows').text = str(results.total_flows)
            ET.SubElement(stats, 'UniqueSessions').text = str(results.unique_sessions)
            
            # Add anomalies
            anomalies_elem = ET.SubElement(root, 'Anomalies')
            for anomaly in results.anomalies:
                anomaly_elem = ET.SubElement(anomalies_elem, 'Anomaly')
                for key, value in anomaly.items():
                    ET.SubElement(anomaly_elem, key).text = str(value)
            
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
        
        print(f"Results saved to {output_dir} in {format_type} format")
    
    def generate_report(self, results: FlowAnalysisResult, output_file: str):
        """Generate a human-readable analysis report."""
        with open(output_file, 'w') as f:
            f.write("Palo Alto Packet Flow Analysis Report\n")
            f.write("=" * 40 + "\n\n")
            
            f.write(f"Analysis Summary:\n")
            f.write(f"- Total Flows Analyzed: {results.total_flows:,}\n")
            f.write(f"- Unique Sessions: {results.unique_sessions:,}\n")
            f.write(f"- Anomalies Detected: {len(results.anomalies)}\n")
            f.write(f"- Security Events: {len(results.security_events)}\n\n")
            
            f.write("Top Applications:\n")
            for app, count in list(results.top_applications.items())[:5]:
                f.write(f"- {app}: {count:,} flows\n")
            f.write("\n")
            
            f.write("Flow Distribution by Action:\n")
            for action, count in results.flow_distribution.items():
                f.write(f"- {action}: {count:,} flows\n")
            f.write("\n")
            
            if results.anomalies:
                f.write("Critical Anomalies:\n")
                for anomaly in results.anomalies[:5]:
                    f.write(f"- {anomaly['type']}: {anomaly['description']}\n")
                f.write("\n")
            
            f.write("Bandwidth Statistics:\n")
            f.write(f"- Total Bytes Transferred: {results.bandwidth_stats['total_bytes_sent'] + results.bandwidth_stats['total_bytes_received']:,}\n")
            f.write(f"- Total Packets: {results.bandwidth_stats['total_packets']:,}\n")
        
        print(f"Report generated: {output_file}")