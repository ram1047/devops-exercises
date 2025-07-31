"""
Real-time Flow Monitor Module
============================

This module provides real-time monitoring capabilities for Palo Alto Networks
firewalls, including live flow analysis, alerting, and dashboard updates.
"""

import time
import asyncio
import requests
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from collections import deque, defaultdict
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urljoin
import ssl
from dataclasses import dataclass

from .analyzer import FlowRecord, PacketFlowAnalyzer
from .utils import format_bytes, format_duration


@dataclass
class AlertRule:
    """Represents an alerting rule."""
    name: str
    condition: str
    threshold: float
    severity: str
    enabled: bool = True
    cooldown: int = 300  # 5 minutes


@dataclass
class Alert:
    """Represents a triggered alert."""
    rule_name: str
    message: str
    severity: str
    timestamp: datetime
    data: Dict[str, Any]


class PaloAltoAPI:
    """API client for Palo Alto Networks firewall."""
    
    def __init__(self, firewall_ip: str, api_key: Optional[str] = None, 
                 username: Optional[str] = None, password: Optional[str] = None):
        """Initialize API client."""
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.username = username
        self.password = password
        self.base_url = f"https://{firewall_ip}/api/"
        self.session = requests.Session()
        
        # Disable SSL warnings for self-signed certificates
        requests.packages.urllib3.disable_warnings()
        self.session.verify = False
        
        # Authenticate if credentials provided
        if not api_key and username and password:
            self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get API key."""
        auth_url = urljoin(self.base_url, "")
        params = {
            'type': 'keygen',
            'user': self.username,
            'password': self.password
        }
        
        try:
            response = self.session.get(auth_url, params=params, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            if root.get('status') == 'success':
                self.api_key = root.find('.//key').text
                logging.info("Successfully authenticated with firewall")
            else:
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else "Unknown error"
                raise Exception(f"Authentication failed: {error_text}")
                
        except Exception as e:
            logging.error(f"Failed to authenticate: {e}")
            raise
    
    def get_traffic_logs(self, query: str = "", count: int = 100) -> List[Dict[str, Any]]:
        """Get traffic logs from firewall."""
        if not self.api_key:
            raise Exception("Not authenticated")
        
        params = {
            'type': 'log',
            'log-type': 'traffic',
            'key': self.api_key,
            'query': query,
            'nlogs': count
        }
        
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            
            if root.get('status') != 'success':
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else "Unknown error"
                raise Exception(f"API call failed: {error_text}")
            
            # Extract log entries
            logs = []
            for entry in root.findall('.//entry'):
                log_data = {}
                for child in entry:
                    log_data[child.tag] = child.text
                logs.append(log_data)
            
            return logs
            
        except Exception as e:
            logging.error(f"Failed to get traffic logs: {e}")
            raise
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information from firewall."""
        if not self.api_key:
            raise Exception("Not authenticated")
        
        params = {
            'type': 'op',
            'cmd': '<show><system><info></info></system></show>',
            'key': self.api_key
        }
        
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            root = ET.fromstring(response.content)
            
            if root.get('status') != 'success':
                raise Exception("Failed to get system info")
            
            # Extract system information
            system_info = {}
            info_element = root.find('.//system')
            if info_element is not None:
                for child in info_element:
                    system_info[child.tag] = child.text
            
            return system_info
            
        except Exception as e:
            logging.error(f"Failed to get system info: {e}")
            return {}
    
    def get_interface_stats(self) -> Dict[str, Any]:
        """Get interface statistics."""
        if not self.api_key:
            raise Exception("Not authenticated")
        
        params = {
            'type': 'op',
            'cmd': '<show><interface>all</interface></show>',
            'key': self.api_key
        }
        
        try:
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            root = ET.fromstring(response.content)
            
            if root.get('status') != 'success':
                return {}
            
            # Parse interface information
            interfaces = {}
            for interface in root.findall('.//ifnet/entry'):
                name = interface.find('name')
                if name is not None:
                    interface_name = name.text
                    interfaces[interface_name] = {}
                    
                    for child in interface:
                        if child.tag != 'name':
                            interfaces[interface_name][child.tag] = child.text
            
            return interfaces
            
        except Exception as e:
            logging.error(f"Failed to get interface stats: {e}")
            return {}


class FlowMonitor:
    """Real-time flow monitoring class."""
    
    def __init__(self, firewall_ip: str, api_key: Optional[str] = None, 
                 config: Optional[Dict[str, Any]] = None):
        """Initialize flow monitor."""
        self.firewall_ip = firewall_ip
        self.api_client = PaloAltoAPI(firewall_ip, api_key)
        self.config = config or {}
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        
        # Data storage
        self.flow_buffer = deque(maxlen=10000)  # Keep last 10k flows
        self.metrics_history = deque(maxlen=1440)  # 24 hours of minute-based metrics
        
        # Alerting
        self.alert_rules = []
        self.active_alerts = {}
        self.alert_callbacks = []
        
        # Initialize analyzer
        self.analyzer = PacketFlowAnalyzer(config.get('analyzer', {}))
        
        # Setup default alert rules
        self._setup_default_alerts()
    
    def _setup_default_alerts(self):
        """Setup default alerting rules."""
        default_rules = [
            AlertRule(
                name="high_bandwidth",
                condition="bandwidth_mbps > 100",
                threshold=100.0,
                severity="medium"
            ),
            AlertRule(
                name="excessive_denied_traffic",
                condition="denied_flows_per_minute > 50",
                threshold=50.0,
                severity="high"
            ),
            AlertRule(
                name="port_scan_detected",
                condition="unique_dest_ports_per_ip > 20",
                threshold=20.0,
                severity="high"
            ),
            AlertRule(
                name="anomaly_spike",
                condition="anomalies_per_minute > 5",
                threshold=5.0,
                severity="critical"
            )
        ]
        
        self.alert_rules.extend(default_rules)
    
    def add_alert_rule(self, rule: AlertRule):
        """Add a custom alert rule."""
        self.alert_rules.append(rule)
        logging.info(f"Added alert rule: {rule.name}")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add a callback function for alerts."""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self, interval: int = 30, enable_alerts: bool = True):
        """Start real-time monitoring."""
        if self.is_monitoring:
            logging.warning("Monitoring already started")
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval, enable_alerts),
            daemon=True
        )
        self.monitor_thread.start()
        
        logging.info(f"Started monitoring firewall {self.firewall_ip} with {interval}s interval")
    
    def stop_monitoring(self):
        """Stop monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logging.info("Monitoring stopped")
    
    def _monitor_loop(self, interval: int, enable_alerts: bool):
        """Main monitoring loop."""
        while self.is_monitoring:
            try:
                # Collect flow data
                flows = self._collect_flows()
                
                # Update metrics
                metrics = self._calculate_metrics(flows)
                self.metrics_history.append({
                    'timestamp': datetime.now(),
                    'metrics': metrics
                })
                
                # Check alerts
                if enable_alerts:
                    self._check_alerts(metrics, flows)
                
                # Log current status
                self._log_status(metrics)
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
            
            # Wait for next interval
            time.sleep(interval)
    
    def _collect_flows(self) -> List[FlowRecord]:
        """Collect flow data from firewall."""
        try:
            # Get recent traffic logs
            log_data = self.api_client.get_traffic_logs(count=500)
            
            # Convert to FlowRecord objects
            flows = []
            for log_entry in log_data:
                try:
                    flow = self._parse_log_entry(log_entry)
                    if flow:
                        flows.append(flow)
                        self.flow_buffer.append(flow)
                except Exception as e:
                    logging.debug(f"Failed to parse log entry: {e}")
                    continue
            
            return flows
            
        except Exception as e:
            logging.error(f"Failed to collect flows: {e}")
            return []
    
    def _parse_log_entry(self, log_entry: Dict[str, str]) -> Optional[FlowRecord]:
        """Parse a log entry into a FlowRecord."""
        try:
            return FlowRecord(
                timestamp=log_entry.get('time_generated', ''),
                source_ip=log_entry.get('src', ''),
                dest_ip=log_entry.get('dst', ''),
                source_port=int(log_entry.get('sport', 0)),
                dest_port=int(log_entry.get('dport', 0)),
                protocol=log_entry.get('proto', 'unknown'),
                action=log_entry.get('action', 'unknown'),
                policy_name=log_entry.get('rule', 'unknown'),
                application=log_entry.get('app', 'unknown'),
                session_id=log_entry.get('sessionid', ''),
                bytes_sent=int(log_entry.get('bytes_sent', 0)),
                bytes_received=int(log_entry.get('bytes_received', 0)),
                packets_sent=int(log_entry.get('packets', 0)),
                packets_received=0,  # Not available in some logs
                duration=float(log_entry.get('elapsed', 0)),
                zone_from=log_entry.get('from', 'unknown'),
                zone_to=log_entry.get('to', 'unknown'),
                threat_name=log_entry.get('threatid'),
                category=log_entry.get('category'),
                severity=log_entry.get('severity')
            )
        except (ValueError, KeyError) as e:
            logging.debug(f"Failed to parse log entry: {e}")
            return None
    
    def _calculate_metrics(self, flows: List[FlowRecord]) -> Dict[str, Any]:
        """Calculate current monitoring metrics."""
        now = datetime.now()
        
        # Basic counts
        total_flows = len(flows)
        denied_flows = len([f for f in flows if f.action in ['deny', 'drop']])
        
        # Bandwidth calculation
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in flows)
        bandwidth_mbps = total_bytes * 8 / (1024 * 1024) / 60  # Approximate Mbps
        
        # Top talkers
        ip_bytes = defaultdict(int)
        for flow in flows:
            ip_bytes[flow.source_ip] += flow.bytes_sent + flow.bytes_received
        
        top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Application distribution
        app_counts = defaultdict(int)
        for flow in flows:
            app_counts[flow.application] += 1
        
        top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Port scanning detection
        ip_ports = defaultdict(set)
        for flow in flows:
            ip_ports[flow.source_ip].add(flow.dest_port)
        
        max_ports_per_ip = max(len(ports) for ports in ip_ports.values()) if ip_ports else 0
        
        # Analyze for anomalies
        if flows:
            analysis_result = self.analyzer.analyze(flows)
            anomaly_count = len(analysis_result.anomalies)
        else:
            anomaly_count = 0
        
        return {
            'timestamp': now,
            'total_flows': total_flows,
            'denied_flows': denied_flows,
            'denied_flows_per_minute': denied_flows,
            'bandwidth_mbps': bandwidth_mbps,
            'total_bytes': total_bytes,
            'top_talkers': top_talkers,
            'top_applications': top_apps,
            'unique_dest_ports_per_ip': max_ports_per_ip,
            'anomalies_per_minute': anomaly_count,
            'unique_sources': len(set(f.source_ip for f in flows)),
            'unique_destinations': len(set(f.dest_ip for f in flows))
        }
    
    def _check_alerts(self, metrics: Dict[str, Any], flows: List[FlowRecord]):
        """Check alert conditions and trigger alerts."""
        current_time = datetime.now()
        
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            
            # Check if rule is in cooldown
            if rule.name in self.active_alerts:
                last_alert_time = self.active_alerts[rule.name]
                if (current_time - last_alert_time).seconds < rule.cooldown:
                    continue
            
            # Evaluate condition
            try:
                condition_met = self._evaluate_condition(rule.condition, metrics)
                
                if condition_met:
                    alert = Alert(
                        rule_name=rule.name,
                        message=f"Alert triggered: {rule.condition}",
                        severity=rule.severity,
                        timestamp=current_time,
                        data=metrics
                    )
                    
                    self._trigger_alert(alert)
                    self.active_alerts[rule.name] = current_time
                    
            except Exception as e:
                logging.error(f"Error evaluating alert rule {rule.name}: {e}")
    
    def _evaluate_condition(self, condition: str, metrics: Dict[str, Any]) -> bool:
        """Evaluate alert condition."""
        # Simple expression evaluator
        # In production, you'd want a more secure expression parser
        try:
            # Replace metric names with values
            expr = condition
            for key, value in metrics.items():
                if isinstance(value, (int, float)):
                    expr = expr.replace(key, str(value))
            
            # Evaluate the expression
            return eval(expr)
        except:
            return False
    
    def _trigger_alert(self, alert: Alert):
        """Trigger an alert and notify callbacks."""
        logging.warning(f"ALERT [{alert.severity.upper()}]: {alert.message}")
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logging.error(f"Error in alert callback: {e}")
    
    def _log_status(self, metrics: Dict[str, Any]):
        """Log current monitoring status."""
        logging.info(
            f"Monitor Status - Flows: {metrics['total_flows']}, "
            f"Denied: {metrics['denied_flows']}, "
            f"Bandwidth: {metrics['bandwidth_mbps']:.2f} Mbps, "
            f"Anomalies: {metrics['anomalies_per_minute']}"
        )
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current monitoring metrics."""
        if self.metrics_history:
            return self.metrics_history[-1]['metrics']
        return {}
    
    def get_metrics_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get metrics history for specified time period."""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        return [
            entry for entry in self.metrics_history
            if entry['timestamp'] >= cutoff_time
        ]
    
    def get_recent_flows(self, count: int = 100) -> List[FlowRecord]:
        """Get recent flows from buffer."""
        return list(self.flow_buffer)[-count:]
    
    def export_metrics(self, output_file: str, format_type: str = 'json'):
        """Export metrics history to file."""
        metrics_data = [
            {
                'timestamp': entry['timestamp'].isoformat(),
                'metrics': entry['metrics']
            }
            for entry in self.metrics_history
        ]
        
        try:
            with open(output_file, 'w') as f:
                if format_type == 'json':
                    json.dump(metrics_data, f, indent=2, default=str)
                elif format_type == 'csv':
                    import csv
                    if metrics_data:
                        fieldnames = ['timestamp'] + list(metrics_data[0]['metrics'].keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for entry in metrics_data:
                            row = {'timestamp': entry['timestamp']}
                            row.update(entry['metrics'])
                            writer.writerow(row)
            
            logging.info(f"Metrics exported to: {output_file}")
            
        except Exception as e:
            logging.error(f"Failed to export metrics: {e}")
    
    def create_dashboard_data(self) -> Dict[str, Any]:
        """Create data structure for dashboard visualization."""
        current_metrics = self.get_current_metrics()
        recent_flows = self.get_recent_flows()
        
        # Convert flows to dict format for JSON serialization
        flows_data = []
        for flow in recent_flows:
            flows_data.append({
                'timestamp': flow.timestamp,
                'source_ip': flow.source_ip,
                'dest_ip': flow.dest_ip,
                'source_port': flow.source_port,
                'dest_port': flow.dest_port,
                'protocol': flow.protocol,
                'action': flow.action,
                'application': flow.application,
                'bytes_sent': flow.bytes_sent,
                'bytes_received': flow.bytes_received
            })
        
        return {
            'current_metrics': current_metrics,
            'flows': flows_data,
            'metrics_history': [
                {
                    'timestamp': entry['timestamp'].isoformat(),
                    'total_flows': entry['metrics'].get('total_flows', 0),
                    'denied_flows': entry['metrics'].get('denied_flows', 0),
                    'bandwidth_mbps': entry['metrics'].get('bandwidth_mbps', 0)
                }
                for entry in self.get_metrics_history(60)
            ]
        }


def email_alert_callback(alert: Alert):
    """Sample email alert callback."""
    # This would integrate with an email service
    logging.info(f"EMAIL ALERT: {alert.message}")


def slack_alert_callback(alert: Alert):
    """Sample Slack alert callback."""
    # This would integrate with Slack API
    logging.info(f"SLACK ALERT: {alert.message}")


# Example usage
if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Create monitor
    monitor = FlowMonitor("192.168.1.1", api_key="your_api_key_here")
    
    # Add alert callbacks
    monitor.add_alert_callback(email_alert_callback)
    monitor.add_alert_callback(slack_alert_callback)
    
    # Start monitoring
    try:
        monitor.start_monitoring(interval=30, enable_alerts=True)
        
        # Keep running
        while True:
            time.sleep(60)
            current_metrics = monitor.get_current_metrics()
            print(f"Current metrics: {current_metrics}")
            
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped")