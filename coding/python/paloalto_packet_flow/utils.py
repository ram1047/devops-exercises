"""
Utility Functions Module
========================

This module provides common utility functions for logging, configuration
management, file operations, and other helper functions used throughout
the Palo Alto packet flow analysis tool.
"""

import os
import json
import logging
import logging.handlers
from typing import Dict, Any, Optional, List
from datetime import datetime
import ipaddress
import re
from pathlib import Path

# Optional YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None, 
                 max_log_size: int = 10 * 1024 * 1024, backup_count: int = 5):
    """Setup logging configuration."""
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_log_size, backupCount=backup_count
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    logging.info(f"Logging configured with level: {log_level}")


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or return default configuration."""
    default_config = {
        'parser': {
            'timestamp_format': '%Y-%m-%d %H:%M:%S',
            'timezone': 'UTC',
            'ignore_malformed': True,
            'max_errors': 100
        },
        'analyzer': {
            'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389, 5900, 5985, 5986],
            'anomaly_thresholds': {
                'bytes_per_second': 10000000,  # 10MB/s
                'packets_per_second': 1000,
                'session_duration': 3600,  # 1 hour
                'failed_connections': 10
            },
            'malicious_ips': []
        },
        'visualizer': {
            'default_layout': 'hierarchical',
            'color_theme': 'default',
            'max_nodes': 100
        },
        'monitor': {
            'poll_interval': 30,
            'alert_threshold': 5,
            'retry_attempts': 3,
            'timeout': 30
        }
    }
    
    if not config_path:
        return default_config
    
    if not os.path.exists(config_path):
        logging.warning(f"Config file not found: {config_path}, using defaults")
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                if YAML_AVAILABLE:
                    user_config = yaml.safe_load(f)
                else:
                    raise ImportError("PyYAML not available for YAML config files")
            else:
                user_config = json.load(f)
        
        # Merge with defaults
        merged_config = merge_configs(default_config, user_config)
        logging.info(f"Configuration loaded from: {config_path}")
        return merged_config
        
    except Exception as e:
        logging.error(f"Failed to load config from {config_path}: {e}")
        return default_config


def merge_configs(default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge user configuration with defaults."""
    result = default.copy()
    
    for key, value in user.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    
    return result


def save_config(config: Dict[str, Any], config_path: str):
    """Save configuration to file."""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    try:
        with open(config_path, 'w') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                if YAML_AVAILABLE:
                    yaml.dump(config, f, default_flow_style=False, indent=2)
                else:
                    raise ImportError("PyYAML not available for YAML config files")
            else:
                json.dump(config, f, indent=2)
        
        logging.info(f"Configuration saved to: {config_path}")
    except Exception as e:
        logging.error(f"Failed to save config to {config_path}: {e}")
        raise


def validate_ip_address(ip_str: str) -> bool:
    """Validate if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate if a port number is valid."""
    return 0 <= port <= 65535


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def categorize_port(port: int) -> str:
    """Categorize a port number based on well-known services."""
    well_known_ports = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
        25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
        993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3389: 'rdp',
        5900: 'vnc', 5985: 'winrm', 5986: 'winrm-https'
    }
    
    if port in well_known_ports:
        return well_known_ports[port]
    elif 1 <= port <= 1023:
        return 'well-known'
    elif 1024 <= port <= 49151:
        return 'registered'
    elif 49152 <= port <= 65535:
        return 'dynamic'
    else:
        return 'unknown'


def format_bytes(bytes_count: int) -> str:
    """Format byte count in human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in human readable format."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f}h"
    else:
        days = seconds / 86400
        return f"{days:.2f}d"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing invalid characters."""
    # Remove invalid characters for filesystem
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Truncate if too long
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename


def ensure_directory(directory_path: str):
    """Ensure directory exists, create if it doesn't."""
    Path(directory_path).mkdir(parents=True, exist_ok=True)


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def compress_logs(log_directory: str, days_to_keep: int = 30):
    """Compress and clean old log files."""
    import gzip
    import shutil
    from datetime import timedelta
    
    cutoff_date = datetime.now() - timedelta(days=days_to_keep)
    
    for file_path in Path(log_directory).glob('*.log'):
        file_stat = file_path.stat()
        file_date = datetime.fromtimestamp(file_stat.st_mtime)
        
        if file_date < cutoff_date:
            # Compress old log files
            compressed_path = file_path.with_suffix('.log.gz')
            
            if not compressed_path.exists():
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Remove original file after compression
                file_path.unlink()
                logging.info(f"Compressed and removed old log file: {file_path}")


def parse_time_range(time_str: str) -> Dict[str, datetime]:
    """Parse time range string and return start/end datetime objects."""
    # Support formats like "1h", "30m", "2d", "1w"
    time_pattern = re.compile(r'^(\d+)([hmsdw])$')
    match = time_pattern.match(time_str.lower())
    
    if not match:
        raise ValueError(f"Invalid time format: {time_str}")
    
    value, unit = match.groups()
    value = int(value)
    
    now = datetime.now()
    
    if unit == 's':
        delta = timedelta(seconds=value)
    elif unit == 'm':
        delta = timedelta(minutes=value)
    elif unit == 'h':
        delta = timedelta(hours=value)
    elif unit == 'd':
        delta = timedelta(days=value)
    elif unit == 'w':
        delta = timedelta(weeks=value)
    else:
        raise ValueError(f"Unsupported time unit: {unit}")
    
    return {
        'start': now - delta,
        'end': now
    }


def create_filter_expression(filters: Dict[str, Any]) -> str:
    """Create a filter expression from filter dictionary."""
    expressions = []
    
    for field, value in filters.items():
        if isinstance(value, str):
            expressions.append(f"{field} == '{value}'")
        elif isinstance(value, list):
            # Multiple values (OR condition)
            value_exprs = [f"{field} == '{v}'" for v in value]
            expressions.append(f"({' or '.join(value_exprs)})")
        elif isinstance(value, dict):
            # Range or comparison
            if 'min' in value:
                expressions.append(f"{field} >= {value['min']}")
            if 'max' in value:
                expressions.append(f"{field} <= {value['max']}")
            if 'eq' in value:
                expressions.append(f"{field} == {value['eq']}")
            if 'ne' in value:
                expressions.append(f"{field} != {value['ne']}")
        else:
            expressions.append(f"{field} == {value}")
    
    return ' and '.join(expressions) if expressions else ''


def calculate_network_statistics(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate basic network statistics from flows."""
    if not flows:
        return {}
    
    total_flows = len(flows)
    unique_sources = len(set(flow.get('source_ip', '') for flow in flows))
    unique_destinations = len(set(flow.get('dest_ip', '') for flow in flows))
    
    # Calculate bandwidth
    total_bytes = sum(
        flow.get('bytes_sent', 0) + flow.get('bytes_received', 0) 
        for flow in flows
    )
    
    # Calculate duration
    durations = [flow.get('duration', 0) for flow in flows if flow.get('duration', 0) > 0]
    avg_duration = sum(durations) / len(durations) if durations else 0
    
    # Protocol distribution
    protocols = {}
    for flow in flows:
        protocol = flow.get('protocol', 'unknown')
        protocols[protocol] = protocols.get(protocol, 0) + 1
    
    return {
        'total_flows': total_flows,
        'unique_sources': unique_sources,
        'unique_destinations': unique_destinations,
        'total_bytes': total_bytes,
        'total_bytes_formatted': format_bytes(total_bytes),
        'average_duration': avg_duration,
        'average_duration_formatted': format_duration(avg_duration),
        'protocol_distribution': protocols
    }


def generate_report_summary(analysis_results: Dict[str, Any]) -> str:
    """Generate a text summary of analysis results."""
    summary_lines = [
        "PALO ALTO PACKET FLOW ANALYSIS SUMMARY",
        "=" * 45,
        "",
        f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Flows Analyzed: {analysis_results.get('total_flows', 0):,}",
        f"Unique Sessions: {analysis_results.get('unique_sessions', 0):,}",
        ""
    ]
    
    # Top applications
    if analysis_results.get('top_applications'):
        summary_lines.extend([
            "TOP APPLICATIONS:",
            "-" * 20
        ])
        for app, count in list(analysis_results['top_applications'].items())[:5]:
            summary_lines.append(f"  {app}: {count:,} flows")
        summary_lines.append("")
    
    # Security summary
    anomaly_count = len(analysis_results.get('anomalies', []))
    event_count = len(analysis_results.get('security_events', []))
    
    summary_lines.extend([
        "SECURITY SUMMARY:",
        "-" * 20,
        f"  Anomalies Detected: {anomaly_count}",
        f"  Security Events: {event_count}",
        ""
    ])
    
    # Critical issues
    critical_anomalies = [
        a for a in analysis_results.get('anomalies', []) 
        if a.get('severity') == 'critical'
    ]
    
    if critical_anomalies:
        summary_lines.extend([
            "CRITICAL ISSUES:",
            "-" * 20
        ])
        for anomaly in critical_anomalies[:3]:
            summary_lines.append(f"  • {anomaly.get('description', 'Unknown issue')}")
        summary_lines.append("")
    
    # Bandwidth summary
    if analysis_results.get('bandwidth_stats'):
        bandwidth = analysis_results['bandwidth_stats']
        total_bytes = bandwidth.get('total_bytes_sent', 0) + bandwidth.get('total_bytes_received', 0)
        summary_lines.extend([
            "BANDWIDTH SUMMARY:",
            "-" * 20,
            f"  Total Data Transferred: {format_bytes(total_bytes)}",
            f"  Total Packets: {bandwidth.get('total_packets', 0):,}",
            ""
        ])
    
    return "\n".join(summary_lines)


class ProgressTracker:
    """Simple progress tracker for long-running operations."""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()
    
    def update(self, increment: int = 1):
        """Update progress."""
        self.current += increment
        if self.current > self.total:
            self.current = self.total
        
        # Print progress every 10% or every 1000 items
        if self.current % max(1, self.total // 10) == 0 or self.current % 1000 == 0:
            self._print_progress()
    
    def _print_progress(self):
        """Print current progress."""
        percentage = (self.current / self.total * 100) if self.total > 0 else 0
        elapsed = datetime.now() - self.start_time
        
        if self.current > 0:
            eta = elapsed * (self.total - self.current) / self.current
            eta_str = format_duration(eta.total_seconds())
        else:
            eta_str = "Unknown"
        
        print(f"\r{self.description}: {self.current}/{self.total} "
              f"({percentage:.1f}%) - ETA: {eta_str}", end="", flush=True)
    
    def finish(self):
        """Mark progress as complete."""
        self.current = self.total
        self._print_progress()
        print()  # New line


def create_sample_config() -> Dict[str, Any]:
    """Create a sample configuration file."""
    return {
        "parser": {
            "timestamp_format": "%Y-%m-%d %H:%M:%S",
            "timezone": "UTC",
            "ignore_malformed": True,
            "max_errors": 100,
            "field_separator": ","
        },
        "analyzer": {
            "suspicious_ports": [22, 23, 135, 139, 445, 1433, 3389, 5900],
            "anomaly_thresholds": {
                "bytes_per_second": 10000000,
                "packets_per_second": 1000,
                "session_duration": 3600,
                "failed_connections": 10
            },
            "malicious_ips": [
                "192.0.2.1",
                "198.51.100.1"
            ]
        },
        "visualizer": {
            "default_layout": "hierarchical",
            "color_theme": "default",
            "max_nodes": 100,
            "output_formats": ["html", "svg", "png"]
        },
        "monitor": {
            "poll_interval": 30,
            "alert_threshold": 5,
            "retry_attempts": 3,
            "timeout": 30,
            "enable_alerts": False
        }
    }