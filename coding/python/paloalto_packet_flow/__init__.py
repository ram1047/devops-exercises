"""
Palo Alto Packet Flow Analysis Tool
===================================

A comprehensive Python package for analyzing, visualizing, and monitoring
packet flows in Palo Alto Networks firewalls.

Features:
- Multi-format log parsing (CSV, Syslog, PAN-OS native)
- Advanced flow analysis and anomaly detection
- Interactive visualizations and dashboards
- Real-time monitoring with alerting
- Export capabilities in multiple formats

Basic usage:
    from paloalto_packet_flow import PacketFlowAnalyzer, LogParser
    
    # Parse logs
    parser = LogParser({})
    flows = parser.parse_file('traffic.log')
    
    # Analyze flows
    analyzer = PacketFlowAnalyzer({})
    results = analyzer.analyze(flows)
    
    # Generate report
    analyzer.save_results(results, './output', 'json')
"""

__version__ = "1.0.0"
__author__ = "Palo Alto Packet Flow Analysis Team"
__email__ = "support@example.com"
__license__ = "MIT"

# Core modules
from .analyzer import (
    PacketFlowAnalyzer,
    FlowRecord,
    FlowAnalysisResult
)

from .parser import (
    LogParser,
    LogParseError,
    LogParserConfig
)

from .visualizer import (
    FlowVisualizer,
    VisualizationError
)

from .monitor import (
    FlowMonitor,
    PaloAltoAPI,
    AlertRule,
    Alert,
    email_alert_callback,
    slack_alert_callback
)

from .utils import (
    setup_logging,
    load_config,
    save_config,
    validate_ip_address,
    validate_port,
    is_private_ip,
    categorize_port,
    format_bytes,
    format_duration,
    create_sample_config,
    ProgressTracker
)

# Package metadata
__all__ = [
    # Analyzer
    'PacketFlowAnalyzer',
    'FlowRecord',
    'FlowAnalysisResult',
    
    # Parser
    'LogParser',
    'LogParseError',
    'LogParserConfig',
    
    # Visualizer
    'FlowVisualizer',
    'VisualizationError',
    
    # Monitor
    'FlowMonitor',
    'PaloAltoAPI',
    'AlertRule',
    'Alert',
    'email_alert_callback',
    'slack_alert_callback',
    
    # Utils
    'setup_logging',
    'load_config',
    'save_config',
    'validate_ip_address',
    'validate_port',
    'is_private_ip',
    'categorize_port',
    'format_bytes',
    'format_duration',
    'create_sample_config',
    'ProgressTracker'
]


def get_version():
    """Get package version."""
    return __version__


def print_banner():
    """Print package banner."""
    banner = f"""
╔═══════════════════════════════════════════════════════════════╗
║              Palo Alto Packet Flow Analysis Tool             ║
║                         Version {__version__}                           ║
╠═══════════════════════════════════════════════════════════════╣
║  Comprehensive packet flow analysis for Palo Alto Networks   ║
║  firewalls with real-time monitoring and visualization.      ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


# Configuration shortcuts
def create_default_config():
    """Create a default configuration dictionary."""
    return create_sample_config()


def quick_analyze(log_file: str, output_dir: str = './output'):
    """Quick analysis function for simple use cases."""
    from . import LogParser, PacketFlowAnalyzer
    
    print(f"Starting quick analysis of {log_file}...")
    
    # Parse logs
    parser = LogParser({})
    flows = parser.parse_file(log_file)
    
    if not flows:
        print("No flows found in log file")
        return None
    
    # Analyze flows
    analyzer = PacketFlowAnalyzer({})
    results = analyzer.analyze(flows)
    
    # Save results
    analyzer.save_results(results, output_dir, 'json')
    
    # Generate summary report
    report_path = f"{output_dir}/summary_report.txt"
    analyzer.generate_report(results, report_path)
    
    print(f"Analysis complete! Results saved to {output_dir}")
    return results


def quick_visualize(data_file: str, output_file: str = 'visualization.html'):
    """Quick visualization function for simple use cases."""
    from . import FlowVisualizer
    
    print(f"Creating visualization from {data_file}...")
    
    visualizer = FlowVisualizer({})
    viz_content = visualizer.create_visualization(data_file, output_format='html')
    visualizer.save(viz_content, output_file)
    
    print(f"Visualization saved to {output_file}")


def start_monitoring(firewall_ip: str, api_key: str, interval: int = 30):
    """Quick start monitoring function."""
    from . import FlowMonitor, setup_logging
    import logging
    
    # Setup basic logging
    setup_logging('INFO')
    
    print(f"Starting monitoring of firewall {firewall_ip}...")
    
    # Create and start monitor
    monitor = FlowMonitor(firewall_ip, api_key)
    monitor.start_monitoring(interval=interval, enable_alerts=True)
    
    try:
        import time
        while True:
            time.sleep(60)
            metrics = monitor.get_current_metrics()
            if metrics:
                print(f"Current flows: {metrics.get('total_flows', 0)}, "
                      f"Denied: {metrics.get('denied_flows', 0)}, "
                      f"Bandwidth: {metrics.get('bandwidth_mbps', 0):.2f} Mbps")
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped")


# Version check function
def check_dependencies():
    """Check if optional dependencies are available."""
    dependencies = {
        'matplotlib': 'Plotting and chart generation',
        'plotly': 'Interactive visualizations',
        'networkx': 'Network graph layouts',
        'pandas': 'Data manipulation (recommended)',
        'requests': 'API communication',
        'yaml': 'YAML configuration support'
    }
    
    available = {}
    missing = []
    
    for dep, description in dependencies.items():
        try:
            __import__(dep)
            available[dep] = True
        except ImportError:
            available[dep] = False
            missing.append((dep, description))
    
    print("Dependency Status:")
    print("=" * 50)
    
    for dep, status in available.items():
        status_str = "✓ Available" if status else "✗ Missing"
        print(f"{dep:15} {status_str}")
    
    if missing:
        print(f"\nMissing optional dependencies:")
        for dep, desc in missing:
            print(f"  {dep}: {desc}")
        print(f"\nInstall with: pip install {' '.join(dep for dep, _ in missing)}")
    else:
        print(f"\nAll dependencies available!")
    
    return available


# Main entry point for CLI usage
def main():
    """Main entry point for command line usage."""
    import sys
    from .main import main as cli_main
    
    # Print banner
    print_banner()
    
    # Run CLI
    sys.exit(cli_main())


if __name__ == "__main__":
    main()