#!/usr/bin/env python3
"""
Palo Alto Packet Flow Analysis Tool
===================================

A comprehensive tool for analyzing packet flows in Palo Alto Networks firewalls.
This tool provides capabilities for:
- Packet flow visualization
- Security policy analysis
- Traffic pattern detection
- Flow state tracking
- Performance monitoring
"""

import argparse
import sys
from typing import Dict, Any
from .analyzer import PacketFlowAnalyzer
from .visualizer import FlowVisualizer
from .parser import LogParser
from .utils import setup_logging, load_config


def main():
    """Main entry point for the Palo Alto Packet Flow Analysis Tool."""
    parser = argparse.ArgumentParser(
        description="Palo Alto Packet Flow Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze --log-file traffic.log --output-dir ./results
  %(prog)s visualize --flow-data flows.json --format svg
  %(prog)s monitor --firewall-ip 192.168.1.1 --api-key YOUR_KEY
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze packet flows from logs')
    analyze_parser.add_argument('--log-file', required=True, help='Path to traffic log file')
    analyze_parser.add_argument('--output-dir', default='./output', help='Output directory for results')
    analyze_parser.add_argument('--format', choices=['json', 'csv', 'xml'], default='json', help='Output format')
    analyze_parser.add_argument('--filter', help='Filter expression for flows')
    
    # Visualize command
    viz_parser = subparsers.add_parser('visualize', help='Create flow visualizations')
    viz_parser.add_argument('--flow-data', required=True, help='Path to flow data file')
    viz_parser.add_argument('--output', help='Output file path')
    viz_parser.add_argument('--format', choices=['svg', 'png', 'html'], default='html', help='Visualization format')
    viz_parser.add_argument('--layout', choices=['hierarchical', 'circular', 'force'], default='hierarchical', help='Layout algorithm')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Real-time flow monitoring')
    monitor_parser.add_argument('--firewall-ip', required=True, help='Firewall IP address')
    monitor_parser.add_argument('--api-key', help='API key for authentication')
    monitor_parser.add_argument('--interval', type=int, default=30, help='Monitoring interval in seconds')
    monitor_parser.add_argument('--alerts', action='store_true', help='Enable alerting')
    
    # Global options
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    log_level = 'DEBUG' if args.debug else ('INFO' if args.verbose else 'WARNING')
    setup_logging(log_level)
    
    # Load configuration
    config = load_config(args.config)
    
    try:
        if args.command == 'analyze':
            return analyze_flows(args, config)
        elif args.command == 'visualize':
            return visualize_flows(args, config)
        elif args.command == 'monitor':
            return monitor_flows(args, config)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def analyze_flows(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    """Analyze packet flows from log files."""
    print(f"Analyzing flows from: {args.log_file}")
    
    # Parse logs
    parser = LogParser(config.get('parser', {}))
    flows = parser.parse_file(args.log_file, filter_expr=args.filter)
    
    # Analyze flows
    analyzer = PacketFlowAnalyzer(config.get('analyzer', {}))
    analysis_results = analyzer.analyze(flows)
    
    # Save results
    analyzer.save_results(analysis_results, args.output_dir, args.format)
    
    print(f"Analysis complete. Results saved to: {args.output_dir}")
    print(f"Processed {len(flows)} flows")
    print(f"Found {len(analysis_results.get('anomalies', []))} anomalies")
    
    return 0


def visualize_flows(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    """Create flow visualizations."""
    print(f"Creating visualization from: {args.flow_data}")
    
    visualizer = FlowVisualizer(config.get('visualizer', {}))
    visualization = visualizer.create_visualization(
        args.flow_data, 
        layout=args.layout,
        output_format=args.format
    )
    
    output_path = args.output or f"flow_visualization.{args.format}"
    visualizer.save(visualization, output_path)
    
    print(f"Visualization saved to: {output_path}")
    return 0


def monitor_flows(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    """Monitor flows in real-time."""
    print(f"Starting real-time monitoring of: {args.firewall_ip}")
    
    from .monitor import FlowMonitor
    
    monitor = FlowMonitor(
        firewall_ip=args.firewall_ip,
        api_key=args.api_key,
        config=config.get('monitor', {})
    )
    
    monitor.start_monitoring(
        interval=args.interval,
        enable_alerts=args.alerts
    )
    
    return 0


if __name__ == '__main__':
    sys.exit(main())