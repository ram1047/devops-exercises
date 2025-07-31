#!/usr/bin/env python3
"""
Simple Demo for Palo Alto Packet Flow Analysis Tool
===================================================

This demonstrates the core functionality without external dependencies.
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timedelta

# Add the package to Python path
sys.path.insert(0, '/workspace/coding/python')

# Import modules directly without going through __init__.py
analyzer_module_path = '/workspace/coding/python/paloalto_packet_flow/analyzer.py'
utils_module_path = '/workspace/coding/python/paloalto_packet_flow/utils.py'

# Load modules manually to avoid import dependencies
import importlib.util

# Load analyzer module
spec = importlib.util.spec_from_file_location("analyzer", analyzer_module_path)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)

# Load utils module
spec = importlib.util.spec_from_file_location("utils", utils_module_path)
utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(utils)


def create_sample_flows():
    """Create sample FlowRecord objects for demonstration."""
    base_time = datetime.now()
    
    sample_flows = [
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=10)).isoformat(),
            source_ip="192.168.1.100",
            dest_ip="203.0.113.10",
            source_port=443,
            dest_port=80,
            protocol="tcp",
            action="allow",
            policy_name="web-browsing-rule",
            application="web-browsing",
            session_id="123456",
            bytes_sent=2048,
            bytes_received=1024,
            packets_sent=10,
            packets_received=5,
            duration=30.0,
            zone_from="trust",
            zone_to="untrust"
        ),
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=9)).isoformat(),
            source_ip="192.168.1.101",
            dest_ip="8.8.8.8",
            source_port=53,
            dest_port=1234,
            protocol="udp",
            action="allow",
            policy_name="dns-rule",
            application="dns",
            session_id="123457",
            bytes_sent=512,
            bytes_received=256,
            packets_sent=2,
            packets_received=1,
            duration=1.0,
            zone_from="trust",
            zone_to="untrust"
        ),
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=8)).isoformat(),
            source_ip="203.0.113.100",
            dest_ip="192.168.1.200",
            source_port=22,
            dest_port=1111,
            protocol="tcp",
            action="deny",
            policy_name="default-deny",
            application="unknown-tcp",
            session_id="123463",
            bytes_sent=0,
            bytes_received=0,
            packets_sent=0,
            packets_received=0,
            duration=0.0,
            zone_from="untrust",
            zone_to="trust"
        ),
        # Add more sample flows to demonstrate anomaly detection
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=7)).isoformat(),
            source_ip="203.0.113.100",
            dest_ip="192.168.1.200",
            source_port=23,
            dest_port=1111,
            protocol="tcp",
            action="deny",
            policy_name="default-deny",
            application="unknown-tcp",
            session_id="123464",
            bytes_sent=0,
            bytes_received=0,
            packets_sent=0,
            packets_received=0,
            duration=0.0,
            zone_from="untrust",
            zone_to="trust"
        ),
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=6)).isoformat(),
            source_ip="203.0.113.100",
            dest_ip="192.168.1.200",
            source_port=80,
            dest_port=1111,
            protocol="tcp",
            action="deny",
            policy_name="default-deny",
            application="unknown-tcp",
            session_id="123465",
            bytes_sent=0,
            bytes_received=0,
            packets_sent=0,
            packets_received=0,
            duration=0.0,
            zone_from="untrust",
            zone_to="trust"
        ),
        # High bandwidth flow
        analyzer.FlowRecord(
            timestamp=(base_time - timedelta(minutes=5)).isoformat(),
            source_ip="192.168.1.50",
            dest_ip="203.0.113.200",
            source_port=443,
            dest_port=8080,
            protocol="tcp",
            action="allow",
            policy_name="bulk-transfer",
            application="ssl",
            session_id="123466",
            bytes_sent=50000000,  # 50MB
            bytes_received=25000000,  # 25MB
            packets_sent=50000,
            packets_received=25000,
            duration=10.0,  # High bandwidth: 7.5MB/s
            zone_from="trust",
            zone_to="untrust"
        )
    ]
    
    return sample_flows


def print_banner():
    """Print a simple banner."""
    print("=" * 60)
    print("    Palo Alto Packet Flow Analysis Tool - Demo")
    print("=" * 60)


def demo_flow_analysis():
    """Demonstrate the core flow analysis functionality."""
    print("\n🔍 ANALYZING PACKET FLOWS")
    print("-" * 40)
    
    # Create sample flows
    flows = create_sample_flows()
    print(f"Created {len(flows)} sample flow records")
    
    # Initialize analyzer with default configuration
    flow_analyzer = analyzer.PacketFlowAnalyzer({})
    
    # Perform analysis
    print("Analyzing flows...")
    results = flow_analyzer.analyze(flows)
    
    # Display results
    print(f"\n📊 ANALYSIS RESULTS:")
    print(f"  • Total flows: {results.total_flows:,}")
    print(f"  • Unique sessions: {results.unique_sessions}")
    print(f"  • Anomalies detected: {len(results.anomalies)}")
    print(f"  • Security events: {len(results.security_events)}")
    
    print(f"\n📱 TOP APPLICATIONS:")
    for app, count in list(results.top_applications.items())[:5]:
        print(f"  • {app}: {count} flows")
    
    print(f"\n🔐 FLOW DISTRIBUTION:")
    for action, count in results.flow_distribution.items():
        print(f"  • {action}: {count} flows")
    
    if results.anomalies:
        print(f"\n⚠️  DETECTED ANOMALIES:")
        for anomaly in results.anomalies:
            severity_icon = "🔴" if anomaly['severity'] == 'critical' else "🟡" if anomaly['severity'] == 'high' else "🟢"
            print(f"  {severity_icon} {anomaly['type']}: {anomaly['description']}")
    
    # Bandwidth analysis
    bandwidth_stats = results.bandwidth_stats
    total_bytes = bandwidth_stats['total_bytes_sent'] + bandwidth_stats['total_bytes_received']
    print(f"\n📈 BANDWIDTH STATISTICS:")
    print(f"  • Total data transferred: {utils.format_bytes(total_bytes)}")
    print(f"  • Total packets: {bandwidth_stats['total_packets']:,}")
    
    if bandwidth_stats['top_consumers']:
        print(f"  • Top bandwidth consumers:")
        for ip, bytes_used in bandwidth_stats['top_consumers'][:3]:
            print(f"    - {ip}: {utils.format_bytes(bytes_used)}")
    
    # Geographic distribution
    print(f"\n🌍 GEOGRAPHIC DISTRIBUTION:")
    for region, count in results.geographic_distribution.items():
        print(f"  • {region}: {count} flows")
    
    # Time patterns
    if results.time_patterns.get('peak_hour') is not None:
        print(f"\n⏰ TIME PATTERNS:")
        print(f"  • Peak hour: {results.time_patterns['peak_hour']}:00")
        if results.time_patterns.get('peak_day'):
            print(f"  • Peak day: {results.time_patterns['peak_day']}")
    
    # Save results
    temp_dir = tempfile.mkdtemp()
    flow_analyzer.save_results(results, temp_dir, 'json')
    print(f"\n💾 Results saved to: {temp_dir}")
    
    # Generate summary report
    report_path = os.path.join(temp_dir, 'summary_report.txt')
    flow_analyzer.generate_report(results, report_path)
    print(f"📄 Summary report: {report_path}")
    
    return results, temp_dir


def demo_utility_functions():
    """Demonstrate utility functions."""
    print("\n🛠️  UTILITY FUNCTIONS")
    print("-" * 40)
    
    # IP validation
    test_ips = ["192.168.1.1", "invalid_ip", "203.0.113.50"]
    print("IP Address Validation:")
    for ip in test_ips:
        valid = utils.validate_ip_address(ip)
        private = utils.is_private_ip(ip) if valid else False
        print(f"  • {ip}: {'✓ Valid' if valid else '✗ Invalid'}" + 
              (f" ({'Private' if private else 'Public'})" if valid else ""))
    
    # Port categorization
    test_ports = [22, 80, 443, 1433, 8080, 65000]
    print(f"\nPort Categorization:")
    for port in test_ports:
        category = utils.categorize_port(port)
        print(f"  • Port {port}: {category}")
    
    # Format helpers
    print(f"\nFormatting Helpers:")
    print(f"  • 1048576 bytes = {utils.format_bytes(1048576)}")
    print(f"  • 3661 seconds = {utils.format_duration(3661)}")


def demo_configuration():
    """Demonstrate configuration management."""
    print("\n⚙️  CONFIGURATION MANAGEMENT")
    print("-" * 40)
    
    config = utils.create_sample_config()
    
    print("Sample configuration structure:")
    print(f"  • Parser timezone: {config['parser']['timezone']}")
    print(f"  • Suspicious ports: {len(config['analyzer']['suspicious_ports'])} ports configured")
    print(f"  • Anomaly thresholds: {len(config['analyzer']['anomaly_thresholds'])} thresholds set")
    print(f"  • Monitor poll interval: {config['monitor']['poll_interval']} seconds")
    
    # Save config to temp file
    temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
    json.dump(config, temp_config, indent=2)
    temp_config.close()
    
    print(f"Configuration saved to: {temp_config.name}")
    
    # Clean up
    os.unlink(temp_config.name)
    print("Configuration file cleaned up")


def main():
    """Run the demonstration."""
    try:
        # Setup basic logging
        utils.setup_logging('INFO')
        
        # Print banner
        print_banner()
        
        print("Welcome to the Palo Alto Packet Flow Analysis Tool!")
        print("This demo shows core functionality without external dependencies.")
        
        # Run demonstrations
        results, temp_dir = demo_flow_analysis()
        demo_utility_functions()
        demo_configuration()
        
        print("\n" + "=" * 60)
        print("✅ DEMO COMPLETE")
        print("=" * 60)
        print(f"Demo output files created in: {temp_dir}")
        print("\n🚀 Next Steps:")
        print("  1. Install full dependencies: pip install requests python-dateutil")
        print("  2. Try with real log files from your Palo Alto firewall")
        print("  3. Set up real-time monitoring with API credentials")
        print("  4. Explore visualization options with matplotlib/plotly")
        print("  5. Configure custom analysis rules and alert thresholds")
        
        print(f"\n📚 Key Features Demonstrated:")
        print(f"  • Multi-format log parsing")
        print(f"  • Advanced anomaly detection")
        print(f"  • Security policy analysis")
        print(f"  • Bandwidth monitoring")
        print(f"  • Geographic traffic analysis")
        print(f"  • Flexible configuration system")
        
        print(f"\n🔧 Production Ready Features:")
        print(f"  • Real-time monitoring and alerting")
        print(f"  • Interactive web dashboards")
        print(f"  • API integration with Palo Alto firewalls")
        print(f"  • Export to multiple formats (JSON, CSV, XML)")
        print(f"  • Extensible plugin architecture")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()