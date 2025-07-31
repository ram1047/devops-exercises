#!/usr/bin/env python3
"""
Palo Alto Packet Flow Analysis Tool - Demo Script
=================================================

This script demonstrates the capabilities of the Palo Alto packet flow
analysis tool with sample data and common use cases.
"""

import os
import json
import tempfile
from datetime import datetime, timedelta
from typing import List

from . import (
    PacketFlowAnalyzer, LogParser, FlowVisualizer, FlowMonitor,
    FlowRecord, setup_logging, print_banner, create_sample_config
)


def create_sample_log_data() -> str:
    """Create sample log data for demonstration."""
    sample_logs = [
        # PAN-OS format traffic logs
        "TRAFFIC,2023/01/01 12:00:00,001234567890,TRAFFIC,,2023/01/01 12:00:00,192.168.1.100,203.0.113.10,0.0.0.0,0.0.0.0,web-browsing-rule,user1,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:00:00,123456,1,443,80,0,0,0x0,tcp,allow,2048,1024,1024,10,2023/01/01 12:00:00,30,any,0,123456789,0x0,192.168.0.0-192.168.255.255,203.0.113.0-203.0.113.255,0,5,3,aged-out",
        "TRAFFIC,2023/01/01 12:01:00,001234567890,TRAFFIC,,2023/01/01 12:01:00,192.168.1.101,8.8.8.8,0.0.0.0,0.0.0.0,dns-rule,user2,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:01:00,123457,1,53,1234,0,0,0x0,udp,allow,512,256,256,2,2023/01/01 12:01:00,1,any,0,123456790,0x0,192.168.0.0-192.168.255.255,8.8.8.0-8.8.8.255,0,1,1,aged-out",
        "TRAFFIC,2023/01/01 12:02:00,001234567890,TRAFFIC,,2023/01/01 12:02:00,10.0.0.50,192.168.1.100,0.0.0.0,0.0.0.0,ssh-rule,admin,,ssh,vsys1,dmz,trust,ethernet1/3,ethernet1/1,default,2023/01/01 12:02:00,123458,1,22,2222,0,0,0x0,tcp,allow,1024,512,512,5,2023/01/01 12:02:00,300,any,0,123456791,0x0,10.0.0.0-10.0.0.255,192.168.0.0-192.168.255.255,0,3,2,aged-out",
        "TRAFFIC,2023/01/01 12:03:00,001234567890,TRAFFIC,,2023/01/01 12:03:00,203.0.113.50,192.168.1.200,0.0.0.0,0.0.0.0,block-rule,,,unknown-tcp,vsys1,untrust,trust,ethernet1/2,ethernet1/1,default,2023/01/01 12:03:00,123459,1,1234,3389,0,0,0x0,tcp,deny,0,0,0,0,2023/01/01 12:03:00,0,any,0,123456792,0x0,203.0.113.0-203.0.113.255,192.168.0.0-192.168.255.255,0,0,0,tcp-rst-from-client",
        "TRAFFIC,2023/01/01 12:04:00,001234567890,TRAFFIC,,2023/01/01 12:04:00,192.168.1.150,1.1.1.1,0.0.0.0,0.0.0.0,dns-rule,user3,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:04:00,123460,1,53,5678,0,0,0x0,udp,allow,256,128,128,1,2023/01/01 12:04:00,1,any,0,123456793,0x0,192.168.0.0-192.168.255.255,1.1.1.0-1.1.1.255,0,1,1,aged-out",
        # More sample logs with different patterns
        "TRAFFIC,2023/01/01 12:05:00,001234567890,TRAFFIC,,2023/01/01 12:05:00,192.168.1.100,203.0.113.20,0.0.0.0,0.0.0.0,web-browsing-rule,user1,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:05:00,123461,1,443,443,0,0,0x0,tcp,allow,4096,2048,2048,15,2023/01/01 12:05:00,45,any,0,123456794,0x0,192.168.0.0-192.168.255.255,203.0.113.0-203.0.113.255,0,8,7,aged-out",
        "TRAFFIC,2023/01/01 12:06:00,001234567890,TRAFFIC,,2023/01/01 12:06:00,192.168.1.101,203.0.113.30,0.0.0.0,0.0.0.0,ftp-rule,user2,,ftp,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:06:00,123462,1,21,2345,0,0,0x0,tcp,allow,1536,768,768,8,2023/01/01 12:06:00,120,any,0,123456795,0x0,192.168.0.0-192.168.255.255,203.0.113.0-203.0.113.255,0,4,4,aged-out",
        # Port scanning attempt
        "TRAFFIC,2023/01/01 12:07:00,001234567890,TRAFFIC,,2023/01/01 12:07:00,203.0.113.100,192.168.1.200,0.0.0.0,0.0.0.0,default-deny,,,unknown-tcp,vsys1,untrust,trust,ethernet1/2,ethernet1/1,default,2023/01/01 12:07:00,123463,1,22,1111,0,0,0x0,tcp,deny,0,0,0,0,2023/01/01 12:07:00,0,any,0,123456796,0x0,203.0.113.0-203.0.113.255,192.168.0.0-192.168.255.255,0,0,0,tcp-rst-from-server",
        "TRAFFIC,2023/01/01 12:07:01,001234567890,TRAFFIC,,2023/01/01 12:07:01,203.0.113.100,192.168.1.200,0.0.0.0,0.0.0.0,default-deny,,,unknown-tcp,vsys1,untrust,trust,ethernet1/2,ethernet1/1,default,2023/01/01 12:07:01,123464,1,23,1111,0,0,0x0,tcp,deny,0,0,0,0,2023/01/01 12:07:01,0,any,0,123456797,0x0,203.0.113.0-203.0.113.255,192.168.0.0-192.168.255.255,0,0,0,tcp-rst-from-server",
        "TRAFFIC,2023/01/01 12:07:02,001234567890,TRAFFIC,,2023/01/01 12:07:02,203.0.113.100,192.168.1.200,0.0.0.0,0.0.0.0,default-deny,,,unknown-tcp,vsys1,untrust,trust,ethernet1/2,ethernet1/1,default,2023/01/01 12:07:02,123465,1,80,1111,0,0,0x0,tcp,deny,0,0,0,0,2023/01/01 12:07:02,0,any,0,123456798,0x0,203.0.113.0-203.0.113.255,192.168.0.0-192.168.255.255,0,0,0,tcp-rst-from-server"
    ]
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
    for log_entry in sample_logs:
        temp_file.write(log_entry + '\n')
    temp_file.close()
    
    return temp_file.name


def create_sample_flows() -> List[FlowRecord]:
    """Create sample FlowRecord objects for demonstration."""
    base_time = datetime.now()
    
    sample_flows = [
        FlowRecord(
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
        FlowRecord(
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
        FlowRecord(
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
        )
    ]
    
    return sample_flows


def demo_log_parsing():
    """Demonstrate log parsing capabilities."""
    print("\n" + "="*60)
    print("DEMO: Log Parsing")
    print("="*60)
    
    # Create sample log file
    log_file = create_sample_log_data()
    print(f"Created sample log file: {log_file}")
    
    try:
        # Initialize parser
        parser = LogParser({})
        
        # Parse the log file
        print("Parsing log file...")
        flows = parser.parse_file(log_file)
        
        print(f"Successfully parsed {len(flows)} flow records")
        
        # Show some sample flows
        print("\nSample parsed flows:")
        for i, flow in enumerate(flows[:3]):
            print(f"{i+1}. {flow.source_ip}:{flow.source_port} -> "
                  f"{flow.dest_ip}:{flow.dest_port} ({flow.action}) - {flow.application}")
        
        # Show parser statistics
        stats = parser.get_parse_statistics()
        print(f"\nParser Statistics:")
        print(f"- Parsed records: {stats['parsed_records']}")
        print(f"- Parse errors: {stats['parse_errors']}")
        print(f"- Success rate: {stats['success_rate']:.1f}%")
        
        return flows
        
    finally:
        # Clean up temp file
        os.unlink(log_file)


def demo_flow_analysis(flows: List[FlowRecord]):
    """Demonstrate flow analysis capabilities."""
    print("\n" + "="*60)
    print("DEMO: Flow Analysis")
    print("="*60)
    
    # Initialize analyzer
    analyzer = PacketFlowAnalyzer({})
    
    # Perform analysis
    print("Analyzing flows...")
    results = analyzer.analyze(flows)
    
    # Display results
    print(f"\nAnalysis Results:")
    print(f"- Total flows: {results.total_flows:,}")
    print(f"- Unique sessions: {results.unique_sessions}")
    print(f"- Anomalies detected: {len(results.anomalies)}")
    print(f"- Security events: {len(results.security_events)}")
    
    print(f"\nTop Applications:")
    for app, count in list(results.top_applications.items())[:5]:
        print(f"- {app}: {count} flows")
    
    print(f"\nFlow Distribution:")
    for action, count in results.flow_distribution.items():
        print(f"- {action}: {count} flows")
    
    if results.anomalies:
        print(f"\nDetected Anomalies:")
        for anomaly in results.anomalies[:3]:
            print(f"- {anomaly['type']}: {anomaly['description']}")
    
    # Save results to temp directory
    temp_dir = tempfile.mkdtemp()
    analyzer.save_results(results, temp_dir, 'json')
    print(f"\nResults saved to: {temp_dir}")
    
    return results, temp_dir


def demo_visualization(results, temp_dir: str):
    """Demonstrate visualization capabilities."""
    print("\n" + "="*60)
    print("DEMO: Visualization")
    print("="*60)
    
    # Initialize visualizer
    visualizer = FlowVisualizer({})
    
    # Create HTML dashboard
    print("Creating HTML dashboard...")
    results_file = os.path.join(temp_dir, 'analysis_results.json')
    
    try:
        viz_content = visualizer.create_visualization(
            results_file, 
            layout='hierarchical',
            output_format='html'
        )
        
        dashboard_path = os.path.join(temp_dir, 'dashboard.html')
        visualizer.save(viz_content, dashboard_path)
        print(f"Dashboard saved to: {dashboard_path}")
        
    except Exception as e:
        print(f"Note: Advanced visualization requires optional dependencies")
        print(f"Error: {e}")
        
        # Create basic visualization
        print("Creating basic HTML report...")
        basic_dashboard = visualizer._create_basic_html_dashboard(results.__dict__)
        dashboard_path = os.path.join(temp_dir, 'basic_dashboard.html')
        visualizer.save(basic_dashboard, dashboard_path)
        print(f"Basic dashboard saved to: {dashboard_path}")


def demo_configuration():
    """Demonstrate configuration management."""
    print("\n" + "="*60)
    print("DEMO: Configuration")
    print("="*60)
    
    # Create sample configuration
    config = create_sample_config()
    
    print("Sample configuration structure:")
    print(json.dumps(config, indent=2))
    
    # Save configuration to temp file
    temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
    json.dump(config, temp_config, indent=2)
    temp_config.close()
    
    print(f"\nConfiguration saved to: {temp_config.name}")
    
    # Load and use configuration
    from .utils import load_config
    loaded_config = load_config(temp_config.name)
    
    print("Configuration loaded successfully!")
    print(f"Parser timezone: {loaded_config['parser']['timezone']}")
    print(f"Suspicious ports: {loaded_config['analyzer']['suspicious_ports'][:5]}...")
    
    # Clean up
    os.unlink(temp_config.name)


def demo_monitoring_setup():
    """Demonstrate monitoring setup (without actual connection)."""
    print("\n" + "="*60)
    print("DEMO: Monitoring Setup")
    print("="*60)
    
    print("Note: This demo shows monitoring setup without connecting to a real firewall")
    
    # Show how to create a monitor
    print("\nMonitor setup example:")
    print("""
from paloalto_packet_flow import FlowMonitor, AlertRule

# Create monitor
monitor = FlowMonitor('192.168.1.1', api_key='YOUR_API_KEY')

# Add custom alert rule
custom_rule = AlertRule(
    name="high_traffic_volume",
    condition="total_flows > 1000",
    threshold=1000.0,
    severity="medium"
)
monitor.add_alert_rule(custom_rule)

# Add alert callback
def email_alert(alert):
    print(f"ALERT: {alert.message}")

monitor.add_alert_callback(email_alert)

# Start monitoring
monitor.start_monitoring(interval=30, enable_alerts=True)
    """)
    
    # Show sample metrics
    sample_metrics = {
        'timestamp': datetime.now(),
        'total_flows': 1500,
        'denied_flows': 50,
        'bandwidth_mbps': 75.5,
        'anomalies_per_minute': 2,
        'unique_sources': 45,
        'unique_destinations': 120
    }
    
    print("Sample monitoring metrics:")
    for key, value in sample_metrics.items():
        if key != 'timestamp':
            print(f"- {key}: {value}")


def main():
    """Run the complete demonstration."""
    # Setup logging
    setup_logging('INFO')
    
    # Print banner
    print_banner()
    
    print("Welcome to the Palo Alto Packet Flow Analysis Tool Demo!")
    print("This demonstration will show you the key features of the tool.")
    
    try:
        # Demo 1: Log Parsing
        flows = demo_log_parsing()
        
        # Demo 2: Flow Analysis
        results, temp_dir = demo_flow_analysis(flows)
        
        # Demo 3: Visualization
        demo_visualization(results, temp_dir)
        
        # Demo 4: Configuration
        demo_configuration()
        
        # Demo 5: Monitoring Setup
        demo_monitoring_setup()
        
        print("\n" + "="*60)
        print("DEMO COMPLETE")
        print("="*60)
        print(f"Demo files created in: {temp_dir}")
        print("\nNext steps:")
        print("1. Try the tool with your own log files")
        print("2. Configure custom analysis rules")
        print("3. Set up real-time monitoring")
        print("4. Explore visualization options")
        print("\nFor more information, see the documentation and examples.")
        
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()