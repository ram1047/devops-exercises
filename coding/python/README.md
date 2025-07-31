# Palo Alto Packet Flow Analysis Tool

A comprehensive Python package for analyzing, visualizing, and monitoring packet flows in Palo Alto Networks firewalls.

## 🚀 Features

- **Multi-format Log Parsing**: Support for CSV, Syslog, and PAN-OS native log formats
- **Advanced Flow Analysis**: Comprehensive packet flow analysis with anomaly detection
- **Real-time Monitoring**: Live monitoring with customizable alerting
- **Interactive Visualizations**: Network diagrams, charts, and dashboards
- **Flexible Export**: Multiple output formats (JSON, CSV, XML, HTML)
- **API Integration**: Direct integration with Palo Alto firewalls via REST API
- **Extensible Architecture**: Plugin-based design for custom analyzers and visualizers

## 📋 Requirements

- Python 3.7 or higher
- Palo Alto Networks firewall (for real-time monitoring)

## 🛠️ Installation

### Basic Installation

```bash
pip install paloalto-packet-flow
```

### Installation with All Features

```bash
pip install paloalto-packet-flow[all]
```

### Installation Options

- `pip install paloalto-packet-flow[visualization]` - For charts and network diagrams
- `pip install paloalto-packet-flow[data]` - For enhanced data processing
- `pip install paloalto-packet-flow[dev]` - For development tools

### Development Installation

```bash
git clone https://github.com/your-org/paloalto-packet-flow.git
cd paloalto-packet-flow
pip install -e .[dev]
```

## 🚀 Quick Start

### Command Line Usage

```bash
# Analyze traffic logs
paloalto-flow analyze --log-file traffic.log --output-dir ./results

# Create visualizations
paloalto-flow visualize --flow-data results/analysis_results.json --format html

# Start real-time monitoring
paloalto-flow monitor --firewall-ip 192.168.1.1 --api-key YOUR_API_KEY
```

### Python Library Usage

```python
from paloalto_packet_flow import LogParser, PacketFlowAnalyzer, FlowVisualizer

# Parse logs
parser = LogParser({})
flows = parser.parse_file('traffic.log')

# Analyze flows
analyzer = PacketFlowAnalyzer({})
results = analyzer.analyze(flows)

# Create visualization
visualizer = FlowVisualizer({})
viz_content = visualizer.create_visualization(results, output_format='html')
visualizer.save(viz_content, 'flow_analysis.html')

print(f"Analyzed {len(flows)} flows")
print(f"Found {len(results.anomalies)} anomalies")
```

### Quick Functions

```python
import paloalto_packet_flow as paf

# Quick analysis
results = paf.quick_analyze('traffic.log', './output')

# Quick visualization
paf.quick_visualize('./output/analysis_results.json', 'dashboard.html')

# Quick monitoring
paf.start_monitoring('192.168.1.1', 'your_api_key')
```

## 📊 Log Format Support

### Supported Formats

1. **CSV Format** - Standard comma-separated values
2. **Syslog Format** - RFC3164/RFC5424 compliant syslog messages
3. **PAN-OS Native** - Native Palo Alto log format
4. **Custom Formats** - Extensible parser for custom log formats

### Sample Log Entries

#### PAN-OS Traffic Log
```
TRAFFIC,2023/01/01 12:00:00,001234567890,TRAFFIC,,2023/01/01 12:00:00,192.168.1.100,203.0.113.10,0.0.0.0,0.0.0.0,rule1,user1,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2023/01/01 12:00:00,123456,1,80,443,0,0,0x0,tcp,allow,1500,750,750,3,2023/01/01 12:00:00,30,any,0,123456789,0x0,192.168.0.0-192.168.255.255,203.0.113.0-203.0.113.255,0,3,1,aged-out
```

#### Syslog Format
```
Jan 01 12:00:00 firewall-01 1,2023/01/01 12:00:00,001234567890,TRAFFIC,end,2048,2023/01/01 12:00:00,192.168.1.100,203.0.113.10
```

## 🔧 Configuration

### Configuration File Example

```yaml
# config.yaml
parser:
  timestamp_format: "%Y-%m-%d %H:%M:%S"
  timezone: "UTC"
  ignore_malformed: true
  max_errors: 100

analyzer:
  suspicious_ports: [22, 23, 135, 139, 445, 1433, 3389, 5900]
  anomaly_thresholds:
    bytes_per_second: 10000000  # 10MB/s
    packets_per_second: 1000
    session_duration: 3600      # 1 hour
    failed_connections: 10
  malicious_ips:
    - "192.0.2.1"
    - "198.51.100.1"

visualizer:
  default_layout: "hierarchical"
  color_theme: "default"
  max_nodes: 100

monitor:
  poll_interval: 30
  alert_threshold: 5
  retry_attempts: 3
  timeout: 30
  enable_alerts: true
```

### Using Configuration

```python
from paloalto_packet_flow import load_config, PacketFlowAnalyzer

config = load_config('config.yaml')
analyzer = PacketFlowAnalyzer(config.get('analyzer', {}))
```

## 📈 Analysis Features

### Flow Analysis

- **Traffic Patterns**: Identify communication patterns and trends
- **Bandwidth Analysis**: Monitor data transfer rates and volume
- **Application Mapping**: Track application usage and protocols
- **Geographic Distribution**: Analyze traffic by source/destination regions
- **Time-based Analysis**: Understand traffic patterns over time

### Anomaly Detection

- **High Bandwidth Usage**: Detect unusually high data transfer rates
- **Port Scanning**: Identify potential port scanning activities
- **Failed Connections**: Monitor excessive connection failures
- **Suspicious Destinations**: Flag connections to known malicious IPs
- **Protocol Anomalies**: Detect unusual protocol usage patterns

### Security Analysis

- **Threat Detection**: Identify and categorize security threats
- **Policy Violations**: Track traffic blocked by security policies
- **Suspicious Ports**: Monitor access to high-risk ports
- **Connection Patterns**: Analyze unusual connection behaviors

## 🖥️ Real-time Monitoring

### Setting Up Monitoring

```python
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
    # Send email notification here

monitor.add_alert_callback(email_alert)

# Start monitoring
monitor.start_monitoring(interval=30, enable_alerts=True)
```

### Default Alert Rules

1. **High Bandwidth**: Triggers when bandwidth exceeds 100 Mbps
2. **Excessive Denied Traffic**: Alerts on >50 denied flows per minute
3. **Port Scan Detection**: Detects access to >20 unique ports from single IP
4. **Anomaly Spike**: Triggers when >5 anomalies detected per minute

## 📊 Visualization Options

### Dashboard Types

1. **HTML Dashboard**: Interactive web-based dashboard with charts
2. **Network Diagrams**: Visual representation of network flows
3. **Statistical Charts**: Bar charts, pie charts, and time series
4. **Sankey Diagrams**: Flow-based visualizations

### Visualization Examples

```python
from paloalto_packet_flow import FlowVisualizer

visualizer = FlowVisualizer({})

# Create network diagram
network_viz = visualizer.create_visualization(
    'flows.json', 
    layout='force', 
    output_format='svg'
)

# Create dashboard
dashboard = visualizer.create_visualization(
    'analysis_results.json',
    layout='hierarchical',
    output_format='html'
)

# Create Sankey diagram
sankey = visualizer.create_flow_sankey(flows)
```

## 🔌 API Integration

### Palo Alto API Setup

1. Generate API key from your Palo Alto firewall
2. Ensure API access is enabled
3. Configure appropriate permissions for log access

```python
from paloalto_packet_flow import PaloAltoAPI

api = PaloAltoAPI('192.168.1.1', api_key='YOUR_API_KEY')

# Get system information
system_info = api.get_system_info()

# Get traffic logs
logs = api.get_traffic_logs(query="(action eq allow)", count=1000)

# Get interface statistics
interfaces = api.get_interface_stats()
```

## 📊 Export Options

### Supported Export Formats

- **JSON**: Structured data export for further processing
- **CSV**: Tabular data for spreadsheet applications
- **XML**: Structured markup for integration
- **HTML**: Human-readable reports and dashboards

### Export Examples

```python
# Export analysis results
analyzer.save_results(results, './output', 'json')

# Export monitoring metrics
monitor.export_metrics('./metrics.csv', 'csv')

# Generate summary report
analyzer.generate_report(results, './report.txt')
```

## 🧪 Testing

Run the test suite:

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Run tests with coverage
pytest --cov=paloalto_packet_flow tests/
```

## 📚 Examples

Check the `examples/` directory for:

- Basic usage examples
- Advanced configuration scenarios
- Custom analyzer implementations
- Integration examples

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/your-org/paloalto-packet-flow.git
cd paloalto-packet-flow
pip install -e .[dev]
pre-commit install
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://paloalto-packet-flow.readthedocs.io/)
- 🐛 [Issue Tracker](https://github.com/your-org/paloalto-packet-flow/issues)
- 💬 [Discussions](https://github.com/your-org/paloalto-packet-flow/discussions)

## 🙏 Acknowledgments

- Palo Alto Networks for their comprehensive logging capabilities
- The Python networking and security community
- Contributors and users of this tool

## 📋 Changelog

### Version 1.0.0
- Initial release
- Multi-format log parsing
- Real-time monitoring
- Interactive visualizations
- Comprehensive analysis engine
- API integration

---

**Made with ❤️ for network security professionals**