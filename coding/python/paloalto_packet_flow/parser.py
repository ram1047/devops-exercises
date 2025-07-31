"""
Log Parser Module
================

This module handles parsing of various Palo Alto Networks firewall log formats
including traffic logs, threat logs, and system logs in different formats like
syslog, CSV, and custom structured formats.
"""

import re
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Iterator
from dataclasses import dataclass
import gzip
import xml.etree.ElementTree as ET

from .analyzer import FlowRecord


class LogParseError(Exception):
    """Custom exception for log parsing errors."""
    pass


@dataclass
class LogParserConfig:
    """Configuration for log parser."""
    timestamp_format: str = "%Y-%m-%d %H:%M:%S"
    timezone: str = "UTC"
    field_separator: str = ","
    ignore_malformed: bool = True
    max_errors: int = 100


class LogParser:
    """Main log parser class for Palo Alto firewall logs."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the parser with configuration."""
        self.config = LogParserConfig(**config)
        self.error_count = 0
        self.parsed_count = 0
        
        # Common Palo Alto log field mappings
        self.traffic_log_fields = [
            'future_use', 'receive_time', 'serial_number', 'type', 'threat_content_type',
            'config_version', 'generate_time', 'source_address', 'destination_address',
            'nat_source_ip', 'nat_destination_ip', 'rule_name', 'source_user',
            'destination_user', 'application', 'virtual_system', 'source_zone',
            'destination_zone', 'inbound_interface', 'outbound_interface', 'log_action',
            'time_logged', 'session_id', 'repeat_count', 'source_port', 'destination_port',
            'nat_source_port', 'nat_destination_port', 'flags', 'ip_protocol',
            'action', 'bytes', 'bytes_sent', 'bytes_received', 'packets', 'start_time',
            'elapsed_time', 'category', 'padding', 'sequence_number', 'action_flags',
            'source_country', 'destination_country', 'cpadding', 'packets_sent',
            'packets_received', 'session_end_reason', 'device_group_hierarchy1',
            'device_group_hierarchy2', 'device_group_hierarchy3', 'device_group_hierarchy4',
            'virtual_system_name', 'device_name', 'action_source', 'source_vm_uuid',
            'destination_vm_uuid', 'tunnel_id_imsi', 'monitor_tag_imei', 'parent_session_id',
            'parent_start_time', 'tunnel_type', 'sctp_association_id', 'sctp_chunks',
            'sctp_chunks_sent', 'sctp_chunks_received'
        ]
        
        # Regex patterns for different log formats
        self.syslog_pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.+)'
        )
        
        self.threat_pattern = re.compile(
            r'THREAT,(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}),(.+)'
        )
        
        self.traffic_pattern = re.compile(
            r'TRAFFIC,(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}),(.+)'
        )
    
    def parse_file(self, file_path: str, filter_expr: Optional[str] = None) -> List[FlowRecord]:
        """Parse a log file and return a list of flow records."""
        flows = []
        
        print(f"Parsing log file: {file_path}")
        
        try:
            # Determine if file is compressed
            if file_path.endswith('.gz'):
                file_opener = gzip.open
                mode = 'rt'
            else:
                file_opener = open
                mode = 'r'
            
            with file_opener(file_path, mode, encoding='utf-8', errors='ignore') as f:
                # Auto-detect format from first few lines
                first_lines = []
                for _ in range(5):
                    try:
                        line = next(f).strip()
                        if line:
                            first_lines.append(line)
                    except StopIteration:
                        break
                
                # Reset file pointer
                f.seek(0)
                
                # Determine format
                log_format = self._detect_format(first_lines)
                print(f"Detected log format: {log_format}")
                
                # Parse based on format
                if log_format == 'csv':
                    flows = self._parse_csv_format(f, filter_expr)
                elif log_format == 'syslog':
                    flows = self._parse_syslog_format(f, filter_expr)
                elif log_format == 'panos':
                    flows = self._parse_panos_format(f, filter_expr)
                else:
                    # Try generic parsing
                    flows = self._parse_generic_format(f, filter_expr)
        
        except Exception as e:
            raise LogParseError(f"Failed to parse log file {file_path}: {str(e)}")
        
        print(f"Successfully parsed {len(flows)} flow records")
        if self.error_count > 0:
            print(f"Encountered {self.error_count} parsing errors")
        
        return flows
    
    def _detect_format(self, sample_lines: List[str]) -> str:
        """Auto-detect the log format from sample lines."""
        if not sample_lines:
            return 'unknown'
        
        # Check for CSV format (comma-separated, possibly with headers)
        if any(',' in line and len(line.split(',')) > 10 for line in sample_lines):
            return 'csv'
        
        # Check for syslog format
        if any(self.syslog_pattern.match(line) for line in sample_lines):
            return 'syslog'
        
        # Check for PAN-OS format
        if any(line.startswith(('TRAFFIC,', 'THREAT,', 'CONFIG,')) for line in sample_lines):
            return 'panos'
        
        return 'generic'
    
    def _parse_csv_format(self, file_obj, filter_expr: Optional[str]) -> List[FlowRecord]:
        """Parse CSV format logs."""
        flows = []
        reader = csv.reader(file_obj)
        
        # Try to detect if first row is header
        first_row = next(reader, None)
        if not first_row:
            return flows
        
        # Check if first row looks like headers
        has_headers = any(field.lower() in ['timestamp', 'source', 'destination', 'action'] 
                         for field in first_row)
        
        if not has_headers:
            # Process first row as data
            flow = self._parse_csv_row(first_row)
            if flow and self._passes_filter(flow, filter_expr):
                flows.append(flow)
        
        # Process remaining rows
        for row_num, row in enumerate(reader, start=2 if has_headers else 1):
            try:
                flow = self._parse_csv_row(row)
                if flow and self._passes_filter(flow, filter_expr):
                    flows.append(flow)
                self.parsed_count += 1
            except Exception as e:
                self._handle_parse_error(f"Row {row_num}: {str(e)}", row)
        
        return flows
    
    def _parse_csv_row(self, row: List[str]) -> Optional[FlowRecord]:
        """Parse a single CSV row into a FlowRecord."""
        try:
            # Map common positions for standard PAN-OS traffic logs
            if len(row) >= 30:  # Minimum fields for traffic log
                return FlowRecord(
                    timestamp=self._parse_timestamp(row[1] if len(row) > 1 else row[0]),
                    source_ip=row[7] if len(row) > 7 else '',
                    dest_ip=row[8] if len(row) > 8 else '',
                    source_port=int(row[23]) if len(row) > 23 and row[23].isdigit() else 0,
                    dest_port=int(row[24]) if len(row) > 24 and row[24].isdigit() else 0,
                    protocol=row[28] if len(row) > 28 else 'unknown',
                    action=row[30] if len(row) > 30 else 'unknown',
                    policy_name=row[11] if len(row) > 11 else 'unknown',
                    application=row[14] if len(row) > 14 else 'unknown',
                    session_id=row[22] if len(row) > 22 else '',
                    bytes_sent=int(row[32]) if len(row) > 32 and row[32].isdigit() else 0,
                    bytes_received=int(row[33]) if len(row) > 33 and row[33].isdigit() else 0,
                    packets_sent=int(row[44]) if len(row) > 44 and row[44].isdigit() else 0,
                    packets_received=int(row[45]) if len(row) > 45 and row[45].isdigit() else 0,
                    duration=float(row[35]) if len(row) > 35 and self._is_float(row[35]) else 0.0,
                    zone_from=row[16] if len(row) > 16 else 'unknown',
                    zone_to=row[17] if len(row) > 17 else 'unknown',
                    threat_name=row[36] if len(row) > 36 and row[36] != '' else None,
                    category=row[36] if len(row) > 36 else None,
                    severity=None  # Would need to be mapped from threat logs
                )
            else:
                # Try to extract basic information from shorter rows
                return self._parse_minimal_row(row)
                
        except (ValueError, IndexError) as e:
            raise LogParseError(f"Failed to parse CSV row: {str(e)}")
    
    def _parse_syslog_format(self, file_obj, filter_expr: Optional[str]) -> List[FlowRecord]:
        """Parse syslog format logs."""
        flows = []
        
        for line_num, line in enumerate(file_obj, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                match = self.syslog_pattern.match(line)
                if match:
                    timestamp_str, hostname, facility, message = match.groups()
                    flow = self._parse_syslog_message(timestamp_str, message)
                    if flow and self._passes_filter(flow, filter_expr):
                        flows.append(flow)
                    self.parsed_count += 1
            except Exception as e:
                self._handle_parse_error(f"Line {line_num}: {str(e)}", line)
        
        return flows
    
    def _parse_panos_format(self, file_obj, filter_expr: Optional[str]) -> List[FlowRecord]:
        """Parse PAN-OS native format logs."""
        flows = []
        
        for line_num, line in enumerate(file_obj, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                if line.startswith('TRAFFIC,'):
                    flow = self._parse_traffic_log(line)
                elif line.startswith('THREAT,'):
                    flow = self._parse_threat_log(line)
                else:
                    continue
                
                if flow and self._passes_filter(flow, filter_expr):
                    flows.append(flow)
                self.parsed_count += 1
                
            except Exception as e:
                self._handle_parse_error(f"Line {line_num}: {str(e)}", line)
        
        return flows
    
    def _parse_traffic_log(self, line: str) -> Optional[FlowRecord]:
        """Parse a PAN-OS traffic log line."""
        fields = line.split(',')
        
        if len(fields) < 30:
            return None
        
        try:
            return FlowRecord(
                timestamp=self._parse_timestamp(fields[1]),
                source_ip=fields[7],
                dest_ip=fields[8],
                source_port=int(fields[23]) if fields[23].isdigit() else 0,
                dest_port=int(fields[24]) if fields[24].isdigit() else 0,
                protocol=fields[28],
                action=fields[30],
                policy_name=fields[11],
                application=fields[14],
                session_id=fields[22],
                bytes_sent=int(fields[31]) if fields[31].isdigit() else 0,
                bytes_received=int(fields[32]) if fields[32].isdigit() else 0,
                packets_sent=int(fields[44]) if len(fields) > 44 and fields[44].isdigit() else 0,
                packets_received=int(fields[45]) if len(fields) > 45 and fields[45].isdigit() else 0,
                duration=float(fields[35]) if len(fields) > 35 and self._is_float(fields[35]) else 0.0,
                zone_from=fields[16],
                zone_to=fields[17]
            )
        except (ValueError, IndexError):
            return None
    
    def _parse_threat_log(self, line: str) -> Optional[FlowRecord]:
        """Parse a PAN-OS threat log line."""
        fields = line.split(',')
        
        if len(fields) < 20:
            return None
        
        try:
            return FlowRecord(
                timestamp=self._parse_timestamp(fields[1]),
                source_ip=fields[7],
                dest_ip=fields[8],
                source_port=int(fields[18]) if fields[18].isdigit() else 0,
                dest_port=int(fields[19]) if fields[19].isdigit() else 0,
                protocol=fields[20],
                action=fields[21],
                policy_name=fields[11],
                application=fields[14],
                session_id=fields[17],
                bytes_sent=0,  # Not available in threat logs
                bytes_received=0,
                packets_sent=0,
                packets_received=0,
                duration=0.0,
                zone_from=fields[15],
                zone_to=fields[16],
                threat_name=fields[22] if len(fields) > 22 else None,
                category=fields[23] if len(fields) > 23 else None,
                severity=fields[24] if len(fields) > 24 else None
            )
        except (ValueError, IndexError):
            return None
    
    def _parse_generic_format(self, file_obj, filter_expr: Optional[str]) -> List[FlowRecord]:
        """Parse generic/unknown format logs using pattern matching."""
        flows = []
        
        # Define common patterns to extract flow information
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        port_pattern = re.compile(r':(\d+)')
        action_pattern = re.compile(r'\b(allow|deny|drop|accept|reject|block)\b', re.IGNORECASE)
        
        for line_num, line in enumerate(file_obj, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                # Extract IPs
                ips = ip_pattern.findall(line)
                if len(ips) >= 2:
                    source_ip, dest_ip = ips[0], ips[1]
                else:
                    continue
                
                # Extract ports
                ports = port_pattern.findall(line)
                source_port = int(ports[0]) if len(ports) > 0 else 0
                dest_port = int(ports[1]) if len(ports) > 1 else 0
                
                # Extract action
                action_match = action_pattern.search(line)
                action = action_match.group(1).lower() if action_match else 'unknown'
                
                # Create basic flow record
                flow = FlowRecord(
                    timestamp=datetime.now().isoformat(),
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    source_port=source_port,
                    dest_port=dest_port,
                    protocol='unknown',
                    action=action,
                    policy_name='unknown',
                    application='unknown',
                    session_id=f"generic_{line_num}",
                    bytes_sent=0,
                    bytes_received=0,
                    packets_sent=0,
                    packets_received=0,
                    duration=0.0,
                    zone_from='unknown',
                    zone_to='unknown'
                )
                
                if self._passes_filter(flow, filter_expr):
                    flows.append(flow)
                self.parsed_count += 1
                
            except Exception as e:
                self._handle_parse_error(f"Line {line_num}: {str(e)}", line)
        
        return flows
    
    def _parse_minimal_row(self, row: List[str]) -> Optional[FlowRecord]:
        """Parse minimal information from short CSV rows."""
        if len(row) < 3:
            return None
        
        try:
            return FlowRecord(
                timestamp=self._parse_timestamp(row[0]) if row[0] else datetime.now().isoformat(),
                source_ip=row[1] if len(row) > 1 else '0.0.0.0',
                dest_ip=row[2] if len(row) > 2 else '0.0.0.0',
                source_port=int(row[3]) if len(row) > 3 and row[3].isdigit() else 0,
                dest_port=int(row[4]) if len(row) > 4 and row[4].isdigit() else 0,
                protocol=row[5] if len(row) > 5 else 'unknown',
                action=row[6] if len(row) > 6 else 'unknown',
                policy_name='unknown',
                application='unknown',
                session_id='',
                bytes_sent=0,
                bytes_received=0,
                packets_sent=0,
                packets_received=0,
                duration=0.0,
                zone_from='unknown',
                zone_to='unknown'
            )
        except (ValueError, IndexError):
            return None
    
    def _parse_syslog_message(self, timestamp_str: str, message: str) -> Optional[FlowRecord]:
        """Parse the message part of a syslog entry."""
        # This would need to be customized based on your specific syslog format
        # For now, we'll try to extract basic information
        
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = ip_pattern.findall(message)
        
        if len(ips) >= 2:
            return FlowRecord(
                timestamp=self._parse_timestamp(timestamp_str),
                source_ip=ips[0],
                dest_ip=ips[1],
                source_port=0,
                dest_port=0,
                protocol='unknown',
                action='unknown',
                policy_name='unknown',
                application='unknown',
                session_id='',
                bytes_sent=0,
                bytes_received=0,
                packets_sent=0,
                packets_received=0,
                duration=0.0,
                zone_from='unknown',
                zone_to='unknown'
            )
        
        return None
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse and normalize timestamp."""
        if not timestamp_str:
            return datetime.now().isoformat()
        
        # Try different timestamp formats
        formats = [
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S.%f",
            "%b %d %H:%M:%S",
            self.config.timestamp_format
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.strip(), fmt)
                return dt.isoformat()
            except ValueError:
                continue
        
        # If all formats fail, return current time
        return datetime.now().isoformat()
    
    def _is_float(self, value: str) -> bool:
        """Check if a string can be converted to float."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def _passes_filter(self, flow: FlowRecord, filter_expr: Optional[str]) -> bool:
        """Check if a flow record passes the filter expression."""
        if not filter_expr:
            return True
        
        # Simple filter implementation
        # In practice, you might want to use a more sophisticated expression parser
        try:
            # Replace field names with actual values
            expr = filter_expr
            expr = expr.replace('source_ip', f"'{flow.source_ip}'")
            expr = expr.replace('dest_ip', f"'{flow.dest_ip}'")
            expr = expr.replace('action', f"'{flow.action}'")
            expr = expr.replace('application', f"'{flow.application}'")
            expr = expr.replace('source_port', str(flow.source_port))
            expr = expr.replace('dest_port', str(flow.dest_port))
            
            # Evaluate the expression (be careful with eval in production!)
            return eval(expr)
        except:
            # If filter evaluation fails, include the record
            return True
    
    def _handle_parse_error(self, error_msg: str, data: Any):
        """Handle parsing errors."""
        self.error_count += 1
        
        if not self.config.ignore_malformed:
            raise LogParseError(f"Parse error: {error_msg}")
        
        if self.error_count <= self.config.max_errors:
            print(f"Warning: {error_msg}")
        elif self.error_count == self.config.max_errors + 1:
            print(f"Warning: Suppressing further error messages (max {self.config.max_errors} reached)")
    
    def get_parse_statistics(self) -> Dict[str, int]:
        """Get parsing statistics."""
        return {
            'parsed_records': self.parsed_count,
            'parse_errors': self.error_count,
            'success_rate': (self.parsed_count / (self.parsed_count + self.error_count) * 100) 
                           if (self.parsed_count + self.error_count) > 0 else 0
        }