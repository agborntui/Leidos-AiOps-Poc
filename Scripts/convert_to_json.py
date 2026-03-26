#!/usr/bin/env python3
"""
Convert SNMP trap events to JSON format
"""

import json
import sys
import re
from typing import Dict, Optional, List


def parse_snmp_trap_line(line: str) -> Optional[Dict]:
    """
    Parse a single SNMP trap line in InfluxDB line protocol format.
    
    Format: measurement,tag1=value1,tag2=value2 field1=value1,field2=value2 timestamp
    """
    line = line.strip()
    if not line or not line.startswith('snmp_trap'):
        return None
    
    try:
        # Split line into three parts: tags, fields, timestamp
        first_space = line.find(' ')
        if first_space == -1:
            return None
        
        last_space = line.rfind(' ')
        if last_space == first_space:
            measurement_tags = line[:first_space]
            fields_str = line[first_space+1:]
            timestamp = None
        else:
            measurement_tags = line[:first_space]
            fields_str = line[first_space+1:last_space]
            try:
                timestamp = int(line[last_space+1:])
            except ValueError:
                fields_str = line[first_space+1:]
                timestamp = None
        
        # Parse measurement and tags
        tags_dict = {}
        tag_parts = measurement_tags.split(',')
        measurement = tag_parts[0]
        
        for tag in tag_parts[1:]:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags_dict[key] = value
        
        # Parse fields
        fields_dict = {}
        field_pattern = r'(\w+(?:\.\d+)?)=("(?:[^"\\]|\\.)*"|[^,\s]+)'
        for match in re.finditer(field_pattern, fields_str):
            key = match.group(1)
            value = match.group(2)
            
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
                fields_dict[key] = value
            elif value.endswith('i'):
                try:
                    fields_dict[key] = int(value[:-1])
                except ValueError:
                    fields_dict[key] = value
            else:
                try:
                    fields_dict[key] = float(value)
                except ValueError:
                    fields_dict[key] = value
        
        # Create event object
        event = {
            'type': 'snmp_trap',
            'severity': 'warning' if tags_dict.get('name') == 'linkDown' else 'info',
            'summary': f"{tags_dict.get('name', 'unknown')} event from {tags_dict.get('source', 'unknown')}",
            'source': tags_dict.get('source', 'unknown'),
            'resource': tags_dict.get('source', 'unknown'),
            'event_type': tags_dict.get('name', 'unknown'),
            'mib': tags_dict.get('mib', 'unknown'),
            'oid': tags_dict.get('oid', ''),
            'host': tags_dict.get('host', 'unknown'),
            'collector': tags_dict.get('collector', 'telegraf'),
            'timestamp': timestamp,
            'tags': tags_dict,
            'fields': fields_dict
        }
        
        return event
        
    except Exception as e:
        print(f"Error parsing line: {e}", file=sys.stderr)
        return None


def convert_file_to_json(input_file: str, output_file: str, max_events: Optional[int] = None):
    """Convert SNMP trap file to JSON."""
    events = []
    total_lines = 0
    parsed_events = 0
    
    print(f"Reading from: {input_file}")
    print(f"Writing to: {output_file}")
    if max_events:
        print(f"Max events: {max_events}")
    print("-" * 60)
    
    try:
        with open(input_file, 'r') as f:
            for line in f:
                total_lines += 1
                
                if max_events and parsed_events >= max_events:
                    break
                
                event = parse_snmp_trap_line(line)
                if event:
                    events.append(event)
                    parsed_events += 1
                    
                    if parsed_events % 1000 == 0:
                        print(f"Parsed {parsed_events} events...")
        
        # Write to JSON file
        with open(output_file, 'w') as f:
            json.dump(events, f, indent=2)
        
        print("-" * 60)
        print(f"Conversion complete!")
        print(f"Total lines read: {total_lines}")
        print(f"Events parsed: {parsed_events}")
        print(f"Output file: {output_file}")
        print(f"File size: {len(json.dumps(events))} bytes")
        
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Convert SNMP trap events to JSON format'
    )
    parser.add_argument(
        'input_file',
        help='Input SNMP trap file'
    )
    parser.add_argument(
        'output_file',
        nargs='?',
        help='Output JSON file (default: input_file.json)'
    )
    parser.add_argument(
        '--max-events',
        type=int,
        help='Maximum number of events to convert (default: all)'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty print JSON (default: True)',
        default=True
    )
    
    args = parser.parse_args()
    
    # Determine output file
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = args.input_file.rsplit('.', 1)[0] + '.json'
    
    convert_file_to_json(args.input_file, output_file, args.max_events)


if __name__ == '__main__':
    main()

# Made with Bob
