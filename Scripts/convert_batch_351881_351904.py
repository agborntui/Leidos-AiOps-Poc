#!/usr/bin/env python3
"""
Convert lines 351881-351904 from linkdown_events.txt to charles_event.json format
and send to IBM CP4AIOps webhook
"""

import json
import re
import subprocess
from datetime import datetime

def parse_snmp_line(line):
    """Parse SNMP trap line to extract data"""
    line = line.strip()
    if not line or not line.startswith('snmp_trap'):
        return None
    
    try:
        # Split into tags, fields, timestamp
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
        
        # Parse tags
        tags = {}
        for tag in measurement_tags.split(',')[1:]:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
        
        # Convert timestamp
        if timestamp:
            timestamp_sec = timestamp / 1_000_000_000
            occurrence_time = datetime.utcfromtimestamp(timestamp_sec).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        else:
            occurrence_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        # Create event
        event = {
            "sender": {
                "service": tags.get('collector', 'telegraf'),
                "name": tags.get('host', 'ec-net-telegraf-01'),
                "type": "snmp_trap"
            },
            "resource": {
                "name": tags.get('source', 'unknown'),
                "hostname": tags.get('source', 'unknown'),
                "type": "Router",
                "ipaddress": tags.get('source', 'unknown'),
                "location": "Interface"
            },
            "type": {
                "classification": "Service",
                "eventType": "problem" if tags.get('name') == 'linkDown' else "resolution"
            },
            "severity": 6,
            "summary": f"{tags.get('name', 'unknown')} Ip Interface {tags.get('source', 'unknown')}",
            "occurrenceTime": occurrence_time,
            "expirySeconds": 0
        }
        
        return event
    except Exception as e:
        print(f"Error parsing line: {e}")
        return None

# Read lines 351881-351904 from linkdown_events.txt
print("Reading lines 351881-351904 from linkdown_events.txt...")
start_line = 351881
end_line = 351904
events = []

with open('linkdown_events.txt', 'r') as f:
    for i, line in enumerate(f, 1):
        if i >= start_line and i <= end_line:
            event = parse_snmp_line(line)
            if event:
                events.append(event)
        if i > end_line:
            break

print(f"Parsed {len(events)} events from lines {start_line}-{end_line}")

# Save to JSON file
output_file = 'linkdown_batch_351881-351904.json'
with open(output_file, 'w') as f:
    json.dump(events, f, indent=2)

print(f"Saved to {output_file}")

# Send each event to webhook
print("\nSending events to IBM CP4AIOps...")
success_count = 0
fail_count = 0

for i, event in enumerate(events, start_line):
    # Create temp file for single event
    temp_file = f'temp_event_{i}.json'
    with open(temp_file, 'w') as f:
        json.dump([event], f)
    
    # Send via curl
    cmd = [
        'curl', '-X', 'POST',
        '-H', 'Content-Type: application/json',
        '-u', 'admin:IBMD3m0s',
        '-d', f'@{temp_file}',
        'https://whconn-b2811577-75db-485e-9e75-673811de640f-cp4aiops.apps.itz-mlp5ji.pok-lb.techzone.ibm.com/webhook-connector/31yed65l51z',
        '-s', '-w', '\n%{http_code}'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\n')
        http_code = lines[-1] if lines else '000'
        
        if http_code == '200':
            success_count += 1
            response_json = '\n'.join(lines[:-1])
            try:
                response_data = json.loads(response_json)
                uid = response_data.get('UID', 'unknown')
                print(f"Line {i}: ✅ Success (UID: {uid})")
            except:
                print(f"Line {i}: ✅ Success")
        else:
            fail_count += 1
            print(f"Line {i}: ❌ Failed (HTTP {http_code})")
    except Exception as e:
        fail_count += 1
        print(f"Line {i}: ❌ Error: {e}")
    
    # Clean up temp file
    import os
    try:
        os.remove(temp_file)
    except:
        pass

print("\n" + "="*50)
print(f"Summary:")
print(f"Lines processed: {start_line}-{end_line}")
print(f"Total events: {len(events)}")
print(f"Successful: {success_count}")
print(f"Failed: {fail_count}")
print(f"Success rate: {(success_count/len(events)*100):.1f}%" if events else "N/A")
print("="*50)


