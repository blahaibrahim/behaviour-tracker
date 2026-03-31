import csv
import urllib3
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

# Suppress warnings about the self-signed Docker certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. Connect to the local Elasticsearch database
print("Connecting to Elasticsearch...")
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "cQ99oIok_2_pTjGoyGFU"),
    verify_certs=False
)

if not es.ping():
    print("Failed to connect to Elasticsearch! Check if it's running.")
    exit()
print("Connected successfully!\n")

# Helper function to safely grab nested dictionary keys
def get_field(doc, path, default=""):
    keys = path.split('.')
    val = doc
    for key in keys:
        if isinstance(val, dict) and key in val:
            val = val[key]
        else:
            return default
    return val

# ==========================================
# EXTRACTION 1: AUTHENTICATION (auth.csv)
# ==========================================
print("Extracting Auth data...")
auth_query = {
    "query": {
        "query_string": {
            "query": "winlog.channel:\"Security\" AND event.code:(4624 OR 4625 OR 4634)"
        }
    }
}
with open('auth.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Time", "Source User", "Target User", "Computer", "Auth Type", "Logon Type", "Orientation", "Status"])
    
    for hit in scan(es, query=auth_query, index="winlogbeat-*"):
        src = hit['_source']
        time = get_field(src, '@timestamp')
        comp = get_field(src, 'winlog.computer_name')
        src_user = get_field(src, 'winlog.event_data.SubjectUserName')
        tgt_user = get_field(src, 'winlog.event_data.TargetUserName')
        auth_type = get_field(src, 'winlog.event_data.AuthenticationPackageName')
        logon_type = get_field(src, 'winlog.event_data.LogonType')
        
        evt_id = str(get_field(src, 'event.code'))
        status = "Success" if evt_id == "4624" else "Fail" if evt_id == "4625" else "LogOff"
        orientation = "LogOn" if evt_id in ["4624", "4625"] else "LogOff"
        
        writer.writerow([time, src_user, tgt_user, comp, auth_type, logon_type, orientation, status])

# ==========================================
# EXTRACTION 2: PROCESSES (proc.csv)
# ==========================================
print("Extracting Process data...")
proc_query = {
    "query": {
        "query_string": {
            "query": "winlog.channel:\"Microsoft-Windows-Sysmon/Operational\" AND event.code:(1 OR 5)"
        }
    }
}
with open('proc.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Time", "User", "Computer", "Process Name", "Start/End"])
    
    for hit in scan(es, query=proc_query, index="winlogbeat-*"):
        src = hit['_source']
        time = get_field(src, '@timestamp')
        comp = get_field(src, 'winlog.computer_name')
        
        # Check ECS mapped field first, fallback to raw Sysmon field
        user = get_field(src, 'user.name') or get_field(src, 'winlog.event_data.User')
        proc_name = get_field(src, 'process.executable') or get_field(src, 'winlog.event_data.Image')
        
        evt_id = str(get_field(src, 'event.code'))
        state = "Start" if evt_id == "1" else "End"
        
        writer.writerow([time, user, comp, proc_name, state])

# ==========================================
# EXTRACTION 3: DNS (dns.csv)
# ==========================================
print("Extracting DNS data...")
dns_query = {
    "query": {
        "query_string": {
            "query": "winlog.channel:\"Microsoft-Windows-Sysmon/Operational\" AND event.code:22"
        }
    }
}
with open('dns.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Time", "Computer", "Resolved Host"])
    
    for hit in scan(es, query=dns_query, index="winlogbeat-*"):
        src = hit['_source']
        time = get_field(src, '@timestamp')
        comp = get_field(src, 'winlog.computer_name')
        
        # Check ECS mapped field first, fallback to raw Sysmon field
        query_name = get_field(src, 'dns.question.name') or get_field(src, 'winlog.event_data.QueryName')
        
        writer.writerow([time, comp, query_name])

# ==========================================
# EXTRACTION 4: NETWORK FLOWS (flows.csv)
# ==========================================
print("Extracting Network Flow data...")
flows_query = {
    "query": {
        "query_string": {
            "query": "winlog.channel:\"Microsoft-Windows-Sysmon/Operational\" AND event.code:3"
        }
    }
}
with open('flows.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(["Time", "Computer", "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol"])
    
    for hit in scan(es, query=flows_query, index="winlogbeat-*"):
        src = hit['_source']
        time = get_field(src, '@timestamp')
        comp = get_field(src, 'winlog.computer_name')
        
        # Check ECS mapped fields first, fallback to raw Sysmon fields
        src_ip = get_field(src, 'source.ip') or get_field(src, 'winlog.event_data.SourceIp')
        src_port = get_field(src, 'source.port') or get_field(src, 'winlog.event_data.SourcePort')
        dst_ip = get_field(src, 'destination.ip') or get_field(src, 'winlog.event_data.DestinationIp')
        dst_port = get_field(src, 'destination.port') or get_field(src, 'winlog.event_data.DestinationPort')
        protocol = get_field(src, 'network.transport') or get_field(src, 'winlog.event_data.Protocol')
        
        writer.writerow([time, comp, src_ip, src_port, dst_ip, dst_port, protocol])

print("\nDone! Check your folder for auth.csv, proc.csv, dns.csv, and flows.csv.")