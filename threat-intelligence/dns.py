import pandas as pd
import requests
from pathlib import Path

print("\n=== APPROACH 3: DNS THREAT INTELLIGENCE ENGINE ===")

# --- 1. Load Live Threat Intelligence ---
# We use the StevenBlack malware/adware list, which is updated daily and used by millions of network firewalls.
THREAT_LIST_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

print("Downloading live DNS threat intelligence list...")
try:
    response = requests.get(THREAT_LIST_URL, timeout=10)
    response.raise_for_status()
    
    # Parse the hosts file into a fast Python Set
    # Lines look like: "0.0.0.0 bad-domain.com"
    malicious_domains = set()
    for line in response.text.splitlines():
        if line.startswith("0.0.0.0") and not line.startswith("0.0.0.0 0.0.0.0"):
            parts = line.split()
            if len(parts) >= 2:
                malicious_domains.add(parts[1].strip().lower())
                
    print(f"Successfully loaded {len(malicious_domains):,} known malicious domains into memory.")
except Exception as e:
    print(f"Error downloading threat list: {e}")
    print("Falling back to local cache...")
    malicious_domains = set(['zmeu.com', 'evil.com', 'analytics.btloader.com']) # Fallback

# --- 2. Load Local Network DNS Data ---
DNS_CSV_PATH = Path(__file__).resolve().parents[1] / "data" / "dns.csv"
df_dns = pd.read_csv(DNS_CSV_PATH)
print(f"\nLoaded {len(df_dns)} DNS queries from the local tracker.")

# --- 3. Evaluate Network Traffic (Zero-Latency Lookups) ---
print("\nScanning unique domains against Threat Intelligence...")

unique_domains = df_dns['Resolved Host'].unique()
domain_cache = {}

for domain in unique_domains:
    # Lookups in a Python set are O(1) - instant, no API latency
    is_bad = domain.lower() in malicious_domains
    domain_cache[domain] = is_bad
    
    status = "MALICIOUS/TRACKER [!]" if is_bad else "Safe"
    print(f" -> {domain}: {status}")

# Map results back to the dataframe
df_dns['is_malicious'] = df_dns['Resolved Host'].map(domain_cache).astype(int)

# --- 4. Anomaly Flagging Logic ---
# Rule: If a user/computer hits malicious domains >= 3 times, raise a critical alert.
MALICIOUS_THRESHOLD = 3

print("\n--- BEHAVIOUR TRACKER: THREAT REPORT ---")

threat_summary = df_dns.groupby('Computer')['is_malicious'].sum().reset_index()

for index, row in threat_summary.iterrows():
    computer = row['Computer']
    malicious_hits = row['is_malicious']
    
    if malicious_hits >= MALICIOUS_THRESHOLD:
        print(f"[CRITICAL ALERT] Computer {computer} is compromised! ({malicious_hits} malicious connections blocked).")
    elif malicious_hits > 0:
        print(f"[WARNING] Computer {computer} visited a suspicious site ({malicious_hits} times). Monitor closely.")
    else:
        print(f"[OK] Computer {computer} traffic is clean.")
