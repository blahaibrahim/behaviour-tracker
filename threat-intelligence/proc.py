import pandas as pd
import requests
import json
from pathlib import Path

print("\n=== APPROACH 3: PROCESS THREAT INTELLIGENCE (LOLBAS Integration) ===")

# --- 1. Load Industry Standard Threat Intelligence (LOLBAS) ---
# LOLBAS (Living Off The Land Binaries And Scripts) is the industry standard dataset 
# documenting every Windows binary that can be abused by threat actors.
LOLBAS_API_URL = "https://lolbas-project.github.io/api/lolbas.json"

print("Downloading live LOLBAS threat intelligence dataset...")
try:
    response = requests.get(LOLBAS_API_URL, timeout=10)
    response.raise_for_status()
    lolbas_data = response.json()
    
    # Extract all executable names (e.g., 'powershell.exe') into a fast lookup set.
    # We convert to lowercase for case-insensitive matching.
    abusable_binaries = set(item['Name'].lower() for item in lolbas_data)
    
    print(f"Successfully loaded {len(abusable_binaries)} documented 'Living off the Land' binaries.")
    
except Exception as e:
    print(f"Error downloading LOLBAS dataset: {e}")
    # Fallback to a minimal list if the internet is down during a presentation
    abusable_binaries = {'powershell.exe', 'cmd.exe', 'wmic.exe', 'vssadmin.exe', 'certutil.exe', 'bitsadmin.exe'}

# --- 2. Load Local Network Process Data ---
PROC_CSV_PATH = Path(__file__).resolve().parents[1] / "data" / "proc.csv"
df_proc = pd.read_csv(PROC_CSV_PATH)
print(f"\nLoaded {len(df_proc)} process events from the local tracker.")

# --- 3. Feature Extraction & Evaluation ---
print("\nScanning executed processes against the LOLBAS dataset...")

# Extract just the executable name from the full file path
df_proc['exe_name'] = df_proc['Process Name'].str.split('\\').str[-1].str.lower()

# Filter for only "Start" events
df_proc = df_proc[df_proc['Start/End'] == 'Start']

# Flag processes if they exist in the LOLBAS database
df_proc['is_lolbas'] = df_proc['exe_name'].apply(lambda x: 1 if x in abusable_binaries else 0)

# Print out the findings for visibility
unique_exes = df_proc[['exe_name', 'is_lolbas']].drop_duplicates()
for _, row in unique_exes.iterrows():
    status = "LOLBAS IDENTIFIED [!]" if row['is_lolbas'] == 1 else "Safe"
    print(f" -> {row['exe_name']}: {status}")

# --- 4. Anomaly Flagging Logic ---
print("\n--- BEHAVIOUR TRACKER: PROCESS THREAT REPORT ---")

threat_summary = df_proc.groupby(['Computer', 'User'])['is_lolbas'].sum().reset_index()

for index, row in threat_summary.iterrows():
    computer = row['Computer']
    user = row['User']
    lolbas_hits = row['is_lolbas']
    
    if lolbas_hits >= 2:
        print(f"[CRITICAL ALERT] Multiple LOLBAS executions by User '{user}' on Computer '{computer}' ({lolbas_hits} events). High probability of lateral movement or payload execution!")
    elif lolbas_hits == 1:
        print(f"[WARNING] User '{user}' on Computer '{computer}' executed a LOLBAS tool. Monitor closely.")
    else:
        print(f"[OK] User '{user}' on Computer '{computer}' process execution is clean.")
