# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.19.1
#   kernelspec:
#     display_name: Python 3
#     language: python
#     name: python3
# ---

# %%
import os
import subprocess

data_dir = './lanl_data'
model_dir = './saved_models'
os.makedirs(data_dir, exist_ok=True)
os.makedirs(model_dir, exist_ok=True)

print("Installing aria2 for multi-threaded downloading")
subprocess.run("sudo apt-get update > /dev/null 2>&1 && sudo apt-get install -y aria2 > /dev/null 2>&1", shell=True)

urls = {
    "redteam.txt.gz": "https://csr.lanl.gov/data-fence/1774313780/_qhbLmkHe22dfLBm4hZ62skbI9A=/cyber1/redteam.txt.gz",
    "auth.txt.gz": "https://csr.lanl.gov/data-fence/1774313780/_qhbLmkHe22dfLBm4hZ62skbI9A=/cyber1/auth.txt.gz",
    "flows.txt.gz": "https://csr.lanl.gov/data-fence/1774313780/_qhbLmkHe22dfLBm4hZ62skbI9A=/cyber1/flows.txt.gz"
}

# %%
for filename, url in urls.items():
    dest_path = os.path.join(data_dir, filename)
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 1024:
        print(f"{filename} already exists. Skipping.")
        continue
        
    print(f"\nDownloading {filename}...")
    # Added '-q' (quiet) to disable the excessive console printing
    cmd = ["aria2c", "-q", "-x", "16", "-s", "16", "-k", "1M", "--dir", data_dir, "--out", filename, url]
    subprocess.run(cmd)

print("\nDownloads completed successfully!")

# %%
import gc
import json
import math
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, average_precision_score
import warnings
warnings.filterwarnings('ignore')

files = {
    "Auth":  (os.path.join(data_dir, 'auth.txt.gz'),  ['time', 'src_user', 'dest_user', 'src_comp', 'dest_comp', 'auth_type', 'logon_type', 'auth_orientation', 'success']),
    "Flow":  (os.path.join(data_dir, 'flows.txt.gz'), ['time', 'duration', 'src_comp', 'src_port', 'dest_comp', 'dest_port', 'protocol', 'pkt_cnt', 'byte_cnt'])
}
redteam_file = os.path.join(data_dir, 'redteam.txt.gz')

# %%
print("Loading Red Team ground truth data...")
red_cols = ['time', 'src_user', 'src_comp', 'dest_comp']
redteam_df = pd.read_csv(redteam_file, names=red_cols, na_values=['?'])

red_times = set(redteam_df['time'])
red_keys = set(zip(redteam_df['time'], redteam_df['src_comp']))
print(f"Loaded {len(redteam_df)} known malicious events.")

# %%
def scan_and_sample(filepath, columns, chunksize=15_000_000):
    print(f"\nScanning logs (~{os.path.getsize(filepath) / (1024**3):.1f} GB compressed)...")
    processed_chunks = []
    current_chunk = 0
    total_anomalies = 0
    
    for chunk in pd.read_csv(filepath, names=columns, chunksize=chunksize, dtype=str, na_values=['?']):
        current_chunk += 1
        chunk['time'] = pd.to_numeric(chunk['time'], errors='coerce').fillna(0).astype(np.int32)
        
        potential = chunk[chunk['time'].isin(red_times)]
        anomalies = pd.DataFrame()
        if not potential.empty:
            chunk_keys = list(zip(potential['time'], potential['src_comp']))
            mask = pd.Series(chunk_keys).isin(red_keys).values
            anomalies = potential[mask].copy()
            if not anomalies.empty:
                anomalies['is_anomaly'] = 1
                total_anomalies += len(anomalies)
        
        benign = chunk.sample(frac=0.001, random_state=42).copy()
        benign['is_anomaly'] = 0
        
        processed_chunks.append(pd.concat([anomalies, benign]))
        if current_chunk % 5 == 0:
            print(f"  -> Scanned Chunk {current_chunk} | Anomalies Found: {total_anomalies}")

    return pd.concat(processed_chunks, ignore_index=True)


# %%
def train_and_save_model(df, model_name, max_depth=6):
    print(f"\n{'='*40}")
    print(f" TRAINING MODEL: {model_name}")
    print(f"{'='*40}")
    
    X = df.drop(columns=['is_anomaly'])
    y = df['is_anomaly'].astype(np.int8)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Calculate weight, capping it to prevent total precision collapse
    raw_weight = len(y_train[y_train == 0]) / max(len(y_train[y_train == 1]), 1)
    scale_weight = min(raw_weight, 200) # Cap weight at 200x penalty
    
    xgb_params = {
        'objective': 'binary:logistic',
        'tree_method': 'hist',
        'device': 'cuda', # Change to 'cpu' if not using a GPU
        'enable_categorical': True, 
        'n_estimators': 300,
        'learning_rate': 0.05,
        'max_depth': max_depth,
        'scale_pos_weight': scale_weight,
        'max_delta_step': 1, # Highly recommended by XGBoost for extreme class imbalance
        'random_state': 42
    }
    
    model = xgb.XGBClassifier(**xgb_params)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    print(f"\n--- {model_name} Classification Report ---")
    print(classification_report(y_test, y_pred))
    
    auprc = average_precision_score(y_test, y_pred_proba)
    print(f"Area Under Precision-Recall Curve (AUPRC): {auprc:.4f}")
    
    # Save Model
    model_path = os.path.join(model_dir, f'lanl_{model_name.lower()}_xgb.json')
    model.save_model(model_path)
    
    # Save Metadata
    metadata = {
        "model_name": f"LANL_{model_name}_Anomaly_Detector",
        "algorithm": "XGBoost",
        "features": list(X_train.columns),
        "auprc_score": round(float(auprc), 4)
    }
    with open(os.path.join(model_dir, f'{model_name.lower()}_metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=4)
        
    print(f"-> Successfully saved {model_name} model & metadata.")


# %%
# ==========================================
# 1. AUTHENTICATION
# ==========================================
def engineer_auth(df):
    # Temporal
    df['hour_of_day'] = (df['time'] % 86400) // 3600
    df['is_off_hours'] = df['hour_of_day'].apply(lambda x: 1 if x < 8 or x > 18 else 0).astype(np.int8)
    
    # Relational
    df['is_lateral_movement'] = np.where(df['dest_comp'].notna(), (df['src_comp'] != df['dest_comp']).astype(int), 0).astype(np.int8)
    df['is_account_switch'] = np.where(df['dest_user'].notna(), (df['src_user'] != df['dest_user']).astype(int), 0).astype(np.int8)
    df['is_network_logon'] = np.where(df['logon_type'] == '3', 1, 0).astype(np.int8)
    df['is_interactive_logon'] = np.where(df['logon_type'].isin(['2', '10']), 1, 0).astype(np.int8)
    
    # String Identity Checks (BEFORE WE DROP THEM)
    df['src_user_is_machine'] = df['src_user'].str.endswith('$', na=False).astype(np.int8)
    df['src_user_is_system'] = df['src_user'].str.contains('SYSTEM|ANONYMOUS', case=False, na=False).astype(np.int8)
    
    # We kept auth_type! It transfers safely between networks.
    for col in ['logon_type', 'auth_orientation', 'success', 'auth_type']:
        df[col] = df[col].fillna("Missing").astype(str).astype('category')
        
    # Now we drop the raw identifiers safely
    df.drop(columns=['time', 'src_user', 'dest_user', 'src_comp', 'dest_comp'], inplace=True, errors='ignore')
    return df

# %%
print("\n>>> Processing Authentication Logs...")
df_auth = scan_and_sample(*files["Auth"])
df_auth = engineer_auth(df_auth)
train_and_save_model(df_auth, "Auth", max_depth=8) # Increased depth slightly to capture complex interactions
del df_auth
gc.collect()


# %%
# ==========================================
# 2. NETWORK FLOWS
# ==========================================
def engineer_flow(df):
    for col in ['duration', 'src_port', 'dest_port', 'pkt_cnt', 'byte_cnt']:
        df[col] = pd.to_numeric(df[col], errors='coerce').astype(np.float32)

    df['hour_of_day'] = (df['time'] % 86400) // 3600
    df['is_off_hours'] = df['hour_of_day'].apply(lambda x: 1 if x < 8 or x > 18 else 0).astype(np.int8)
    df['is_lateral_movement'] = np.where(df['dest_comp'].notna(), (df['src_comp'] != df['dest_comp']).astype(int), 0).astype(np.int8)
    
    df['bytes_per_packet'] = np.where(df['pkt_cnt'] > 0, df['byte_cnt'] / df['pkt_cnt'], 0).astype(np.float32)
    df['is_short_flow'] = np.where(df['duration'] < 2.0, 1, 0).astype(np.int8)
    df['is_long_flow'] = np.where(df['duration'] > 60.0, 1, 0).astype(np.int8)
    df['protocol'] = df['protocol'].fillna("Missing").astype(str).astype('category')
        
    df.drop(columns=['time', 'src_comp', 'dest_comp'], inplace=True, errors='ignore')
    return df

# %%
print("\n>>> Processing Network Flow Logs...")
df_flow = scan_and_sample(*files["Flow"])
df_flow = engineer_flow(df_flow)
train_and_save_model(df_flow, "Flow", max_depth=8)
del df_flow
gc.collect()

print("\nAuth and Flow Environment-Agnostic Models have been successfully trained and exported!")