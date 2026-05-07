# Security Event Tracker

A Windows-focused security telemetry pipeline that captures endpoint and network activity, stores it in Elasticsearch, converts it into LANL-style CSV datasets, and runs threat/anomaly analysis workflows.

## What this project does

This repository provides:

- Infrastructure to collect telemetry from one or more Windows machines.
- Dockerized Elastic Stack (Elasticsearch + Kibana) as the central store.
- Agent configuration and install automation for Sysmon, Winlogbeat, and Packetbeat.
- A dataset extraction script that outputs LANL-like CSV files:
  - `auth.csv` (authentication)
  - `proc.csv` (process execution)
  - `dns.csv` (DNS resolution)
  - `flows.csv` (network flows)
- A production-style flow anomaly inference script using a saved XGBoost model.
- Threat-intelligence scripts for:
  - DNS domain reputation checks.
  - Process execution checks against LOLBAS.

## High-level architecture

1. Windows hosts generate telemetry:
   - Sysmon event logs
   - Windows Security logs
   - Packet-level/network flow telemetry
2. Beats ship logs over HTTPS to Elasticsearch.
3. Kibana is used for inspection/visualization.
4. `scripts/extract_lanl_format.py` pulls from Elasticsearch indices and writes LANL-style CSV files.
5. Analytics layer:
   - `scripts/infer_flows.py` scores flow records with saved XGBoost model artifacts.
   - `threat-intelligence/*.py` adds rule-based intelligence from live feeds.

## Repository structure

```text
security-event-tracker/
  configs/
    Sysmon64.exe                   # Sysmon installer binary
    sysmonconfig-export.xml        # Sysmon configuration
    winlogbeat.yml                 # Winlogbeat config template used by install script
    packetbeat.yml                 # Packetbeat config template used by install script

  data/                            # Generated datasets (ignored by git)
    auth.csv
    proc.csv
    dns.csv
    flows.csv
    flows_inference.csv

  docker/
    docker-compose.yml             # Elasticsearch + Kibana stack

  model/
    auth-notebook.ipynb            # Unsupervised auth anomaly modeling notebook
    flows-notebook.ipynb           # Supervised flow anomaly modeling notebook
    saved/
      best_transformer.pth         # Saved auth Transformer weights
      lanl_flow_xgb.json           # Saved XGBoost flow model
      flow_metadata.json           # Feature contract + model metadata

  scripts/
    install_agents.ps1             # Admin automation for local agent setup
    extract_lanl_format.py         # Elasticsearch -> LANL-style CSV extraction
    infer_flows.py                 # Flow anomaly inference pipeline

  threat-intelligence/
    dns.py                         # DNS threat feed matching
    proc.py                        # LOLBAS process matching

  Setup.md                         # Step-by-step operational setup notes
  requirements.txt                 # Python dependencies
  README.md
```

## Tech stack

- Python: data extraction, inference, threat intelligence.
- Elastic Stack 8.12.0:
  - Elasticsearch (storage/search)
  - Kibana (visualization)
- Windows telemetry agents:
  - Sysmon
  - Winlogbeat
  - Packetbeat
- ML stack:
  - XGBoost (flow anomaly detector)
  - PyTorch (auth notebook model artifact)
  - pandas/numpy/scikit-learn

## Prerequisites

- Windows host(s).
- Docker Desktop on central server host.
- Python 3.10+ recommended.
- Administrative PowerShell for agent installation.
- Manual software installs (as expected by scripts/docs):
  - Npcap
  - Winlogbeat
  - Packetbeat

## Quick start

### 1. Start the Elastic services

```powershell
cd docker
docker-compose up -d
```

Services/ports:

- Elasticsearch: `https://localhost:9200`
- Kibana: `https://localhost:5601`

### 2. Configure endpoint telemetry agents

Run as Administrator:

```powershell
cd scripts
.\install_agents.ps1
```

What it does:

- Installs Sysmon using `configs/sysmonconfig-export.xml`.
- Copies `configs/winlogbeat.yml` into `C:\Program Files\Winlogbeat\winlogbeat.yml`.
- Copies `configs/packetbeat.yml` into `C:\Program Files\Elastic\Packetbeat\packetbeat.yml`.
- Restarts `winlogbeat` and `packetbeat` services.

### 3. Adjust Packetbeat interface ID

`configs/packetbeat.yml` uses:

```yaml
packetbeat.interfaces.device: 5
```

You must set this to your real NIC index on each host:

```powershell
cd "C:\Program Files\Elastic\Packetbeat"
.\packetbeat.exe devices
```

Then update the `device` value and restart service.

### 4. Extract LANL-style datasets

```powershell
pip install -r requirements.txt
python scripts/extract_lanl_format.py
```

Outputs:

- `data/auth.csv`
- `data/proc.csv`
- `data/dns.csv`
- `data/flows.csv`

### 5. Run flow anomaly inference

```powershell
python scripts/infer_flows.py --input data/flows.csv --output data/flows_inference.csv
```

Output adds:

- `anomaly_score`
- `predicted_anomaly`

## Detailed component documentation

### `docker/docker-compose.yml`

Defines a single-node local Elastic stack:

- `elasticsearch:8.12.0`
- `kibana:8.12.0`
- Exposed ports:
  - `9200` for Elasticsearch
  - `5601` for Kibana
- Security is enabled with a configured `elastic` password.

### `scripts/install_agents.ps1`

Purpose: one-command local endpoint setup (run as Administrator).

Steps implemented:

1. Check for admin privileges.
2. Install Sysmon (`sysmon64.exe -accepteula -i sysmonconfig-export.xml`).
3. Deploy Winlogbeat config and restart `winlogbeat` service.
4. Deploy Packetbeat config and restart `packetbeat` service.
5. Print reminder to set Packetbeat NIC.

Operational note:

- The script currently contains a stray token (`first`) after `cd $RepoRoot\configs`. PowerShell treats this as an attempted command and prints an error, but the script may still continue with subsequent steps.

### `scripts/extract_lanl_format.py`

Purpose: convert Elastic telemetry to LANL-style CSVs.

Connection behavior:

- Connects to `https://localhost:9200`.
- Uses basic auth `elastic` with configured password.
- Disables TLS certificate verification (`verify_certs=False`).

Extraction logic:

- Authentication (`auth.csv`) from `winlogbeat-*`:
  - Query: Security channel + event IDs `4624`, `4625`, `4634`.
  - Maps to status/orientation fields (`Success`, `Fail`, `LogOff`).
- Process events (`proc.csv`) from `winlogbeat-*`:
  - Sysmon channel + event IDs `1` (start), `5` (end).
- DNS (`dns.csv`) from `winlogbeat-*`:
  - Sysmon DNS event ID `22`.
- Flows (`flows.csv`) from `packetbeat-*`:
  - `type:"flow"` query.
  - Computes packet/byte totals from source + destination counters.
  - Converts `event.duration` nanoseconds to seconds.

### `scripts/infer_flows.py`

Purpose: production inference over flow CSV using saved XGBoost artifacts.

Key behaviors:

- Accepts LANL-like columns and this repo's extractor columns.
- Normalizes column names (`Time` -> `time`, `Packet Count` -> `pkt_cnt`, etc.).
- Handles missing `src_comp` / `dest_comp` using IP fallbacks.
- Converts time to Unix seconds from either numeric or timestamp formats.
- Engineers features:
  - `hour_of_day`, `is_off_hours`
  - `is_lateral_movement`
  - `bytes_per_packet`
  - `is_short_flow`, `is_long_flow`
- Preserves categorical compatibility with training-time categories.
- Loads feature contract from `model/saved/flow_metadata.json`.
- Writes `anomaly_score` and thresholded `predicted_anomaly`.

CLI options:

```text
--input      default: data/flows.csv
--model      default: model/saved/lanl_flow_xgb.json
--metadata   default: model/saved/flow_metadata.json
--output     default: data/flows_inference.csv
--threshold  default: 0.5
```

### `threat-intelligence/dns.py`

Purpose: reputation scoring of resolved domains.

Workflow:

1. Downloads StevenBlack hosts list.
2. Parses malicious domains into an in-memory `set`.
3. Loads `data/dns.csv`.
4. Flags each domain as malicious/safe (`is_malicious`).
5. Aggregates by `Computer` and prints alerts:
   - Critical if malicious hits >= 3.

Fallback behavior:

- If feed download fails, uses small static fallback domain set.

### `threat-intelligence/proc.py`

Purpose: detect potential living-off-the-land abuse.

Workflow:

1. Downloads LOLBAS JSON feed.
2. Builds set of abusable binary names.
3. Loads `data/proc.csv` and keeps `Start` events.
4. Extracts executable name from path and flags `is_lolbas`.
5. Aggregates by `(Computer, User)` and prints alerts:
   - Critical if LOLBAS hits >= 2.

Fallback behavior:

- If feed download fails, uses a minimal hardcoded binary list.

## Data dictionary

### `auth.csv`

Columns:

- `Time`
- `Source User`
- `Target User`
- `Computer`
- `Auth Type`
- `Logon Type`
- `Orientation`
- `Status`

### `proc.csv`

Columns:

- `Time`
- `User`
- `Computer`
- `Process Name`
- `Start/End`

### `dns.csv`

Columns:

- `Time`
- `Computer`
- `Resolved Host`

### `flows.csv`

Columns:

- `Time`
- `Duration (s)`
- `Computer`
- `Source IP`
- `Source Port`
- `Dest IP`
- `Dest Port`
- `Protocol`
- `Packet Count`
- `Byte Count`

### `flows_inference.csv`

Contains all input flow columns plus:

- `anomaly_score` (`float`, probability-like score)
- `predicted_anomaly` (`0` or `1` after thresholding)

## Model artifacts

### Flow model (`model/saved/lanl_flow_xgb.json`)

- Algorithm: XGBoost binary classifier.
- Feature contract read from `model/saved/flow_metadata.json`.

`flow_metadata.json` includes:

- `model_name`: `LANL_Flow_Anomaly_Detector`
- `algorithm`: `XGBoost`
- `features`:
  - `duration`
  - `src_port`
  - `dest_port`
  - `protocol`
  - `pkt_cnt`
  - `byte_cnt`
  - `hour_of_day`
  - `is_off_hours`
  - `is_lateral_movement`
  - `bytes_per_packet`
  - `is_short_flow`
  - `is_long_flow`
- `auprc_score`: `0.8854`

### Auth model (`model/saved/best_transformer.pth`)

- Generated by `model/auth-notebook.ipynb`.
- Notebook describes an unsupervised Transformer-style sequence anomaly approach for authentication logs.

## Notebook scope

### `model/flows-notebook.ipynb`

- Builds supervised flow anomaly model from LANL-like sources.
- Performs large-file scanning/sampling and feature engineering.
- Trains XGBoost with time-aware split and saves artifacts.
- Includes threshold tuning section for operations.

### `model/auth-notebook.ipynb`

- Builds unsupervised anomaly detection for authentication events.
- Covers parsing, token vocabulary construction, sequence modeling, and anomaly scoring/evaluation.

## Configuration notes

### Winlogbeat (`configs/winlogbeat.yml`)

Configured event channels include:

- Application
- System
- Security
- `Microsoft-Windows-Sysmon/Operational`
- PowerShell channels/events

Output:

- Elasticsearch host defaults to `https://localhost:9200`.
- Uses `elastic` username/password.
- SSL verification disabled.

### Packetbeat (`configs/packetbeat.yml`)

Configured with:

- Explicit NIC index (`packetbeat.interfaces.device: 5`).
- Flow collection enabled.
- Multiple protocol decoders enabled (DNS, HTTP, TLS, MySQL, etc.).
- Elasticsearch output to `https://localhost:9200` with SSL verification disabled.

## Running threat-intelligence scripts

```powershell
python threat-intelligence/dns.py
python threat-intelligence/proc.py
```

Expected behavior:

- Verbose console output per domain/process.
- Summary risk messages by host or host/user pair.

## Security and operational caveats

Current code/config choices to review before production use:

- Credentials are hardcoded in committed files (`docker-compose`, Beat configs, extractor script).
- TLS verification is disabled in several components.
- External threat-intel scripts depend on internet access at runtime.
- Data files may become very large; storage and retention controls are not yet automated.
- No CI tests currently validate extraction or inference correctness.

## Troubleshooting

- Elasticsearch connection fails:
  - Ensure `docker-compose up -d` is running.
  - Verify `https://localhost:9200` is reachable.
  - Confirm credentials match configured password.
- No flow data in `flows.csv`:
  - Confirm Packetbeat service is running.
  - Confirm NIC index in `packetbeat.yml` is correct.
- Missing Sysmon events:
  - Verify Sysmon is installed with `sysmonconfig-export.xml`.
  - Confirm Winlogbeat is shipping `Microsoft-Windows-Sysmon/Operational`.
- Threat-intel scripts fail to download feeds:
  - Check internet/proxy settings.
  - Scripts will fallback to minimal local indicators.

## Current limitations

- Extraction script targets localhost and fixed credentials by default.
- Threat-intel scripts print findings but do not persist enriched output files.
- Alert thresholds are static and environment-specific.
- No packaged service wrappers for scheduled extraction/inference.

## Suggested next improvements

- Move secrets to environment variables or secret manager.
- Enable certificate validation and proper PKI.
- Add unit/integration tests for extraction and inference schemas.
- Add persistent enriched outputs for threat-intel scripts.
- Add configurable thresholds and YAML/CLI config for all scripts.

## License

No license file is currently present in this repository.
