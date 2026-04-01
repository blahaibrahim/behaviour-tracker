# LANL Dataset Generator Pipeline

This repository contains the infrastructure and agents required to generate local PC telemetry mirroring the Los Alamos National Laboratory (LANL) Comprehensive Cyber Security Events dataset.

## Phase 1: Start the Database
1. Install Docker Desktop.
2. Open a terminal in the `/docker` folder.
3. Run `docker-compose up -d`.
4. Wait 1 minute, then go to `https://localhost:5601` (User: `elastic`, Pass: `cQ99oIok_2_pTjGoyGFU`).

## Phase 2: Install Prerequisites on the Target PC
You must manually install these three programs on any PC you want to monitor:
1. **Npcap:** Download and install from `npcap.com` (Check the "WinPcap API-compatible" box during install).
2. **Winlogbeat:** Download the `.zip` from Elastic, extract to `C:\Program Files\Winlogbeat`, and run the `install-service` script.
3. **Packetbeat:** Download the `.msi` from Elastic and install it.

## Phase 3: Run the Automation Script
1. Open PowerShell as Administrator.
2. Navigate to the `/scripts` folder in this repository.
3. Run `.\install_agents.ps1`. This will apply all our custom configurations and start the logging.

## Phase 4: Fix Packetbeat Network Card
Because every PC has a different Wi-Fi card, you must tell Packetbeat which one to listen to:
1. Open PowerShell as Admin and run: `cd "C:\Program Files\Elastic\Packetbeat"`
2. Run `.\packetbeat.exe devices` and find your active Wi-Fi/Ethernet number.
3. Open `packetbeat.yml` in that folder, change `device: 5` to your specific number.
4. Run `Restart-Service packetbeat`.

## Phase 5: Extract the Data
1. Install dependencies: `pip install -r requirements.txt`
2. Run the extraction script: `python scripts/extract_lanl.py`
3. Enjoy your `auth.csv`, `proc.csv`, `dns.csv`, and `flows.csv`!