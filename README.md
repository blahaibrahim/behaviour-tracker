# LANL Dataset Generator

This repository contains the setup required to generate local PC telemetry mirroring the Los Alamos National Laboratory (LANL) Cyber Security Events dataset.

## PART 1: SERVER SETUP
This computer will host the database and collect logs from all other PCs.

### Phase 1: Start the Database
1. Install Docker Desktop.
2. Open a terminal in the `/docker` folder.
3. Run `docker-compose up -d`.
4. Wait 1 minute, then go to `https://localhost:5601`.

### Phase 2: Install Prerequisites on the Target PC
You must manually install these three programs on any PC you want to monitor:
1. **Npcap:** Download and install from `npcap.com` (Check the "WinPcap API-compatible" box during install).
2. **Winlogbeat:** Download the `.zip` from Elastic, extract to `C:\Program Files\Winlogbeat`, and run the `install-service` script.
3. **Packetbeat:** Download the `.msi` from Elastic and install it.

### Phase 3: Run the Automation Script
1. Open PowerShell as Administrator.
2. Navigate to the `/scripts` folder in this repository.
3. Run `.\install_agents.ps1`. This will apply all our custom configurations and start the logging.

### Phase 4: Fix Packetbeat Network Card
Because every PC has a different Wi-Fi card, you must tell Packetbeat which one to listen to:
1. Open PowerShell as Admin and run: `cd "C:\Program Files\Elastic\Packetbeat"`
2. Run `.\packetbeat.exe devices` and find your active Wi-Fi/Ethernet number.
3. Open `packetbeat.yml` in that folder, change `device: 5` to your specific number.
4. Run `Restart-Service packetbeat`.

### Phase 5: Extract the Data
1. Install dependencies: `pip install -r requirements.txt`
2. Run the extraction script: `python scripts/extract_lanl.py`
3. Find extracted data in `auth.csv`, `proc.csv`, `dns.csv`, and `flows.csv`

### Phase 6: Open the Firewall
1. By default, Windows blocks incoming logs. Open PowerShell as Administrator and run:
`New-NetFirewallRule -DisplayName "Allow Elasticsearch (9200)" -Direction Inbound -LocalPort 9200 -Protocol TCP -Action Allow`
2. Get the Server IP
Open a terminal, run `ipconfig`, and write down your IPv4 Address (e.g., `192.168.1.50`). You will need to give this IP to your team for Part 2!

## PART 2: ENDPOINT SETUP
Follow these steps to configure a PC to send its telemetry to the Server.

**1. Point the Configs to the Server**
Before installing anything, open `/configs/winlogbeat.yml` and `/configs/packetbeat.yml` in this repo. 
Change the Elasticsearch host from `localhost` to the Server's IP address you got in Part 1:
```yaml
  hosts: ["https://192.168.1.50:9200"]  <-- CHANGE THIS