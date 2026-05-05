# LANL Dataset Generator

This repository contains the setup required to generate local PC telemetry mirroring the Los Alamos National Laboratory (LANL) Cyber Security Events dataset.

## PART 1: SERVER SETUP
This computer will host the database and collect logs from the network.

### Phase 1: Start the Database
1. Install Docker Desktop.
2. Open a terminal in the `docker` folder.
3. Run `docker-compose up -d`.
4. Wait 1 minute, then go to `https://localhost:5601`, user: `Elastic`, Pass: `found in docker terminal output`.

### Phase 2: Open the Secure Firewall
Open PowerShell as Administrator and run:

`New-NetFirewallRule -DisplayName "Allow Elasticsearch (9200)" -Direction Inbound -LocalPort 9200 -Protocol TCP -Action Allow -RemoteAddress LocalSubnet`

### Phase 3: Get the Server IP
Open a terminal, run `ipconfig`, and write down your IPv4 Address. You will need to give this IP to your team for Part 2.

### Phase 4: Install Local Prerequisites
You must manually install these three programs to monitor this PC:
1. **Npcap:** Download and install from `npcap.com` (Check the "WinPcap API-compatible" box during install).
2. **Winlogbeat:** Download the `.zip` from Elastic, extract to `C:\Program Files\Winlogbeat`, and run the `install-service` script.
3. **Packetbeat:** Download the `.msi` from Elastic and install it.

### Phase 5: Run the Automation Script
1. Open PowerShell as Administrator.
2. Navigate to the `scripts` folder in this repository.
3. Run `.\install_agents.ps1`. This will apply all our custom configurations and start the logging.

### Phase 6: Fix Packetbeat Network Card
1. Open PowerShell as Admin and run: `cd "C:\Program Files\Elastic\Packetbeat"`
2. Run `.\packetbeat.exe devices` and find your active Wi-Fi/Ethernet number.
3. Open `packetbeat.yml` in that folder, change `device: 5` to your specific number.
4. Run `Restart-Service packetbeat`.


## PART 2: ENDPOINT SETUP
Follow these steps to configure additional team PCs to send telemetry to the Server.

### Phase 1: Point Configs to the Server
Before installing anything, open `configs/winlogbeat.yml` and `configs/packetbeat.yml` in this repo. 
Change the Elasticsearch host from `localhost` to the Server's IP address you got in Part 1 (Phase 3):
```yaml
output.elasticsearch:
  hosts: ["https://192.168.1.100:9200"]  # <-- CHANGE TO SERVER IP
```

### Phase 2: Install Agents and Run Automation
Repeat **Phase 4**, **Phase 5**, and **Phase 6** from the Server setup above on the endpoint PC. Once the `packetbeat` service is restarted, the endpoint will actively stream logs to the central database.


## PART 3: EXTRACTING THE DATA
Once your network has generated enough data, run this on the Server PC to generate your LANL dataset.

1. Open a terminal in the main repo folder.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the extraction script: `python scripts/extract_lanl_format.py`
4. Find the extracted data in `data/auth.csv`, `data/proc.csv`, `data/dns.csv`, and `data/flows.csv`.
