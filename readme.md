# AI-Assisted OT Security Monitor

> **Real-time anomaly detection for Industrial Control Systems using open-source tools and machine learning — built to run on a single laptop with no cloud dependency.**

Industrial Control Systems (ICS) that run factories, water plants, and energy grids were designed for reliability, not security. They speak legacy protocols like Modbus and DNP3, carry no authentication, and were never meant to be connected to IP networks. As IT–OT convergence accelerates, these systems are increasingly exposed — yet most security tools built for enterprise IT are blind to OT-specific behavior.

This project builds a lightweight, self-contained OT security monitoring prototype that runs entirely on a local Ubuntu machine (or WSL-2 on Windows). It simulates a real ICS environment using OpenPLC and Conpot, captures OT network traffic with Zeek and its ICS analyzer suite, classifies anomalies with Isolation Forest and One-Class SVM trained on publicly available ICS datasets, and presents live alerts to operators through a dark-themed dashboard — all without sending a single packet to the internet.

---

## Table of Contents

- [What This Project Does](#what-this-project-does)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Dataset Details](#dataset-details)
- [ML Models](#ml-models)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup Guide](#setup-guide)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Install System Dependencies](#2-install-system-dependencies)
  - [3. Install OpenPLC](#3-install-openplc)
  - [4. Install Conpot](#4-install-conpot)
  - [5. Install Zeek with ICS Analyzers](#5-install-zeek-with-ics-analyzers)
  - [6. Python Environment](#6-python-environment)
  - [7. Train the Models](#7-train-the-models)
- [Running the System](#running-the-system)
- [Testing with Simulated Attacks](#testing-with-simulated-attacks)
- [Dashboard Walkthrough](#dashboard-walkthrough)
- [Alert Types and Severity](#alert-types-and-severity)
- [Replacing Synthetic Data with Real Datasets](#replacing-synthetic-data-with-real-datasets)
- [Known Limitations](#known-limitations)
- [References](#references)

---

## What This Project Does

The system has three layers working simultaneously:

**Simulation layer** — OpenPLC runs a ladder logic program that mimics a water pump controller, exposing a real Modbus TCP server on port 502. Conpot runs alongside it as an ICS honeypot, emulating additional SCADA endpoints (Modbus, S7comm, BACnet, EtherNet/IP, DNP3, SNMP, FTP, TFTP) to attract and log attacker probes.

**Detection layer** — Zeek passively captures all network traffic on the host interface and parses OT protocols using the `icsnpp` plugin suite. A Python watchdog tails Zeek's `conn.log` in real time, extracts flow features, and runs two ML models in parallel: an Isolation Forest trained on process-level sensor behavior (BATADAL schema) and a One-Class SVM trained on network traffic patterns (TON_IoT schema). Every anomalous flow is written to a SQLite database with a severity label and anomaly score.

**Presentation layer** — A FastAPI backend serves the alert database over a REST API. A standalone HTML/JS dashboard polls the API every 5 seconds and renders a live alert feed, severity breakdown donut chart, alert type bar chart, and active port ranking — all styled for operators who need to read it under pressure.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WSL-2 / Ubuntu                              │
│                                                                     │
│  ┌──────────────┐    Modbus TCP     ┌──────────────────────────┐   │
│  │   OpenPLC    │◄─────────────────►│      Network Layer       │   │
│  │  Port 502    │                   │   (any interface)        │   │
│  │  PLC Sim     │                   └──────────┬───────────────┘   │
│  └──────────────┘                              │ Passive Capture   │
│                                                ▼                   │
│  ┌──────────────┐   Modbus/S7/      ┌──────────────────────────┐   │
│  │   Conpot     │   BACnet/DNP3     │       Zeek IDS           │   │
│  │  Honeypot    │◄─────────────────►│  + icsnpp-modbus         │   │
│  │  Multi-port  │                   │  + icsnpp-dnp3           │   │
│  └──────────────┘                   └──────────┬───────────────┘   │
│                                                │ conn.log          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  ML Detection Pipeline                       │  │
│  │                                                              │  │
│  │  BATADAL Schema ──► Isolation Forest ──► Process Alerts     │  │
│  │  TON_IoT Schema ──► One-Class SVM   ──► Network Alerts     │  │
│  │                                          │                   │  │
│  │                                   SQLite alerts.db           │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                         │                          │
│                             ┌───────────▼──────────────┐           │
│                             │   FastAPI  :8000          │           │
│                             │  /api/alerts  /api/stats  │           │
│                             └───────────┬──────────────┘           │
└─────────────────────────────────────────┼────────────────────────-─┘
                                          │ HTTP
                                          ▼
                               ┌──────────────────────┐
                               │  Operator Dashboard  │
                               │  (Windows Browser)   │
                               │                      │
                               │  • Live Alert Feed   │
                               │  • Severity Chart    │
                               │  • Alert Type Bars   │
                               │  • Port Rankings     │
                               └──────────────────────┘
```

### Data Flow

```
OpenPLC / Conpot
      │  OT protocol traffic (Modbus, DNP3, S7, BACnet)
      ▼
Zeek + icsnpp  ←── passive tap on network interface
      │  conn.log  modbus.log  dnp3.log  (TSV, tailed live)
      ▼
pipeline/zeek_parser.py  ←── feature extraction per flow
      │
      ├──► NetworkDetector (One-Class SVM)   ← TON_IoT-trained
      │          │  score + severity
      │
      └──► Force-flag OT port connections as ≥ LOW
                 │
                 ▼
          data/alerts.db  (SQLite)
                 │
          api/main.py  (FastAPI)
                 │  /api/alerts  /api/stats  /health
                 ▼
         dashboard/index.html  ← polls every 5 seconds
```

---

## Tech Stack

| Layer | Tool | Purpose |
|---|---|---|
| PLC Simulation | **OpenPLC v3** | Runs real ladder logic, exposes Modbus TCP on port 502 |
| ICS Honeypot | **Conpot 0.6** | Emulates Modbus, S7, BACnet, DNP3, SNMP, FTP, TFTP |
| Network Capture | **Zeek 6.x** | Passive traffic analysis with OT protocol dissection |
| ICS Analyzers | **icsnpp suite** | Zeek plugins for Modbus, DNP3, EtherNet/IP, BACnet |
| Process Anomaly | **Isolation Forest** (scikit-learn) | Detects sensor-level deviations — BATADAL schema |
| Network Anomaly | **One-Class SVM** (scikit-learn) | Detects abnormal flow patterns — TON_IoT schema |
| Feature Store | **SQLite** | Lightweight, zero-config alert and event storage |
| API | **FastAPI + Uvicorn** | REST backend serving alerts and statistics |
| Dashboard | **Vanilla HTML/CSS/JS + Chart.js** | Single-file operator UI, no build step required |
| Language | **Python 3.10–3.12** | Detection pipeline, API, training scripts |
| Environment | **WSL-2 Ubuntu 22.04** (or native Ubuntu) | Host OS |

---

## Dataset Details

The project ships with a **synthetic data bootstrap** (`bootstrap_train.py`) that generates realistic training data matching the schema of two public ICS research datasets. You can swap in the real datasets at any time to improve model accuracy — the preprocessing scripts are included.

### BATADAL (Battle of the Attack Detection Algorithms)

- **Source:** [batadal.net/data.html](https://www.batadal.net/data.html)
- **What it contains:** 7 months of time-series sensor readings from a simulated water distribution network — pressure, flow rates, tank levels, and pump states. Contains 7 labeled attack scenarios (sensor tampering, actuator manipulation, replay attacks).
- **How it is used:** Trains the Isolation Forest process-level anomaly detector. Features extracted: raw sensor values, per-sensor delta (rate of change), and 5-window rolling mean and standard deviation for each sensor.
- **Bootstrap schema:** 7 synthetic sensor channels, 8,000 normal samples + 2,000 attack samples with pressure spikes, flow drops, frozen readings, and pump state flips.

### TON_IoT Network Dataset

- **Source:** [research.unsw.edu.au/projects/toniot-datasets](https://research.unsw.edu.au/projects/toniot-datasets)
- **What it contains:** Large-scale network flow dataset covering IoT and ICS protocols (Modbus, DNP3, MQTT, HTTP, DNS). Labels include Normal, Scanning, DoS, Backdoor, Injection, MITM, Ransomware, XSS, Password attacks.
- **How it is used:** Trains the One-Class SVM network-level anomaly detector. Features: flow duration, byte counts, packet counts, missed bytes, protocol encoding, connection state encoding.
- **Bootstrap schema:** 8-feature flow vectors, 10,000 normal samples + 3,000 attack samples across scan, DoS, injection, MITM, and backdoor categories.

---

## ML Models

### Isolation Forest (Process-Level)

Isolation Forest is an ensemble anomaly detection algorithm that isolates observations by randomly partitioning features. Anomalies require fewer partitions to isolate and receive higher anomaly scores. It is well-suited for multivariate sensor data where normal behavior forms a stable cluster and attacks cause abrupt deviations.

- Trained exclusively on normal sensor readings (unsupervised)
- `contamination=0.05` (expects ~5% anomaly rate at runtime)
- `n_estimators=200` for stable scores
- Achieves ~95% accuracy on bootstrap validation data
- Saved to: `models/isolation_forest.pkl` + `models/process_scaler.pkl`

### One-Class SVM (Network-Level)

One-Class SVM learns a boundary around the normal traffic distribution using an RBF kernel. Any flow that falls outside the boundary is flagged as anomalous. It is effective for network intrusion detection where the attack space is unknown and diverse.

- Trained exclusively on normal network flows (unsupervised)
- `nu=0.05`, `kernel='rbf'`, `gamma='scale'`
- Achieves ~96% accuracy on bootstrap validation data
- Saved to: `models/ocsvm.pkl` + `models/network_scaler.pkl`

### Severity Scoring

Both detectors produce a continuous anomaly score. Severity is bucketed as follows:

| Severity | Network (OC-SVM score) | Process (IF score) |
|---|---|---|
| LOW | < 0.20 | < 0.30 |
| MEDIUM | 0.20 – 0.40 | 0.30 – 0.50 |
| HIGH | 0.40 – 0.60 | 0.50 – 0.65 |
| CRITICAL | ≥ 0.60 | ≥ 0.65 |

Any flow to a known OT port (502, 5020, 20000, 102, 44818, 47808) is force-flagged as at least LOW severity even if the model scores it as normal — because any unsolicited connection to a PLC port is operationally significant.

---

## Project Structure

```
ot-security-monitor/
│
├── bootstrap_train.py          # Generate synthetic data + train both models
│
├── pipeline/
│   ├── __init__.py
│   ├── detector.py             # Isolation Forest + OC-SVM inference classes
│   └── zeek_parser.py          # Tail conn.log → extract features → write alerts
│
├── api/
│   └── main.py                 # FastAPI backend (/api/alerts /api/stats /health)
│
├── dashboard/
│   └── index.html              # Single-file operator dashboard (no build step)
│
├── zeek_scripts/
│   └── ics_monitor.zeek        # Custom Zeek script with ICS analyzers + OT tagging
│
├── models/                     # Created by bootstrap_train.py
│   ├── isolation_forest.pkl
│   ├── ocsvm.pkl
│   ├── process_scaler.pkl
│   ├── network_scaler.pkl
│   ├── process_feature_names.pkl
│   └── network_feature_names.pkl
│
├── data/                       # Created by bootstrap_train.py
│   ├── batadal/
│   │   └── combined.parquet    # Synthetic BATADAL-schema training data
│   ├── toniot/
│   │   └── combined.parquet    # Synthetic TON_IoT-schema training data
│   └── alerts.db               # SQLite — written by zeek_parser.py at runtime
│
└── validation/
    └── replay_batadal.py       # Offline validation against labeled attack scenarios
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Ubuntu | 22.04 LTS | Native or WSL-2 on Windows 10/11 |
| Python | 3.10 – 3.12 | System Python or pyenv |
| Zeek | 6.x | Installed to `/opt/zeek/` |
| nmap | 7.x | For generating test traffic |
| Git | Any | For cloning the repo |
| 4 GB RAM | — | Minimum; 8 GB recommended |
| WSL-2 network | — | Set to `networkingMode=mirrored` in `.wslconfig` for best results |

---

## Setup Guide

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/ot-security-monitor.git
cd ot-security-monitor
```

### 2. Install System Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    git curl wget build-essential cmake \
    python3-pip python3-venv \
    libssl-dev libpcap-dev \
    net-tools tcpdump nmap sqlite3
```

### 3. Install OpenPLC

OpenPLC simulates a real PLC and exposes Modbus TCP on port 502.

```bash
git clone https://github.com/thiagoralves/OpenPLC_v3.git ~/OpenPLC_v3
cd ~/OpenPLC_v3
./install.sh linux
```

Start OpenPLC:

```bash
cd ~/OpenPLC_v3
sudo ./start_openplc.sh
```

The web interface is available at `http://localhost:8080` (credentials: `openplc` / `openplc`). Upload a ladder logic program via Programs → Upload Program. The runtime will expose Modbus TCP on port 502.

### 4. Install Conpot

Conpot is an ICS honeypot that emulates multiple SCADA protocols simultaneously.

```bash
# Python 3.10 is recommended for Conpot compatibility
python3.10 -m venv ~/.venvs/conpot310
source ~/.venvs/conpot310/bin/activate
pip install conpot
deactivate
```

Start Conpot (the `-f` flag uses a testing config that avoids requiring root for low ports):

```bash
source ~/.venvs/conpot310/bin/activate
conpot --template default -f
```

Conpot will start listeners on these ports (in testing mode):
- `5020/tcp` — Modbus TCP
- `10201/tcp` — S7comm
- `8800/tcp` — HTTP
- `47808/udp` — BACnet
- `2121/tcp` — FTP
- `6969/udp` — TFTP

### 5. Install Zeek with ICS Analyzers

```bash
# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install -y zeek

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Install ICS analyzer plugins
zkg install icsnpp-modbus
zkg install icsnpp-dnp3
zkg install icsnpp-enip
```

> **WSL-2 note:** Zeek will warn about invalid TCP checksums due to NIC offloading. Always use the `-C` flag (ignore checksums) when starting Zeek on WSL-2.

Set Zeek to write logs to a fixed directory:

```bash
sudo mkdir -p /home/$USER/zeek-logs
# Edit /opt/zeek/etc/zeekctl.cfg and set:
# LogDir = /home/<your-username>/zeek-logs
```

### 6. Python Environment

```bash
python3 -m venv ~/ot-security-env
source ~/ot-security-env/bin/activate

pip install \
    pandas numpy scikit-learn joblib pyarrow \
    fastapi uvicorn aiofiles
```

### 7. Train the Models

```bash
source ~/ot-security-env/bin/activate
cd ~/ot-security-monitor
python bootstrap_train.py
```

Expected output:

```
[1/4] Generating BATADAL-schema synthetic data …
   Normal: 8,000  |  Attack: 2,000
[2/4] Generating TON_IoT-schema synthetic data …
   Normal: 10,000  |  Attack: 3,000
[3/4] Training Isolation Forest (process anomaly) …
   Accuracy: ~95%
[4/4] Training One-Class SVM (network anomaly) …
   Accuracy: ~96%
✓ Bootstrap training complete. All models saved to models/
```

---

## Running the System

The system requires five terminal sessions running simultaneously.

```
Terminal 1 — OpenPLC (PLC simulation)
Terminal 2 — Conpot  (ICS honeypot)
Terminal 3 — Zeek    (traffic capture)
Terminal 4 — Parser  (ML inference)
Terminal 5 — API     (FastAPI server)
```

### Terminal 1 — OpenPLC

```bash
cd ~/OpenPLC_v3
sudo ./start_openplc.sh
```

### Terminal 2 — Conpot

```bash
source ~/.venvs/conpot310/bin/activate
conpot --template default -f
```

### Terminal 3 — Zeek

```bash
# -C suppresses checksum offloading warning on WSL-2
cd zeek-logs
sudo /opt/zeek/bin/zeek -C -i any ~/ot-security-monitor/zeek_scripts/ics_monitor.zeek
```

You should see OT connection events as they arrive:

```
[OT-CONN] 127.0.0.1:46324 → 127.0.0.1:502  (502/tcp)
[MODBUS ] src=127.0.0.1  func=17  is_request=T
```

### Terminal 4 — ML Parser

```bash
source ~/ot-security-env/bin/activate
cd ~/ot-security-monitor

# Point to wherever Zeek is writing conn.log
python pipeline/zeek_parser.py \
    --log ~/zeek-logs/conn.log \
    --db  data/alerts.db
```

Alerts appear in real time:

```
[ALERT] CRITICAL | 127.0.0.1:47076 → 127.0.0.1:5020 (tcp) | ot_protocol_probe | score=19.17
[ALERT] LOW      | 127.0.0.1:60546 → 127.0.0.1:502  (tcp) | ot_protocol_probe | score=-0.64
```

### Terminal 5 — API + Dashboard

```bash
source ~/ot-security-env/bin/activate
cd ~/ot-security-monitor
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` in your browser. On WSL-2, this is accessible from the Windows browser directly.

---

## Testing with Simulated Attacks

With all five terminals running, use the following commands to generate ICS attack traffic and verify the detection pipeline responds:

```bash
# Probe the real OpenPLC Modbus server (port 502)
nmap -p 502 --script modbus-discover localhost

# Probe the Conpot honeypot Modbus server (port 5020)
nmap -p 5020 --script modbus-discover localhost

# Scan all common OT ports at once
nmap -p 502,5020,20000,102,44818,47808 localhost

# Generate high-volume traffic (DoS simulation)
nmap -p 502 --min-rate 1000 localhost
```

Each nmap run should produce new ALERT lines in Terminal 4 and new rows in the dashboard within 5 seconds.

**Expected detection:** Port 502 and 5020 connections are always flagged as `ot_protocol_probe`. Refused connections to closed ports (80, 443) are flagged as `refused_connection`. High-rate traffic triggers higher anomaly scores and CRITICAL severity.

**Expected Conpot log (Terminal 2):**

```
New modbus session from 127.0.0.1
New Modbus connection from 127.0.0.1:58430
```

---

## Dashboard Walkthrough

The dashboard at `http://localhost:8000` has four main panels:

**Stat cards (top row)**
Five cards showing total alerts, CRITICAL count, HIGH count, MEDIUM count, and total flows analyzed. The CRITICAL card turns red when populated.

**Live alert feed (main panel)**
A live-updating table showing every alert with timestamp, severity badge, source IP:port, destination IP:port, protocol, anomaly type, and ML score. Rows animate in when new. A severity dropdown filters the feed. Rows to OT ports (502, 5020, DNP3) appear immediately after any nmap scan.

**Severity breakdown (top-right)**
A donut chart showing the CRITICAL / HIGH / MEDIUM / LOW split updated on every poll cycle.

**Alert types (mid-right)**
Horizontal bar chart showing `ot_protocol_probe`, `network_anomaly`, and `refused_connection` counts. This makes it immediately visible what kind of activity is dominant.

**Active target ports (bottom-right)**
Ranked list of destination ports being hit, with amber glow dots for OT ports and gray dots for IT ports.

**Service status (header)**
Four pulsing green dots for OpenPLC, Conpot, Zeek, and the API. The API dot turns red if the backend becomes unreachable.

---

## Alert Types and Severity

| Alert Type | Trigger | Typical Severity |
|---|---|---|
| `ot_protocol_probe` | Any connection to port 502, 5020, 102, 20000, 44818, 47808 | CRITICAL (first contact) / LOW (subsequent) |
| `network_anomaly` | OC-SVM flags a flow as outside the normal distribution | CRITICAL (high score) |
| `refused_connection` | `conn_state` is RSTRH, RSTO, or REJ — target actively refused | CRITICAL |
| `syn_no_reply` | `conn_state` is S0 — SYN sent, no response | MEDIUM |

---

## Replacing Synthetic Data with Real Datasets

The `bootstrap_train.py` script generates training data that matches the schema of BATADAL and TON_IoT but does not replace them. Once you download the real datasets, retrain the models as follows:

### Real BATADAL Data

1. Download from [batadal.net/data.html](https://www.batadal.net/data.html) (free, no registration)
2. Place CSVs in `data/batadal/`
3. Edit `bootstrap_train.py` — replace the synthetic generation block (Step 1) with:

```python
df_normal = pd.read_csv('data/batadal/BATADAL_dataset03.csv')
df_attack  = pd.read_csv('data/batadal/BATADAL_dataset04.csv')
```

4. Re-run: `python bootstrap_train.py`

### Real TON_IoT Data

1. Request access at [research.unsw.edu.au/projects/toniot-datasets](https://research.unsw.edu.au/projects/toniot-datasets)
2. Place `Train_Test_Network.csv` in `data/toniot/`
3. Edit the TON_IoT block in `bootstrap_train.py` similarly
4. Re-run: `python bootstrap_train.py`

---

## Known Limitations

**Synthetic training data** — The default models are trained on synthetic data matching the schema of BATADAL and TON_IoT. Real-world detection accuracy will improve significantly after retraining on the actual datasets.

**Localhost-only traffic** — In the default WSL-2 setup, all traffic is between `127.0.0.1` addresses. In a real deployment, Zeek would be placed on a network tap monitoring actual PLC traffic from external sources.

**No process-level feedback loop** — The Isolation Forest process detector is trained offline on BATADAL data and does not currently receive live sensor readings from OpenPLC. Wiring OpenPLC's Modbus registers into a sensor polling loop (via `pymodbus`) and feeding that into the detector is the natural next step.

**Single-host simulation** — OpenPLC and Conpot run on the same host as the detector. A more realistic testbed would place them on separate virtual machines or containers with a virtual network switch in between.

**No alert deduplication** — If Zeek logs the same connection twice (once when opened, once when closed), the parser may emit two alerts for the same event.

---

## References

1. Taormina, R. et al. *The Battle of the Attack Detection Algorithms: Disclosing Cyber Attacks on Water Distribution Networks.* Journal of Water Resources Planning and Management, 2018.

2. Moustafa, N. *TON_IoT Datasets: A novel set of IoT-based network traffic traces for evaluating AI-based Network Intrusion Detection Systems.* IEEE Access, 2021.

3. Zahoor, A., Babar, M.Z., Abbasi, W., et al. *IoT security using isolation forest and one class SVM algorithms.* Scientific Reports 15, 36586, 2025. [doi:10.1038/s41598-025-20445-4](https://doi.org/10.1038/s41598-025-20445-4)

4. [OpenPLC Runtime](https://github.com/thiagoralves/OpenPLC_v3) — Thiago Alves, MushMush Foundation

5. [Conpot](https://github.com/mushorg/conpot) — MushMush Foundation

6. [Zeek Network Security Monitor](https://zeek.org)

7. [ICSNPP Zeek Plugin Suite](https://github.com/cisagov/icsnpp) — CISA

---

## License

MIT License. See `LICENSE` for details.

---

*Built as part of a Hitachi Problem Statement 3 — AI-Assisted OT Security Monitoring.*