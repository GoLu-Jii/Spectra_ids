# SPECTRA High-Speed Telemetry & Threat Traffic Generator (SIH Problem Statement 1745)

Designed specifically for the **Smart India Hackathon (SIH 1745)** 3-PC physical demonstration setup.

Supports **ALL 6 SPECTRA PRD Threat Vectors**:
1. 🔥 **Volumetric / Protocol DDoS**
2. ⚡ **Reconnaissance / Port Scan**
3. 📡 **Botnet C2 Beaconing**
4. 🌐 **DGA + DNS Tunnelling**
5. 🔒 **Malware in Encrypted Sessions (TLS/QUIC)**
6. 📤 **Data Exfiltration Anomaly**

---

## 🖥️ 3-PC Setup Architecture & Topology

```text
┌────────────────────────────────┐         High-Speed Ingress Traffic           ┌────────────────────────────────┐
│     PC 1: Traffic Generator    │ ───────────────────────────────────────────> │     PC 2: Target Receiver      │
│  (Sender Node - IP: PC1_IP)    │ ────────┐                                    │  (Target Node - IP: PC2_IP)    │
└────────────────────────────────┘         │ (Dual Stream over WiFi / Hotspot)  └────────────────────────────────┘
                                           │
                                           ▼
                                ┌────────────────────────────────┐
                                │ PC 3: SPECTRA Analysis Engine  │
                                │  (Backend API + SOC Dashboard) │
                                └────────────────────────────────┘
```

---

## 🚀 Step-by-Step Demo Execution Guide

### 1. On PC 2 (Target Receiver Node)

Open Terminal / PowerShell on **PC 2** and start the live receiver CLI:

```bash
python -m traffic_generator.minimal_receiver
```
> **📌 Read PC 2's IP**: Note down the local IPv4 address displayed at the top of PC 2's screen (e.g. `10.179.194.55`).

---

### 2. On PC 1 (Traffic Generator Node)

Open Terminal / PowerShell on **PC 1** and start the traffic generator CLI, providing PC 2's IP and PC 3's IP:

```bash
python -m traffic_generator.minimal_cli <PC2_TARGET_IP> 8000 <PC3_ANALYZER_IP>
```
*Example:*
```bash
python -m traffic_generator.minimal_cli 10.179.194.55 8000 10.179.194.102
```

> **Note for WiFi / Mobile Hotspot Demos**: Specifying PC 3's Analyzer IP enables **Dual-Stream Mode**, sending frames to BOTH PC 2 (Target Receiver) AND PC 3 (SPECTRA Analyzer) simultaneously so PC 3 receives 100% of live packets without requiring a hardware SPAN switch.

#### Keyboard Hotkey Controls (Live 250ms Screen Refresh):
* **`S`**: **Start / Stop Transmission Engine**
* **`1`**: **Toggle Normal Background Stream** (80-90% majority traffic)
* **`2`**: **Toggle Volumetric DDoS SYN/UDP Flood Attack**
* **`3`**: **Toggle Reconnaissance Port Scan Attack** (Ports 1-1000)
* **`4`**: **Toggle Botnet C2 Beaconing Stream**
* **`5`**: **Toggle DGA + DNS Tunnelling Request Stream**
* **`6`**: **Toggle Malware in Encrypted Sessions Stream (TLS/QUIC)**
* **`7`**: **Toggle Data Exfiltration Anomaly Stream**
* **`8`**: **BURST ALL 6 THREAT VECTORS SIMULTANEOUSLY**
* **`C`**: **Change Target PC 2 IP / Port** dynamically
* **`A`**: **Set / Update Analyzer PC 3 IP** dynamically
* **`Q`**: **Quit Generator**

---

### 3. On PC 3 (SPECTRA Passive Analysis Node)

#### Terminal 1: Start ML Backend API
```powershell
cd Spectra_ids
.\.venv\Scripts\python.exe -m uvicorn backend.app.p0_demo:app --host 0.0.0.0 --port 8000 --reload
```

#### Terminal 2: Start React SOC Dashboard
```powershell
cd Spectra_ids\frontend_demo
npm run dev -- --host 0.0.0.0
```

#### Open Web Browser on PC 3:
Navigate to:
```text
http://localhost:5173
```
Confirm top-right status shows **🟢 LIVE WEBSOCKET** / **ONLINE**.

---

## 🎭 Live Pitch Demonstration Walkthrough for Judges

1. **Normal Baseline Operation**:
   * On PC 1, press **`S`** to start sending normal baseline traffic.
   * Observe PC 1 & PC 2 terminal screens updating continuously live every 250ms.

2. **All 6 Threat Vectors Injection**:
   * On PC 1, press hotkeys **`2`**, **`3`**, **`4`**, **`5`**, **`6`**, **`7`** or press **`8`** to burst **ALL 6 THREAT VECTORS**.
   * On PC 3 Dashboard, observe all 6 threat family rows activating with real-time packet ingress and forensic payload evidence.
