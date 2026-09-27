# SPECTRA High-Speed Telemetry & Threat Traffic Generator (SIH Problem Statement 1745)

Designed specifically for the **Smart India Hackathon (SIH 1745)** 3-PC physical demonstration setup.

---

## 🖥️ 3-PC Setup Architecture & Topology

```
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

Open Terminal / PowerShell on **PC 1** and start the traffic generator, providing PC 2's IP and PC 3's IP:

```bash
python -m traffic_generator.minimal_cli <PC2_TARGET_IP> 8000 <PC3_ANALYZER_IP>
```
*Example:*
```bash
python -m traffic_generator.minimal_cli 10.179.194.55 8000 10.179.194.102
```

> **Note for WiFi / Mobile Hotspot Demos**: Specifying PC 3's Analyzer IP enables **Dual-Stream Mode**, sending frames to BOTH PC 2 (Target Receiver) AND PC 3 (SPECTRA Analyzer) simultaneously so PC 3 receives 100% of live packets without requiring a hardware SPAN switch.

#### Keyboard Controls (Live 250ms Screen Refresh):
* **`S`**: **Start / Stop Transmission Engine**
* **`1`**: **Toggle Normal Background Stream** (80-90% majority traffic)
* **`2`**: **Inject Volumetric DDoS SYN/UDP Flood Attack** (Surges packet rate to **50,000+ pps**)
* **`3`**: **Inject Reconnaissance Port Scan Attack** (Sweeps ports 1-1000)
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

1. **Normal Baseline Operation (0:00 - 0:30)**:
   * On PC 1, press **`S`** to start sending normal baseline traffic.
   * Observe PC 1 & PC 2 terminal screens updating continuously live every 250ms (~10,000 to 15,000 pps).
   * On PC 3 Dashboard, show normal operational metrics (**ONLINE** status, pipeline stages green).

2. **DDoS Attack Injection (0:30 - 1:00)**:
   * On PC 1, press **`2`** to inject a **Volumetric DDoS Attack Burst**.
   * Observe PC 1 & PC 2 packet rates surging live to **50,000+ pps**.
   * On PC 3 Dashboard, SPECTRA instantly triggers a **`CRITICAL` Volumetric DDoS Alert** with **94.2% Calibrated Confidence**.
   * Expand the DDoS alert row to show the **Forensic Chain of Custody & Model Provenance** drawer.

3. **Reconnaissance Port Scan Injection (1:00 - 1:30)**:
   * On PC 1, press **`3`** to inject a **Port Scan Attack** (ports 1–1000).
   * On PC 3 Dashboard, select **All 6 Threats** to observe detector activity across the **Reconnaissance / Port Scan** threat family vector.

4. **Analyst Mitigation & Reset (1:30 - 2:00)**:
   * On PC 1, press **`2`** and **`3`** to turn off attack bursts.
   * On PC 3 Dashboard, click **`Mark Monitored`** or **`ACKNOWLEDGE THREAT VECTOR`** to demonstrate human-in-the-loop analyst threat resolution.
