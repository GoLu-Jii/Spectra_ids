# SPECTRA High-Speed Telemetry & Threat Traffic Generator (SIH Problem Statement 1745)

Built for the **Smart India Hackathon (SIH 1745)** 3-PC physical demonstration.

---

## Operating Modes

You can run the generator in **two different minimal terminal UI styles**:

### Mode A: Textual Full Terminal UI (Rich Cards & Mouse Support)
* **PC 1 Sender**: `python -m traffic_generator.sender_tui`
* **PC 2 Receiver**: `python -m traffic_generator.receiver_tui`

### Mode B: Ultra-Minimal Single-Screen CLI (Lightweight Keyboard Prompt)
* **PC 1 Sender**: `python -m traffic_generator.minimal_cli [target_ip] [target_port]`
* **PC 2 Receiver**: `python -m traffic_generator.minimal_receiver [bind_ip] [bind_port]`

---

## Quick Start (3-PC Setup)

### 1. On PC 2 (Target Receiver Node)

Run either:
```bash
python -m traffic_generator.receiver_tui
```
*or for the ultra-minimal text prompt:*
```bash
python -m traffic_generator.minimal_receiver
```
> Read PC 2's local Ethernet IP address displayed on the header banner (e.g., `192.168.1.50`).

---

### 2. On PC 1 (Traffic Generator Node)

Run either:
```bash
python -m traffic_generator.sender_tui --target 192.168.1.50 --port 8000
```
*or for ultra-minimal text CLI:*
```bash
python -m traffic_generator.minimal_cli 192.168.1.50 8000
```

#### Controls:
* **`S`** or `[1]`: **Start / Stop Transmission Engine**
* **`N`** or `[1]`: **Toggle Normal Background Stream** (80-90% majority traffic)
* **`D`** or `[2]`: **Inject Volumetric DDoS SYN/UDP Flood Attack** (surges to 50,000+ pps)
* **`P`** or `[3]`: **Inject Reconnaissance Port Scan Attack** (scans ports 1-1000)
* **`C`**: **Change Target IP or Port** dynamically

---

### 3. On PC 3 (SPECTRA Analysis Enclave)

* Runs Zeek + FastAPI backend + SPECTRA Dashboard (`frontend_demo/`).
* Receives mirrored passive feed from TAP/SPAN switch port and classifies threat vectors live on the dashboard.
