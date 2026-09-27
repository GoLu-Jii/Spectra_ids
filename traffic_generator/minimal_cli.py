"""SPECTRA Ultra-Minimal Live-Refreshing Terminal CLI for Traffic Generation (SIH 1745).

Lightweight, single-screen interactive terminal CLI:
- Continuously auto-refreshes screen live every 250ms (no blocking input!)
- Instant hotkey actions: [1], [2], [3], [S], [C], [A], [Q]
- Supports dual-destination streaming to PC 2 Target AND PC 3 Analyzer!
"""

from __future__ import annotations

import os
import sys
import time
from typing import List

from traffic_generator.generator import TrafficEngine
from traffic_generator.sender_tui import get_system_ips


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def get_key_nonblocking() -> str | None:
    """Non-blocking keyboard character check (Windows & Posix)."""
    if sys.platform == "win32":
        import msvcrt
        if msvcrt.kbhit():
            try:
                ch = msvcrt.getch()
                return ch.decode("utf-8", errors="ignore").upper()
            except Exception:
                return None
        return None
    else:
        import select
        if select.select([sys.stdin], [], [], 0)[0]:
            try:
                ch = sys.stdin.read(1)
                return ch.upper()
            except Exception:
                return None
        return None


def main() -> None:
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    analyzer_ip = sys.argv[3] if len(sys.argv) > 3 else None

    engine = TrafficEngine(
        target_ip=target_ip,
        target_port=target_port,
        analyzer_ip=analyzer_ip,
        worker_threads=8,
    )
    local_ips = get_system_ips()

    last_pkts = 0
    last_bytes = 0
    last_time = time.time()

    pps = 0.0
    mbps = 0.0

    prompt_mode = False

    try:
        while True:
            now = time.time()
            dt = now - last_time
            if dt >= 0.25:
                current_pkts = engine.stats.total_packets
                current_bytes = engine.stats.total_bytes
                pps = (current_pkts - last_pkts) / dt if dt > 0 else 0
                mbps = ((current_bytes - last_bytes) * 8) / (dt * 1_000_000) if dt > 0 else 0
                last_pkts = current_pkts
                last_bytes = current_bytes
                last_time = now

            if not prompt_mode:
                status_str = "RUNNING ▶" if engine.running else "STOPPED ■"
                ddos_str = "ACTIVE 🔥" if engine.ddos_active else "OFF"
                scan_str = "ACTIVE ⚡" if engine.portscan_active else "OFF"
                norm_str = "ACTIVE ℹ" if engine.normal_active else "OFF"
                analyzer_str = engine.analyzer_ip if engine.analyzer_ip else "NONE (Direct Target Only)"

                clear_screen()
                print("===============================================================")
                print("     SPECTRA ULTRA-MINIMAL TRAFFIC GENERATOR CLI (SIH 1745)     ")
                print("===============================================================")
                print(f" Local IPs     : {', '.join(local_ips)}")
                print(f" Target PC 2   : {engine.target_ip}:{engine.target_port}")
                print(f" Analyzer PC 3 : {analyzer_str}")
                print(f" Engine Status : {status_str}")
                print(f" Rate (PPS)    : {int(pps):,} pps")
                print(f" Bandwidth     : {mbps:.1f} Mbps")
                print(f" Total Sent    : {engine.stats.total_packets:,} pkts")
                print("---------------------------------------------------------------")
                print(f" [1] Normal Background Traffic : {norm_str}")
                print(f" [2] Volumetric DDoS Flood     : {ddos_str}")
                print(f" [3] Recon Port Scan           : {scan_str}")
                print("---------------------------------------------------------------")
                print(" [S] Start / Stop Engine")
                print(" [C] Change Target PC 2 IP / Port")
                print(" [A] Set Analyzer PC 3 IP (Dual Stream for WiFi)")
                print(" [Q] Quit")
                print("===============================================================")
                print(" Press Hotkey [1-3, S, C, A, Q] (Live Refresh Active)...")

            # Check non-blocking key input
            key = get_key_nonblocking()
            if key == "S":
                if engine.running:
                    engine.stop()
                else:
                    engine.start()
                    last_pkts = engine.stats.total_packets
                    last_bytes = engine.stats.total_bytes
                    last_time = time.time()
            elif key == "1":
                engine.toggle_normal()
            elif key == "2":
                engine.toggle_ddos()
            elif key == "3":
                engine.toggle_portscan()
            elif key == "C":
                prompt_mode = True
                print("\n --- Change Target PC 2 Address ---")
                new_ip = input(" Enter Target PC 2 IP (e.g. 10.179.194.55): ").strip()
                new_port_str = input(" Enter Target Port [default 8000]: ").strip()
                if new_ip:
                    engine.target_ip = new_ip
                if new_port_str:
                    try:
                        engine.target_port = int(new_port_str)
                    except ValueError:
                        pass
                prompt_mode = False
            elif key == "A":
                prompt_mode = True
                print("\n --- Set Analyzer PC 3 IP Address ---")
                new_analyzer = input(" Enter Analyzer PC 3 IP (or leave blank to clear): ").strip()
                engine.analyzer_ip = new_analyzer if new_analyzer else None
                prompt_mode = False
            elif key == "Q":
                engine.stop()
                print("\nExiting SPECTRA Generator CLI.")
                break

            time.sleep(0.05)

    except KeyboardInterrupt:
        engine.stop()
        print("\nExiting SPECTRA Generator CLI.")


if __name__ == "__main__":
    main()
