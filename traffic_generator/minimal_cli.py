"""SPECTRA Ultra-Minimal Terminal CLI for Traffic Generation (SIH Problem Statement 1745).

Lightweight, single-screen interactive terminal CLI:
- Simple keyboard-driven options [1-6]
- Direct IP/Port dynamic configuration
- High-speed multi-threaded transmission (50,000+ pps)
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


def main() -> None:
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

    engine = TrafficEngine(target_ip=target_ip, target_port=target_port, worker_threads=8)
    local_ips = get_system_ips()

    last_pkts = 0
    last_bytes = 0
    last_time = time.time()

    while True:
        clear_screen()
        now = time.time()
        dt = now - last_time
        if dt > 0:
            current_pkts = engine.stats.total_packets
            current_bytes = engine.stats.total_bytes
            pps = (current_pkts - last_pkts) / dt
            mbps = ((current_bytes - last_bytes) * 8) / (dt * 1_000_000)
        else:
            pps = 0.0
            mbps = 0.0

        status_str = "RUNNING ▶" if engine.running else "STOPPED ■"
        ddos_str = "ACTIVE 🔥" if engine.ddos_active else "OFF"
        scan_str = "ACTIVE ⚡" if engine.portscan_active else "OFF"
        norm_str = "ACTIVE ℹ" if engine.normal_active else "OFF"

        print("===============================================================")
        print("     SPECTRA ULTRA-MINIMAL TRAFFIC GENERATOR CLI (SIH 1745)     ")
        print("===============================================================")
        print(f" Local IPs     : {', '.join(local_ips)}")
        print(f" Target PC 2   : {engine.target_ip}:{engine.target_port}")
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
        print(" [C] Change Target IP / Port")
        print(" [Q] Quit")
        print("===============================================================")

        choice = input(" Select Action [1-3, S, C, Q]: ").strip().upper()

        if choice == "S":
            if engine.running:
                engine.stop()
            else:
                engine.start()
                last_pkts = engine.stats.total_packets
                last_bytes = engine.stats.total_bytes
                last_time = time.time()
        elif choice == "1":
            engine.toggle_normal()
        elif choice == "2":
            engine.toggle_ddos()
        elif choice == "3":
            engine.toggle_portscan()
        elif choice == "C":
            new_ip = input(" Enter Target PC 2 IP (e.g. 192.168.1.50): ").strip()
            new_port_str = input(" Enter Target Port [default 8000]: ").strip()
            if new_ip:
                engine.target_ip = new_ip
            if new_port_str:
                try:
                    engine.target_port = int(new_port_str)
                except ValueError:
                    pass
        elif choice == "Q":
            engine.stop()
            print("\nExiting SPECTRA Generator CLI.")
            break


if __name__ == "__main__":
    main()
