"""SPECTRA Ultra-Minimal Live Receiver CLI (SIH 1745).

Lightweight single-screen terminal listener for PC 2 target node.
- Auto-refreshes screen continuously every 250ms
- Socket address reuse enabled (SO_REUSEADDR)
- Displays active LAN IPs for easy IP discovery
"""

from __future__ import annotations

import os
import socket
import sys
import time
from threading import Thread

from traffic_generator.sender_tui import get_system_ips


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def main() -> None:
    listen_ip = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    listen_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

    local_ips = get_system_ips()
    total_packets = 0
    total_bytes = 0
    running = True
    bind_error = None

    def _listener():
        nonlocal total_packets, total_bytes, bind_error
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.bind((listen_ip, listen_port))

            while running:
                try:
                    data, _ = sock.recvfrom(65535)
                    if data:
                        total_packets += 1
                        total_bytes += len(data)
                except Exception:
                    pass
        except Exception as e:
            bind_error = str(e)

    t = Thread(target=_listener, daemon=True)
    t.start()

    last_pkts = 0
    last_bytes = 0
    last_time = time.time()

    pps = 0.0
    mbps = 0.0

    try:
        while True:
            now = time.time()
            dt = now - last_time

            if dt >= 0.25:
                delta_pkts = total_packets - last_pkts
                delta_bytes = total_bytes - last_bytes

                pps = delta_pkts / dt if dt > 0 else 0
                mbps = ((delta_bytes * 8) / (dt * 1_000_000)) if dt > 0 else 0

                last_pkts = total_packets
                last_bytes = total_bytes
                last_time = now

            clear_screen()
            print("===============================================================")
            print("     SPECTRA ULTRA-MINIMAL TARGET RECEIVER CLI (PC 2)          ")
            print("===============================================================")
            print(f" Receiver LAN IPs : {', '.join(local_ips)}")
            print(f" Listening Address: {listen_ip}:{listen_port}")
            if bind_error:
                print(f" ERROR            : Socket Bind Failed ({bind_error})")
                print("                     Port 8000 may be in use by uvicorn/backend.")
                print("                     Run with: python -m traffic_generator.minimal_receiver 0.0.0.0 8080")
            else:
                print(f" Ingress Rate     : {int(pps):,} pps")
                print(f" Ingress Bandwidth: {mbps:.1f} Mbps")
                print(f" Total Received   : {total_packets:,} pkts")
            print("---------------------------------------------------------------")
            print(" Status           : ENCLAVE ONLINE (Press Ctrl+C to stop)")
            print("===============================================================")

            time.sleep(0.25)

    except KeyboardInterrupt:
        running = False
        print("\nReceiver stopped.")


if __name__ == "__main__":
    main()
