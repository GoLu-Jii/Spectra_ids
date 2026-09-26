"""SPECTRA High-Speed Threat & Telemetry Traffic Engine.

Designed for SIH Demonstration (3-PC Setup):
- High-throughput multi-threaded packet generation (50,000+ pps target)
- Mixed traffic profiles: Normal Background (80-90%) + DDoS SYN/UDP Flood + Port Scan
- Real-time stats reporting (packets/sec, Mbps, active threats)
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class GeneratorStats:
    total_packets: int = 0
    total_bytes: int = 0
    normal_packets: int = 0
    ddos_packets: int = 0
    portscan_packets: int = 0
    current_pps: float = 0.0
    current_mbps: float = 0.0
    start_time: float = field(default_factory=time.time)


class TrafficEngine:
    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 8000,
        worker_threads: int = 8,
    ) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.worker_threads = worker_threads
        self.running = False
        self.stats = GeneratorStats()

        # Threat Toggles
        self.normal_active = True
        self.ddos_active = False
        self.portscan_active = False

        # Configurable Attack Parameters
        self.ddos_target_port = 80
        self.portscan_start_port = 1
        self.portscan_end_port = 1000
        self.current_scan_port = 1

        # Pre-built payload buffers for maximum throughput
        self._normal_payloads = [
            b"GET /api/v1/health HTTP/1.1\r\nHost: spectra.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"POST /api/v1/telemetry HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"status\":\"ok\",\"timestamp\":1727390000}",
            os.urandom(256),
            os.urandom(512),
            os.urandom(1024),
        ]
        self._ddos_payload = os.urandom(1200)  # Heavy 1200-byte UDP flood payload

        self._executor: ThreadPoolExecutor | None = None
        self._lock = asyncio.Lock()

    def set_target(self, target_ip: str, target_port: int) -> None:
        self.target_ip = target_ip
        self.target_port = target_port

    def toggle_ddos(self, state: bool | None = None) -> bool:
        if state is None:
            self.ddos_active = not self.ddos_active
        else:
            self.ddos_active = state
        return self.ddos_active

    def toggle_portscan(self, state: bool | None = None) -> bool:
        if state is None:
            self.portscan_active = not self.portscan_active
        else:
            self.portscan_active = state
        return self.portscan_active

    def toggle_normal(self, state: bool | None = None) -> bool:
        if state is None:
            self.normal_active = not self.normal_active
        else:
            self.normal_active = state
        return self.normal_active

    def _worker_loop(self, worker_id: int) -> None:
        """High-speed socket transmission loop executed across thread workers."""
        # Create non-blocking UDP socket per worker for max pps
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)

        target = self.target_ip
        default_port = self.target_port

        local_pkt_cnt = 0
        local_byte_cnt = 0
        local_normal_cnt = 0
        local_ddos_cnt = 0
        local_scan_cnt = 0

        last_sync = time.time()

        while self.running:
            target = self.target_ip
            default_port = self.target_port
            try:
                # 1. DDoS Attack Burst Mode (Heavy UDP/SYN flood)
                if self.ddos_active:
                    # Send batch of 50 packets per iteration
                    for _ in range(50):
                        dport = self.ddos_target_port
                        sock.sendto(self._ddos_payload, (target, dport))
                        local_pkt_cnt += 1
                        local_byte_cnt += 1200
                        local_ddos_cnt += 1

                # 2. Port Scan Burst Mode (Scanning sequential ports)
                if self.portscan_active:
                    for _ in range(20):
                        scan_port = (self.current_scan_port % (self.portscan_end_port - self.portscan_start_port + 1)) + self.portscan_start_port
                        self.current_scan_port += 1
                        payload = b"SYN_PROBE_SPECTRA_" + str(scan_port).encode()
                        sock.sendto(payload, (target, scan_port))
                        local_pkt_cnt += 1
                        local_byte_cnt += len(payload)
                        local_scan_cnt += 1

                # 3. Normal Background Traffic (80-90% volume stream)
                if self.normal_active or (not self.ddos_active and not self.portscan_active):
                    for _ in range(30):
                        payload = random.choice(self._normal_payloads)
                        dest_p = default_port if random.random() > 0.3 else random.randint(1024, 65535)
                        sock.sendto(payload, (target, dest_p))
                        local_pkt_cnt += 1
                        local_byte_cnt += len(payload)
                        local_normal_cnt += 1

                # Periodic stats update every 100ms
                now = time.time()
                if now - last_sync >= 0.1:
                    self.stats.total_packets += local_pkt_cnt
                    self.stats.total_bytes += local_byte_cnt
                    self.stats.normal_packets += local_normal_cnt
                    self.stats.ddos_packets += local_ddos_cnt
                    self.stats.portscan_packets += local_scan_cnt

                    local_pkt_cnt = 0
                    local_byte_cnt = 0
                    local_normal_cnt = 0
                    local_ddos_cnt = 0
                    local_scan_cnt = 0
                    last_sync = now

            except Exception:
                time.sleep(0.001)

        sock.close()

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.stats = GeneratorStats()
        self._executor = ThreadPoolExecutor(max_workers=self.worker_threads)
        for i in range(self.worker_threads):
            self._executor.submit(self._worker_loop, i)

    def stop(self) -> None:
        self.running = False
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None
