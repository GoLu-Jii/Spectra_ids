"""SPECTRA High-Speed Threat & Telemetry Traffic Engine.

Designed for SIH Demonstration (3-PC Setup):
- High-throughput multi-threaded packet generation (50,000+ pps target)
- Mixed traffic profiles across ALL 6 SPECTRA PRD Threat Families:
  1. Volumetric / Protocol DDoS
  2. Botnet C2 Beaconing
  3. DGA + DNS Tunnelling
  4. Malware in Encrypted Sessions (TLS/QUIC)
  5. Reconnaissance / Port Scan
  6. Data Exfiltration Anomaly
- Real-time stats reporting for all 6 threat vectors
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
    c2_packets: int = 0
    dns_tunnel_packets: int = 0
    tls_malware_packets: int = 0
    exfil_packets: int = 0
    current_pps: float = 0.0
    current_mbps: float = 0.0
    start_time: float = field(default_factory=time.time)


class TrafficEngine:
    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 8000,
        analyzer_ip: str | None = None,
        worker_threads: int = 8,
    ) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.analyzer_ip = analyzer_ip
        self.worker_threads = worker_threads
        self.running = False
        self.stats = GeneratorStats()

        # Threat Toggles (All 6 PRD Threat Vectors)
        self.normal_active = True
        self.ddos_active = False
        self.portscan_active = False
        self.c2_active = False
        self.dns_tunnel_active = False
        self.tls_malware_active = False
        self.exfil_active = False

        # Configurable Attack Parameters
        self.ddos_target_port = 80
        self.portscan_start_port = 1
        self.portscan_end_port = 1000
        self.current_scan_port = 1

        # Pre-built payload buffers for all 6 threat classes + normal background
        self._normal_payloads = [
            b"GET /api/v1/health HTTP/1.1\r\nHost: spectra.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"POST /api/v1/telemetry HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"status\":\"ok\",\"timestamp\":1727390000}",
            os.urandom(256),
            os.urandom(512),
            os.urandom(1024),
        ]
        
        # 1. DDoS Payload (Heavy 1200-byte UDP flood)
        self._ddos_payload = os.urandom(1200)

        # 2. C2 Beaconing Payloads (Periodic command-and-control HTTP/HTTPS calls)
        self._c2_payloads = [
            b"POST /api/v1/c2/beacon HTTP/1.1\r\nHost: c2-command-control.botnet.net\r\nX-Beacon-Period: 30s\r\nX-Bot-ID: bot-worker-092\r\n\r\n",
            b"GET /gateway/heartbeat?id=c2_agent_77&session=a9f82c1 HTTP/1.1\r\nHost: command-and-control.infra.cc\r\nUser-Agent: C2-Agent/1.0\r\n\r\n",
        ]

        # 3. DGA + DNS Tunnelling Payloads (High-entropy subdomain query simulation)
        self._dns_tunnel_payloads = [
            b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1a" + os.urandom(16).hex().encode() + b"\x07spectra\x03org\x00\x00\x10\x00\x01",
            b"DNS_TUNNEL_PAYLOAD_EXFIL_DATA_ENTROPY_4.82_" + os.urandom(64),
        ]

        # 4. Malware in Encrypted Sessions Payloads (TLS handshake / JA3 anomaly header simulation)
        self._tls_malware_payloads = [
            b"\x16\x03\x01\x00\xca\x01\x00\x00\xc6\x03\x03" + os.urandom(32) + b"_JA3_771fd2b5e201d0583167070864617168",
            b"TLS_ANOMALY_MALWARE_ENCRYPTED_SESSION_BURST_" + os.urandom(128),
        ]

        # 5. Data Exfiltration Payloads (High-volume outbound payload chunks)
        self._exfil_payloads = [
            b"EXFIL_DATA_CHUNK_BLOB_DB_DUMP_ROW_" + os.urandom(1024),
            b"POST /api/v1/export/database HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n" + os.urandom(1500),
        ]

        self._executor: ThreadPoolExecutor | None = None

    def set_target(self, target_ip: str, target_port: int, analyzer_ip: str | None = None) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        if analyzer_ip is not None:
            self.analyzer_ip = analyzer_ip

    def toggle_normal(self, state: bool | None = None) -> bool:
        self.normal_active = not self.normal_active if state is None else state
        return self.normal_active

    def toggle_ddos(self, state: bool | None = None) -> bool:
        self.ddos_active = not self.ddos_active if state is None else state
        return self.ddos_active

    def toggle_portscan(self, state: bool | None = None) -> bool:
        self.portscan_active = not self.portscan_active if state is None else state
        return self.portscan_active

    def toggle_c2(self, state: bool | None = None) -> bool:
        self.c2_active = not self.c2_active if state is None else state
        return self.c2_active

    def toggle_dns_tunnel(self, state: bool | None = None) -> bool:
        self.dns_tunnel_active = not self.dns_tunnel_active if state is None else state
        return self.dns_tunnel_active

    def toggle_tls_malware(self, state: bool | None = None) -> bool:
        self.tls_malware_active = not self.tls_malware_active if state is None else state
        return self.tls_malware_active

    def toggle_exfil(self, state: bool | None = None) -> bool:
        self.exfil_active = not self.exfil_active if state is None else state
        return self.exfil_active

    def toggle_all_threats(self, state: bool | None = None) -> bool:
        if state is None:
            all_on = (
                self.ddos_active
                and self.portscan_active
                and self.c2_active
                and self.dns_tunnel_active
                and self.tls_malware_active
                and self.exfil_active
            )
            target_state = not all_on
        else:
            target_state = state

        self.ddos_active = target_state
        self.portscan_active = target_state
        self.c2_active = target_state
        self.dns_tunnel_active = target_state
        self.tls_malware_active = target_state
        self.exfil_active = target_state
        return target_state

    def _worker_loop(self, worker_id: int) -> None:
        """High-speed socket transmission loop executed across thread workers."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)

        local_pkt_cnt = 0
        local_byte_cnt = 0
        local_normal_cnt = 0
        local_ddos_cnt = 0
        local_scan_cnt = 0
        local_c2_cnt = 0
        local_dns_cnt = 0
        local_tls_cnt = 0
        local_exfil_cnt = 0

        last_sync = time.time()

        def _send(payload: bytes, port: int) -> None:
            nonlocal local_pkt_cnt, local_byte_cnt
            target = self.target_ip
            analyzer = self.analyzer_ip
            sock.sendto(payload, (target, port))
            if analyzer:
                try:
                    sock.sendto(payload, (analyzer, port))
                except Exception:
                    pass
            local_pkt_cnt += 1
            local_byte_cnt += len(payload)

        while self.running:
            default_port = self.target_port
            try:
                # 1. Volumetric DDoS Attack Burst (Heavy UDP/SYN flood)
                if self.ddos_active:
                    for _ in range(30):
                        dport = self.ddos_target_port
                        _send(self._ddos_payload, dport)
                        local_ddos_cnt += 1

                # 2. Port Scan Burst (Scanning sequential ports 1-1000)
                if self.portscan_active:
                    for _ in range(15):
                        scan_port = (self.current_scan_port % (self.portscan_end_port - self.portscan_start_port + 1)) + self.portscan_start_port
                        self.current_scan_port += 1
                        payload = b"SYN_PROBE_SPECTRA_" + str(scan_port).encode()
                        _send(payload, scan_port)
                        local_scan_cnt += 1

                # 3. Botnet C2 Beaconing Flow (HTTP/HTTPS periodic beaconing)
                if self.c2_active:
                    for _ in range(15):
                        payload = random.choice(self._c2_payloads)
                        _send(payload, 443)
                        local_c2_cnt += 1

                # 4. DGA + DNS Tunnelling Flow (High-entropy UDP query simulation on port 53)
                if self.dns_tunnel_active:
                    for _ in range(15):
                        payload = random.choice(self._dns_tunnel_payloads)
                        _send(payload, 53)
                        local_dns_cnt += 1

                # 5. Malware in Encrypted Sessions Flow (TLS/QUIC anomaly header payload on port 443)
                if self.tls_malware_active:
                    for _ in range(15):
                        payload = random.choice(self._tls_malware_payloads)
                        _send(payload, 443)
                        local_tls_cnt += 1

                # 6. Data Exfiltration Anomaly Flow (High-volume outbound payload burst)
                if self.exfil_active:
                    for _ in range(15):
                        payload = random.choice(self._exfil_payloads)
                        _send(payload, 443)
                        local_exfil_cnt += 1

                # 7. Normal Background Traffic (80-90% volume stream)
                no_threats = not (
                    self.ddos_active
                    or self.portscan_active
                    or self.c2_active
                    or self.dns_tunnel_active
                    or self.tls_malware_active
                    or self.exfil_active
                )
                if self.normal_active or no_threats:
                    for _ in range(25):
                        payload = random.choice(self._normal_payloads)
                        dest_p = default_port if random.random() > 0.3 else random.randint(1024, 65535)
                        _send(payload, dest_p)
                        local_normal_cnt += 1

                # Periodic stats update every 100ms
                now = time.time()
                if now - last_sync >= 0.1:
                    self.stats.total_packets += local_pkt_cnt
                    self.stats.total_bytes += local_byte_cnt
                    self.stats.normal_packets += local_normal_cnt
                    self.stats.ddos_packets += local_ddos_cnt
                    self.stats.portscan_packets += local_scan_cnt
                    self.stats.c2_packets += local_c2_cnt
                    self.stats.dns_tunnel_packets += local_dns_cnt
                    self.stats.tls_malware_packets += local_tls_cnt
                    self.stats.exfil_packets += local_exfil_cnt

                    local_pkt_cnt = 0
                    local_byte_cnt = 0
                    local_normal_cnt = 0
                    local_ddos_cnt = 0
                    local_scan_cnt = 0
                    local_c2_cnt = 0
                    local_dns_cnt = 0
                    local_tls_cnt = 0
                    local_exfil_cnt = 0
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
