"""SPECTRA Target Receiver & Passive Mirror Enclave — PC 2 Receiver Terminal UI (Textual).

Smart India Hackathon (SIH Problem Statement 1745) - 3-PC Setup:
- PC 1 (Traffic Generator): Sends high-throughput traffic + threat injections
- PC 2 (This Machine): Receives traffic streams and displays ingress telemetry in real-time
- PC 3 (SPECTRA Analysis Enclave): Analyzes mirrored TAP feed in SPECTRA Dashboard
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from threading import Thread
from typing import List

try:
    import psutil
except ImportError:
    psutil = None

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Footer, Header, Label, Log, Static


def get_system_ips() -> List[str]:
    """Retrieve all local active IPv4 addresses from network interfaces."""
    ips = []
    if psutil:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ips.append(f"{iface}: {addr.address}")
        except Exception:
            pass
    if not ips:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if not ip.startswith("127."):
                ips.append(ip)
        except Exception:
            pass
    return ips or ["127.0.0.1"]


class ReceiverStatCard(Static):
    def __init__(self, title: str, value: str = "0", subtext: str = "", id_name: str = "") -> None:
        super().__init__(id=id_name)
        self.title_text = title
        self.val_text = value
        self.sub_text = subtext

    def compose(self) -> ComposeResult:
        yield Label(self.title_text, classes="card-title")
        yield Label(self.val_text, id=f"{self.id}-val", classes="card-value")
        yield Label(self.sub_text, id=f"{self.id}-sub", classes="card-sub")

    def update_val(self, val: str, sub: str = "") -> None:
        val_widget = self.query_one(f"#{self.id}-val", Label)
        val_widget.update(val)
        if sub:
            sub_widget = self.query_one(f"#{self.id}-sub", Label)
            sub_widget.update(sub)


class ReceiverApp(App):
    CSS = """
    Screen {
        background: #141417;
        color: #F1F5F9;
        font-family: monospace;
    }

    Header {
        background: #1C1C21;
        color: #10B981;
        text-style: bold;
    }

    Footer {
        background: #1C1C21;
        color: #8A8D9B;
    }

    .header-banner {
        background: #1C1C21;
        border-bottom: 1px solid #2B2C34;
        padding: 1 2;
        height: 5;
        content-align: center middle;
    }

    .title {
        color: #10B981;
        text-style: bold;
        font-size: 16;
    }

    .subtitle {
        color: #8A8D9B;
        font-size: 11;
    }

    .top-grid {
        height: 7;
        margin: 1 2;
    }

    ReceiverStatCard {
        background: #1C1C21;
        border: 1px solid #2B2C34;
        padding: 1;
        margin-right: 1;
        height: 100%;
        flex: 1;
    }

    .card-title {
        color: #8A8D9B;
        font-size: 10;
        text-style: bold;
    }

    .card-value {
        color: #10B981;
        font-size: 16;
        text-style: bold;
    }

    .card-sub {
        color: #64748B;
        font-size: 10;
    }

    .log-panel {
        background: #090A0F;
        border: 1px solid #2B2C34;
        margin: 1 2;
        height: 1fr;
    }

    Log {
        color: #CBD5E1;
        background: #090A0F;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def __init__(self, listen_ip: str = "0.0.0.0", listen_port: int = 8000) -> None:
        super().__init__()
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.local_ips = get_system_ips()

        self.total_packets = 0
        self.total_bytes = 0
        self.last_packets = 0
        self.last_bytes = 0
        self.last_time = time.time()

        self.running = True
        self.socket = None
        self._thread = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        ip_str = " | ".join(self.local_ips)
        yield Container(
            Static("SPECTRA Target Enclave & Receiver Node — PC 2 RECEIVER", classes="title"),
            Static(f"Listening on {self.listen_ip}:{self.listen_port} · PC 2 LAN Ethernet IPs: [ {ip_str} ]", classes="subtitle"),
            classes="header-banner",
        )

        yield Horizontal(
            ReceiverStatCard("INGRESS PACKET RATE", "0 pps", "Observed packet rate", id_name="card-pps"),
            ReceiverStatCard("INGRESS BANDWIDTH", "0.0 Mbps", "Observed bandwidth", id_name="card-mbps"),
            ReceiverStatCard("CUMULATIVE PACKETS", "0", "Total packets received", id_name="card-total"),
            ReceiverStatCard("ENCLAVE STATUS", "ONLINE", "Passive monitoring enclave active", id_name="card-status"),
            classes="top-grid",
        )

        yield Container(
            Log(id="log-box", highlight=True),
            classes="log-panel",
        )

        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#log-box", Log)
        log.write_line("[bold green]SPECTRA Receiver Node Initialized.[/bold green]")
        log.write_line(f"Detected Local Ethernet LAN IPs: [bold yellow]{', '.join(self.local_ips)}[/bold yellow]")
        log.write_line(f"Binding UDP socket on {self.listen_ip}:{self.listen_port}...")

        # Start socket listener thread
        self._thread = Thread(target=self._listener_loop, daemon=True)
        self._thread.start()

        self.set_interval(1.0, self._update_metrics)

    def _listener_loop(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            sock.bind((self.listen_ip, self.listen_port))
            self.socket = sock

            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    if data:
                        self.total_packets += 1
                        self.total_bytes += len(data)
                except Exception:
                    pass
        except Exception as e:
            pass

    def _update_metrics(self) -> None:
        now = time.time()
        dt = now - self.last_time
        if dt <= 0:
            return

        current_pkts = self.total_packets
        current_bytes = self.total_bytes

        delta_pkts = current_pkts - self.last_packets
        delta_bytes = current_bytes - self.last_bytes

        pps = delta_pkts / dt
        mbps = (delta_bytes * 8) / (dt * 1_000_000)

        self.last_packets = current_pkts
        self.last_bytes = current_bytes
        self.last_time = now

        card_pps = self.query_one("#card-pps", ReceiverStatCard)
        card_mbps = self.query_one("#card-mbps", ReceiverStatCard)
        card_total = self.query_one("#card-total", ReceiverStatCard)

        card_pps.update_val(f"{int(pps):,} pps")
        card_mbps.update_val(f"{mbps:.1f} Mbps")
        card_total.update_val(f"{current_pkts:,}")

        log = self.query_one("#log-box", Log)
        if delta_pkts > 0:
            log.write_line(f"[cyan]📥 Ingress Telemetry:[/cyan] {int(pps):,} pps ({mbps:.1f} Mbps) | Total Received: {current_pkts:,} pkts")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPECTRA PC 2 Receiver TUI")
    parser.add_argument("--bind", "-b", default="0.0.0.0", help="IP address to bind listener to")
    parser.add_argument("--port", "-p", type=int, default=8000, help="UDP port to listen on")
    args = parser.parse_args()

    app = ReceiverApp(listen_ip=args.bind, listen_port=args.port)
    app.run()


if __name__ == "__main__":
    main()
