"""SPECTRA High-Speed Traffic Generator — PC 1 Sender Terminal UI (Textual).

Smart India Hackathon (SIH Problem Statement 1745) - 3-PC Setup:
- PC 1 (This Machine): Sends high-throughput traffic + all 6 threat injections
- PC 2 (Target Receiver): Receives traffic streams
- PC 3 (SPECTRA Passive Analysis Enclave): Analyzes live mirror feed in Dashboard
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import time
from typing import List

try:
    import psutil
except ImportError:
    psutil = None

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, Footer, Header, Input, Label, Log, Static

from traffic_generator.generator import TrafficEngine


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


class StatCard(Static):
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


class SenderApp(App):
    CSS = """
    Screen {
        background: #141417;
        color: #F1F5F9;
        font-family: monospace;
    }

    Header {
        background: #1C1C21;
        color: #FF7B4B;
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
        color: #FF7B4B;
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

    StatCard {
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
        color: #FF7B4B;
        font-size: 16;
        text-style: bold;
    }

    .card-sub {
        color: #64748B;
        font-size: 10;
    }

    .control-panel {
        background: #1C1C21;
        border: 1px solid #2B2C34;
        margin: 1 2;
        padding: 1;
        height: 11;
    }

    .input-row {
        height: 3;
        margin-bottom: 1;
    }

    .btn-row {
        height: 3;
        margin-bottom: 1;
    }

    Input {
        background: #141417;
        border: 1px solid #2B2C34;
        color: #F1F5F9;
        width: 32;
        margin-right: 2;
    }

    Button {
        margin-right: 1;
        height: 3;
        border: none;
    }

    #btn-start {
        background: #10B981;
        color: #FFFFFF;
    }

    #btn-stop {
        background: #EF4444;
        color: #FFFFFF;
    }

    #btn-normal {
        background: #3B82F6;
        color: #FFFFFF;
    }

    #btn-ddos {
        background: #FF7B4B;
        color: #FFFFFF;
    }

    #btn-portscan {
        background: #F59E0B;
        color: #FFFFFF;
    }

    #btn-c2 {
        background: #8B5CF6;
        color: #FFFFFF;
    }

    #btn-dns {
        background: #06B6D4;
        color: #FFFFFF;
    }

    #btn-tls {
        background: #EC4899;
        color: #FFFFFF;
    }

    #btn-exfil {
        background: #D97706;
        color: #FFFFFF;
    }

    #btn-all {
        background: #DC2626;
        color: #FFFFFF;
        text-style: bold;
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
        ("s", "toggle_engine", "Start/Stop Engine"),
        ("1", "toggle_normal", "Toggle Normal"),
        ("2", "toggle_ddos", "Toggle DDoS"),
        ("3", "toggle_portscan", "Toggle PortScan"),
        ("4", "toggle_c2", "Toggle C2 Beacon"),
        ("5", "toggle_dns", "Toggle DGA DNS"),
        ("6", "toggle_tls", "Toggle TLS Malware"),
        ("7", "toggle_exfil", "Toggle Data Exfil"),
        ("8", "toggle_all", "Burst ALL 6"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 8000) -> None:
        super().__init__()
        self.engine = TrafficEngine(target_ip=target_ip, target_port=target_port, worker_threads=8)
        self.local_ips = get_system_ips()
        self._last_pkts = 0
        self._last_bytes = 0
        self._last_time = time.time()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        ip_str = " | ".join(self.local_ips)
        yield Container(
            Static("SPECTRA High-Speed Telemetry & Threat Generator — PC 1 SENDER", classes="title"),
            Static(f"Smart India Hackathon (SIH 1745) · PC 1 Ethernet IPs: [ {ip_str} ]", classes="subtitle"),
            classes="header-banner",
        )

        yield Horizontal(
            StatCard("PACKET RATE (PPS)", "0 pps", "Target: 50,000+ pps", id_name="card-pps"),
            StatCard("THROUGHPUT (MBPS)", "0.0 Mbps", "Peak egress rate", id_name="card-mbps"),
            StatCard("TOTAL PACKETS SENT", "0", "Accumulated packets", id_name="card-total"),
            StatCard("ACTIVE THREAT MODE", "NORMAL", "Normal background stream", id_name="card-threat"),
            classes="top-grid",
        )

        yield Container(
            Horizontal(
                Static("Target PC 2 IP: ", classes="card-title"),
                Input(value=self.engine.target_ip, placeholder="Target IP (e.g. 192.168.1.50)", id="input-ip"),
                Static("Target Port: ", classes="card-title"),
                Input(value=str(self.engine.target_port), placeholder="Target Port", id="input-port"),
                classes="input-row",
            ),
            Horizontal(
                Button("START ENGINE (S)", id="btn-start"),
                Button("STOP ENGINE", id="btn-stop"),
                Button("NORMAL (1)", id="btn-normal"),
                Button("DDoS (2)", id="btn-ddos"),
                Button("PORT SCAN (3)", id="btn-portscan"),
                classes="btn-row",
            ),
            Horizontal(
                Button("C2 BEACON (4)", id="btn-c2"),
                Button("DNS TUNNEL (5)", id="btn-dns"),
                Button("TLS MALWARE (6)", id="btn-tls"),
                Button("DATA EXFIL (7)", id="btn-exfil"),
                Button("BURST ALL 6 THREATS (8)", id="btn-all"),
                classes="btn-row",
            ),
            classes="control-panel",
        )

        yield Container(
            Log(id="log-box", highlight=True),
            classes="log-panel",
        )

        yield Footer()

    def on_mount(self) -> None:
        log = self.query_one("#log-box", Log)
        log.write_line("[bold green]SPECTRA Traffic Generator Initialized (6-Vector Threat Engine).[/bold green]")
        log.write_line(f"PC 1 Network Interfaces Detected: {', '.join(self.local_ips)}")
        log.write_line(f"Current Target Destination: {self.engine.target_ip}:{self.engine.target_port}")
        log.write_line("Hotkeys: [b]S[/b] Start/Stop | [b]1-7[/b] Threat Toggles | [b]8[/b] Burst All 6 Threats.")
        self.set_interval(1.0, self._update_metrics)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "input-ip":
            new_ip = event.value.strip()
            if new_ip:
                self.engine.target_ip = new_ip
        elif event.input.id == "input-port":
            try:
                self.engine.target_port = int(event.value.strip())
            except ValueError:
                pass

    def _update_metrics(self) -> None:
        now = time.time()
        dt = now - self._last_time
        if dt <= 0:
            return

        current_pkts = self.engine.stats.total_packets
        current_bytes = self.engine.stats.total_bytes

        delta_pkts = current_pkts - self._last_pkts
        delta_bytes = current_bytes - self._last_bytes

        pps = delta_pkts / dt
        mbps = (delta_bytes * 8) / (dt * 1_000_000)

        self._last_pkts = current_pkts
        self._last_bytes = current_bytes
        self._last_time = now

        card_pps = self.query_one("#card-pps", StatCard)
        card_mbps = self.query_one("#card-mbps", StatCard)
        card_total = self.query_one("#card-total", StatCard)
        card_threat = self.query_one("#card-threat", StatCard)

        card_pps.update_val(f"{int(pps):,} pps")
        card_mbps.update_val(f"{mbps:.1f} Mbps")
        card_total.update_val(f"{current_pkts:,}")

        modes = []
        if self.engine.ddos_active:
            modes.append("DDoS")
        if self.engine.portscan_active:
            modes.append("PortScan")
        if self.engine.c2_active:
            modes.append("C2Beacon")
        if self.engine.dns_tunnel_active:
            modes.append("DNSTunnel")
        if self.engine.tls_malware_active:
            modes.append("TLSMalware")
        if self.engine.exfil_active:
            modes.append("DataExfil")
        if self.engine.normal_active:
            modes.append("Normal")

        threat_label = " + ".join(modes) if modes else "STANDBY / IDLE"
        card_threat.update_val(threat_label)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "btn-start":
            self.action_toggle_engine(True)
        elif button_id == "btn-stop":
            self.action_toggle_engine(False)
        elif button_id == "btn-normal":
            self.action_toggle_normal()
        elif button_id == "btn-ddos":
            self.action_toggle_ddos()
        elif button_id == "btn-portscan":
            self.action_toggle_portscan()
        elif button_id == "btn-c2":
            self.action_toggle_c2()
        elif button_id == "btn-dns":
            self.action_toggle_dns()
        elif button_id == "btn-tls":
            self.action_toggle_tls()
        elif button_id == "btn-exfil":
            self.action_toggle_exfil()
        elif button_id == "btn-all":
            self.action_toggle_all()

    def action_toggle_engine(self, state: bool | None = None) -> None:
        log = self.query_one("#log-box", Log)
        ip_input = self.query_one("#input-ip", Input)
        port_input = self.query_one("#input-port", Input)

        self.engine.target_ip = ip_input.value.strip() or "127.0.0.1"
        try:
            self.engine.target_port = int(port_input.value.strip())
        except ValueError:
            self.engine.target_port = 8000

        if state is True or (state is None and not self.engine.running):
            self.engine.start()
            log.write_line(f"[bold green]▶ ENGINE STARTED[/bold green] -> Transmitting high-speed stream to {self.engine.target_ip}:{self.engine.target_port}")
        else:
            self.engine.stop()
            log.write_line("[bold red]■ ENGINE STOPPED[/bold red] -> Standby mode")

    def action_toggle_normal(self) -> None:
        state = self.engine.toggle_normal()
        log = self.query_one("#log-box", Log)
        status = "ENABLED" if state else "DISABLED"
        log.write_line(f"[cyan]ℹ Background Normal Traffic: {status}[/cyan]")

    def action_toggle_ddos(self) -> None:
        state = self.engine.toggle_ddos()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold red]🔥 THREAT VECTOR INJECTED: Volumetric DDoS SYN/UDP Flood[/bold red]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: DDoS Flood Stopped[/yellow]")

    def action_toggle_portscan(self) -> None:
        state = self.engine.toggle_portscan()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold orange1]⚡ THREAT VECTOR INJECTED: Reconnaissance Port Scan (Ports 1-1000)[/bold orange1]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: Port Scan Stopped[/yellow]")

    def action_toggle_c2(self) -> None:
        state = self.engine.toggle_c2()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold magenta]📡 THREAT VECTOR INJECTED: Botnet C2 Beaconing Stream[/bold magenta]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: Botnet C2 Stopped[/yellow]")

    def action_toggle_dns(self) -> None:
        state = self.engine.toggle_dns_tunnel()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold cyan]🌐 THREAT VECTOR INJECTED: DGA + DNS Tunnelling Request Stream[/bold cyan]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: DNS Tunnelling Stopped[/yellow]")

    def action_toggle_tls(self) -> None:
        state = self.engine.toggle_tls_malware()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold pink1]🔒 THREAT VECTOR INJECTED: Malware in Encrypted Sessions Stream[/bold pink1]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: TLS Malware Stream Stopped[/yellow]")

    def action_toggle_exfil(self) -> None:
        state = self.engine.toggle_exfil()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold yellow]📤 THREAT VECTOR INJECTED: Data Exfiltration Anomaly Stream[/bold yellow]")
        else:
            log.write_line("[yellow]✓ Threat Vector Ceased: Data Exfiltration Stopped[/yellow]")

    def action_toggle_all(self) -> None:
        state = self.engine.toggle_all_threats()
        log = self.query_one("#log-box", Log)
        if state:
            log.write_line("[bold red blink]🚨 BURST MODE ACTIVATED: ALL 6 SPECTRA PRD THREAT VECTORS SIMULTANEOUSLY INJECTED![/bold red blink]")
        else:
            log.write_line("[bold green]✓ ALL THREAT VECTORS CLEARED: Returning to Normal Baseline Stream[/bold green]")


def main() -> None:
    parser = argparse.ArgumentParser(description="SPECTRA PC 1 Traffic Generator Sender TUI")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target Destination IP (PC 2 IP)")
    parser.add_argument("--port", "-p", type=int, default=8000, help="Target Destination Port")
    args = parser.parse_args()

    app = SenderApp(target_ip=args.target, target_port=args.port)
    app.run()


if __name__ == "__main__":
    main()
