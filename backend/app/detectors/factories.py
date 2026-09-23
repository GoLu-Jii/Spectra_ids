from __future__ import annotations

from typing import Any

from ..config.detectors import DetectorConfig


def create_ddos_detector(artifact: Any, config: DetectorConfig) -> Any:
    """Construct the repository's actual DDoS detector implementation."""
    from detectors.ddos.ddos_detector import DDoSDetector

    return DDoSDetector()


def create_port_scan_detector(artifact: Any, config: DetectorConfig) -> Any:
    """Construct the repository's actual Port Scan detector implementation."""
    from detectors.port_scan.portscan_detector import PortScanDetector

    return PortScanDetector()


DETECTOR_FACTORIES = {
    "ddos": create_ddos_detector,
    "port_scan": create_port_scan_detector,
}