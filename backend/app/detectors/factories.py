from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config.detectors import DetectorConfig


def create_ddos_detector(artifact: Any, config: DetectorConfig) -> Any:
    """Construct the repository's actual DDoS detector implementation."""
    from detectors.ddos.ddos_detector import DDoSDetector

    return DDoSDetector()


def create_port_scan_detector(artifact: Any, config: DetectorConfig) -> Any:
    """Bind the actual Port Scan implementation to its native JSON model."""
    from detectors.port_scan.portscan_detector import FINAL_FEATURES, PortScanDetector

    implementation = PortScanDetector.__new__(PortScanDetector)
    implementation.model_path = Path(config.artifact_path or "")
    implementation.schema_path = Path("detectors/port_scan/spectra_portscan_feature_schema.json")
    implementation.model = artifact
    with implementation.schema_path.open("r", encoding="utf-8") as stream:
        implementation.feature_schema = json.load(stream)
    if implementation.feature_schema.get("features") != FINAL_FEATURES:
        raise ValueError("Port Scan feature schema does not match detector contract")
    return implementation


DETECTOR_FACTORIES = {
    "ddos": create_ddos_detector,
    "port_scan": create_port_scan_detector,
}