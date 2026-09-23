from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ExpectedArtifactFormat = Literal["joblib", "pickle", "gzip+joblib"]


@dataclass(frozen=True)
class DetectorConfig:
    """Versionable metadata for one detector handoff."""

    detector_name: str
    detector_version: str
    model_name: str
    model_version: str
    feature_schema: str
    required_features: tuple[str, ...]
    threshold: float | None
    score_type: Literal["probability", "anomaly"]
    artifact_path: str | None
    expected_format: ExpectedArtifactFormat | None
    dependencies: tuple[tuple[str, str | None], ...] = ()
    handoff_status: str = "UNKNOWN"


DETECTOR_CONFIGS: dict[str, DetectorConfig] = {
    "ddos": DetectorConfig(
        detector_name="ddos",
        detector_version="1.0.0",
        model_name="spectra_ddos_detector",
        model_version="1.0.0",
        feature_schema="detectors/ddos/spectra_ddos_feature_schema.json",
        required_features=(),
        threshold=0.139203,
        score_type="probability",
        artifact_path="detectors/ddos/spectra_ddos_detector.joblib",
        expected_format="joblib",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=2.0.0")),
        handoff_status="READY FOR BACKEND INTEGRATION",
    ),
    "c2_beaconing": DetectorConfig(
        detector_name="c2_beaconing",
        detector_version="1.0.0",
        model_name="botnet_c2_detector",
        model_version="legacy-unversioned-artifact",
        feature_schema="c2-beaconing-v1",
        required_features=(),
        threshold=0.20,
        score_type="probability",
        artifact_path="detectors/C2 Beaconing/botnet_c2_detector.pkl.gz",
        expected_format="gzip+joblib",
        dependencies=(("joblib", ">=1.4.0"), ("sklearn", None)),
        handoff_status="READY FOR RUNTIME VALIDATION",
    ),
    "dga": DetectorConfig(
        detector_name="dga",
        detector_version="1.1.0",
        model_name="DGA_XGBoost",
        model_version="unverified-corrupt-artifact",
        feature_schema="dga-23-features-v1",
        required_features=(),
        threshold=0.68,
        score_type="probability",
        artifact_path="detectors/P2-B — DGA  DNS TUNNELLING/DGA/DGA_XGBoost.pkl",
        expected_format="pickle",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=2.0.0")),
        handoff_status="BLOCKED",
    ),
    "dns_tunnelling": DetectorConfig(
        detector_name="dns_tunnelling",
        detector_version="2.0.0",
        model_name="dns_tunnelling_xgb_model",
        model_version="2.0.0-rebuilt",
        feature_schema="detectors/P2-B — DGA  DNS TUNNELLING/DNS_Tunelling/dns_tunnelling_schema.json",
        required_features=(),
        threshold=0.50,
        score_type="probability",
        artifact_path="detectors/P2-B — DGA  DNS TUNNELLING/DNS_Tunelling/dns_tunnelling_xgb_model.pkl",
        expected_format="pickle",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=3.4.1")),
        handoff_status="READY FOR RUNTIME VALIDATION",
    ),
    "malware_tls": DetectorConfig(
        detector_name="malware_tls",
        detector_version="1.0.0",
        model_name="malware_tls_streaming_model",
        model_version="1.0.0",
        feature_schema="detectors/malware_tls/feature_schema.json",
        required_features=(),
        threshold=0.6235448718070984,
        score_type="probability",
        artifact_path="detectors/malware_tls/malware_tls_streaming_model.pkl",
        expected_format="pickle",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=2.0.0")),
        handoff_status="BLOCKED",
    ),
    "quic": DetectorConfig(
        detector_name="quic",
        detector_version="0.0.0",
        model_name="",
        model_version="",
        feature_schema="",
        required_features=(),
        threshold=None,
        score_type="anomaly",
        artifact_path=None,
        expected_format=None,
        handoff_status="BLOCKED",
    ),
    "port_scan": DetectorConfig(
        detector_name="port_scan",
        detector_version="1.0.0",
        model_name="spectra_portscan_detector",
        model_version="1.0.0",
        feature_schema="detectors/port_scan/spectra_portscan_feature_schema.json",
        required_features=(),
        threshold=0.50166595,
        score_type="probability",
        artifact_path="detectors/port_scan/spectra_portscan_detector.joblib",
        expected_format="joblib",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=2.0.0")),
        handoff_status="READY FOR BACKEND INTEGRATION",
    ),
    "exfiltration": DetectorConfig(
        detector_name="exfiltration",
        detector_version="2.0.0",
        model_name="dns_exfiltration_stateful_xgb_final",
        model_version="2.0.0-rebuilt",
        feature_schema="exfiltration-10-features-v2",
        required_features=(),
        threshold=0.85,
        score_type="probability",
        artifact_path="detectors/Exfiltration/dns_exfiltration_stateful_xgb_final.pkl",
        expected_format="pickle",
        dependencies=(("joblib", ">=1.4.0"), ("xgboost", ">=3.4.1")),
        handoff_status="READY FOR RUNTIME VALIDATION",
    ),
}
