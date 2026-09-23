"""
Automated smoke and integration test suite for the SPECTRA PortScan Detector.

Tests use the actual un-mocked joblib model artifact and detector adapter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from detectors.port_scan.portscan_detector import PortScanDetector, FINAL_FEATURES


BASE_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = BASE_DIR / "fixtures" / "portscan"


@pytest.fixture
def benign_flow() -> dict:
    fixture_path = FIXTURES_DIR / "benign_flow.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def attack_flow() -> dict:
    fixture_path = FIXTURES_DIR / "attack_flow.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def detector() -> PortScanDetector:
    return PortScanDetector()


def test_portscan_model_load_and_schema(detector: PortScanDetector) -> None:
    """Smoke test: Verify artifact loads and schema features match expectation."""
    assert detector.model is not None
    assert detector.feature_schema["features"] == FINAL_FEATURES
    assert len(FINAL_FEATURES) == 8


def test_portscan_feature_building(
    detector: PortScanDetector, benign_flow: dict
) -> None:
    """Verify feature builder produces 8 features in exact frozen order."""
    flow_df = pd.DataFrame([benign_flow])
    features = detector.build_features(flow_df)

    assert list(features.columns) == FINAL_FEATURES
    assert features.shape == (1, 8)
    assert not features.isnull().any().any()


def test_portscan_predict_benign_flow(
    detector: PortScanDetector, benign_flow: dict
) -> None:
    """Integration test: Verify benign flow scores below threshold."""
    result = detector.predict_flow(benign_flow)

    assert result["status"] == "BENIGN"
    assert result["threat_class"] == "Benign"
    assert result["detector_name"] == "portscan"
    assert result["raw_score"] < result["threshold"]
    assert len(result["evidence"]) == 8
    assert set(FINAL_FEATURES).issubset(result["evidence"].keys())


def test_portscan_predict_attack_flow(
    detector: PortScanDetector, attack_flow: dict
) -> None:
    """Integration test: Verify attack flow scores above threshold."""
    result = detector.predict_flow(attack_flow)

    assert result["status"] == "DETECTED"
    assert result["threat_class"] == "PortScan"
    assert result["detector_name"] == "portscan"
    assert result["raw_score"] >= result["threshold"]
    assert len(result["evidence"]) == 8


def test_portscan_predict_batch(
    detector: PortScanDetector, benign_flow: dict, attack_flow: dict
) -> None:
    """Integration test: Verify batch prediction on multiple flows."""
    batch_df = pd.DataFrame([benign_flow, attack_flow])
    results = detector.predict_batch(batch_df)

    assert len(results) == 2
    assert results[0]["status"] == "BENIGN"
    assert results[1]["status"] == "DETECTED"
    assert results[1]["threat_class"] == "PortScan"
