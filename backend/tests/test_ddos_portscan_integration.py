import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from backend.app.config.detectors import DETECTOR_CONFIGS
from backend.app.detectors.adapter import DetectorAdapter
from backend.app.detectors.factories import DETECTOR_FACTORIES
from backend.app.detectors.loader import DetectorLoader
from backend.app.detectors.registry import DetectorRegistry

REPOSITORY_ROOT = Path(__file__).parents[2]
XGBOOST_AVAILABLE = importlib.util.find_spec("xgboost") is not None


def test_ddos_and_port_scan_factories_are_explicit():
    assert set(DETECTOR_FACTORIES) == {"ddos", "port_scan"}
    assert DETECTOR_FACTORIES["ddos"].__name__ == "create_ddos_detector"
    assert DETECTOR_FACTORIES["port_scan"].__name__ == "create_port_scan_detector"


def test_ddos_registration_and_port_scan_registration_are_isolated():
    registry = DetectorRegistry()
    loader = DetectorLoader(REPOSITORY_ROOT)
    configs = {
        "ddos": DETECTOR_CONFIGS["ddos"],
        "port_scan": DETECTOR_CONFIGS["port_scan"],
    }

    results = loader.load_all(
        configs,
        factories=DETECTOR_FACTORIES,
        registry=registry,
    )

    assert set(results) == {"ddos", "port_scan"}
    if XGBOOST_AVAILABLE:
        assert results["ddos"].health.ready_for_inference is True
        assert results["port_scan"].health.ready_for_inference is True
        assert registry.get("ddos").detector_name == "ddos"
        assert registry.get("portscan").detector_name == "portscan"
    else:
        assert results["ddos"].health.dependency_available is False
        assert results["port_scan"].health.dependency_available is False
        assert registry.list() == []


def test_missing_dependency_is_explicit_and_does_not_load_factory(tmp_path):
    config = replace(
        DETECTOR_CONFIGS["ddos"],
        artifact_path="missing.joblib",
        dependencies=(("dependency_that_does_not_exist_spectra", None),),
    )
    called = False

    def factory(artifact, detector_config):
        nonlocal called
        called = True
        raise AssertionError("factory must not run when dependency is unavailable")

    result = DetectorLoader(tmp_path).load(config, factory=factory)

    assert result.health.dependency_available is False
    assert result.health.ready_for_inference is False
    assert called is False
    assert "Dependency unavailable" in result.health.error_reason


def test_missing_artifact_is_explicit(tmp_path):
    config = replace(DETECTOR_CONFIGS["port_scan"], artifact_path="missing.joblib")

    result = DetectorLoader(tmp_path).load(config, factory=DETECTOR_FACTORIES["port_scan"])

    if XGBOOST_AVAILABLE:
        assert result.health.dependency_available is True
        assert result.health.artifact_present is False
        assert result.health.ready_for_inference is False
    else:
        assert result.health.dependency_available is False
        assert result.health.ready_for_inference is False


def test_prediction_normalization_and_metadata_preservation():
    class ExistingDetectorShape:
        def predict_flow(self, flow):
            return {
                "status": "BENIGN",
                "threat_class": "Benign",
                "score_type": "model_score",
                "raw_score": 0.01,
                "threshold": 0.50166595,
                "evidence": {"Destination Port": flow["Destination Port"]},
                "context": {"feature_count": 8},
                "detector_name": "portscan",
                "detector_version": "1.0",
                "model_name": "XGBoost",
                "model_version": "1.0",
                "feature_schema": "spectra_portscan_feature_schema.json",
            }

    adapter = DetectorAdapter(ExistingDetectorShape(), DETECTOR_CONFIGS["port_scan"])
    prediction = adapter.predict({"Destination Port": 443}, {"flow_id": "flow-1"})

    assert prediction.status == "BENIGN"
    assert prediction.score_type == "model_score"
    assert prediction.raw_score == 0.01
    assert prediction.threshold == 0.50166595
    assert prediction.detector_name == "portscan"
    assert prediction.detector_version == "1.0"
    assert prediction.model_name == "XGBoost"
    assert prediction.model_version == "1.0"
    assert prediction.feature_schema == "spectra_portscan_feature_schema.json"
    assert prediction.evidence == {"Destination Port": 443}
    assert prediction.context == {"feature_count": 8}


def test_actual_fixture_runtime_is_separate_from_adapter_tests():
    if not XGBOOST_AVAILABLE:
        return

    fixture_paths = {
        "ddos": REPOSITORY_ROOT / "tests/fixtures/ddos/benign_flow.json",
        "port_scan": REPOSITORY_ROOT / "tests/fixtures/portscan/benign_flow.json",
    }
    for name, path in fixture_paths.items():
        result = DetectorLoader(REPOSITORY_ROOT).load(
            DETECTOR_CONFIGS[name], factory=DETECTOR_FACTORIES[name]
        )
        assert result.health.ready_for_inference is True
        with path.open("r", encoding="utf-8") as stream:
            flow = json.load(stream)
        prediction = result.adapter.predict(flow, {"fixture": path.name})
        assert prediction.status in {"BENIGN", "DETECTED"}
        assert prediction.raw_score is not None
        assert prediction.score_type == "model_score"
