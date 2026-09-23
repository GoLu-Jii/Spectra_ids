import pickle
from dataclasses import replace

from backend.app.config.detectors import DetectorConfig
from backend.app.detectors.loader import DetectorLoader
from backend.app.detectors.registry import DetectorRegistry


def config(path, **changes):
    value = DetectorConfig(
        detector_name="loader_detector",
        detector_version="1.0.0",
        model_name="loader_model",
        model_version="1.0.0",
        feature_schema="loader-v1",
        required_features=(),
        threshold=0.5,
        score_type="probability",
        artifact_path=str(path),
        expected_format="pickle",
    )
    return replace(value, **changes)


class DetectorImplementation:
    def predict(self, features, context):
        return {"status": "BENIGN", "raw_score": 0.1}


def write_pickle(path, value):
    with path.open("wb") as stream:
        pickle.dump(value, stream)


def test_missing_artifact_reports_health(tmp_path):
    result = DetectorLoader(tmp_path).load(config("missing.pkl"))

    assert result.adapter is None
    assert result.health.artifact_present is False
    assert result.health.artifact_loadable is False
    assert result.health.ready_for_inference is False
    assert "not found" in result.health.error_reason


def test_incompatible_dependency_reports_health(tmp_path):
    artifact = tmp_path / "model.pkl"
    write_pickle(artifact, {"model": "value"})
    result = DetectorLoader(tmp_path).load(
        config("model.pkl", dependencies=(("package_that_cannot_exist_spectra", None),))
    )

    assert result.health.dependency_available is False
    assert result.health.ready_for_inference is False
    assert "Dependency unavailable" in result.health.error_reason


def test_model_load_failure_reports_health(tmp_path):
    artifact = tmp_path / "model.pkl"
    artifact.write_bytes(b"not a pickle")

    result = DetectorLoader(tmp_path).load(config("model.pkl"))

    assert result.health.artifact_present is True
    assert result.health.artifact_loadable is False
    assert "Artifact load failed" in result.health.error_reason


def test_successful_lazy_load_and_registration(tmp_path):
    artifact = tmp_path / "model.pkl"
    write_pickle(artifact, {"model": "value"})
    registry = DetectorRegistry()

    result = DetectorLoader(tmp_path).load_all(
        {"loader_detector": config("model.pkl")},
        factories={"loader_detector": lambda loaded, detector_config: DetectorImplementation()},
        registry=registry,
    )

    assert result["loader_detector"].health.registered is True
    assert result["loader_detector"].health.artifact_loadable is True
    assert result["loader_detector"].health.ready_for_inference is True
    assert registry.get("loader_detector").predict({}, {}).status == "BENIGN"


def test_one_broken_detector_does_not_stop_other_registrations(tmp_path):
    good = tmp_path / "good.pkl"
    write_pickle(good, {"model": "value"})
    configs = {
        "good": config("good.pkl", detector_name="good"),
        "broken": config("missing.pkl", detector_name="broken"),
    }
    registry = DetectorRegistry()

    results = DetectorLoader(tmp_path).load_all(
        configs,
        factories={"good": lambda loaded, detector_config: DetectorImplementation()},
        registry=registry,
    )

    assert results["broken"].health.ready_for_inference is False
    assert results["good"].health.ready_for_inference is True
    assert registry.list() == ["good"]
