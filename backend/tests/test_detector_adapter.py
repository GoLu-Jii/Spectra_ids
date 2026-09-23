from backend.app.config.detectors import DetectorConfig
from backend.app.detectors.adapter import DetectorAdapter, DetectorOutputError
from backend.app.detectors.registry import DetectorRegistry


def config() -> DetectorConfig:
    return DetectorConfig(
        detector_name="test_detector",
        detector_version="2.1.0",
        model_name="test_model",
        model_version="7.0.0",
        feature_schema="test-schema-v3",
        required_features=("feature_a",),
        threshold=0.75,
        score_type="probability",
        artifact_path=None,
        expected_format=None,
    )


class DetectorImplementation:
    def predict(self, features, context):
        return {
            "status": "DETECTED",
            "threat_class": "test-threat",
            "score_type": "probability",
            "raw_score": 0.91,
            "evidence": {"feature_a": features["feature_a"]},
            "context": context,
        }


def test_successful_adapter_registration_and_prediction_normalization():
    registry = DetectorRegistry()
    adapter = DetectorAdapter(DetectorImplementation(), config())

    registry.register(adapter)
    prediction = registry.get("test_detector").predict(
        {"feature_a": 10}, {"flow_id": "flow-1"}
    )

    assert prediction.status == "DETECTED"
    assert prediction.threat_class == "test-threat"
    assert prediction.raw_score == 0.91
    assert prediction.threshold == 0.75
    assert prediction.evidence == {"feature_a": 10}
    assert prediction.context == {"flow_id": "flow-1"}
    assert prediction.detector_name == "test_detector"
    assert prediction.detector_version == "2.1.0"
    assert prediction.model_name == "test_model"
    assert prediction.model_version == "7.0.0"
    assert prediction.feature_schema == "test-schema-v3"


def test_duplicate_adapter_registration_is_rejected():
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(DetectorImplementation(), config()))

    try:
        registry.register(DetectorAdapter(DetectorImplementation(), config()))
        assert False, "duplicate registration should fail"
    except ValueError as exc:
        assert "already registered" in str(exc)


def test_conflicting_metadata_is_not_silently_repaired():
    class ConflictingImplementation:
        def predict(self, features, context):
            return {
                "status": "BENIGN",
                "model_version": "wrong-version",
            }

    adapter = DetectorAdapter(ConflictingImplementation(), config())

    try:
        adapter.predict({}, {})
        assert False, "conflicting metadata should fail"
    except DetectorOutputError as exc:
        assert "model_version" in str(exc)
