from datetime import datetime

from backend.app.detectors.base import BaseThreatDetector
from backend.app.schemas.alert import Alert
from backend.app.schemas.prediction import Prediction


def test_prediction_validation():
    prediction = Prediction(
        status="DETECTED",
        threat_class="DDoS",
        score_type="probability",
        raw_score=0.91,
        threshold=0.5,
        evidence={"bytes_per_second": 1000},
        context={"src_ip": "10.0.0.2"},
        detector_name="ddos",
        detector_version="1.0.0",
        model_name="ddos_xgb",
        model_version="1.0.0",
        feature_schema="ddos-v1",
    )

    assert prediction.status == "DETECTED"
    assert prediction.raw_score == 0.91
    assert prediction.feature_schema == "ddos-v1"


def test_alert_validation():
    alert = Alert(
        alert_id="ALT-001",
        timestamp=datetime.utcnow(),
        flow_id="flow-1",
        threat_class="DDoS",
        severity="HIGH",
        confidence=0.91,
        evidence={"reason": "rate spike"},
        src_ip="10.0.0.2",
        dst_ip="10.0.0.3",
        protocol="TCP",
        model="ddos_xgb",
        model_version="1.0.0",
        feature_schema="ddos-v1",
        status="NEW",
        raw_model_probability=0.91,
    )

    assert alert.alert_id == "ALT-001"
    assert alert.severity == "HIGH"
    assert alert.status == "NEW"
    assert alert.confidence == 0.91


def test_detector_interface_contract():
    class DummyDetector(BaseThreatDetector):
        @property
        def detector_name(self):
            return "dummy"

        @property
        def detector_version(self):
            return "1.0.0"

        @property
        def required_features(self):
            return ["a", "b"]

        @property
        def model_name(self):
            return "dummy_model"

        @property
        def model_version(self):
            return "1.0.0"

        @property
        def feature_schema(self):
            return "dummy-v1"

        def predict(self, features, context):
            return {"status": "BENIGN", "features": features, "context": context}

    detector = DummyDetector()

    assert detector.detector_name == "dummy"
    assert detector.model_name == "dummy_model"
    assert detector.required_features == ["a", "b"]
    assert detector.predict({"a": 1, "b": 2}, {"src_ip": "1.1.1.1"})["status"] == "BENIGN"


def test_registry_registration_and_retrieval():
    class DummyDetector(BaseThreatDetector):
        @property
        def detector_name(self):
            return "ddos"

        @property
        def detector_version(self):
            return "1.0.0"

        @property
        def required_features(self):
            return ["pkt_rate"]

        @property
        def model_name(self):
            return "ddos_model"

        @property
        def model_version(self):
            return "1.0.0"

        @property
        def feature_schema(self):
            return "ddos-v1"

        def predict(self, features, context):
            return {"status": "BENIGN"}

    registry = __import__("backend.app.detectors.registry", fromlist=["DetectorRegistry"]).DetectorRegistry()
    detector = DummyDetector()

    registry.register(detector)

    assert registry.get("ddos") is detector
    assert registry.list() == ["ddos"]
    assert "ddos" in registry


def test_duplicate_detector_handling():
    class DummyDetector(BaseThreatDetector):
        @property
        def detector_name(self):
            return "ddos"

        @property
        def detector_version(self):
            return "1.0.0"

        @property
        def required_features(self):
            return ["pkt_rate"]

        @property
        def model_name(self):
            return "ddos_model"

        @property
        def model_version(self):
            return "1.0.0"

        @property
        def feature_schema(self):
            return "ddos-v1"

        def predict(self, features, context):
            return {"status": "BENIGN"}

    registry = __import__("backend.app.detectors.registry", fromlist=["DetectorRegistry"]).DetectorRegistry()
    registry.register(DummyDetector())

    try:
        registry.register(DummyDetector())
        assert False, "duplicate registration should raise ValueError"
    except ValueError:
        pass
