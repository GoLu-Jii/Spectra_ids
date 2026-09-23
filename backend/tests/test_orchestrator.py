from datetime import datetime, timedelta, timezone

from backend.app.config.detectors import DetectorConfig
from backend.app.detectors.adapter import DetectorAdapter
from backend.app.detectors.health import DetectorHealth
from backend.app.detectors.registry import DetectorRegistry
from backend.app.ingestion.events import NormalizedEvent
from backend.app.pipeline.ordering import ReorderBuffer, ReorderConfig
from backend.app.pipeline.orchestrator import RuntimeOrchestrator
from backend.app.pipeline.windows import DetectorWindowManager, WindowConfig

BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def config(name: str, required_features: tuple[str, ...] = ()) -> DetectorConfig:
    return DetectorConfig(
        detector_name=name,
        detector_version="1.0.0",
        model_name=f"{name}-model",
        model_version="1.0.0",
        feature_schema=f"{name}-schema-v1",
        required_features=required_features,
        threshold=0.5,
        score_type="probability",
        artifact_path=None,
        expected_format=None,
    )


def event(seconds: int, flow_id: str, metadata: dict[str, object] | None = None):
    return NormalizedEvent(
        observed_at=BASE + timedelta(seconds=seconds),
        event_type="conn",
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=12345,
        destination_port=443,
        protocol="tcp",
        flow_id=flow_id,
        raw_metadata=metadata or {},
    )


def health(name: str, ready: bool = True, error_reason: str | None = None):
    return DetectorHealth(
        detector_name=name,
        registered=True,
        artifact_present=True,
        artifact_loadable=ready,
        dependency_available=ready,
        ready_for_inference=ready,
        error_reason=error_reason,
    )


def make_orchestrator(registry, health_map):
    return RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(seconds=0), 20)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=30), timedelta(seconds=1))),
        registry,
        health_map,
    )


class DetectingImplementation:
    def __init__(self):
        self.calls = 0

    def predict(self, features, context):
        self.calls += 1
        return {
            "status": "DETECTED",
            "threat_class": "TestThreat",
            "score_type": "probability",
            "raw_score": 0.9,
            "threshold": 0.5,
            "evidence": {"source": "fixture"},
            "context": {"detector_context": context["grouping_key"]},
        }


def test_valid_event_reaches_ordering_windowing_and_ready_detector():
    implementation = DetectingImplementation()
    name = "ready_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(implementation, config(name)))
    orchestrator = make_orchestrator(registry, {name: health(name)})

    assert orchestrator.process_event(event(0, "first")) == ()
    alerts = orchestrator.process_event(event(1, "second"))

    assert len(alerts) == 1
    assert implementation.calls == 1
    assert orchestrator.get_metrics()["events_processed"] == 2


def test_unavailable_detector_is_not_invoked_and_reason_remains_observable():
    implementation = DetectingImplementation()
    name = "blocked_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(implementation, config(name)))
    orchestrator = make_orchestrator(
        registry, {name: health(name, ready=False, error_reason="xgboost unavailable")}
    )

    orchestrator.process_event(event(0, "first"))
    orchestrator.process_event(event(1, "second"))

    assert implementation.calls == 0
    failures = orchestrator.get_runtime_state()["runtime_failures"]
    assert any("xgboost unavailable" in item["reason"] for item in failures)


def test_detector_exception_does_not_crash_other_detector():
    class FailingImplementation:
        def predict(self, features, context):
            raise RuntimeError("detector exploded")

    failing = "failing"
    working = "working"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(FailingImplementation(), config(failing)))
    working_impl = DetectingImplementation()
    registry.register(DetectorAdapter(working_impl, config(working)))
    orchestrator = make_orchestrator(
        registry, {failing: health(failing), working: health(working)}
    )

    orchestrator.process_event(event(0, "first"))
    alerts = orchestrator.process_event(event(1, "second"))

    assert len(alerts) == 1
    assert alerts[0].threat_class == "TestThreat"
    assert working_impl.calls == 1
    assert orchestrator.get_metrics()["detector_failures"] == 1


def test_prediction_becomes_alert_with_evidence_context_and_metadata():
    name = "lineage_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(DetectingImplementation(), config(name)))
    orchestrator = make_orchestrator(registry, {name: health(name)})

    orchestrator.process_event(event(0, "flow-1"))
    alert = orchestrator.process_event(event(1, "flow-2"))[0]

    assert alert.alert_id.startswith("ALT-")
    assert alert.flow_id == "flow-2"
    assert alert.threat_class == "TestThreat"
    assert alert.confidence == 0.9
    assert alert.raw_model_probability == 0.9
    assert alert.evidence == {"source": "fixture"}
    assert alert.model == f"{name}-model"
    assert alert.model_version == "1.0.0"
    assert alert.feature_schema == f"{name}-schema-v1"


def test_flush_drains_ordering_and_pending_windows():
    implementation = DetectingImplementation()
    name = "flush_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(implementation, config(name)))
    orchestrator = RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(seconds=10), 20)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=30), timedelta(seconds=10))),
        registry,
        {name: health(name)},
    )

    assert orchestrator.process_event(event(0, "pending")) == ()
    alerts = orchestrator.flush()

    assert len(alerts) == 1
    assert implementation.calls == 1
    assert orchestrator.ordering.stats.current_buffer_depth == 0


def test_metrics_preserve_intervals_and_flush_does_not_repeat_exact_emission():
    implementation = DetectingImplementation()
    name = "metrics_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(implementation, config(name)))
    orchestrator = make_orchestrator(registry, {name: health(name)})

    orchestrator.process_event(event(0, "first"))
    orchestrator.process_event(event(1, "second"))
    orchestrator.flush()
    orchestrator.flush()

    metrics = orchestrator.get_metrics()
    assert metrics == {
        "events_received": 2,
        "events_processed": 2,
        "events_rejected_or_late": 0,
        "detector_invocations": 2,
        "detector_failures": 0,
        "alerts_produced": 2,
    }
    assert implementation.calls == 2


def test_same_context_at_different_scoring_intervals_is_scored_twice():
    implementation = DetectingImplementation()
    name = "interval_detector"
    registry = DetectorRegistry()
    registry.register(DetectorAdapter(implementation, config(name)))
    orchestrator = RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(seconds=0), 20)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=30), timedelta(seconds=1))),
        registry,
        {name: health(name)},
    )

    orchestrator.process_event(event(0, "first"))
    alerts = orchestrator.process_event(event(2, "second"))

    assert len(alerts) == 2
    assert implementation.calls == 2


def test_missing_declared_input_is_skipped_without_feature_invention():
    name = "strict_detector"
    registry = DetectorRegistry()
    implementation = DetectingImplementation()
    registry.register(DetectorAdapter(implementation, config(name, ("required",))))
    orchestrator = make_orchestrator(registry, {name: health(name)})

    orchestrator.process_event(event(0, "first"))
    assert orchestrator.process_event(event(1, "second")) == ()

    assert implementation.calls == 0
    failures = orchestrator.get_runtime_state()["runtime_failures"]
    assert "missing required detector inputs" in failures[-1]["reason"]
