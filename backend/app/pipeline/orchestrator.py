from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Mapping

from ..detectors.base import BaseThreatDetector
from ..detectors.health import DetectorHealth
from ..ingestion.events import NormalizedEvent
from ..schemas.alert import Alert
from ..schemas.prediction import Prediction
from .ordering import ReorderBuffer, ReorderOutcome
from .windows import DetectorWindowManager, WindowEmission


@dataclass
class OrchestratorMetrics:
    events_received: int = 0
    events_processed: int = 0
    events_rejected_or_late: int = 0
    detector_invocations: int = 0
    detector_failures: int = 0
    alerts_produced: int = 0


@dataclass(frozen=True)
class DetectorRuntimeFailure:
    detector_name: str
    reason: str


class RuntimeOrchestrator:
    """Coordinate ingestion ordering, generic windows, and ready detectors."""

    def __init__(
        self,
        ordering: ReorderBuffer,
        windows: DetectorWindowManager,
        registry: Any,
        health: Mapping[str, DetectorHealth] | None = None,
    ) -> None:
        self.ordering = ordering
        self.windows = windows
        self.registry = registry
        self.health = dict(health or {})
        self.metrics = OrchestratorMetrics()
        self._runtime_failures: list[DetectorRuntimeFailure] = []
        self._scored_opportunities: set[
            tuple[str, Any, object, object, tuple[Any, ...]]
        ] = set()

    def process_event(
        self,
        event: NormalizedEvent,
        event_id: str | None = None,
    ) -> tuple[Alert, ...]:
        """Accept one canonical event and return newly produced alerts."""
        self.metrics.events_received += 1
        try:
            outcome = self.ordering.push(event, event_id=event_id)
        except Exception as exc:
            self.metrics.events_rejected_or_late += 1
            self._record_failure("ordering", str(exc))
            return ()

        if outcome.late or not outcome.accepted:
            self.metrics.events_rejected_or_late += 1
        alerts: list[Alert] = []
        for entry in outcome.released:
            alerts.extend(self._process_ordered(entry.event, entry.event_id))
        return tuple(alerts)

    def flush(self) -> tuple[Alert, ...]:
        """Drain the reorder buffer and then flush pending detector windows."""
        alerts: list[Alert] = []
        for entry in self.ordering.flush():
            alerts.extend(self._process_ordered(entry.event, entry.event_id))
        try:
            emissions = self.windows.flush()
        except Exception as exc:
            self._record_failure("windowing", str(exc))
            emissions = ()
        for emission in emissions:
            alerts.extend(self._invoke_emission(emission))
        return tuple(alerts)

    def get_metrics(self) -> dict[str, int]:
        """Return stable runtime counters for later API exposure."""
        return {
            "events_received": self.metrics.events_received,
            "events_processed": self.metrics.events_processed,
            "events_rejected_or_late": self.metrics.events_rejected_or_late,
            "detector_invocations": self.metrics.detector_invocations,
            "detector_failures": self.metrics.detector_failures,
            "alerts_produced": self.metrics.alerts_produced,
        }

    def get_runtime_state(self) -> dict[str, object]:
        """Expose detector health and exact runtime failure/skip reasons."""
        return {
            "detector_health": {
                name: value.as_dict() for name, value in self.health.items()
            },
            "runtime_failures": [
                {"detector_name": item.detector_name, "reason": item.reason}
                for item in self._runtime_failures
            ],
        }

    def _process_ordered(self, event: NormalizedEvent, event_id: str) -> list[Alert]:
        self.metrics.events_processed += 1
        alerts: list[Alert] = []
        grouping_key = self._grouping_key(event)
        for detector_name in list(self.registry):
            detector = self.registry.get(detector_name)
            detector_health = self.health.get(detector_name)
            if detector_health is None or not detector_health.ready_for_inference:
                reason = (
                    detector_health.error_reason
                    if detector_health is not None and detector_health.error_reason
                    else "Detector is not ready_for_inference"
                )
                self._record_failure(detector_name, f"Skipped: {reason}")
                continue
            try:
                emissions = self.windows.add(detector_name, grouping_key, event)
            except Exception as exc:
                self._record_failure(detector_name, f"Windowing failed: {exc}")
                continue
            for emission in emissions:
                alerts.extend(self._invoke_emission(emission))
        return alerts

    def _invoke_emission(self, emission: WindowEmission) -> list[Alert]:
        opportunity = (
            emission.detector_name,
            emission.grouping_key,
            emission.scoring_start,
            emission.scoring_end,
            tuple(
                (event.flow_id, event.observed_at.isoformat())
                for event in emission.context_events
            ),
        )
        if opportunity in self._scored_opportunities:
            return []
        self._scored_opportunities.add(opportunity)
        detector = self.registry.get(emission.detector_name)
        detector_health = self.health.get(emission.detector_name)
        if detector_health is None or not detector_health.ready_for_inference:
            reason = (
                detector_health.error_reason
                if detector_health is not None and detector_health.error_reason
                else "Detector is not ready_for_inference"
            )
            self._record_failure(emission.detector_name, f"Skipped: {reason}")
            return []

        source_event = emission.context_events[-1] if emission.context_events else None
        if source_event is None:
            self._record_failure(emission.detector_name, "Skipped: empty detector context")
            return []
        missing = [
            feature
            for feature in detector.required_features
            if feature not in source_event.raw_metadata
        ]
        if missing:
            self._record_failure(
                emission.detector_name,
                "Skipped: current event raw metadata is missing required detector inputs: "
                + ", ".join(missing),
            )
            return []

        context = {
            "event_id": source_event.flow_id,
            "grouping_key": emission.grouping_key,
            "scoring_start": emission.scoring_start,
            "scoring_end": emission.scoring_end,
            "context_event_count": len(emission.context_events),
        }
        try:
            self.metrics.detector_invocations += 1
            prediction = detector.predict(dict(source_event.raw_metadata), context)
            if not isinstance(prediction, Prediction):
                raise TypeError("adapter did not return Prediction")
        except Exception as exc:
            self._record_failure(emission.detector_name, f"Detector invocation failed: {exc}")
            return []
        if prediction.status != "DETECTED":
            return []
        try:
            alert = self._prediction_to_alert(prediction, source_event, emission)
        except Exception as exc:
            self._record_failure(emission.detector_name, f"Alert conversion failed: {exc}")
            return []
        self.metrics.alerts_produced += 1
        return [alert]

    def _prediction_to_alert(
        self,
        prediction: Prediction,
        event: NormalizedEvent,
        emission: WindowEmission,
    ) -> Alert:
        identity = "|".join(
            (
                prediction.detector_name,
                prediction.detector_version,
                str(emission.grouping_key),
                emission.scoring_start.isoformat(),
                emission.scoring_end.isoformat(),
            )
        )
        alert_id = "ALT-" + sha256(identity.encode("utf-8")).hexdigest()[:16]
        confidence = (
            prediction.raw_score
            if prediction.score_type == "probability"
            and prediction.raw_score is not None
            and 0.0 <= prediction.raw_score <= 1.0
            else None
        )
        return Alert(
            alert_id=alert_id,
            timestamp=event.observed_at,
            flow_id=event.flow_id,
            threat_class=prediction.threat_class,
            confidence=confidence,
            evidence=prediction.evidence,
            src_ip=event.source_ip,
            src_port=event.source_port,
            dst_ip=event.destination_ip,
            dst_port=event.destination_port,
            protocol=event.protocol,
            model=prediction.model_name,
            model_version=prediction.model_version,
            feature_schema=prediction.feature_schema,
            raw_model_probability=confidence,
        )

    def _grouping_key(self, event: NormalizedEvent) -> tuple[Any, ...]:
        return (
            event.source_ip,
            event.destination_ip,
            event.source_port,
            event.destination_port,
            event.protocol,
        )

    def _record_failure(self, detector_name: str, reason: str) -> None:
        self.metrics.detector_failures += 1
        self._runtime_failures.append(DetectorRuntimeFailure(detector_name, reason))
