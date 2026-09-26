from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from inspect import isawaitable
from time import monotonic
from typing import Any, Callable, Mapping

from ..detectors.base import BaseThreatDetector
from ..detectors.health import DetectorHealth
from ..detectors.packet_flow_features import (
    CompletedFlowFeatures,
    PacketFlowFeatureProducer,
    select_contract_features,
)
from ..detectors.zeek_flow_features import detector_features_from_zeek
from ..ingestion.events import NormalizedEvent
from ..latency import LatencyMetricsCollector, LatencyTiming
from ..schemas.alert import Alert
from ..schemas.prediction import Prediction
from ..stores import AlertStore
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
    """Coordinate ordering with optional generic windows or per-flow inference."""

    def __init__(
        self,
        ordering: ReorderBuffer,
        windows: DetectorWindowManager | None,
        registry: Any,
        health: Mapping[str, DetectorHealth] | None = None,
        alert_store: AlertStore | None = None,
        latency_metrics: LatencyMetricsCollector | None = None,
        alert_publisher: Callable[[Alert], Awaitable[None] | None] | None = None,
        packet_flow_features: PacketFlowFeatureProducer | None = None,
    ) -> None:
        self.ordering = ordering
        self.windows = windows
        self.registry = registry
        self.health = dict(health or {})
        self.alert_store = alert_store
        self.latency_metrics = latency_metrics or LatencyMetricsCollector()
        self.alert_publisher = alert_publisher
        self.packet_flow_features = packet_flow_features
        self.metrics = OrchestratorMetrics()
        self._runtime_failures: list[DetectorRuntimeFailure] = []
        self._scored_opportunities: set[
            tuple[str, Any, object, object, tuple[Any, ...]]
        ] = set()
        self._scored_events: set[tuple[str, str]] = set()
        self._timings: dict[str, LatencyTiming] = {}

    def process_event(
        self,
        event: NormalizedEvent,
        event_id: str | None = None,
        *,
        zeek_available_at: datetime | None = None,
        capture_timing_available: bool = True,
    ) -> tuple[Alert, ...]:
        """Accept one canonical event and return newly produced alerts."""
        self.metrics.events_received += 1
        timing = LatencyTiming.start(
            event.observed_at,
            zeek_available_at=zeek_available_at,
            capture_timing_available=capture_timing_available,
        )
        identity = event_id or event.flow_id or f"received-{self.metrics.events_received}"
        self._timings[identity] = timing
        if event.flow_id is not None:
            self._timings[event.flow_id] = timing
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
            alerts.extend(
                self._process_ordered(entry.event, entry.event_id, entry.arrival_index)
            )
        return tuple(alerts)

    def flush(self) -> tuple[Alert, ...]:
        """Drain the reorder buffer and then flush pending detector windows."""
        alerts: list[Alert] = []
        for entry in self.ordering.flush():
            alerts.extend(
                self._process_ordered(entry.event, entry.event_id, entry.arrival_index)
            )
        if self.packet_flow_features is not None:
            for incomplete in self.packet_flow_features.flush():
                self._record_incomplete_flow(incomplete)
        if self.windows is not None:
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

    def _process_ordered(
        self, event: NormalizedEvent, event_id: str, arrival_index: int
    ) -> list[Alert]:
        self.metrics.events_processed += 1
        timing = self._timing_for_event(event)
        if timing is not None:
            timing.mark("ordered_at")
        alerts: list[Alert] = []
        packet_flow: CompletedFlowFeatures | None = None
        if self.packet_flow_features is not None and event.event_type.lower() == "packet":
            packet_flow = self.packet_flow_features.observe(
                event, arrival_sequence=arrival_index
            )
        grouping_key = self._grouping_key(event)
        for detector_name in list(self.registry):
            detector = self.registry.get(detector_name)
            contract_name = getattr(detector, "detector_name", detector_name)
            if self.packet_flow_features is not None and contract_name in {
                "ddos",
                "portscan",
            }:
                if event.event_type.lower() != "packet" or packet_flow is None:
                    continue
                alert = self._invoke_packet_flow(
                    detector_name, detector, packet_flow, event, event_id
                )
                if alert is not None:
                    alerts.append(alert)
                continue
            detector_health = self.health.get(detector_name)
            if detector_health is None or not detector_health.ready_for_inference:
                reason = (
                    detector_health.error_reason
                    if detector_health is not None and detector_health.error_reason
                    else "Detector is not ready_for_inference"
                )
                self._record_failure(detector_name, f"Skipped: {reason}")
                continue
            if self.windows is None:
                alert = self._invoke_per_flow(detector_name, event, event_id)
                if alert is not None:
                    alerts.append(alert)
                continue
            try:
                emissions = self.windows.add(detector_name, grouping_key, event)
            except Exception as exc:
                self._record_failure(detector_name, f"Windowing failed: {exc}")
                continue
            for emission in emissions:
                alerts.extend(self._invoke_emission(emission))
        return alerts

    def _invoke_packet_flow(
        self,
        detector_name: str,
        detector: BaseThreatDetector,
        completed: CompletedFlowFeatures,
        source_event: NormalizedEvent,
        event_id: str,
    ) -> Alert | None:
        detector_health = self.health.get(detector_name)
        if detector_health is None or not detector_health.ready_for_inference:
            reason = (
                detector_health.error_reason
                if detector_health is not None and detector_health.error_reason
                else "Detector is not ready_for_inference"
            )
            self._record_failure(detector_name, f"Skipped: {reason}")
            return None
        if completed.features is None:
            self._record_failure(
                detector_name,
                "Skipped: packet-derived flow feature contract is incomplete: "
                + "; ".join(completed.incomplete_reasons),
            )
            return None

        features = select_contract_features(completed.features, detector.required_features)
        if features is None:
            missing = [
                field for field in detector.required_features
                if field not in completed.features
            ]
            self._record_failure(
                detector_name,
                "Skipped: packet-derived flow output is missing required detector inputs: "
                + ", ".join(missing),
            )
            return None

        flow_event = NormalizedEvent(
            observed_at=completed.observed_at,
            event_type="flow_features",
            source_ip=completed.source_ip,
            destination_ip=completed.destination_ip,
            source_port=completed.source_port,
            destination_port=completed.destination_port,
            protocol=(str(completed.protocol) if completed.protocol is not None else None),
            flow_id=completed.flow_id,
            raw_metadata={
                **source_event.raw_metadata,
                "packet_flow_features": dict(completed.features),
                "feature_provenance": dict(completed.provenance),
            },
        )
        identity = (detector_name, event_id)
        if identity in self._scored_events:
            return None
        self._scored_events.add(identity)

        context = {
            "event_id": completed.flow_id or event_id,
            "flow_start_at": completed.flow_start_at,
            "flow_end_at": completed.observed_at,
            "packet_count": completed.packet_count,
            "feature_provenance": dict(completed.provenance),
        }
        timing = self._timing_for_event(source_event)
        if timing is not None:
            timing.mark("feature_ready_at")
            timing.mark("inference_started_at")
        try:
            self.metrics.detector_invocations += 1
            prediction = detector.predict(features, context)
            if not isinstance(prediction, Prediction):
                raise TypeError("adapter did not return Prediction")
        except Exception as exc:
            if timing is not None:
                timing.mark("inference_finished_at")
            self._record_failure(detector_name, f"Detector invocation failed: {exc}")
            return None
        if timing is not None:
            timing.mark("inference_finished_at")
        if prediction.status != "DETECTED":
            return None

        alert_identity = "|".join(
            (prediction.detector_name, prediction.detector_version, event_id)
        )
        try:
            alert = self._prediction_to_alert(prediction, flow_event, alert_identity)
        except Exception as exc:
            self._record_failure(detector_name, f"Alert conversion failed: {exc}")
            return None
        self._record_alert(alert, prediction.detector_name, timing)
        return alert

    def _record_incomplete_flow(self, completed: CompletedFlowFeatures) -> None:
        reason = (
            "Skipped: packet-derived flow feature contract is incomplete: "
            + "; ".join(completed.incomplete_reasons)
        )
        for detector_name in list(self.registry):
            detector = self.registry.get(detector_name)
            if getattr(detector, "detector_name", detector_name) in {"ddos", "portscan"}:
                self._record_failure(detector_name, reason)

    def _invoke_per_flow(
        self, detector_name: str, event: NormalizedEvent, event_id: str
    ) -> Alert | None:
        """Invoke a stateless adapter once for this ordered event, without a window."""
        identity = (detector_name, event_id)
        if identity in self._scored_events:
            return None
        self._scored_events.add(identity)
        detector = self.registry.get(detector_name)
        features = detector_features_from_zeek(event.raw_metadata)
        missing = [
            feature for feature in detector.required_features
            if feature not in features
        ]
        if missing:
            self._record_failure(
                detector_name,
                "Skipped: current event raw metadata is missing required detector inputs: "
                + ", ".join(missing),
            )
            return None

        context = {"event_id": event.flow_id or event_id}
        timing = self._timing_for_event(event)
        if timing is not None:
            timing.mark("feature_ready_at")
            timing.mark("inference_started_at")
        try:
            self.metrics.detector_invocations += 1
            prediction = detector.predict(features, context)
            if not isinstance(prediction, Prediction):
                raise TypeError("adapter did not return Prediction")
        except Exception as exc:
            if timing is not None:
                timing.mark("inference_finished_at")
            self._record_failure(detector_name, f"Detector invocation failed: {exc}")
            return None
        if timing is not None:
            timing.mark("inference_finished_at")
        if prediction.status != "DETECTED":
            return None

        alert_identity = "|".join(
            (prediction.detector_name, prediction.detector_version, event_id)
        )
        try:
            alert = self._prediction_to_alert(prediction, event, alert_identity)
        except Exception as exc:
            self._record_failure(detector_name, f"Alert conversion failed: {exc}")
            return None
        self._record_alert(alert, prediction.detector_name, timing)
        return alert

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
        features = detector_features_from_zeek(source_event.raw_metadata)
        missing = [
            feature
            for feature in detector.required_features
            if feature not in features
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
        timing = self._timing_for_event(source_event)
        if timing is not None:
            timing.mark("feature_ready_at")
            timing.mark("inference_started_at")
        try:
            self.metrics.detector_invocations += 1
            prediction = detector.predict(features, context)
            if not isinstance(prediction, Prediction):
                raise TypeError("adapter did not return Prediction")
        except Exception as exc:
            if timing is not None:
                timing.mark("inference_finished_at")
            self._record_failure(emission.detector_name, f"Detector invocation failed: {exc}")
            return []
        if timing is not None:
            timing.mark("inference_finished_at")
        if prediction.status != "DETECTED":
            return []
        alert_identity = "|".join(
            (
                prediction.detector_name,
                prediction.detector_version,
                str(emission.grouping_key),
                emission.scoring_start.isoformat(),
                emission.scoring_end.isoformat(),
            )
        )
        try:
            alert = self._prediction_to_alert(prediction, source_event, alert_identity)
        except Exception as exc:
            self._record_failure(emission.detector_name, f"Alert conversion failed: {exc}")
            return []
        self._record_alert(alert, prediction.detector_name, timing)
        return [alert]

    def _record_alert(
        self, alert: Alert, detector_name: str, timing: LatencyTiming | None
    ) -> None:
        self.metrics.alerts_produced += 1
        if timing is not None:
            timing.mark("alert_created_at")
            alert.timing = timing.model_dump()
            alert.latency_durations = timing.durations()
            self.latency_metrics.record(timing)
        if self.alert_store is not None:
            try:
                self.alert_store.create(alert)
                stored = True
            except Exception as exc:
                stored = False
                self._record_failure(detector_name, f"Alert store failed: {exc}")
        else:
            stored = False
        if stored and self.alert_publisher is not None:
            try:
                publication = self.alert_publisher(alert)
                if isawaitable(publication):
                    import asyncio

                    asyncio.get_running_loop().create_task(publication)
            except Exception as exc:
                self._record_failure(detector_name, f"Alert publication failed: {exc}")

    def _prediction_to_alert(
        self,
        prediction: Prediction,
        event: NormalizedEvent,
        alert_identity: str,
    ) -> Alert:
        alert_id = "ALT-" + sha256(alert_identity.encode("utf-8")).hexdigest()[:16]
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
            raw_model_score=(
                prediction.raw_score if prediction.score_type == "model_score" else None
            ),
            score_type=prediction.score_type,
            feature_provenance=(
                event.raw_metadata.get("feature_provenance")
                if isinstance(event.raw_metadata.get("feature_provenance"), dict)
                else None
            ),
            timing=None,
            latency_durations={},
        )

    def _timing_for_event(self, event: NormalizedEvent) -> LatencyTiming | None:
        return self._timings.get(event.flow_id) if event.flow_id is not None else None

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
