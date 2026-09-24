from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Mapping

from .config.detectors import DETECTOR_CONFIGS
from .config.orchestrator import (
    MissingRuntimeConfigurationError,
    OrchestratorRuntimeConfig,
    REQUIRED_ORCHESTRATOR_FIELDS,
)
from .detectors.factories import DETECTOR_FACTORIES
from .detectors.loader import DetectorLoader
from .detectors.registry import DetectorRegistry
from .latency import LatencyMetricsCollector
from .pipeline.ordering import ReorderBuffer, ReorderConfig
from .pipeline.orchestrator import RuntimeOrchestrator
from .stores import AlertStore

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INTEGRATED_DETECTOR_KEYS = ("ddos", "port_scan")


def create_orchestrator(
    configuration: OrchestratorRuntimeConfig | Mapping[str, object] | None = None,
) -> RuntimeOrchestrator:
    """Build a fresh orchestrator from all caller-supplied runtime decisions.

    There are intentionally no ordering or window defaults. This factory
    currently supports only the integrated stateless per-flow detector adapters.
    """
    if configuration is None:
        raise MissingRuntimeConfigurationError(
            "Missing required runtime configuration fields: "
            + ", ".join(REQUIRED_ORCHESTRATOR_FIELDS)
        )
    if isinstance(configuration, OrchestratorRuntimeConfig):
        runtime_config = configuration
    else:
        runtime_config = OrchestratorRuntimeConfig.from_mapping(configuration)

    registry = DetectorRegistry()
    detector_configs = {
        key: DETECTOR_CONFIGS[key] for key in INTEGRATED_DETECTOR_KEYS
    }
    load_results = DetectorLoader(REPOSITORY_ROOT).load_all(
        detector_configs,
        factories={key: DETECTOR_FACTORIES[key] for key in INTEGRATED_DETECTOR_KEYS},
        registry=registry,
    )
    unhealthy = [
        f"{key}: {result.health.error_reason or 'not ready for inference'}"
        for key, result in load_results.items()
        if not result.health.ready_for_inference
    ]
    if unhealthy:
        raise RuntimeError("Integrated detector startup failed: " + "; ".join(unhealthy))

    orchestrator = RuntimeOrchestrator(
        ordering=ReorderBuffer(
            ReorderConfig(
                maximum_lateness=timedelta(seconds=runtime_config.maximum_lateness_seconds),
                buffer_capacity=runtime_config.buffer_capacity,
                late_event_behavior=runtime_config.late_event_behavior,
                overflow_behavior=runtime_config.overflow_behavior,
            )
        ),
        windows=None,
        registry=registry,
        health={result.health.detector_name: result.health for result in load_results.values()},
        alert_store=AlertStore(),
        latency_metrics=LatencyMetricsCollector(),
    )
    orchestrator.runtime_configuration = runtime_config.as_dict()
    return orchestrator
