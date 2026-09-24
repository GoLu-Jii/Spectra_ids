from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Mapping

from .config.detectors import DETECTOR_CONFIGS
from .config.orchestrator import (
    OrchestratorRuntimeConfig,
    P0_RUNTIME_CONFIGURATION,
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

    The no-argument form uses the project-owned P0 configuration. Callers may
    pass the same configuration explicitly; alternate values are rejected so
    this deployment factory cannot silently drift from the locked P0 settings.
    """
    if configuration is None:
        runtime_config = P0_RUNTIME_CONFIGURATION
    elif isinstance(configuration, OrchestratorRuntimeConfig):
        runtime_config = configuration
    else:
        runtime_config = OrchestratorRuntimeConfig.from_mapping(configuration)
    if runtime_config != P0_RUNTIME_CONFIGURATION:
        raise ValueError(
            "P0 runtime configuration is locked; expected "
            + repr(P0_RUNTIME_CONFIGURATION.as_dict())
        )

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
