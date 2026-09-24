from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.app.benchmark import _load_factory
from backend.app.config.orchestrator import (
    MissingRuntimeConfigurationError,
    REQUIRED_ORCHESTRATOR_FIELDS,
)
from backend.app.detectors.health import DetectorHealth
from backend.app.runtime_factory import create_orchestrator


TEST_ONLY_CONFIGURATION = {
    "maximum_lateness_seconds": 2.5,
    "buffer_capacity": 37,
    "late_event_behavior": "quarantine",
    "overflow_behavior": "reject",
    "window_config": None,
}


class StubLoader:
    def __init__(self, repository_root):
        self.repository_root = repository_root

    def load_all(self, configs, *, factories, registry):
        results = {}
        for key, config in configs.items():
            # Small test adapter: model loading itself is covered by the detector
            # integration tests and this test only exercises runtime construction.
            adapter = SimpleNamespace(
                detector_name=config.detector_name,
                detector_version=config.detector_version,
                model_name=config.model_name,
                model_version=config.model_version,
                feature_schema=config.feature_schema,
                required_features=list(config.required_features),
            )
            registry.register(adapter)
            results[key] = SimpleNamespace(
                health=DetectorHealth(
                    detector_name=config.detector_name,
                    registered=True,
                    artifact_present=True,
                    artifact_loadable=True,
                    dependency_available=True,
                    ready_for_inference=True,
                )
            )
        return results


def install_stub_loader(monkeypatch):
    import backend.app.runtime_factory as runtime_factory

    monkeypatch.setattr(runtime_factory, "DetectorLoader", StubLoader)


def test_missing_runtime_configuration_lists_all_required_fields():
    with pytest.raises(MissingRuntimeConfigurationError) as error:
        create_orchestrator()

    assert ", ".join(REQUIRED_ORCHESTRATOR_FIELDS) in str(error.value)
    from backend.app.config.orchestrator import OrchestratorRuntimeConfig

    with pytest.raises(MissingRuntimeConfigurationError) as error:
        OrchestratorRuntimeConfig.from_mapping({})
    assert ", ".join(REQUIRED_ORCHESTRATOR_FIELDS) in str(error.value)


def test_supplied_configuration_creates_fresh_per_flow_orchestrators(monkeypatch):
    install_stub_loader(monkeypatch)

    first = create_orchestrator(TEST_ONLY_CONFIGURATION)
    second = create_orchestrator(TEST_ONLY_CONFIGURATION)

    assert first is not second
    assert first.registry.list() == ["ddos", "portscan"]
    assert second.registry.list() == ["ddos", "portscan"]
    assert first.alert_store is not second.alert_store
    assert len(first.alert_store) == len(second.alert_store) == 0
    assert first.latency_metrics is not second.latency_metrics
    assert first.latency_metrics.observations == second.latency_metrics.observations == {}
    assert first.ordering.config.maximum_lateness.total_seconds() == 2.5
    assert first.ordering.config.buffer_capacity == 37
    assert first.ordering.config.late_event_behavior == "quarantine"
    assert first.ordering.config.overflow_behavior == "reject"
    assert second.ordering.config == first.ordering.config
    assert first.windows is None
    assert second.windows is None
    assert first.runtime_configuration == TEST_ONLY_CONFIGURATION


def test_benchmark_factory_loader_passes_explicit_configuration(monkeypatch):
    install_stub_loader(monkeypatch)

    orchestrator = _load_factory(
        "backend.app.runtime_factory:create_orchestrator",
        TEST_ONLY_CONFIGURATION,
    )

    assert orchestrator.registry.list() == ["ddos", "portscan"]
    assert orchestrator.runtime_configuration == TEST_ONLY_CONFIGURATION
