from __future__ import annotations

import gzip
import importlib.metadata
import importlib.util
import pickle
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet

from ..config.detectors import DetectorConfig
from .adapter import DetectorAdapter
from .health import DetectorHealth, unavailable_health
from .registry import DetectorRegistry

DetectorFactory = Callable[[Any, DetectorConfig], Any]


@dataclass(frozen=True)
class DetectorLoadResult:
    health: DetectorHealth
    adapter: DetectorAdapter | None = None
    artifact: Any | None = None


class DetectorLoader:
    """Explicit, lazy artifact loader with isolated per-detector failures."""

    def __init__(self, repository_root: str | Path) -> None:
        self.repository_root = Path(repository_root)

    def load(
        self,
        config: DetectorConfig,
        *,
        factory: DetectorFactory | None = None,
        registered: bool = False,
    ) -> DetectorLoadResult:
        artifact_path = self._artifact_path(config)
        dependency_available, dependency_error = self._check_dependencies(config)
        if not dependency_available:
            return DetectorLoadResult(
                unavailable_health(
                    config,
                    registered=registered,
                    artifact_path=artifact_path,
                    dependency_available=False,
                    error_reason=dependency_error,
                )
            )
        if artifact_path is None:
            return DetectorLoadResult(
                unavailable_health(
                    config,
                    registered=registered,
                    dependency_available=True,
                    error_reason="No artifact path is configured",
                )
            )
        if not artifact_path.is_file():
            return DetectorLoadResult(
                unavailable_health(
                    config,
                    registered=registered,
                    artifact_path=artifact_path,
                    dependency_available=True,
                    error_reason=f"Artifact not found: {artifact_path}",
                )
            )
        try:
            artifact = self._load_artifact(artifact_path, config.expected_format)
        except Exception as exc:
            return DetectorLoadResult(
                DetectorHealth(
                    detector_name=config.detector_name,
                    registered=registered,
                    artifact_present=True,
                    artifact_loadable=False,
                    dependency_available=True,
                    ready_for_inference=False,
                    error_reason=f"Artifact load failed: {exc}",
                )
            )

        if factory is None:
            return DetectorLoadResult(
                DetectorHealth(
                    detector_name=config.detector_name,
                    registered=registered,
                    artifact_present=True,
                    artifact_loadable=True,
                    dependency_available=True,
                    ready_for_inference=False,
                    error_reason="No detector factory supplied",
                ),
                artifact=artifact,
            )
        try:
            adapter = DetectorAdapter(factory(artifact, config), config)
        except Exception as exc:
            return DetectorLoadResult(
                DetectorHealth(
                    detector_name=config.detector_name,
                    registered=registered,
                    artifact_present=True,
                    artifact_loadable=True,
                    dependency_available=True,
                    ready_for_inference=False,
                    error_reason=f"Detector factory failed: {exc}",
                ),
                artifact=artifact,
            )
        return DetectorLoadResult(
            DetectorHealth(
                detector_name=config.detector_name,
                registered=registered,
                artifact_present=True,
                artifact_loadable=True,
                dependency_available=True,
                ready_for_inference=True,
            ),
            adapter=adapter,
            artifact=artifact,
        )

    def load_all(
        self,
        configs: Mapping[str, DetectorConfig],
        *,
        factories: Mapping[str, DetectorFactory] | None = None,
        registry: DetectorRegistry | None = None,
    ) -> dict[str, DetectorLoadResult]:
        """Load configured detectors independently; one failure does not stop others."""
        results: dict[str, DetectorLoadResult] = {}
        for name, config in configs.items():
            is_registered = registry is not None and name in registry
            result = self.load(
                config,
                factory=(factories or {}).get(name),
                registered=is_registered,
            )
            if result.adapter is not None and registry is not None:
                try:
                    registry.register(result.adapter)
                    result = DetectorLoadResult(
                        health=DetectorHealth(
                            detector_name=result.health.detector_name,
                            registered=True,
                            artifact_present=result.health.artifact_present,
                            artifact_loadable=result.health.artifact_loadable,
                            dependency_available=result.health.dependency_available,
                            ready_for_inference=result.health.ready_for_inference,
                            error_reason=result.health.error_reason,
                        ),
                        adapter=result.adapter,
                        artifact=result.artifact,
                    )
                except Exception as exc:
                    result = DetectorLoadResult(
                        health=DetectorHealth(
                            detector_name=config.detector_name,
                            registered=is_registered,
                            artifact_present=result.health.artifact_present,
                            artifact_loadable=result.health.artifact_loadable,
                            dependency_available=result.health.dependency_available,
                            ready_for_inference=False,
                            error_reason=f"Detector registration failed: {exc}",
                        ),
                        artifact=result.artifact,
                    )
            results[name] = result
        return results

    def _artifact_path(self, config: DetectorConfig) -> Path | None:
        if config.artifact_path is None:
            return None
        return self.repository_root / config.artifact_path

    def _load_artifact(self, path: Path, expected_format: str | None) -> Any:
        if expected_format == "gzip+joblib":
            import joblib

            with gzip.open(path, "rb") as stream:
                return joblib.load(stream)
        if expected_format == "joblib":
            import joblib

            return joblib.load(path)
        if expected_format == "pickle":
            with path.open("rb") as stream:
                return pickle.load(stream)
        raise ValueError(f"Unsupported artifact format: {expected_format!r}")

    def _check_dependencies(self, config: DetectorConfig) -> tuple[bool, str | None]:
        for package, requirement in config.dependencies:
            if importlib.util.find_spec(package) is None:
                return False, f"Dependency unavailable: {package}"
            if requirement is None:
                continue
            distribution = {"sklearn": "scikit-learn"}.get(package, package)
            try:
                installed = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError:
                return False, f"Dependency version unavailable: {distribution}"
            if installed not in SpecifierSet(requirement):
                return False, f"Dependency version mismatch: {package} {installed}, requires {requirement}"
        return True, None
