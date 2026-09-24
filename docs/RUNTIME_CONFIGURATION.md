# SPECTRA runtime configuration boundary

## What each configuration controls

SPECTRA has three separate configuration concerns:

- `backend.app.config.runtime.RuntimeConfig` controls Zeek file ingestion mode, file paths, and polling limits.
- `backend.app.config.orchestrator.OrchestratorRuntimeConfig` controls the `RuntimeOrchestrator`: ordering policy and whether detector windows are enabled.
- Benchmark options control only the selected log directory/files, FAST replay mode, and result path. The benchmark CLI receives the orchestrator configuration separately through `--orchestrator-config`.

The project has now approved explicit P0 values for the current stateless DDoS + Port Scan integration. These values are project-owned runtime decisions; they are **not** represented as values supplied by the PRD. The factory's no-argument form uses `P0_RUNTIME_CONFIGURATION`, and alternate values are rejected by the locked P0 factory. Passing a partial mapping still raises `MissingRuntimeConfigurationError` naming the missing fields.

## Current detector runtime

`backend.app.runtime_factory:create_orchestrator(configuration)` loads only the two detector adapters already integrated by the backend: DDoS and Port Scan. Their handoff contracts define inference from a single flow and do not require the generic temporal `DetectorWindowManager`. The factory therefore requires `window_config` to be explicitly `null`; it does not apply the PRD's illustrative 60-second/1-second example.

Each ordered event is sent to each ready integrated detector once using its existing raw feature map. Detector feature definitions, preprocessing, and thresholds remain in the existing detector/configuration code. A future temporal detector must have its own approved runtime adapter and window semantics before it can be enabled here.

The factory also creates a fresh `DetectorRegistry`, `AlertStore` (using its existing bounded in-memory store default), and `LatencyMetricsCollector` for every call. It fails clearly if either integrated detector cannot load or is not ready; it does not silently return a partial registry.

## Required orchestrator fields

Every caller must explicitly provide all of these fields:

| Field | Required value | Meaning |
| --- | --- | --- |
| `maximum_lateness_seconds` | finite number >= 0 | Reorder watermark lateness |
| `buffer_capacity` | integer >= 1 | Maximum buffered event count |
| `late_event_behavior` | `release` or `quarantine` | Handling for events beyond the watermark |
| `overflow_behavior` | `release_oldest` or `reject` | Behavior when the reorder buffer is full |
| `window_config` | `null` for the currently integrated detectors | Explicitly disables generic temporal windows |

The locked P0 values are:

| Field | Project-owned P0 value |
| --- | --- |
| `maximum_lateness_seconds` | `5` |
| `buffer_capacity` | `4096` |
| `late_event_behavior` | `release` |
| `overflow_behavior` | `release_oldest` |
| `window_config` | `null` |

These values were explicitly supplied as project runtime decisions. They are not attributed to the PRD, which requires explicit policies but does not provide these numeric/policy values. Do not substitute unit-test settings. The checked-in representation is [p0_runtime.json](../backend/app/config/p0_runtime.json), and the factory's constant is `P0_RUNTIME_CONFIGURATION`.

The `window_config=null` choice is specific to the existing per-flow DDoS and Port Scan contracts. It does not establish generic window values for other detectors.

## Benchmark use

The benchmark runner separates fixture/replay configuration from orchestrator runtime settings. Supply the same approved runtime settings as JSON:

```sh
python -m backend.app.benchmark \
  --logs-dir /path/to/zeek/logs \
  --logs conn.log,dns.log \
  --orchestrator-factory backend.app.runtime_factory:create_orchestrator \
  --orchestrator-config backend/app/config/p0_runtime.json \
  --replay-mode FAST \
  --output /path/to/result.json
```

The JSON object contains all five required fields; `window_config` is explicitly JSON `null`. Missing or unknown fields fail explicitly. Benchmark flags do not supply or infer runtime settings. Deployment ingestion options remain independently configured through `RuntimeConfig`.

These project-approved P0 values apply only to the integrated stateless DDoS + Port Scan path. They do not establish production sensor/data-diode performance or temporal settings for other detectors.
