# SPECTRA runtime configuration boundary

## What each configuration controls

SPECTRA has three separate configuration concerns:

- `backend.app.config.runtime.RuntimeConfig` controls Zeek file ingestion mode, file paths, and polling limits.
- `backend.app.config.orchestrator.OrchestratorRuntimeConfig` controls the `RuntimeOrchestrator`: ordering policy and whether detector windows are enabled.
- Benchmark options control only the selected log directory/files, FAST replay mode, and result path. The benchmark CLI receives the orchestrator configuration separately through `--orchestrator-config`.

There is no repository production/deployment configuration file or authorized production values for ordering. A deployment must supply an approved `OrchestratorRuntimeConfig` explicitly. The factory has no production defaults and raises `MissingRuntimeConfigurationError` with the missing field names if called without a complete configuration.

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

These fields are mandatory even where an operator chooses zero lateness or an explicit policy. The repository does **not** currently authorize a default for maximum lateness, capacity, too-late policy, or overflow policy. The PRD requires these decisions but does not set their deployment values. Do not copy policy or timing values from unit tests into deployment configuration.

The `window_config=null` choice is specific to the existing per-flow DDoS and Port Scan contracts. It does not establish generic window values for other detectors.

## Benchmark use

The benchmark runner separates fixture/replay configuration from orchestrator runtime settings. Supply the same approved runtime settings as JSON:

```sh
python -m backend.app.benchmark \
  --logs-dir /path/to/zeek/logs \
  --logs conn.log,dns.log \
  --orchestrator-factory backend.app.runtime_factory:create_orchestrator \
  --orchestrator-config /path/to/owner-approved-orchestrator.json \
  --replay-mode FAST \
  --output /path/to/result.json
```

The JSON object must contain all five required fields above; `window_config` must be present with a JSON `null`. Missing or unknown fields fail explicitly. The runtime JSON must record the owner-approved values used for the run. Benchmark flags do not supply or infer runtime settings.

No owner-approved ordering values are checked into this repository yet. Therefore there is no production configuration example or detector-enabled benchmark command with concrete values here.
