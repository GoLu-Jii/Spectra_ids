# SPECTRA P0 readiness and SIH demo

## Readiness decision

P0 is the current passive Zeek-to-dashboard integration for DDoS and Port Scan. The dashboard, alert APIs, replay path, configuration, observability, and benchmark tooling are present. Detector feature parity with original training ETLs and production sensor acceptance remain incomplete or blocked as recorded below. This report does not upgrade any detector status or claim production performance.

## Architecture

Zeek observes traffic from an approved passive TAP/SPAN mirror and writes metadata logs. SPECTRA reads Zeek TSV or JSON log files through the ingestion reader, normalizer, five-second reorder buffer, and packet-flow feature producer. Completed flows reach the DDoS and Port Scan adapters, then the alert store and bounded WebSocket publisher. FastAPI exposes `/health`, `/stats`, `/alerts`, `/alerts/{alert_id}`, and `/ws`; the React dashboard reads the REST endpoints and merges live WebSocket alerts.

The P0 factory is `backend.app.runtime_factory:create_orchestrator`. It registers only DDoS and Port Scan and uses the locked values in `backend/app/config/p0_runtime.json`: 5 seconds maximum lateness, capacity 4096, release late events, release oldest on overflow, and no generic detector windows. The explicit optional ordered-runtime factory is separate from P0 and is not the deployment factory.

## Supported detector scope and frozen status

| Detector | P0 factory | Current documented status | Exact remaining blocker |
|---|---|---|---|
| DDoS | Enabled | Packet-path inference functionally exercised; training feature parity incomplete; production validation blocked | Original training ETL, extractor version and complete capture evidence are missing; no production capture acceptance |
| Port Scan | Enabled | Packet-path inference functionally exercised; training feature parity incomplete; production validation blocked | Original training flow construction/extractor version and complete capture evidence are missing; no production capture acceptance |
| C2 beaconing | Not enabled | Model/contract fixture exercised; runtime telemetry incomplete; parity incomplete; production validation blocked | Artifact provenance/hyperparameter mismatch and missing verified C2 input telemetry semantics |
| DNS tunnelling | Not enabled | Model fixture exercised; runtime telemetry incomplete; parity incomplete; production validation blocked | Missing training packet-to-29-feature ETL; frame/payload length, direction, response matching, and grouping parity unresolved |
| Data exfiltration | Not enabled | Stateful fixture and alert plumbing exercised; runtime telemetry blocked; parity incomplete; production validation blocked | Missing packet-to-27-column ETL and enrichment sources/versions, plus production state-boundary contract |
| DGA | Not enabled | Blocked / incomplete handoff | Required model/vectorizer/resource bundle is incomplete |
| TLS malware | Not enabled | Blocked / incomplete handoff | Feature-name mapping, producer, and runtime dependencies/modules are incomplete |
| QUIC | Not enabled | Blocked / not implemented as a supervised detector | No approved model, feature contract, or validated sensor metadata source |

“Functionally exercised” means the documented controlled packet-path or checked-in model fixture reached inference. It does not mean training parity, live sensor acceptance, or production validation. In particular, DNS tunnelling and exfiltration training ETLs must not be reconstructed without their original source/data.

## Readiness checks

1. **DDoS and Port Scan packet path:** implemented packet-log aggregation and per-flow inference are covered by backend integration tests and the recorded controlled synthetic packet-path run. Original training-feature parity remains incomplete. This is not evidence of a real attack-capture result.
2. **REST alert delivery:** `/alerts` returns stored alert history; `/alerts/{alert_id}` retrieves an alert; missing IDs return 404. Covered by `backend/tests/test_api_delivery.py`.
3. **WebSocket live alert delivery:** `/ws` fans stored alerts out to connected clients, tracks delivery timing, clients, queue depth, drops, and send failures. Bounded queues can drop a slow client. Covered by `backend/tests/test_api_delivery.py`.
4. **React dashboard:** displays alert details, detector/runtime health, ingestion state, counters, and latency distributions. It now labels the P0 detector scope directly: only DDoS and Port Scan are enabled, and blocked/unintegrated families are not presented as active.
5. **LIVE Zeek runtime:** file tailing is implemented for appended Zeek records. LIVE begins at existing files’ current ends; it is passive file consumption, not capture-interface control. Linux Zeek and passive mirror deployment are required. Native Windows live capture and production mirror visibility are not validated.
6. **REPLAY fallback:** selected existing Zeek logs can be read once through the same reader/normalizer/orchestrator path. `FAST` replay is unpaced; timestamp-preserving replay is not implemented. Checked-in DNS53 logs are parser/plumbing fixtures, not attack validation.
7. **Runtime health/stats:** `/health` reports service/runtime state, active detector registration and health, failures, and Zeek ingestion state. `/stats` reports orchestrator counters, latency summaries, alert count, WebSocket delivery counters, and Zeek counters. `zeek_source_available` means a selected file exists; it does not prove Zeek is running or traffic is visible.
8. **Latency instrumentation:** records available processing stages and delivery timing and reports P50/P95/P99/MAX/count. Empty samples remain unavailable. Replay does not synthesize capture-to-alert or capture-to-dashboard timing.
9. **Benchmark runner:** `backend.app.benchmark` emits replay/run metadata, input hashes, configuration, Git/Python/OS/Zeek/model metadata, rates, timing distributions, queue/drop counters, and resource measurements where available. The checked-in fixture is not detector-complete. No performance value is asserted by this report.
10. **P0 runtime configuration:** factory enforces the project-owned frozen values above. It loads only DDoS and Port Scan. Optional detector registration does not change the P0 factory.
11. **Reproducibility metadata:** benchmark output records inputs/configuration and environment metadata. For reproducibility, retain exact Zeek version/configuration, raw PCAP and generated-log hashes, model/artifact identifiers, Python/dependency versions, runtime JSON, Git SHA, and any working-tree diff. A Git SHA alone does not describe uncommitted files.
12. **Passive/read-only boundary:** SPECTRA reads Zeek metadata logs and does not open packet-capture interfaces, send packets, decrypt payloads, or communicate with monitored hosts. The sensor must use an approved passive mirror/data-diode-compatible path with no return route. SPECTRA does not enforce hardware isolation; sensor-side `capture_loss.log` and `reporter.log` remain separate diagnostics.

## Test and benchmark record

Requested backend command (the provided `..\.venv` path was not present from the repository root; the project interpreter is `..venv`):

```text
..venvScriptspython.exe -m pytest backend	ests -q
114 passed, 15 warnings in 8.68s
```

Warnings included the Starlette/httpx deprecation, serialized XGBoost/sklearn version compatibility notices, and a deprecated `datetime.utcnow()` use. No tests failed.

No real benchmark run or production performance measurement was performed for this task. Existing fixture benchmark tests validate runner behavior only. Do not quote their runtime as sensor performance.

## Live-runtime limitations and dependency/model warnings

- LIVE requires a supported Linux Zeek build, a passive feed, readable/rotating log files, and deployment-owned ASGI wiring. Windows is for development, tests, and replay; WSL does not prove hardware isolation or mirrored traffic visibility.
- Current DDoS/Port Scan packet path documents Zeek-observed transport-payload bytes; exact parity to the absent training ETLs is not established.
- C2 artifact metadata says sklearn 1.6.1 while the current environment emitted an unpickle warning under sklearn 1.9.1. C2 metadata and checked-in trainer hyperparameters disagree. Treat artifact provenance/runtime compatibility as unresolved.
- XGBoost emitted a serialized-model compatibility warning. Record/pin the producing and consuming versions for deployments; do not infer compatibility from a successful local test alone.
- DNS tunnelling's production Zeek path lacks proven training-equivalent packet length, client direction, and packet-level response matching. Exfiltration lacks its complete enriched 27-column input producer. Neither detector is P0-enabled.
- In-memory alert storage and WebSocket queues are bounded process-local mechanisms, not durable clustered delivery.

## SIH demo procedure

1. Use a Linux sensor or approved prepared Zeek log set. For LIVE, confirm the sensor receives only the approved passive mirror and has no route back into the protected network. Do not generate active probes from SPECTRA.
2. Pin/record Python, Zeek, dependencies, model artifact hashes, Zeek policy/configuration, log selection, and Git SHA plus the working-tree diff. Start Zeek writing the selected metadata logs.
3. Build the orchestrator with `backend.app.runtime_factory:create_orchestrator` and the exact `backend/app/config/p0_runtime.json` configuration. Attach it with `configure_zeek_runtime(orchestrator, RuntimeConfig.from_env())`; set `SPECTRA_RUNTIME_MODE=LIVE` and the approved Zeek log directory/files before starting the ASGI service.
4. Open the React dashboard. Confirm the P0 scope says DDoS and Port Scan only; the other families are not enabled. Confirm `/health` reports LIVE, the expected selected files, and advancing ingestion counters; confirm `/stats` counters and latency sample counts are interpreted as observed measurements.
5. Observe alerts from approved traffic already present on the mirrored segment. Open an alert and inspect its evidence/timing. Confirm the same alert appears through `/alerts` and `/ws`. Keep the Zeek capture-loss/reporter diagnostics alongside the demo record.
6. Stop the service cleanly. Save logs, health/stats snapshots, benchmark output if separately run, hashes, version/configuration records, and the exact Git/worktree state. Do not describe a no-alert run as detector validation.

If no approved live mirror or complete attack capture is available, state that limitation and use REPLAY with the available Zeek fixture to demonstrate ingestion/API/dashboard plumbing only. The DNS53 fixture is benign and is not evidence of DDoS/Port Scan attack detection. Do not manufacture alerts or present feature JSON as captured telemetry.

## PCAP fallback procedure

1. Use a legally approved PCAP with recorded SHA-256 and capture provenance. Keep the original immutable.
2. Run a separately versioned Zeek build/configuration offline against that PCAP and preserve its command, version, policy, generated-log hashes, and sensor diagnostics. Do not make SPECTRA parse raw PCAP or inject traffic.
3. Point `SPECTRA_RUNTIME_MODE=REPLAY` at the generated Zeek logs and select the actual generated files. Replay is FAST and unpaced. Save the benchmark JSON and its configuration/environment/input metadata.
4. Inspect `/health`, `/stats`, REST alerts, WebSocket delivery, and dashboard output. Report parser/inference counts and missing fields as observed. This fallback does not establish LIVE performance, zero capture loss, training parity, or detector accuracy unless the capture itself has appropriate ground truth and complete provenance.

## Remaining non-P0 work

- Acquire original training ETLs and source data before attempting any C2, DNS tunnelling, or Exfiltration parity work.
- Recover and reconcile C2 source file schemas, exact artifact-producing parameters, timestamp/counter/direction semantics, and model provenance.
- Recover DNS tunnelling's original CSV producer, packet-length/direction/transaction matching rules, grouping, and capture/window semantics.
- Recover Exfiltration's PCAP-to-27-column producer, row scope/order, RR/TTL semantics, reverse-DNS and unique-country/ASN sources and database versions, and state key.
- Restore complete DGA/TLS handoffs and define any approved QUIC model/metadata contract.
- Acquire a detector-complete, provenance-backed attack capture and execute documented production acceptance on the supported Linux passive sensor. Capture real benchmark values only from that measured run.
- Resolve model serialization/runtime version warnings and pin the supported deployment environment.
