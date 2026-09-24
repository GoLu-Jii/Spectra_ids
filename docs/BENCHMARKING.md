# SPECTRA replay benchmarking

## Runner

The standard-library runner is `backend.app.benchmark`. It consumes existing Zeek log files through `ZeekRuntime` in `REPLAY` mode, using the same reader, normalizer and supplied `RuntimeOrchestrator` as the application. The orchestrator must be fresh and must use the real detector/model configuration intended for the run.

```sh
python -m backend.app.benchmark \
  --logs-dir /path/to/zeek/fixture \
  --logs conn.log,dns.log \
  --orchestrator-factory backend.app.runtime_factory:create_orchestrator \
  --orchestrator-config /path/to/owner-approved-orchestrator.json \
  --replay-mode FAST \
  --output results/spectra-benchmark.json
```

The factory takes the separate JSON orchestrator configuration and returns a new configured `RuntimeOrchestrator`. The JSON must explicitly supply every ordering field and `window_config: null`; the factory adds the currently integrated per-flow DDoS and Port Scan adapters, a fresh empty `AlertStore`, and a fresh latency collector. See [runtime configuration](RUNTIME_CONFIGURATION.md). Benchmark fixture/replay arguments do not supply runtime values. The benchmark refuses missing selected files or a previously used orchestrator. `FAST` is the only replay rate currently implemented by SPECTRA; it processes records without wall-clock pacing while yielding to the asyncio loop. There is no fixed-rate replay mode in the current runtime, and the runner does not add one. Timestamp-preserving replay is not implemented.

The JSON result records fixture names and SHA-256 digests, optional source PCAP hash, configuration digest, runtime/replay mode, Git SHA, Python/OS, Zeek version, detector/model metadata, timestamps, rates, distributions, queue/drop counters, resources and limitations. When Zeek ran in WSL but the benchmark runs on Windows, pass `--zeek-version` explicitly so the generating Zeek build is recorded. `input_records` counts successfully decoded Zeek records; parse errors are reported separately. `accepted_events` comes from the existing reorder buffer, and `processed_events` comes from the orchestrator. `flows_per_second` counts `conn.log` records. Packet/sec and Mbps are reported only when every selected packet record contains supported explicit `packets` and/or byte fields; otherwise they are null with a reason.

## Metric interpretation

- **Input/replay rate** is decoded input records divided by elapsed runner wall time. It is an unpaced replay rate, not the offered rate of a network sensor.
- **Accepted rate** uses the reorder buffer's accepted event counter. **Processed rate** uses the orchestrator's processed event counter.
- **Latency distributions** reuse backend-collected P50/P95/P99/MAX/COUNT values. Empty samples have count zero and null percentiles. Replay capture-to-alert and capture-to-dashboard are marked unavailable because old fixture `observed_at` timestamps are not the replay start time or a real delivery time. Do not interpret inference time as evidence-acquisition time.
- **Queue depth/peak** refer to the existing reorder buffer; WebSocket fan-out queue depth/peak and client drops are separate fields when an `AlertDelivery` publisher is attached. Reorder `overflow_count` counts pushes that encounter a full buffer; with `release_oldest`, this can be nonzero while application event drops remain zero. Application drops are normalized events not accepted by the reorder buffer. Late events, too-late events, parser errors, normalization errors and detector failures remain separate.
- **Capture loss** requires sensor capture diagnostics such as Zeek `capture_loss.log`; **Zeek log loss** is not measured by this file reader. Both are explicitly null when absent. SPECTRA application drops do not stand in for either value.
- **CPU** is process CPU time divided by elapsed wall time, expressed on a one-core basis. Memory uses the current OS process API; its peak field is the process high-water mark and may include work before this benchmark. It is not an isolated benchmark-only peak.

## Reproduction and limitations

The repository includes a small real Zeek DNS53 output fixture at `backend/tests/fixtures/zeek/dns53/`; its provenance and hashes are recorded beside it. It contains one connection and one DNS record and is not detector-complete. Do not convert the detector feature JSON examples into pretend Zeek records. For a real detector benchmark, use a detector-complete packet-derived fixture and preserve its files, hashes, Zeek configuration/version, orchestrator configuration, model/artifact identifiers, Python version and Git SHA with the JSON result. The current working tree's `HEAD` SHA is recorded; local uncommitted changes are not represented by that SHA, so retain the working tree diff or benchmark only from a commit.

The project-owned P0 decisions for the currently integrated stateless DDoS + Port Scan path are `maximum_lateness_seconds=5`, `buffer_capacity=4096`, `late_event_behavior=release`, `overflow_behavior=release_oldest`, and `window_config=null`. They are not attributed to the PRD and are not general settings for other detectors or production sensor performance. Benchmark tests use a tiny temporary TSV input strictly to verify the runner; their timing is test behavior and is not a performance result.

On Windows, process measurements describe this development process only. Windows replay cannot validate Linux Zeek capture, passive mirror visibility, packet loss or data-diode deployment. A benchmark run on a developer machine must not be presented as production sensor performance. For LIVE validation, run the separately documented passive Linux Zeek setup and collect sensor-side loss diagnostics; do not imply that LIVE performance has been validated by replay.
