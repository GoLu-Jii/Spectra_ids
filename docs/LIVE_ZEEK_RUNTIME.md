# SPECTRA passive Zeek runtime

## Runtime integration

The ingestion runtime connects Zeek log files to the existing `normalize_zeek_record` and `RuntimeOrchestrator` path. It does not open a capture interface, send packets, decrypt payloads, or communicate with monitored hosts. Configure an existing orchestrator, then call `backend.app.main.configure_zeek_runtime(orchestrator, config)` before the ASGI server starts. FastAPI startup starts the runtime task; shutdown cancels it, flushes the orchestrator and closes WebSocket sender tasks.

`RuntimeConfig.from_env()` reads:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SPECTRA_RUNTIME_MODE` | `TEST` | `LIVE`, `REPLAY`, or `TEST` |
| `SPECTRA_ZEEK_LOG_DIR` | `var/log/zeek` | Zeek log directory; relative paths use the SPECTRA process working directory |
| `SPECTRA_ZEEK_LOG_FILES` | `conn.log,dns.log,ssl.log,tls.log,packet.log` | Comma-separated supported files; absent files are allowed |
| `SPECTRA_TAIL_INTERVAL_SECONDS` | `0.25` | LIVE file-check interval |
| `SPECTRA_TAIL_MAX_BYTES_PER_FILE_POLL` | `65536` | Maximum bytes read from each file per poll |
| `SPECTRA_TAIL_MAX_PENDING_LINE_BYTES` | `1048576` | Maximum retained incomplete record size |
| `SPECTRA_FLUSH_ON_SHUTDOWN` | `true` | Flush pending orchestrator ordering/window state on shutdown |

The runtime does not rebuild or replace the supplied orchestrator. Continue to set ordering buffer and window semantics according to the existing detector/runtime configuration.

LIVE begins at each already-existing file's current end so historical log content is not replayed into LIVE. A newly created selected log is read from its beginning. Complete records appended thereafter are processed incrementally. Partial final lines are held until completed; oversized partial lines are discarded and counted. Rotation is detected by file identity/size and the replacement file is read from its beginning. The existing Zeek parser handles JSON-lines and Zeek TSV `#fields` logs. The selected filename supplies the event type for records that do not carry one explicitly.

REPLAY reads existing selected files once in configured filename and file-record order, uses the same decoder and normalization, and does not set `zeek_available_at`. TEST leaves ingestion to the test harness. The default is TEST so a developer process does not silently begin consuming sensor logs.

Health includes `zeek_runtime` state when a runtime is attached. Stats includes its ingestion counters alongside the existing orchestrator, latency, alert and WebSocket metrics. `late_events` and `too_late_events` come from the existing ordering counters. `tail_overflow_events` counts oversized Zeek log records discarded by the tailer; it is not an ordering queue overflow metric. `zeek_available_at` is recorded only when a complete LIVE record is read; it is retained in alert timing and feeds the existing `zeek_to_ingest` duration. No availability time is synthesized for replay.

`zeek_source_available` means at least one configured log file is currently present in the configured directory. It does not prove that the Zeek process is alive, the sensor interface is receiving mirrored packets, or the file is still growing; those checks require sensor-side monitoring beyond the current log reader.

## Linux passive sensor deployment

The production sensor is a Linux monitoring host. Obtain traffic from an approved passive TAP/SPAN mirror or a data-diode-compatible telemetry path. The sensor NIC and host must have no return route into the protected production network. Zeek observes the mirrored traffic and writes metadata logs; SPECTRA reads those files only. This application does not configure the mirror or enforce hardware isolation.

1. Install a supported Zeek package/build for the chosen Linux distribution and record its exact version. Configure Zeek to monitor the designated passive interface and to write standard TSV logs with `#fields` headers to a local spool directory. Use the standard `conn`, `dns`, `ssl` (or `tls` if emitted by the installed Zeek configuration), and `packet` logs as needed. Keep Zeek's `capture_loss.log` and `reporter.log` for separate sensor diagnostics; they are not currently normalized by this runtime.
2. Ensure the SPECTRA service account has read permission on the log directory and Zeek can rotate/write its logs. Set environment variables, for example:

   ```sh
   export SPECTRA_RUNTIME_MODE=LIVE
   export SPECTRA_ZEEK_LOG_DIR=/var/log/zeek/current
   export SPECTRA_ZEEK_LOG_FILES=conn.log,dns.log,ssl.log
   export SPECTRA_TAIL_INTERVAL_SECONDS=0.25
   ```

3. Start SPECTRA through the deployment host that builds the approved `RuntimeOrchestrator`, invokes `configure_zeek_runtime(orchestrator, RuntimeConfig.from_env())`, and then runs the FastAPI app. Example wiring:

   ```python
   from backend.app.config.runtime import RuntimeConfig
   from backend.app.main import app, configure_zeek_runtime

   orchestrator = create_approved_runtime_orchestrator()  # existing deployment configuration
   configure_zeek_runtime(orchestrator, RuntimeConfig.from_env())
   ```

   Run that configured ASGI application with the deployment's process manager (for example, Uvicorn). The `create_approved_runtime_orchestrator()` function represents the site's existing detector, ordering and window configuration; Task 10 does not invent those detector semantics.
4. Verify `GET /health` reports the selected runtime mode, `zeek_runtime.running: true`, source availability and consumed filenames. Verify `/stats` counters advance when Zeek writes records. Connect the dashboard or a WebSocket client to `/ws` and confirm only alerts produced by the configured detectors arrive.
5. On shutdown, the runtime task is cancelled, pending orchestrator state is flushed, and WebSocket sender tasks are closed.

Windows is supported for development, replay and tests only. WSL2 may be used to exercise the Linux file-processing path with prepared logs, but it is not evidence of production mirror visibility or hardware isolation. This repository change does not validate native Windows live capture or establish a hardware data diode.

## Development and reproducibility

- Python runtime tested here: Python 3.13.3. Use the repository's pinned/approved Python environment in deployment and record its exact version.
- Zeek: use a supported Linux build and record the exact version, interface, local policy/configuration, log types and log directory with deployment records. The runtime assumes standard Zeek TSV `#fields` headers or JSON-lines and UTC/numeric Zeek `ts` values supported by the existing normalizer.
- Keep LIVE, REPLAY and TEST explicit. For a local deterministic exercise, choose `REPLAY` and a fixture log set; for unit tests, use `TEST`.
- No throughput or latency target is claimed by this integration. The runtime exposes measured ingestion timestamps and existing backend metrics but no benchmark result.
