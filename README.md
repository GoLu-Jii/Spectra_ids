# SPECTRA

AI-Assisted Passive Cyber Threat Detection for Critical Infrastructure.

This repository contains the final SPECTRA implementation based on the frozen project PRD, ML detector specification, AI implementation rules, and technology stack.

## Status

Final implementation phase.

## Architecture

Passive Traffic → Zeek → Ingestion → Normalization → Feature Engine → ML Detectors → Alerts → FastAPI/WebSocket → React Dashboard

## Zeek runtime

Task 10 provides a bounded Zeek file tailer and `ZeekRuntime` adapter. Configure an existing `RuntimeOrchestrator` and pass it to `configure_zeek_runtime(orchestrator, RuntimeConfig.from_env())` before starting the FastAPI app. LIVE starts at the current end of configured log files, then consumes appended complete records. REPLAY reads configured files once in deterministic file/record order. TEST does not start an ingestion task.

See [docs/LIVE_ZEEK_RUNTIME.md](docs/LIVE_ZEEK_RUNTIME.md) for environment variables and the Linux/WSL passive sensor procedure.
