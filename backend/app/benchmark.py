from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import importlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config.runtime import RuntimeConfig
from .runtime import ZeekRuntime

LATENCY_METRICS = (
    "capture_to_alert",
    "capture_to_dashboard",
    "zeek_to_ingest",
    "queue_wait",
    "window_wait",
    "feature_time",
    "inference_time",
    "alert_generation_time",
    "delivery_time",
)


def run_replay_benchmark(
    orchestrator: Any,
    *,
    logs_dir: str | Path,
    log_files: tuple[str, ...],
    replay_mode: str = "FAST",
    repository_root: str | Path | None = None,
    source_pcap: str | Path | None = None,
    source_pcap_origin: str | None = None,
    zeek_version: str | None = None,
) -> dict[str, object]:
    """Replay one explicit Zeek log set through a fresh existing orchestrator."""
    if replay_mode != "FAST":
        raise ValueError("Only FAST replay exists in the current SPECTRA runtime")
    directory = Path(logs_dir)
    paths = [directory / name for name in log_files]
    existing = [path for path in paths if path.is_file()]
    if len(existing) != len(paths):
        missing = [str(path) for path in paths if not path.is_file()]
        raise FileNotFoundError("Zeek benchmark log file(s) not found: " + ", ".join(missing))
    _require_fresh_orchestrator(orchestrator)

    fixture_hash = hashlib.sha256()
    fixture_files = []
    for path in paths:
        content_hash = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                content_hash.update(chunk)
        digest = content_hash.hexdigest()
        fixture_hash.update(path.name.encode("utf-8"))
        fixture_hash.update(bytes.fromhex(digest))
        fixture_files.append({"name": path.name, "size_bytes": path.stat().st_size, "sha256": digest})

    source_pcap_metadata = None
    if source_pcap is not None:
        pcap_path = Path(source_pcap)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"Source PCAP not found: {pcap_path}")
        source_pcap_metadata = {
            "name": pcap_path.name,
            "path": str(pcap_path.resolve()),
            "origin": source_pcap_origin,
            "size_bytes": pcap_path.stat().st_size,
            "sha256": _sha256_file(pcap_path),
        }

    root = Path(repository_root) if repository_root is not None else Path.cwd()
    models = _model_versions(orchestrator)
    runtime_config = RuntimeConfig(mode="REPLAY", zeek_log_dir=directory, log_files=log_files)
    configuration = {
        "runtime_mode": "REPLAY",
        "replay_mode": replay_mode,
        "replay_rate": "unpaced",
        "log_files": list(log_files),
        "ordering": repr(orchestrator.ordering.config),
        "windows": (
            repr(orchestrator.windows.config)
            if orchestrator.windows is not None
            else None
        ),
        "runtime_configuration": getattr(orchestrator, "runtime_configuration", None),
        "models": models,
    }
    config_id = hashlib.sha256(
        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    start_utc = datetime.now(timezone.utc)
    memory_start = _memory_snapshot()
    cpu_start = time.process_time()
    clock_start = time.perf_counter()
    runtime = ZeekRuntime(runtime_config, orchestrator)
    completed = False
    try:
        asyncio.run(_run_runtime(runtime))
        completed = True
    finally:
        elapsed = time.perf_counter() - clock_start
    cpu_seconds = time.process_time() - cpu_start
    end_utc = datetime.now(timezone.utc)
    memory_end = _memory_snapshot()

    runtime_state = runtime.snapshot()
    orchestration = orchestrator.get_metrics()
    ordering = orchestrator.ordering.stats
    total_input = runtime.records_read
    conn_records = runtime.records_by_type.get("conn", 0)
    packet_records = runtime.records_by_type.get("packet", 0)
    packet_counts_complete = packet_records > 0 and runtime.packet_count_observations == packet_records
    packet_bytes_complete = packet_records > 0 and runtime.packet_bytes_observations == packet_records

    collected = orchestrator.latency_metrics.report()
    latencies = summarize_latencies(collected)
    for name in ("capture_to_alert", "capture_to_dashboard"):
        latencies[name] = _unavailable_latency(
            "Not a valid elapsed replay latency; replay does not preserve capture/delivery wall time"
        )

    received = orchestration.get("events_received", 0)
    app_drops = max(0, received - ordering.events_accepted)
    elapsed_value = elapsed if elapsed > 0 else None
    store = orchestrator.alert_store
    delivery = getattr(orchestrator.alert_publisher, "__self__", None)
    delivery_metrics = delivery.snapshot() if delivery is not None and hasattr(delivery, "snapshot") else None
    throughput = {
        "input_records": total_input,
        "elapsed_seconds": elapsed,
        "input_records_per_second": _rate(total_input, elapsed_value),
        "accepted_events": ordering.events_accepted,
        "accepted_events_per_second": _rate(ordering.events_accepted, elapsed_value),
        "processed_events": orchestration.get("events_processed", 0),
        "processed_events_per_second": _rate(orchestration.get("events_processed", 0), elapsed_value),
        "conn_records": conn_records,
        "conn_records_per_second": _rate(conn_records, elapsed_value) if conn_records else None,
        "flows_per_second": _rate(conn_records, elapsed_value) if conn_records else None,
        "flows_per_second_unavailable_reason": None if conn_records else "No conn.log records in the selected fixture",
        "packet_count": runtime.packet_count_total if packet_counts_complete else None,
        "packets_per_second": _rate(runtime.packet_count_total, elapsed_value) if packet_counts_complete else None,
        "packet_rate_unavailable_reason": None if packet_counts_complete else "Selected packet.log records do not all contain supported explicit packet counts",
        "packet_bytes": runtime.packet_bytes_total if packet_bytes_complete else None,
        "megabits_per_second": runtime.packet_bytes_total * 8 / elapsed_value / 1_000_000 if packet_bytes_complete and elapsed_value else None,
        "bandwidth_unavailable_reason": None if packet_bytes_complete else "Selected packet.log records do not all contain supported explicit byte counts",
    }
    queue_metrics = {
        "current_depth": ordering.current_buffer_depth,
        "maximum_depth": ordering.peak_buffer_depth,
        "overflow_count": ordering.overflow_events,
        "configured_capacity": orchestrator.ordering.config.buffer_capacity,
        "queue_type": "orchestrator reorder buffer",
        "websocket_current_depth": delivery_metrics.get("queue_current_depth") if delivery_metrics else None,
        "websocket_peak_depth": delivery_metrics.get("queue_peak_depth") if delivery_metrics else None,
        "websocket_client_overflow_drops": delivery_metrics.get("client_drops") if delivery_metrics else None,
    }
    limitations = [
        "FAST replay is unpaced and is not live sensor throughput.",
        "Replay does not provide valid capture-to-alert or capture-to-dashboard elapsed wall times.",
        "No capture hardware, passive mirror, or data diode is exercised by this runner.",
        "Temporal evidence-acquisition time is not inferred from detector inference time.",
    ]
    if not models:
        limitations.append("No detector adapters were registered; this run measures ingestion and ordering only.")
    result: dict[str, object] = {
        "metadata": {
            "fixture_identifier": ",".join(path.name for path in paths),
            "logs_directory": str(directory.resolve()),
            "fixture_sha256": fixture_hash.hexdigest(),
            "fixture_files": fixture_files,
            "source_pcap": source_pcap_metadata,
            "runtime_mode": "REPLAY",
            "replay_mode": replay_mode,
            "replay_rate": "unpaced",
            "started_at": start_utc.isoformat(),
            "ended_at": end_utc.isoformat(),
            "git_sha": _git_sha(root),
            "python_version": platform.python_version(),
            "os_platform": platform.platform(),
            "zeek_version": zeek_version or _zeek_version(),
            "configuration_identifier": config_id,
            "configuration": configuration,
            "detectors": models,
        },
        "throughput": throughput,
        "latency": latencies,
        "resource_usage": {
            "process_cpu_seconds": cpu_seconds,
            "process_cpu_percent_one_core_basis": cpu_seconds / elapsed * 100 if elapsed > 0 else None,
            "memory_start": memory_start,
            "memory_end": memory_end,
            "memory_limitations": "Memory values use the current platform process API; peak is a process high-water mark, not an isolated benchmark-only peak.",
        },
        "queue_metrics": queue_metrics,
        "drop_metrics": {
            "application_event_drops": app_drops,
            "rejected_or_late_events": orchestration.get("events_rejected_or_late", 0),
            "late_events": ordering.late_events,
            "too_late_events": ordering.too_late_events,
            "queue_overflow_events": ordering.overflow_events,
            "websocket_client_drops": delivery_metrics.get("client_drops") if delivery_metrics else None,
            "zeek_parse_errors": runtime.parse_errors,
            "normalization_errors": runtime.normalization_errors,
            "source_errors": runtime.source_errors,
            "detector_failures": orchestration.get("detector_failures", 0),
            "capture_loss": {"value": None, "reason": "No sensor capture-loss telemetry is included in the selected logs"},
            "zeek_log_loss": {"value": None, "reason": "Zeek log loss is not measured by this reader"},
        },
        "alert_metrics": {
            "alerts_generated": orchestration.get("alerts_produced", 0),
            "alerts_retained": len(store) if store is not None else None,
            "websocket_delivery": delivery_metrics,
        },
        "detector_metrics": {
            "registered_detector_count": len(models),
            "invocations": orchestration.get("detector_invocations", 0),
            "failures": orchestration.get("detector_failures", 0),
        },
        "runtime_status": {
            "completed": completed,
            "running_after_replay": runtime.running,
            "processed_records": orchestration.get("events_processed", 0),
            "errors": runtime.source_errors + runtime.normalization_errors + orchestration.get("detector_failures", 0),
        },
        "limitations": limitations,
    }
    return result


async def _run_runtime(runtime: ZeekRuntime) -> None:
    await runtime.start()
    if runtime.task is None:
        raise RuntimeError("REPLAY runtime did not create a task")
    await runtime.task
    await runtime.stop()


def write_result(result: dict[str, object], output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_summary(result: dict[str, object]) -> str:
    metadata = result["metadata"]
    throughput = result["throughput"]
    drops = result["drop_metrics"]
    return "\n".join((
        f"SPECTRA replay benchmark: {metadata['fixture_identifier']}",
        f"Mode/rate: {metadata['runtime_mode']} / {metadata['replay_mode']} ({metadata['replay_rate']})",
        f"Input records: {throughput['input_records']}",
        f"Elapsed seconds: {throughput['elapsed_seconds']!r}",
        f"Input records/sec: {throughput['input_records_per_second']!r}",
        f"Accepted events/sec: {throughput['accepted_events_per_second']!r}",
        f"Processed events/sec: {throughput['processed_events_per_second']!r}",
        f"Alerts generated: {result['alert_metrics']['alerts_generated']}",
        f"Application drops: {drops['application_event_drops']}",
        f"Queue overflows: {drops['queue_overflow_events']}",
    ))


def _empty_latency() -> dict[str, object]:
    return {"count": 0, "p50": None, "p95": None, "p99": None, "max": None}


def _unavailable_latency(reason: str) -> dict[str, object]:
    return {**_empty_latency(), "available": False, "reason": reason}


def summarize_latencies(
    collected: dict[str, dict[str, float | int | None]],
) -> dict[str, dict[str, object]]:
    """Return backend-collected distributions, marking absent samples explicitly."""
    return {name: collected.get(name, _empty_latency()) for name in LATENCY_METRICS}


def _rate(count: int, elapsed: float | None) -> float | None:
    return count / elapsed if elapsed is not None and elapsed > 0 else None


def _require_fresh_orchestrator(orchestrator: Any) -> None:
    if orchestrator.get_metrics().get("events_received", 0) != 0:
        raise ValueError("Benchmark requires a fresh RuntimeOrchestrator")
    if orchestrator.ordering.stats.events_accepted != 0:
        raise ValueError("Benchmark requires an unused reorder buffer")
    if orchestrator.alert_store is not None and len(orchestrator.alert_store) != 0:
        raise ValueError("Benchmark requires an empty AlertStore")
    if orchestrator.latency_metrics.observations:
        raise ValueError("Benchmark requires an unused latency collector")


def _model_versions(orchestrator: Any) -> list[dict[str, str | None]]:
    result = []
    for name in orchestrator.registry:
        detector = orchestrator.registry.get(name)
        result.append({
            "detector_name": getattr(detector, "detector_name", name),
            "detector_version": getattr(detector, "detector_version", None),
            "model_name": getattr(detector, "model_name", None),
            "model_version": getattr(detector, "model_version", None),
            "feature_schema": getattr(detector, "feature_schema", None),
        })
    return result


def _git_sha(root: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True,
            text=True, timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _zeek_version() -> str | None:
    executable = shutil_which("zeek")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "--version"], check=True, capture_output=True, text=True, timeout=3
        )
        return (completed.stdout or completed.stderr).strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def _memory_snapshot() -> dict[str, int | None]:
    if os.name == "nt":
        try:
            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                ]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            process = kernel32.GetCurrentProcess()
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            psapi.GetProcessMemoryInfo.restype = ctypes.c_int
            if psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
                return {"current_working_set_bytes": counters.WorkingSetSize,
                        "process_peak_working_set_bytes": counters.PeakWorkingSetSize}
        except (AttributeError, OSError):
            pass
    elif sys.platform == "linux":
        try:
            values = {}
            for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
                if line.startswith(("VmRSS:", "VmHWM:")):
                    key, value, _unit = line.split()
                    values["current_rss_bytes" if key == "VmRSS:" else "process_peak_rss_bytes"] = int(value) * 1024
            return {"current_rss_bytes": values.get("current_rss_bytes"),
                    "process_peak_rss_bytes": values.get("process_peak_rss_bytes")}
        except (OSError, ValueError):
            pass
    return {"current_bytes": None, "process_peak_bytes": None}


def _load_factory(specification: str, configuration: dict[str, object]) -> Any:
    module_name, separator, attribute = specification.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("Orchestrator factory must use module:function syntax")
    factory = getattr(importlib.import_module(module_name), attribute)
    orchestrator = factory(configuration)
    return orchestrator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark SPECTRA against existing Zeek log fixtures")
    parser.add_argument("--logs-dir", required=True)
    parser.add_argument("--logs", required=True, help="Comma-separated existing conn/dns/ssl/tls/packet logs")
    parser.add_argument("--orchestrator-factory", required=True, help="Fresh orchestrator factory as module:function")
    parser.add_argument(
        "--orchestrator-config", required=True, type=Path,
        help="JSON file explicitly supplying all runtime ordering/window configuration fields",
    )
    parser.add_argument("--source-pcap", type=Path, help="Source PCAP path for provenance metadata")
    parser.add_argument("--source-pcap-origin", help="Original source path/identifier for the PCAP")
    parser.add_argument("--zeek-version", help="Zeek version used to generate the selected logs")
    parser.add_argument("--replay-mode", choices=("FAST",), default="FAST")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    filenames = tuple(item.strip() for item in args.logs.split(",") if item.strip())
    try:
        runtime_configuration = json.loads(args.orchestrator_config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Unable to read orchestrator configuration: {exc}") from exc
    if not isinstance(runtime_configuration, dict):
        raise SystemExit("Orchestrator configuration JSON must be an object")
    orchestrator = _load_factory(args.orchestrator_factory, runtime_configuration)
    result = run_replay_benchmark(
        orchestrator, logs_dir=args.logs_dir, log_files=filenames,
        replay_mode=args.replay_mode, repository_root=Path.cwd(),
        source_pcap=args.source_pcap, source_pcap_origin=args.source_pcap_origin,
        zeek_version=args.zeek_version,
    )
    print(render_summary(result))
    if args.output is not None:
        write_result(result, args.output)
        print(f"JSON result: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
