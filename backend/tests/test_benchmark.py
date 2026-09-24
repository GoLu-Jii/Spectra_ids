import json
from datetime import timedelta
import pytest

from backend.app.benchmark import render_summary, run_replay_benchmark, summarize_latencies, write_result
from backend.app.detectors.registry import DetectorRegistry
from backend.app.latency import LatencyMetricsCollector
from backend.app.pipeline.orchestrator import RuntimeOrchestrator
from backend.app.pipeline.ordering import ReorderBuffer, ReorderConfig
from backend.app.pipeline.windows import DetectorWindowManager, WindowConfig


HEADER = "#separator \\x09\n#fields ts\tuid\tid.orig_h\tid.resp_h\tproto\n#types time\tstring\taddr\taddr\tstring\n"
ROWS = (
    "2026-09-24T12:00:00Z\tF1\t192.0.2.1\t198.51.100.1\ttcp\n"
    "2026-09-24T12:00:02Z\tF2\t192.0.2.2\t198.51.100.2\ttcp\n"
)


def make_orchestrator(*, capacity=16):
    return RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(seconds=10), capacity)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=60), timedelta(seconds=1))),
        DetectorRegistry(),
        latency_metrics=LatencyMetricsCollector(),
    )


def test_replay_benchmark_counts_pipeline_events_and_emits_rates(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER + ROWS, encoding="utf-8")
    result = run_replay_benchmark(
        make_orchestrator(), logs_dir=tmp_path, log_files=("conn.log",), repository_root=tmp_path
    )

    assert result["throughput"]["input_records"] == 2
    assert result["throughput"]["conn_records"] == 2
    assert result["throughput"]["accepted_events"] == 2
    assert result["throughput"]["processed_events"] == 2
    assert result["throughput"]["input_records_per_second"] > 0
    assert result["throughput"]["flows_per_second"] > 0
    assert result["metadata"]["runtime_mode"] == "REPLAY"


def test_empty_fixture_has_zero_counts_and_unavailable_rates(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER, encoding="utf-8")
    result = run_replay_benchmark(make_orchestrator(), logs_dir=tmp_path, log_files=("conn.log",))

    assert result["throughput"]["input_records"] == 0
    assert result["throughput"]["flows_per_second"] is None
    assert result["throughput"]["packets_per_second"] is None
    assert result["throughput"]["megabits_per_second"] is None


def test_queue_overflow_and_application_drop_counters_are_reported(tmp_path):
    rows = "".join(
        f"2026-09-24T12:00:{second:02}Z\tF{second}\t192.0.2.{second + 1}\t198.51.100.1\ttcp\n"
        for second in range(4)
    )
    (tmp_path / "conn.log").write_text(HEADER + rows, encoding="utf-8")
    result = run_replay_benchmark(
        make_orchestrator(capacity=1), logs_dir=tmp_path, log_files=("conn.log",)
    )

    assert result["queue_metrics"]["overflow_count"] > 0
    assert result["queue_metrics"]["maximum_depth"] == 1
    assert result["drop_metrics"]["application_event_drops"] == 0


def test_latency_rows_include_count_percentiles_and_unavailable_replay_capture_time(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER + ROWS, encoding="utf-8")
    orchestrator = make_orchestrator()
    result = run_replay_benchmark(
        orchestrator, logs_dir=tmp_path, log_files=("conn.log",)
    )

    summary = summarize_latencies({"inference_time": {
        "count": 4, "p50": 2.5, "p95": 3.85, "p99": 3.97, "max": 4.0,
    }})["inference_time"]
    assert summary["count"] == 4
    assert summary["p50"] == pytest.approx(2.5)
    assert summary["p95"] == pytest.approx(3.85)
    assert summary["p99"] == pytest.approx(3.97)
    assert summary["max"] == pytest.approx(4.0)
    assert result["latency"]["capture_to_alert"]["available"] is False
    assert result["latency"]["zeek_to_ingest"]["count"] == 0
    assert result["latency"]["inference_time"]["count"] == 0


def test_result_serializes_as_json_and_human_summary(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER + ROWS, encoding="utf-8")
    result = run_replay_benchmark(make_orchestrator(), logs_dir=tmp_path, log_files=("conn.log",))
    output = tmp_path / "result.json"
    write_result(result, output)

    decoded = json.loads(output.read_text(encoding="utf-8"))
    assert decoded["metadata"]["configuration_identifier"]
    assert "Input records: 2" in render_summary(decoded)


def test_result_records_source_pcap_and_explicit_zeek_version(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER, encoding="utf-8")
    source_pcap = tmp_path / "source.pcap"
    source_pcap.write_bytes(b"offline capture bytes")

    result = run_replay_benchmark(
        make_orchestrator(),
        logs_dir=tmp_path,
        log_files=("conn.log",),
        source_pcap=source_pcap,
        zeek_version="/opt/zeek/bin/zeek version 8.0.10",
    )

    assert result["metadata"]["source_pcap"]["sha256"] == (
        "cf8835e39ecd9317c59742f06b4c4e745d133eb739b5a2a2d6f053c9ae9d3aec"
    )
    assert result["metadata"]["zeek_version"] == "/opt/zeek/bin/zeek version 8.0.10"


def test_throughput_rate_formula_is_exact():
    from backend.app.benchmark import _rate

    assert _rate(25, 5.0) == 5.0
    assert _rate(25, None) is None
