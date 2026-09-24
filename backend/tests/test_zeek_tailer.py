import asyncio
from datetime import timedelta

from backend.app.config.runtime import RuntimeConfig
from backend.app.detectors.registry import DetectorRegistry
from backend.app.ingestion.zeek_tailer import ZeekLogTailer
from backend.app.latency import LatencyMetricsCollector
from backend.app.pipeline.orchestrator import RuntimeOrchestrator
from backend.app.pipeline.ordering import ReorderBuffer, ReorderConfig
from backend.app.pipeline.windows import DetectorWindowManager, WindowConfig
from backend.app.runtime import ZeekRuntime


HEADER = "#separator \\x09\n#fields ts\tuid\tid.orig_h\tid.resp_h\n#types time\tstring\taddr\taddr\n"
ROW = "2026-09-24T12:00:00Z\tC123\t192.0.2.10\t198.51.100.20\n"


def test_live_tailer_skips_existing_history_and_reads_only_appends(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(HEADER + ROW, encoding="utf-8")
    tailer = ZeekLogTailer(tmp_path, ("conn.log",))

    assert tailer.poll() == []
    with path.open("a", encoding="utf-8") as stream:
        stream.write(ROW.replace("C123", "C124"))
    records = tailer.poll()

    assert len(records) == 1
    assert records[0].record["uid"] == "C124"
    assert records[0].zeek_available_at.tzinfo is not None


def test_live_tailer_keeps_incomplete_eof_record_until_appended(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(HEADER, encoding="utf-8")
    tailer = ZeekLogTailer(tmp_path, ("conn.log",))
    with path.open("a", encoding="utf-8") as stream:
        stream.write(ROW[:-1])
    assert tailer.poll() == []
    with path.open("a", encoding="utf-8") as stream:
        stream.write("\n")
    assert tailer.poll()[0].record["uid"] == "C123"


def test_malformed_line_isolated_and_missing_optional_logs_are_ignored(tmp_path):
    path = tmp_path / "conn.log"
    tailer = ZeekLogTailer(tmp_path, ("conn.log", "dns.log"))
    path.write_text(HEADER + "not-a-zeek-record\n" + ROW, encoding="utf-8")
    records = tailer.poll()
    assert len(records) == 1
    assert tailer.parse_errors == 1
    assert tailer.active_files == ("conn.log",)
    assert tailer.source_available is True


def test_rotation_resets_cursor_and_reads_new_file(tmp_path):
    path = tmp_path / "conn.log"
    rotated = tmp_path / "conn.old"
    path.write_text(HEADER, encoding="utf-8")
    tailer = ZeekLogTailer(tmp_path, ("conn.log",))
    path.rename(rotated)
    path.write_text(HEADER + ROW, encoding="utf-8")

    assert tailer.poll()[0].record["uid"] == "C123"


def _orchestrator():
    return RuntimeOrchestrator(
        ReorderBuffer(ReorderConfig(timedelta(0), 8)),
        DetectorWindowManager(WindowConfig(timedelta(seconds=60), timedelta(seconds=1))),
        DetectorRegistry(),
        latency_metrics=LatencyMetricsCollector(),
    )


def test_live_runtime_ingests_normalized_event_and_records_zeek_time(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(HEADER, encoding="utf-8")
    orchestrator = _orchestrator()
    config = RuntimeConfig(
        mode="LIVE", zeek_log_dir=tmp_path, log_files=("conn.log",), poll_interval_seconds=0.01
    )
    runtime = ZeekRuntime(config, orchestrator)

    async def exercise():
        await runtime.start()
        await asyncio.sleep(0.01)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(ROW)
        await asyncio.sleep(0.05)
        await runtime.stop()

    asyncio.run(exercise())

    timing = orchestrator._timings["C123"]
    assert orchestrator.get_metrics()["events_processed"] == 1
    assert runtime.events_ingested == 1
    assert timing.zeek_available_at is not None
    assert timing.durations()["zeek_to_ingest"] >= 0
    assert runtime.running is False


def test_replay_mode_reads_history_once_and_has_no_zeek_availability_time(tmp_path):
    (tmp_path / "conn.log").write_text(HEADER + ROW, encoding="utf-8")
    orchestrator = _orchestrator()
    runtime = ZeekRuntime(
        RuntimeConfig(mode="REPLAY", zeek_log_dir=tmp_path, log_files=("conn.log",)),
        orchestrator,
    )

    async def exercise():
        await runtime.start()
        await runtime.task

    asyncio.run(exercise())
    assert runtime.events_ingested == 1
    assert orchestrator._timings["C123"].zeek_available_at is None
    assert runtime.snapshot()["files_consumed"] == ["conn.log"]


def test_test_mode_does_not_start_a_live_tailer_or_background_task(tmp_path):
    runtime = ZeekRuntime(RuntimeConfig(mode="TEST", zeek_log_dir=tmp_path), _orchestrator())
    asyncio.run(runtime.start())
    assert runtime.tailer is None
    assert runtime.task is None
    assert runtime.running is False
