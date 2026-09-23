from datetime import datetime, timedelta, timezone

import pytest

from backend.app.latency import LatencyMetricsCollector, LatencyTiming

BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def test_timestamps_are_utc_aware_and_durations_use_monotonic_marks():
    wall_times = iter(BASE + timedelta(seconds=offset) for offset in range(8))
    monotonic_times = iter(float(offset) for offset in range(8))
    timing = LatencyTiming.start(
        BASE,
        now=lambda: next(wall_times),
        mono=lambda: next(monotonic_times),
    )

    timing.mark("ordered_at", now=lambda: next(wall_times), mono=lambda: next(monotonic_times))
    timing.mark("feature_ready_at", now=lambda: next(wall_times), mono=lambda: next(monotonic_times))
    timing.mark("inference_started_at", now=lambda: next(wall_times), mono=lambda: next(monotonic_times))
    timing.mark("inference_finished_at", now=lambda: next(wall_times), mono=lambda: next(monotonic_times))
    timing.mark("alert_created_at", now=lambda: next(wall_times), mono=lambda: next(monotonic_times))

    durations = timing.durations()

    assert timing.observed_at.tzinfo == timezone.utc
    assert timing.alert_created_at.tzinfo == timezone.utc
    assert durations["queue_wait"] == 1.0
    assert durations["window_wait"] == 1.0
    assert durations["inference_time"] == 1.0
    assert durations["alert_generation_time"] == 1.0
    assert durations["capture_to_alert"] == 5.0


def test_latency_collector_reports_percentiles_and_max():
    collector = LatencyMetricsCollector()
    for offset in (1.0, 2.0, 3.0, 4.0):
        timing = LatencyTiming(BASE)
        timing._monotonic_marks.update(
            {
                "ingested_at": 0.0,
                "ordered_at": 0.0,
                "feature_ready_at": 0.0,
                "inference_started_at": 0.0,
                "inference_finished_at": offset,
                "alert_created_at": offset,
            }
        )
        collector.record(timing)

    summary = collector.summary("inference_time")

    assert summary["count"] == 4
    assert summary["p50"] == 2.5
    assert summary["p95"] == pytest.approx(3.85)
    assert summary["p99"] == pytest.approx(3.97)
    assert summary["max"] == 4.0


def test_missing_optional_timestamps_do_not_create_fake_latency():
    timing = LatencyTiming(BASE)
    timing.mark("inference_started_at", now=lambda: BASE, mono=lambda: 10.0)

    durations = timing.durations()

    assert "capture_to_alert" not in durations
    assert "delivery_time" not in durations
    assert "capture_to_dashboard" not in durations
