from datetime import datetime, timedelta, timezone

import pytest

from backend.app.ingestion.events import NormalizedEvent
from backend.app.pipeline.windows import DetectorWindowManager, WindowConfig

BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def event(seconds: int, flow_id: str) -> NormalizedEvent:
    return NormalizedEvent(
        observed_at=BASE + timedelta(seconds=seconds),
        event_type="conn",
        flow_id=flow_id,
    )


def test_window_expiration_removes_old_group_state():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "a"))

    expired = manager.expire(BASE + timedelta(seconds=10))

    assert expired == (("c2", "host-a"),)
    assert manager.get_state("c2", "host-a") is None


def test_flush_emits_and_clears_context():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "a"))
    manager.add("c2", "host-a", event(1, "b"))

    emissions = manager.flush("c2", "host-a")

    assert len(emissions) == 1
    assert [item.flow_id for item in emissions[0].context_events] == ["a", "b"]
    assert manager.get_state("c2", "host-a") is None


def test_multiple_grouping_keys_have_independent_state():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "a"))
    manager.add("c2", "host-b", event(0, "b"))

    manager.add("c2", "host-a", event(5, "a2"))
    assert manager.get_state("c2", "host-b").events[0].flow_id == "b"
    assert manager.get_state("c2", "host-a").events[-1].flow_id == "a2"


def test_detector_names_isolate_state_even_for_same_group():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "c2-event"))
    manager.add("ddos", "host-a", event(0, "ddos-event"))

    assert manager.get_state("c2", "host-a").events[0].flow_id == "c2-event"
    assert manager.get_state("ddos", "host-a").events[0].flow_id == "ddos-event"


def test_context_window_is_distinct_from_scoring_interval():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "a"))

    emissions = manager.add("c2", "host-a", event(5, "b"))

    assert len(emissions) == 1
    assert emissions[0].scoring_end - emissions[0].scoring_start == timedelta(seconds=5)
    assert emissions[0].context_events == (event(0, "a"), event(5, "b"))


def test_window_requires_timestamp_order():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=10), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(5, "later"))

    with pytest.raises(ValueError, match="timestamp-ordered"):
        manager.add("c2", "host-a", event(4, "earlier"))


def test_scoring_emits_at_each_due_interval_without_losing_context():
    manager = DetectorWindowManager(WindowConfig(timedelta(seconds=20), timedelta(seconds=5)))
    manager.add("c2", "host-a", event(0, "a"))

    emissions = manager.add("c2", "host-a", event(16, "b"))

    assert len(emissions) == 3
    assert all(emission.context_events == (event(0, "a"), event(16, "b")) for emission in emissions)
