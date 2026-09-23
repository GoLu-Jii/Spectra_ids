from datetime import datetime, timedelta, timezone

import pytest

from backend.app.ingestion.events import NormalizedEvent
from backend.app.pipeline.ordering import (
    BufferOverflowError,
    ReorderBuffer,
    ReorderConfig,
)

BASE = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def event(seconds: int, flow_id: str) -> NormalizedEvent:
    return NormalizedEvent(
        observed_at=BASE + timedelta(seconds=seconds),
        event_type="conn",
        flow_id=flow_id,
    )


def test_in_order_events_release_by_watermark():
    buffer = ReorderBuffer(ReorderConfig(timedelta(seconds=2), 10))

    first = buffer.push(event(0, "a"))
    second = buffer.push(event(2, "b"))

    assert first.released == ()
    assert [entry.event.flow_id for entry in second.released] == ["a"]
    assert buffer.stats.events_accepted == 2
    assert buffer.stats.events_released == 1


def test_out_of_order_events_are_released_in_timestamp_order():
    buffer = ReorderBuffer(ReorderConfig(timedelta(seconds=3), 10))

    buffer.push(event(0, "a"))
    buffer.push(event(3, "c"))
    outcome = buffer.push(event(1, "b"))

    assert outcome.late is True
    assert [entry.event.flow_id for entry in buffer.flush()] == ["b", "c"]
    assert buffer.stats.late_events == 1


def test_event_within_allowed_lateness_is_accepted():
    buffer = ReorderBuffer(ReorderConfig(timedelta(seconds=5), 10))

    buffer.push(event(10, "new"))
    outcome = buffer.push(event(7, "late-but-allowed"))

    assert outcome.accepted is True
    assert outcome.too_late is False
    assert outcome.quarantined == ()
    assert [entry.event.flow_id for entry in buffer.flush()] == ["late-but-allowed", "new"]


def test_event_beyond_lateness_is_reported_and_quarantined():
    buffer = ReorderBuffer(
        ReorderConfig(timedelta(seconds=5), 10, late_event_behavior="quarantine")
    )

    buffer.push(event(10, "new"))
    outcome = buffer.push(event(1, "too-late"))

    assert outcome.accepted is False
    assert outcome.too_late is True
    assert [entry.event.flow_id for entry in outcome.quarantined] == ["too-late"]
    assert buffer.stats.too_late_events == 1
    assert [entry.event.flow_id for entry in buffer.flush()] == ["new"]


def test_buffer_overflow_releases_oldest_explicitly():
    buffer = ReorderBuffer(
        ReorderConfig(timedelta(seconds=60), 2, overflow_behavior="release_oldest")
    )

    buffer.push(event(0, "a"))
    buffer.push(event(1, "b"))
    outcome = buffer.push(event(2, "c"))

    assert [entry.event.flow_id for entry in outcome.released] == ["a"]
    assert buffer.stats.current_buffer_depth == 2
    assert buffer.stats.peak_buffer_depth == 2


def test_reject_overflow_does_not_silently_accept_event():
    buffer = ReorderBuffer(
        ReorderConfig(timedelta(seconds=60), 1, overflow_behavior="reject")
    )
    buffer.push(event(0, "a"))

    with pytest.raises(BufferOverflowError):
        buffer.push(event(1, "b"))


def test_event_identity_and_arrival_order_are_preserved():
    buffer = ReorderBuffer(ReorderConfig(timedelta(seconds=1), 10))
    original = event(0, "same-flow")

    buffer.push(original, event_id="source-record-1")
    released = buffer.flush()[0]

    assert released.event is original
    assert released.event_id == "source-record-1"
    assert released.arrival_index == 0
