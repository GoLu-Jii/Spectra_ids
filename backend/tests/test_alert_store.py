from datetime import datetime, timezone

import pytest

from backend.app.schemas.alert import Alert
from backend.app.stores import AlertStore, DuplicateAlertError


def alert(alert_id: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        timestamp=datetime(2026, 9, 23, tzinfo=timezone.utc),
        threat_class="TestThreat",
    )


def test_alert_store_create_get_and_list():
    store = AlertStore(max_size=2)
    first = store.create(alert("ALT-1"))
    second = store.create(alert("ALT-2"))

    assert store.get("ALT-1") == first
    assert store.list() == [first, second]


def test_alert_store_is_bounded_fifo():
    store = AlertStore(max_size=2)
    store.create(alert("ALT-1"))
    store.create(alert("ALT-2"))
    store.create(alert("ALT-3"))

    assert store.get("ALT-1") is None
    assert [item.alert_id for item in store.list()] == ["ALT-2", "ALT-3"]


def test_duplicate_alert_ids_are_rejected_deterministically():
    store = AlertStore()
    store.create(alert("ALT-1"))

    with pytest.raises(DuplicateAlertError):
        store.create(alert("ALT-1"))
