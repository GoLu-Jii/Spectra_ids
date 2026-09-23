from datetime import datetime, timezone

import pytest

from backend.app.ingestion.events import NormalizedEvent
from backend.app.ingestion.normalizer import EventNormalizationError, normalize_zeek_record


def test_valid_conn_event():
    event = normalize_zeek_record(
        {
            "event_type": "conn",
            "ts": "2026-09-23T12:00:00Z",
            "uid": "Cabc123",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": "44321",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": "443",
            "proto": "tcp",
            "orig_bytes": "100",
            "resp_bytes": "250",
            "orig_pkts": "2",
            "resp_pkts": "3",
        }
    )

    assert event.event_type == "conn"
    assert event.flow_id == "Cabc123"
    assert event.source_ip == "192.0.2.10"
    assert event.destination_port == 443
    assert event.bytes == 350
    assert event.packets == 5
    assert event.observed_at == datetime(2026, 9, 23, 12, tzinfo=timezone.utc)


def test_valid_dns_event():
    event = normalize_zeek_record(
        {
            "type": "dns",
            "ts": 1790164800,
            "uid": "Cdns123",
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "203.0.113.53",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "example.test",
            "qtype_name": "A",
        }
    )

    assert event.event_type == "dns"
    assert event.flow_id == "Cdns123"
    assert event.destination_port == 53
    assert event.raw_metadata["query"] == "example.test"
    assert event.observed_at.tzinfo is not None


def test_valid_tls_event():
    event = normalize_zeek_record(
        {
            "event_type": "ssl",
            "ts": "2026-09-23T12:00:01+02:00",
            "uid": "Cssl123",
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.30",
            "id.resp_p": "443",
            "version": "TLSv13",
            "server_name": "service.example.test",
        }
    )

    assert event.event_type == "ssl"
    assert event.observed_at == datetime(2026, 9, 23, 10, 0, 1, tzinfo=timezone.utc)
    assert event.raw_metadata["version"] == "TLSv13"


def test_malformed_event_is_rejected():
    with pytest.raises(EventNormalizationError, match="Invalid timestamp"):
        normalize_zeek_record(
            {
                "event_type": "conn",
                "ts": "not-a-timestamp",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
            }
        )


def test_missing_required_field_is_explicit():
    with pytest.raises(EventNormalizationError, match="dns event is missing required field: id.resp_h"):
        normalize_zeek_record(
            {
                "event_type": "dns",
                "ts": "2026-09-23T12:00:00Z",
                "id.orig_h": "192.0.2.10",
                "query": "example.test",
            }
        )


def test_naive_timestamp_is_rejected():
    with pytest.raises(EventNormalizationError, match="timezone"):
        normalize_zeek_record(
            {
                "event_type": "packet",
                "ts": "2026-09-23T12:00:00",
            }
        )


def test_unknown_optional_fields_are_preserved():
    event = normalize_zeek_record(
        {
            "event_type": "packet",
            "ts": "2026-09-23T12:00:00Z",
            "weird_future_field": {"value": 1},
        }
    )

    assert isinstance(event, NormalizedEvent)
    assert event.raw_metadata["weird_future_field"] == {"value": 1}
    assert event.source_ip is None
