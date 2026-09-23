import json

import pytest

from backend.app.ingestion.zeek_reader import ZeekReadError, read_zeek_records


def test_reads_json_lines(tmp_path):
    path = tmp_path / "conn.json"
    path.write_text(
        json.dumps({"event_type": "conn", "ts": "2026-09-23T12:00:00Z"}) + "\n"
        + json.dumps({"event_type": "dns", "ts": "2026-09-23T12:00:01Z"}) + "\n",
        encoding="utf-8",
    )

    records = read_zeek_records(path)

    assert len(records) == 2
    assert records[1]["event_type"] == "dns"


def test_reads_zeek_tsv_with_header(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        "#separator \\x09\n"
        "#fields ts\tuid\tid.orig_h\tid.resp_h\n"
        "#types time\tstring\taddr\taddr\n"
        "2026-09-23T12:00:00Z\tC123\t192.0.2.10\t198.51.100.20\n",
        encoding="utf-8",
    )

    records = read_zeek_records(path)

    assert records == [
        {
            "ts": "2026-09-23T12:00:00Z",
            "uid": "C123",
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.20",
            "event_type": "conn",
        }
    ]


def test_reads_numeric_zeek_timestamp_for_normalization(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        "#fields ts\tid.orig_h\tid.resp_h\n"
        "1790164800\t192.0.2.10\t198.51.100.20\n",
        encoding="utf-8",
    )

    record = read_zeek_records(path)[0]

    assert record["event_type"] == "conn"
    assert record["ts"] == "1790164800"


def test_rejects_malformed_json_line(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"event_type": "conn"}\nnot-json\n', encoding="utf-8")

    with pytest.raises(ZeekReadError, match="line 2"):
        read_zeek_records(path)
