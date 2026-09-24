from pathlib import Path

from backend.app.config.detectors import DETECTOR_CONFIGS
from backend.app.detectors.zeek_flow_features import detector_features_from_zeek
from backend.app.ingestion.normalizer import normalize_zeek_record
from backend.app.ingestion.zeek_reader import iter_zeek_records
from backend.app.runtime_factory import create_orchestrator


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "zeek" / "dns53"


def test_real_zeek_conn_record_maps_only_explicit_contract_fields():
    record = next(iter_zeek_records(FIXTURE_DIR / "conn.log"))
    original = dict(record)

    features = detector_features_from_zeek(record)

    assert record == original
    assert features["Protocol"] == 17
    assert "Destination Port" not in features
    assert "Total Fwd Packets" not in features
    assert "Total Backward Packets" not in features
    assert "Flow Duration" not in features

    assert "Protocol" not in DETECTOR_CONFIGS["port_scan"].required_features
    assert "Protocol" in DETECTOR_CONFIGS["ddos"].required_features


def test_directional_aliases_are_withheld_for_zeek_flipped_direction():
    record = next(iter_zeek_records(FIXTURE_DIR / "conn.log"))

    features = detector_features_from_zeek(record)

    assert record["history"] == "D^"
    assert "Destination Port" not in features
    assert "Total Fwd Packets" not in features
    assert "Total Backward Packets" not in features


def test_non_connection_zeek_record_is_not_projected_as_a_flow():
    record = next(iter_zeek_records(FIXTURE_DIR / "dns.log"))

    features = detector_features_from_zeek(record)

    assert features == record
    assert "Destination Port" not in features
    assert "Total Fwd Packets" not in features


def test_real_fixture_replay_skips_incomplete_detector_contracts():
    orchestrator = create_orchestrator()
    for filename in ("conn.log", "dns.log"):
        for index, record in enumerate(iter_zeek_records(FIXTURE_DIR / filename)):
            event = normalize_zeek_record(record)
            orchestrator.process_event(event, event_id=f"{filename}:{index}")
    orchestrator.flush()

    metrics = orchestrator.get_metrics()
    failures = orchestrator.get_runtime_state()["runtime_failures"]

    assert metrics["events_processed"] == 2
    assert metrics["detector_invocations"] == 0
    assert metrics["detector_failures"] == 0
    assert metrics["alerts_produced"] == 0
    assert failures == []
